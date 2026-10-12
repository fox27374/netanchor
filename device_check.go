package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	gnoicert "github.com/openconfig/gnoi/cert"
	"google.golang.org/grpc/metadata"
)

// deviceExpiryWarn is how close to expiry a certificate is highlighted.
const deviceExpiryWarn = 30 * 24 * time.Hour

// deviceReport is what one live check learned from the device.
type deviceReport struct {
	Model, Serial string // from the Cisco SUDI certificate, when present
	Certs         []DeviceCert
	Served        *DeviceCert
}

// deviceCheckResult is the outcome shown on the device page after a check.
type deviceCheckResult struct {
	Steps   []gnoiStep
	Outcome string
	Class   string // alert class: ok or err
	Refresh bool   // from Refresh certificates, shown in the certificates panel
}

// sudiSubject carries "PID:<model> SN:<serial>" in the subject serialNumber.
var sudiSubject = regexp.MustCompile(`PID:([^\s,]+)\s+SN:([^\s,]+)`)

// isCiscoSUDI reports whether a cert id is the device's factory identity (SUDI/IDEVID).
func isCiscoSUDI(id string) bool {
	return strings.HasPrefix(id, "CISCO_IDEVID")
}

// gnoiInspect connects to the device pinned to its fingerprint with the given credentials,
// lists its certificates and, when served is set, reads the certificate the gRPC
// port presents. It never changes the device.
func gnoiInspect(ctx context.Context, st *Store, allow []*net.IPNet, dev Device, creds deviceCreds, served bool, op string) (deviceReport, []gnoiStep, error) {
	var rep deviceReport
	run := &gnoiRun{device: dev.Name, op: op}
	if normalizeFingerprint(dev.Pin) == "" {
		return rep, run.steps, run.failed("connect", errNoPin)
	}
	req := gnoiPushRequest{Target: net.JoinHostPort(dev.ManagementIP, strconv.Itoa(dev.Port)), Fingerprint: dev.Pin}
	conn, err := gnoiDial(ctx, allow, req.Target, gnoiTLSConfig(req, nil))
	if err != nil {
		return rep, run.steps, run.failed("connect", err)
	}
	defer conn.Close()
	if err := gnoiWaitReady(ctx, conn); err != nil {
		return rep, run.steps, run.failed("connect", err)
	}
	run.ok("connect", "TLS connected to "+req.Target)

	authCtx := metadata.AppendToOutgoingContext(ctx, "username", creds.Username, "password", creds.Password)
	list, err := gnoicert.NewCertificateManagementClient(conn).GetCertificates(authCtx, &gnoicert.GetCertificatesRequest{})
	if err != nil {
		return rep, run.steps, run.failed("auth", gnoiRejected(err))
	}
	run.ok("auth", fmt.Sprintf("%d certificates listed", len(list.GetCertificateInfo())))

	for _, c := range list.GetCertificateInfo() {
		dc := parseDeviceCert(c.GetCertificateId(), c.GetCertificate().GetCertificate())
		rep.Certs = append(rep.Certs, dc)
		if isCiscoSUDI(c.GetCertificateId()) {
			if m := sudiSubject.FindStringSubmatch(dc.Subject); m != nil {
				rep.Model, rep.Serial = m[1], m[2]
			}
		}
	}
	if rep.Model != "" {
		run.ok("identity", "SUDI reports "+rep.Model+" serial "+rep.Serial)
	} else {
		run.ok("identity", "no SUDI certificate with PID and SN; model and serial unchanged")
	}

	if served {
		der, err := gnoiServedCert(ctx, allow, req.Target)
		if err != nil {
			return rep, run.steps, run.failed("served", err)
		}
		sc := parseDCert(der)
		rep.Served = &sc
		run.ok("served", "gRPC port presents "+sc.Subject)
	}
	return rep, run.steps, nil
}

// parseDeviceCert reads a device-reported PEM certificate. Unparseable input
// keeps the cert_id and leaves the rest empty.
func parseDeviceCert(id string, certPEM []byte) DeviceCert {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return DeviceCert{CertID: id}
	}
	dc := parseDCert(block.Bytes)
	dc.CertID = id
	return dc
}

// parseDCert fills subject, issuer, validity and SHA-256 fingerprint from DER.
func parseDCert(der []byte) DeviceCert {
	sum := sha256.Sum256(der)
	dc := DeviceCert{Fingerprint: hexColons(sum[:])}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return dc
	}
	dc.Subject, dc.Issuer = readableDN(c.Subject.String()), readableDN(c.Issuer.String())
	dc.NotBefore, dc.NotAfter = c.NotBefore, c.NotAfter
	return dc
}

// hexAttr matches an attribute Go prints as OID=#<hex DER>, e.g. Cisco's
// unstructuredName carrying the switch FQDN.
var hexAttr = regexp.MustCompile(`(\d+(?:\.\d+)+)=#([0-9a-f]+)`)

var attrNames = map[string]string{"1.2.840.113549.1.9.2": "unstructuredName", "1.2.840.113549.1.9.1": "emailAddress"}

// readableDN decodes string values of attributes Go only prints as hex.
func readableDN(dn string) string {
	return hexAttr.ReplaceAllStringFunc(dn, func(m string) string {
		sub := hexAttr.FindStringSubmatch(m)
		der, err := hex.DecodeString(sub[2])
		if err != nil {
			return m
		}
		var v string
		if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) != 0 {
			return m
		}
		name := sub[1]
		if n, ok := attrNames[name]; ok {
			name = n
		}
		return name + "=" + v
	})
}

// deviceExpiryClass highlights expired and soon-to-expire certificates. No alerts.
func deviceExpiryClass(notAfter, now time.Time) string {
	switch {
	case notAfter.IsZero():
		return ""
	case !notAfter.After(now):
		return "bad"
	case notAfter.Sub(now) < deviceExpiryWarn:
		return "warn"
	}
	return "lock"
}

// timeLeft is the remaining validity: days under a year, else years with one decimal.
func timeLeft(notAfter, now time.Time) string {
	if notAfter.IsZero() {
		return ""
	}
	d := notAfter.Sub(now)
	days := int(d.Hours() / 24)
	switch {
	case d <= 0:
		return "expired"
	case days == 1:
		return "1 day left"
	case days < 365:
		return fmt.Sprintf("%d days left", days)
	}
	return fmt.Sprintf("%.1f years left", d.Hours()/24/365.25)
}

// deviceCertRow is one certificate line with its time left and highlight class.
type deviceCertRow struct {
	DeviceCert
	Class, Left string
	GRPC        bool // the certificate the gRPC port presents
	SUDI        bool // Cisco factory identity; never revoked
}

func newDeviceCertRow(c DeviceCert, now time.Time) deviceCertRow {
	c.Subject, c.Issuer = readableDN(c.Subject), readableDN(c.Issuer) // snapshots stored before decoding existed
	return deviceCertRow{DeviceCert: c, Class: deviceExpiryClass(c.NotAfter, now), Left: timeLeft(c.NotAfter, now)}
}

// deviceSnapshotView turns a stored snapshot into rows for the device page.
func deviceSnapshotView(snap *DeviceSnapshot, now time.Time) (rows []deviceCertRow, served *deviceCertRow) {
	if snap == nil {
		return nil, nil
	}
	matched := false
	for _, c := range snap.Certs {
		row := newDeviceCertRow(c, now)
		row.SUDI = isCiscoSUDI(c.CertID)
		if snap.Served != nil && c.Fingerprint != "" && c.Fingerprint == snap.Served.Fingerprint {
			row.GRPC, matched = true, true
		}
		rows = append(rows, row)
	}
	if snap.Served != nil && !matched { // only shown separately when the device does not list it
		row := newDeviceCertRow(*snap.Served, now)
		served = &row
	}
	return rows, served
}

// deviceCheckCreds returns the stored credentials.
func (s *Server) deviceCheckCreds(dev Device) (deviceCreds, error) {
	if dev.Credentials != nil {
		return s.store.openCredentials(dev.Credentials)
	}
	return deviceCreds{}, errors.New("no credentials are stored: add them with Edit device")
}

// handleDeviceTest connects with the device's verification and credentials and
// fills model and serial from the SUDI certificate.
func (s *Server) handleDeviceTest(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceCheck(w, r, false)
}

// handleDeviceRefresh also reads the served certificate and stores the snapshot.
func (s *Server) handleDeviceRefresh(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceCheck(w, r, true)
}

func (s *Server) handleDeviceCheck(w http.ResponseWriter, r *http.Request, refresh bool) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
		return
	}
	dev, ok, err := s.store.GetDevice(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	creds, err := s.deviceCheckCreds(dev)
	if err != nil {
		s.renderDeviceDetail(w, r, dev, &deviceCheckResult{Outcome: err.Error(), Class: "err", Refresh: refresh}, "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gnoiPushTimeout)
	defer cancel()
	op := "test"
	if refresh {
		op = "refresh"
	}
	rep, steps, err := gnoiInspect(ctx, s.store, s.gnoiAllow, dev, creds, refresh, op)
	res := &deviceCheckResult{Steps: steps, Outcome: "Test connection succeeded.", Class: "ok", Refresh: refresh}
	if err != nil {
		res.Outcome, res.Class = "Failed at "+steps[len(steps)-1].Name+": "+err.Error(), "err"
		s.renderDeviceDetail(w, r, dev, res, "")
		return
	}
	now := time.Now().UTC()
	if refresh {
		res.Outcome = fmt.Sprintf("Certificates refreshed: %d listed.", len(rep.Certs))
		snap := &DeviceSnapshot{Taken: now, Certs: rep.Certs, Served: rep.Served}
		err = s.store.UpdateDevice(dev.ID, func(d *Device) { d.Snapshot = snap })
	} else if rep.Model != "" {
		err = s.store.UpdateDevice(dev.ID, func(d *Device) { d.Model, d.Serial = rep.Model, rep.Serial })
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	dev, _, _ = s.store.GetDevice(dev.ID)
	s.renderDeviceDetail(w, r, dev, res, "")
}

var (
	errRevokeSUDI   = errors.New("Cisco SUDI certificates are the device's factory identity and are never revoked")
	errRevokeServed = errors.New("the gRPC port presents this certificate; revoking it stops the gRPC server until it is fixed on the device CLI")
)

// gnoiRevoke removes one listed certificate from the device with gNOI RevokeCertificates.
// It refuses SUDI certificates and the certificate the gRPC port presents on the connection
// used for the revoke. NetAnchor's own certificate records are not changed.
func gnoiRevoke(ctx context.Context, allow []*net.IPNet, dev Device, creds deviceCreds, certID string) ([]gnoiStep, error) {
	run := &gnoiRun{device: dev.Name, op: "revoke"}
	if isCiscoSUDI(certID) {
		return run.steps, run.failed("check", errRevokeSUDI)
	}
	if normalizeFingerprint(dev.Pin) == "" {
		return run.steps, run.failed("connect", errNoPin)
	}
	req := gnoiPushRequest{Target: net.JoinHostPort(dev.ManagementIP, strconv.Itoa(dev.Port)), Fingerprint: dev.Pin}
	// The verified peer certificate of this connection is the one the gRPC port presents.
	var peer []byte
	cfg := gnoiTLSConfig(req, nil)
	pinned := cfg.VerifyPeerCertificate
	cfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		if err := pinned(raw, chains); err != nil {
			return err
		}
		peer = raw[0]
		return nil
	}
	conn, err := gnoiDial(ctx, allow, req.Target, cfg)
	if err != nil {
		return run.steps, run.failed("connect", err)
	}
	defer conn.Close()
	if err := gnoiWaitReady(ctx, conn); err != nil {
		return run.steps, run.failed("connect", err)
	}
	run.ok("connect", "TLS connected to "+req.Target)

	cli := gnoicert.NewCertificateManagementClient(conn)
	authCtx := metadata.AppendToOutgoingContext(ctx, "username", creds.Username, "password", creds.Password)
	list, err := cli.GetCertificates(authCtx, &gnoicert.GetCertificatesRequest{})
	if err != nil {
		return run.steps, run.failed("auth", gnoiRejected(err))
	}
	run.ok("auth", fmt.Sprintf("%d certificates listed", len(list.GetCertificateInfo())))

	var target []byte
	for _, c := range list.GetCertificateInfo() {
		if c.GetCertificateId() == certID {
			target = c.GetCertificate().GetCertificate()
			break
		}
	}
	if target == nil {
		return run.steps, run.failed("check", fmt.Errorf("certificate %q is not listed on the device", certID))
	}
	block, _ := pem.Decode(target)
	switch {
	case block == nil:
		return run.steps, run.failed("check", errors.New("cannot read the certificate, so it cannot be checked against the gRPC port"))
	case peer == nil:
		return run.steps, run.failed("check", errors.New("cannot read the certificate the gRPC port presents"))
	case bytes.Equal(block.Bytes, peer):
		return run.steps, run.failed("check", errRevokeServed)
	}
	run.ok("check", "not the gRPC certificate and not a SUDI certificate")

	resp, err := cli.RevokeCertificates(authCtx, &gnoicert.RevokeCertificatesRequest{CertificateId: []string{certID}})
	if err != nil {
		return run.steps, run.failed("revoke", gnoiRejected(err))
	}
	if errs := resp.GetCertificateRevocationError(); len(errs) > 0 {
		return run.steps, run.failed("revoke", fmt.Errorf("device refused: %s", errs[0].GetErrorMessage()))
	}
	if !slices.Contains(resp.GetRevokedCertificateId(), certID) {
		return run.steps, run.failed("revoke", errors.New("device did not confirm the revocation"))
	}
	run.ok("revoke", fmt.Sprintf("device revoked %q", certID))
	return run.steps, nil
}

// handleDeviceRevoke removes one certificate from the switch when the confirmation box is
// ticked, then refreshes the snapshot on a fresh connection. NetAnchor records stay as they are.
func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
		return
	}
	dev, ok, err := s.store.GetDevice(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	certID := r.PostForm.Get("cert_id")
	if certID == "" {
		s.renderDeviceDetail(w, r, dev, &deviceCheckResult{Outcome: "no certificate was chosen", Class: "err", Refresh: true}, "")
		return
	}
	if r.PostForm.Get("confirm") != "on" {
		s.renderDeviceDetail(w, r, dev, &deviceCheckResult{Outcome: "tick the confirmation box to remove " + certID + " from the switch", Class: "err", Refresh: true}, "")
		return
	}
	creds, err := s.deviceCheckCreds(dev)
	if err != nil {
		s.renderDeviceDetail(w, r, dev, &deviceCheckResult{Outcome: err.Error(), Class: "err", Refresh: true}, "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gnoiPushTimeout)
	defer cancel()
	steps, err := gnoiRevoke(ctx, s.gnoiAllow, dev, creds, certID)
	res := &deviceCheckResult{Steps: steps, Outcome: "Removed " + certID + " from the switch.", Class: "ok", Refresh: true}
	if err != nil {
		res.Outcome, res.Class = "Failed at "+steps[len(steps)-1].Name+": "+err.Error(), "err"
	}
	// Refresh whenever the revoke was sent, so the snapshot shows what the switch now holds.
	if steps[len(steps)-1].Name == "revoke" {
		refreshCtx, cancelRefresh := context.WithTimeout(r.Context(), gnoiPushTimeout)
		defer cancelRefresh()
		rep, rsteps, rerr := gnoiInspect(refreshCtx, s.store, s.gnoiAllow, dev, creds, true, "refresh")
		res.Steps = append(res.Steps, rsteps...)
		if rerr != nil {
			res.Outcome, res.Class = res.Outcome+" The snapshot was not refreshed: "+rerr.Error(), "err"
		} else {
			snap := &DeviceSnapshot{Taken: time.Now().UTC(), Certs: rep.Certs, Served: rep.Served}
			if err := s.store.UpdateDevice(dev.ID, func(d *Device) { d.Snapshot = snap }); err != nil {
				s.fail(w, r, err)
				return
			}
			res.Outcome += fmt.Sprintf(" Certificates refreshed: %d listed.", len(rep.Certs))
		}
	}
	dev, _, _ = s.store.GetDevice(dev.ID)
	s.renderDeviceDetail(w, r, dev, res, "")
}

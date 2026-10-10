package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	gnoicert "github.com/openconfig/gnoi/cert"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
}

// sudiSubject carries "PID:<model> SN:<serial>" in the subject serialNumber.
var sudiSubject = regexp.MustCompile(`PID:([^\s,]+)\s+SN:([^\s,]+)`)

// gnoiInspect connects to the device with the given verification and credentials,
// lists its certificates and, when served is set, reads the certificate the gRPC
// port presents. It never changes the device.
func gnoiInspect(ctx context.Context, st *Store, allow []*net.IPNet, dev Device, creds deviceCreds, served bool) (deviceReport, []gnoiStep, error) {
	var rep deviceReport
	run := &gnoiRun{}
	req := gnoiPushRequest{Target: net.JoinHostPort(dev.ManagementIP, strconv.Itoa(dev.Port)), Verify: dev.Verify, Fingerprint: dev.Pin}
	var roots *x509.CertPool
	if dev.Verify == gnoiVerifyCA {
		chainPEM, err := st.IssuerChainPEM(dev.CAID)
		if err != nil {
			return rep, run.steps, run.failed("connect", err)
		}
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM(chainPEM)
	}
	conn, err := gnoiDial(ctx, allow, req.Target, gnoiTLSConfig(req, roots, nil))
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
		return rep, run.steps, run.failed("auth", fmt.Errorf("device rejected the request: %s", status.Convert(err).Message()))
	}
	run.ok("auth", fmt.Sprintf("%d certificates listed", len(list.GetCertificateInfo())))

	for _, c := range list.GetCertificateInfo() {
		dc := parseDeviceCert(c.GetCertificateId(), c.GetCertificate().GetCertificate())
		rep.Certs = append(rep.Certs, dc)
		if strings.HasPrefix(c.GetCertificateId(), "CISCO_IDEVID") {
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
	dc.Subject, dc.Issuer = c.Subject.String(), c.Issuer.String()
	dc.NotBefore, dc.NotAfter = c.NotBefore, c.NotAfter
	return dc
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
	return ""
}

// deviceCertRow is one snapshot line with its highlight class.
type deviceCertRow struct {
	DeviceCert
	Class string
}

// deviceSnapshotView turns a stored snapshot into rows for the device page.
func deviceSnapshotView(snap *DeviceSnapshot, now time.Time) (rows []deviceCertRow, served *deviceCertRow) {
	if snap == nil {
		return nil, nil
	}
	for _, c := range snap.Certs {
		rows = append(rows, deviceCertRow{DeviceCert: c, Class: deviceExpiryClass(c.NotAfter, now)})
	}
	if snap.Served != nil {
		served = &deviceCertRow{DeviceCert: *snap.Served, Class: deviceExpiryClass(snap.Served.NotAfter, now)}
	}
	return rows, served
}

// deviceCheckCreds returns the stored credentials, or the ones posted for this
// check when none are stored. The password is never stored or echoed here.
func (s *Server) deviceCheckCreds(dev Device, p url.Values) (deviceCreds, error) {
	if dev.Credentials != nil {
		return s.store.openCredentials(dev.Credentials)
	}
	u, pw := strings.TrimSpace(p.Get("username")), p.Get("password")
	if u == "" || pw == "" {
		return deviceCreds{}, errors.New("no credentials are stored: enter the username and password for this check")
	}
	return deviceCreds{Username: u, Password: pw}, nil
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
	creds, err := s.deviceCheckCreds(dev, r.PostForm)
	if err != nil {
		s.renderDeviceDetail(w, r, dev, nil, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gnoiPushTimeout)
	defer cancel()
	rep, steps, err := gnoiInspect(ctx, s.store, s.gnoiAllow, dev, creds, refresh)
	res := &deviceCheckResult{Steps: steps, Outcome: "Test connection succeeded.", Class: "ok"}
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

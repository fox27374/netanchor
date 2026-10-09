package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	gnoicert "github.com/openconfig/gnoi/cert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Timeouts for one push. The verify window sits inside the overall budget: the
// push fails early only if the budget ends first.
const (
	gnoiConnectTimeout = 10 * time.Second
	gnoiPushTimeout    = 60 * time.Second
	gnoiVerifyAttempt  = 5 * time.Second
	gnoiBackdate       = 24 * time.Hour // switch clocks are often off; the lab switch ran 12 min behind
)

// Verify retry window and spacing. Vars so tests can shorten them.
var (
	gnoiVerifyWindow   = 30 * time.Second
	gnoiVerifyInterval = 2 * time.Second
)

// Server verification modes for the device's gRPC certificate.
const (
	gnoiVerifyCA          = "ca"          // device cert must chain to the selected NetAnchor CA
	gnoiVerifyFingerprint = "fingerprint" // device cert must match a SHA-256 fingerprint the admin confirmed
	gnoiVerifyUnverified  = "unverified"  // no server check: credentials can be intercepted
)

// errGNOIUnverified means the certificate was sent to the device but the verify
// step never saw it. It is not a failed push.
var errGNOIUnverified = errors.New("installed, could not verify, check the device (it may have rebound its gRPC server)")

// gnoiPushRequest is one admin push. Password is used for gRPC metadata only.
type gnoiPushRequest struct {
	Target       string // host:port of the device gRPC server
	Username     string
	Password     string
	Verify       string
	CAID         string // trusted NetAnchor CA (verify=ca) and issuing CA
	Fingerprint  string // pinned server SHA-256 (verify=fingerprint)
	CAPassphrase string
	Template     CertTemplate
	CommonName   string
	Country      string
	State        string
	City         string
	Organization string
	DNSNames     []string
	IPs          []net.IP
	CertID       string
	ValidDays    int
	Admin        string
}

// gnoiStep is one line of the step-by-step result.
type gnoiStep struct {
	Name   string
	Status string // ok, failed or unconfirmed
	Detail string
}

// gnoiPush runs connect, auth, capabilities, generate, sign, install and verify.
// It returns nil when the install is verified, errGNOIUnverified when it was sent
// but not seen again, and any other error for a failed push. Once a serial exists,
// the outcome is recorded on that certificate.
func gnoiPush(ctx context.Context, st *Store, allow []*net.IPNet, req gnoiPushRequest) (steps []gnoiStep, err error) {
	run := &gnoiRun{}
	var serial string
	defer func() {
		if serial == "" {
			return
		}
		outcome := "installed and verified"
		switch {
		case errors.Is(err, errGNOIUnverified):
			outcome = errGNOIUnverified.Error()
		case err != nil:
			outcome = "failed at " + run.last() + ": " + err.Error()
		}
		log.Printf("gNOI push to %s cert %s: %s", req.Target, req.CertID, outcome)
		if rerr := st.AddPush(serial, DevicePush{Target: req.Target, CertID: req.CertID, Admin: req.Admin, Time: time.Now(), Outcome: outcome}); rerr != nil {
			log.Printf("gNOI push: recording outcome for %s: %v", serial, rerr)
		}
	}()
	defer func() { steps = run.steps }()

	if err := validateGNOIRequest(req); err != nil {
		return nil, err
	}
	caCert, caKey, err := loadCA(st, req.CAID, req.CAPassphrase)
	if err != nil {
		return nil, err
	}
	chainPEM, err := st.IssuerChainPEM(req.CAID)
	if err != nil {
		return nil, err
	}
	chain, err := gnoiChainCerts(chainPEM)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(chainPEM)
	tlsCfg := gnoiTLSConfig(req, roots, nil)

	conn, err := gnoiDial(ctx, allow, req.Target, tlsCfg)
	if err != nil {
		return nil, run.failed("connect", err)
	}
	defer conn.Close()
	if err := gnoiWaitReady(ctx, conn); err != nil {
		return nil, run.failed("connect", err)
	}
	run.ok("connect", "TLS connected to "+req.Target)

	cli := gnoicert.NewCertificateManagementClient(conn)
	authCtx := metadata.AppendToOutgoingContext(ctx, "username", req.Username, "password", req.Password)
	list, err := cli.GetCertificates(authCtx, &gnoicert.GetCertificatesRequest{})
	if err != nil {
		return nil, run.failed("auth", fmt.Errorf("device rejected the request: %s", status.Convert(err).Message()))
	}
	for _, c := range list.GetCertificateInfo() {
		if c.GetCertificateId() == req.CertID {
			return nil, run.failed("auth", fmt.Errorf("certificate id %q already exists on the device; this phase only installs new ids", req.CertID))
		}
	}
	run.ok("auth", fmt.Sprintf("%d certificates listed", len(list.GetCertificateInfo())))

	caps, err := cli.CanGenerateCSR(authCtx, &gnoicert.CanGenerateCSRRequest{KeyType: gnoicert.KeyType_KT_RSA, CertificateType: gnoicert.CertificateType_CT_X509, KeySize: 2048})
	if err != nil {
		return nil, run.failed("capabilities", err)
	}
	if !caps.GetCanGenerate() {
		return nil, run.failed("capabilities", errors.New("device cannot generate an RSA 2048 CSR"))
	}
	run.ok("capabilities", "RSA 2048 CSR supported")

	stream, err := cli.Install(authCtx)
	if err != nil {
		return nil, run.failed("generate", err)
	}
	if err := stream.Send(&gnoicert.InstallCertificateRequest{InstallRequest: &gnoicert.InstallCertificateRequest_GenerateCsr{GenerateCsr: &gnoicert.GenerateCSRRequest{
		CertificateId: req.CertID,
		CsrParams: &gnoicert.CSRParams{
			Type: gnoicert.CertificateType_CT_X509, KeyType: gnoicert.KeyType_KT_RSA, MinKeySize: 2048,
			CommonName: req.CommonName, Country: req.Country, State: req.State, City: req.City, Organization: req.Organization,
		},
	}}}); err != nil {
		return nil, run.failed("generate", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, run.failed("generate", err)
	}
	csrPEM := resp.GetGeneratedCsr().GetCsr().GetCsr()
	if len(csrPEM) == 0 {
		return nil, run.failed("generate", errors.New("device returned no CSR"))
	}
	run.ok("generate", "device generated the key and CSR")

	rec, der, err := gnoiSignCSR(st, req, csrPEM, caCert, caKey)
	if err != nil {
		return nil, run.failed("sign", err)
	}
	serial = rec.Serial
	run.ok("sign", "signed as serial "+serial)

	certPEM := encodeCertPEM(der)
	if err := stream.Send(&gnoicert.InstallCertificateRequest{InstallRequest: &gnoicert.InstallCertificateRequest_LoadCertificate{LoadCertificate: &gnoicert.LoadCertificateRequest{
		Certificate:    &gnoicert.Certificate{Type: gnoicert.CertificateType_CT_X509, Certificate: certPEM},
		CaCertificates: chain,
	}}}); err != nil && !errors.Is(err, io.EOF) {
		return nil, run.failed("install", err)
	}
	_ = stream.CloseSend()
	// The device resets open calls after a load, so Unavailable here does not mean the install failed.
	// The verify step decides.
	resp, err = stream.Recv()
	switch {
	case err == nil && resp.GetLoadCertificate() != nil:
		run.ok("install", "device accepted the certificate")
	case err == nil, errors.Is(err, io.EOF), status.Code(err) == codes.Unavailable:
		run.ok("install", "device reset the install stream; verifying on a new connection")
	default:
		return nil, run.failed("install", err)
	}

	verifyCfg := gnoiTLSConfig(req, roots, der)
	deadline := time.Now().Add(gnoiVerifyWindow)
	attempts := 0
	for {
		attempts++
		if seen, verr := gnoiSeenOnDevice(ctx, allow, req, verifyCfg, certPEM); verr == nil && seen {
			run.ok("verify", fmt.Sprintf("certificate %q present on device (attempt %d)", req.CertID, attempts))
			return nil, nil
		}
		if ctx.Err() != nil || !time.Now().Add(gnoiVerifyInterval).Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(gnoiVerifyInterval):
		}
	}
	run.steps = append(run.steps, gnoiStep{Name: "verify", Status: "unconfirmed", Detail: fmt.Sprintf("no answer with the certificate after %d attempts", attempts)})
	return nil, errGNOIUnverified
}

// validateGNOIRequest checks the form before any device is contacted.
func validateGNOIRequest(req gnoiPushRequest) error {
	switch {
	case req.Username == "" || req.Password == "":
		return errors.New("device username and password are required")
	case strings.TrimSpace(req.CommonName) == "":
		return errors.New("common name is required")
	case req.Country == "" || req.State == "" || req.Organization == "":
		return errors.New("country, state and organization are required by the device")
	case !validCertID(req.CertID):
		return errors.New("certificate id must be 1-64 letters, digits, '.', '-' or '_'")
	}
	if !allowedAlgo(req.Template, algoRSA2048) {
		return errors.New("the selected profile does not allow RSA 2048 keys, which the device requires")
	}
	if err := validateIssuePolicy(req.Template, req.CAID, req.ValidDays, algoRSA2048, req.CommonName, req.DNSNames, req.IPs, nil, nil); err != nil {
		return err
	}
	switch req.Verify {
	case gnoiVerifyCA:
	case gnoiVerifyFingerprint:
		if normalizeFingerprint(req.Fingerprint) == "" {
			return errors.New("fetch and confirm the device fingerprint first")
		}
	case gnoiVerifyUnverified:
	default:
		return errors.New("choose how to verify the device")
	}
	return nil
}

// validCertID keeps ids short and free of path or URL characters.
func validCertID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// gnoiSignCSR signs the device's CSR under the normal sign-CSR rules. The
// device's key and subject are kept; SANs come from the form and any device
// extensions are dropped. The subject CN must match the request.
func gnoiSignCSR(st *Store, req gnoiPushRequest, csrPEM []byte, caCert *x509.Certificate, caKey crypto.Signer) (CertRecord, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return CertRecord{}, nil, errors.New("device did not return a PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return CertRecord{}, nil, fmt.Errorf("parsing device CSR: %w", err)
	}
	if csr.Subject.CommonName != req.CommonName {
		return CertRecord{}, nil, fmt.Errorf("device CSR common name %q does not match the request", csr.Subject.CommonName)
	}
	signed := *csr
	signed.DNSNames, signed.IPAddresses = req.DNSNames, req.IPs
	signed.EmailAddresses, signed.URIs = nil, nil
	signed.Extensions = nil
	rec, der, err := signCSRWithoutPersistence(&signed, SignCSRParams{IssuerID: req.CAID, ValidDays: req.ValidDays, Template: req.Template, TemplateName: req.Template.Name, Profile: req.Template.Profile, Backdate: gnoiBackdate}, caCert, caKey, false)
	if err != nil {
		return CertRecord{}, nil, err
	}
	if err := st.SaveCert(rec.Serial, encodeCertPEM(der), nil); err != nil {
		return CertRecord{}, nil, err
	}
	return rec, der, st.AddRecord(rec)
}

// gnoiChainCerts splits the issuer chain PEM into the LoadCertificate chain.
func gnoiChainCerts(chainPEM []byte) ([]*gnoicert.Certificate, error) {
	var out []*gnoicert.Certificate
	for rest := chainPEM; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		out = append(out, &gnoicert.Certificate{Type: gnoicert.CertificateType_CT_X509, Certificate: pem.EncodeToMemory(block)})
	}
	if len(out) == 0 {
		return nil, errors.New("issuer chain is empty")
	}
	return out, nil
}

// gnoiSeenOnDevice opens a fresh connection and reports whether the device lists
// certID with the certificate we sent.
func gnoiSeenOnDevice(ctx context.Context, allow []*net.IPNet, req gnoiPushRequest, cfg *tls.Config, certPEM []byte) (bool, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, gnoiVerifyAttempt)
	defer cancel()
	conn, err := gnoiDial(attemptCtx, allow, req.Target, cfg)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if err := gnoiWaitReady(attemptCtx, conn); err != nil {
		return false, err
	}
	want, _ := pem.Decode(certPEM)
	list, err := gnoicert.NewCertificateManagementClient(conn).GetCertificates(
		metadata.AppendToOutgoingContext(attemptCtx, "username", req.Username, "password", req.Password), &gnoicert.GetCertificatesRequest{})
	if err != nil {
		return false, err
	}
	for _, c := range list.GetCertificateInfo() {
		if c.GetCertificateId() != req.CertID {
			continue
		}
		got, _ := pem.Decode(c.GetCertificate().GetCertificate())
		if got != nil && want != nil && bytes.Equal(got.Bytes, want.Bytes) {
			return true, nil
		}
	}
	return false, nil
}

// gnoiTLSConfig builds the server check for a push. newDER is the certificate
// NetAnchor just issued; in fingerprint mode it is also accepted during verify,
// because the device may rebind its server to it.
func gnoiTLSConfig(req gnoiPushRequest, roots *x509.CertPool, newDER []byte) *tls.Config {
	switch req.Verify {
	case gnoiVerifyCA:
		return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	case gnoiVerifyFingerprint:
		want := normalizeFingerprint(req.Fingerprint)
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("device sent no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) == want || (newDER != nil && bytes.Equal(raw[0], newDER)) {
				return nil
			}
			return errors.New("device certificate does not match the confirmed fingerprint")
		}}
	default:
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // unverified: the form warns the admin
	}
}

// gnoiResolve checks every address the host resolves to against the allowlist
// and returns the first one. The caller dials that address, so DNS cannot change
// the target after the check.
func gnoiResolve(ctx context.Context, allow []*net.IPNet, target string) (host, port string, ip net.IP, err error) {
	host, port, err = net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", "", nil, errors.New("target must be host:port")
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return "", "", nil, errors.New("target port must be 1-65535")
	}
	if len(allow) == 0 {
		return "", "", nil, errors.New("no device targets are allowed: set NETANCHOR_GNOI_ALLOW")
	}
	ips, err := gnoiResolveIPs(ctx, host)
	if err != nil {
		return "", "", nil, err
	}
	ip, err = gnoiCheckAllowed(allow, host, ips)
	return host, port, ip, err
}

// gnoiResolveIPs returns every address host resolves to (or host itself if it is an IP).
func gnoiResolveIPs(ctx context.Context, host string) ([]net.IP, error) {
	if lit := net.ParseIP(host); lit != nil {
		return []net.IP{lit}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s did not resolve", host)
	}
	return ips, nil
}

// gnoiCheckAllowed requires every address to be allowed and returns the first.
func gnoiCheckAllowed(allow []*net.IPNet, host string, ips []net.IP) (net.IP, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s did not resolve", host)
	}
	for _, a := range ips {
		if !gnoiAllowed(allow, a) {
			return nil, fmt.Errorf("%s resolves to %s, which is outside NETANCHOR_GNOI_ALLOW", host, a)
		}
	}
	return ips[0], nil
}

// gnoiAllowed reports whether ip is inside any allowed network.
func gnoiAllowed(allow []*net.IPNet, ip net.IP) bool {
	for _, n := range allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseGNOIAllow parses NETANCHOR_GNOI_ALLOW, a comma-separated list of CIDRs.
func parseGNOIAllow(v string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR (for example 192.0.2.10/32)", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// gnoiDial opens a TLS gRPC connection to the checked address. The TLS name is
// the host from the target, so verification still uses the name.
func gnoiDial(ctx context.Context, allow []*net.IPNet, target string, cfg *tls.Config) (*grpc.ClientConn, error) {
	host, port, ip, err := gnoiResolve(ctx, allow, target)
	if err != nil {
		return nil, err
	}
	c := cfg.Clone()
	if c.ServerName == "" {
		c.ServerName = host
	}
	return grpc.NewClient("passthrough:///"+net.JoinHostPort(ip.String(), port), grpc.WithTransportCredentials(credentials.NewTLS(c)))
}

// gnoiWaitReady waits for the connection to become ready, bounded by the connect timeout.
func gnoiWaitReady(ctx context.Context, conn *grpc.ClientConn) error {
	waitCtx, cancel := context.WithTimeout(ctx, gnoiConnectTimeout)
	defer cancel()
	conn.Connect()
	for {
		state := conn.GetState()
		switch state {
		case connectivity.Ready:
			return nil
		case connectivity.TransientFailure, connectivity.Shutdown:
			return fmt.Errorf("connection failed (%s): check the address, the TLS trust choice and that gRPC is enabled", state)
		}
		if !conn.WaitForStateChange(waitCtx, state) {
			return fmt.Errorf("no connection within %s", gnoiConnectTimeout)
		}
	}
}

// gnoiProbe fetches the device's server certificate fingerprint for confirmation.
// It does a TLS handshake only; no credentials are sent.
func gnoiProbe(ctx context.Context, allow []*net.IPNet, target string) (string, error) {
	host, port, ip, err := gnoiResolve(ctx, allow, target)
	if err != nil {
		return "", err
	}
	dialCtx, cancel := context.WithTimeout(ctx, gnoiConnectTimeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"h2"}}}
	c, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("device sent no certificate")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hexColons(sum[:]), nil
}

// normalizeFingerprint makes "AA:BB..." and "aabb..." compare equal.
func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
}

// gnoiRun collects the step-by-step result.
type gnoiRun struct {
	steps []gnoiStep
}

func (r *gnoiRun) ok(name, detail string) {
	r.steps = append(r.steps, gnoiStep{Name: name, Status: "ok", Detail: detail})
}

func (r *gnoiRun) failed(name string, err error) error {
	r.steps = append(r.steps, gnoiStep{Name: name, Status: "failed", Detail: err.Error()})
	return err
}

func (r *gnoiRun) last() string {
	if len(r.steps) == 0 {
		return "start"
	}
	return r.steps[len(r.steps)-1].Name
}

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gnoicert "github.com/openconfig/gnoi/cert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	testDevUser = "lab-device-user"
	testDevPass = "s3cret-device-pass"
)

// fakeGNOIDevice implements the cert service the way the lab switch behaves.
type fakeGNOIDevice struct {
	gnoicert.UnimplementedCertificateManagementServer
	mu        sync.Mutex
	installed map[string][]byte // cert id -> PEM as listed by GetCertificates
	existing  []string          // ids already on the device before the test
	loadMode  string            // ok, error, silent (accept, never list), reset (list, then Unavailable)
	csrAlg    x509.SignatureAlgorithm
	loads     int
	getCalls  int
	lastCert  []byte // PEM the device received in LoadCertificate
	lastChain int    // number of CA certificates received with it
	devPubKey *rsa.PublicKey
	sudi      []byte // PEM of a CISCO_IDEVID certificate listed by GetCertificates; nil = none
}

type devSnap struct {
	loads, chain, getCalls int
	cert                   []byte
	pub                    *rsa.PublicKey
}

func (f *fakeGNOIDevice) snap() devSnap {
	f.mu.Lock()
	defer f.mu.Unlock()
	return devSnap{loads: f.loads, chain: f.lastChain, getCalls: f.getCalls, cert: f.lastCert, pub: f.devPubKey}
}

func (f *fakeGNOIDevice) auth(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("username"); len(v) != 1 || v[0] != testDevUser {
		return status.Error(codes.Unauthenticated, "bad credentials")
	}
	if v := md.Get("password"); len(v) != 1 || v[0] != testDevPass {
		return status.Error(codes.Unauthenticated, "bad credentials")
	}
	return nil
}

func (f *fakeGNOIDevice) GetCertificates(ctx context.Context, _ *gnoicert.GetCertificatesRequest) (*gnoicert.GetCertificatesResponse, error) {
	if err := f.auth(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	resp := &gnoicert.GetCertificatesResponse{}
	for _, id := range f.existing {
		resp.CertificateInfo = append(resp.CertificateInfo, &gnoicert.CertificateInfo{CertificateId: id, Certificate: &gnoicert.Certificate{Type: gnoicert.CertificateType_CT_X509, Certificate: []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")}})
	}
	if f.sudi != nil {
		resp.CertificateInfo = append(resp.CertificateInfo, &gnoicert.CertificateInfo{CertificateId: "CISCO_IDEVID_SUDI", Certificate: &gnoicert.Certificate{Type: gnoicert.CertificateType_CT_X509, Certificate: f.sudi}})
	}
	for id, c := range f.installed {
		resp.CertificateInfo = append(resp.CertificateInfo, &gnoicert.CertificateInfo{CertificateId: id, Certificate: &gnoicert.Certificate{Type: gnoicert.CertificateType_CT_X509, Certificate: c}})
	}
	return resp, nil
}

func (f *fakeGNOIDevice) CanGenerateCSR(ctx context.Context, req *gnoicert.CanGenerateCSRRequest) (*gnoicert.CanGenerateCSRResponse, error) {
	if err := f.auth(ctx); err != nil {
		return nil, err
	}
	return &gnoicert.CanGenerateCSRResponse{CanGenerate: req.GetKeyType() == gnoicert.KeyType_KT_RSA && req.GetKeySize() == 2048}, nil
}

// Install mirrors the IOS-XE behaviour seen in Phase 0: GenerateCSR needs
// country, state and organization; LoadCertificate resets the call.
func (f *fakeGNOIDevice) Install(stream grpc.BidiStreamingServer[gnoicert.InstallCertificateRequest, gnoicert.InstallCertificateResponse]) error {
	if err := f.auth(stream.Context()); err != nil {
		return err
	}
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	gen := req.GetGenerateCsr()
	if gen == nil {
		return status.Error(codes.InvalidArgument, "first message must be GenerateCsr")
	}
	p := gen.GetCsrParams()
	if p.GetCountry() == "" || p.GetState() == "" || p.GetOrganization() == "" {
		return status.Error(codes.InvalidArgument, "country, state and organization are required")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.devPubKey = &key.PublicKey
	f.mu.Unlock()
	// The device CSR carries SANs and an extension the push must ignore.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: p.GetCommonName(), Country: []string{p.GetCountry()}, Province: []string{p.GetState()}, Organization: []string{p.GetOrganization()}},
		DNSNames:           []string{"device.example"},
		IPAddresses:        []net.IP{net.ParseIP("10.10.10.10")},
		SignatureAlgorithm: f.csrAlg,
	}, key)
	if err != nil {
		return err
	}
	if err := stream.Send(&gnoicert.InstallCertificateResponse{InstallResponse: &gnoicert.InstallCertificateResponse_GeneratedCsr{GeneratedCsr: &gnoicert.GenerateCSRResponse{
		Csr: &gnoicert.CSR{Type: gnoicert.CertificateType_CT_X509, Csr: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})},
	}}}); err != nil {
		return err
	}
	req, err = stream.Recv()
	if err != nil {
		return err
	}
	load := req.GetLoadCertificate()
	if load == nil {
		return status.Error(codes.InvalidArgument, "expected LoadCertificate")
	}
	f.mu.Lock()
	f.loads++
	f.lastCert = load.GetCertificate().GetCertificate()
	f.lastChain = len(load.GetCaCertificates())
	mode := f.loadMode
	f.mu.Unlock()
	switch mode {
	case "error":
		return status.Error(codes.InvalidArgument, "device rejected certificate")
	case "silent":
		// Accepted but never listed: the verify step must give up.
	default:
		f.mu.Lock()
		if f.installed == nil {
			f.installed = map[string][]byte{}
		}
		f.installed[gen.GetCertificateId()] = f.lastCert
		f.mu.Unlock()
	}
	if mode == "reset" {
		return status.Error(codes.Unavailable, "Cancelling all calls")
	}
	return stream.Send(&gnoicert.InstallCertificateResponse{InstallResponse: &gnoicert.InstallCertificateResponse_LoadCertificate{LoadCertificate: &gnoicert.LoadCertificateResponse{}}})
}

// gnoiTestEnv is a store with a root CA, a fake device on loopback, and a request that targets it.
type gnoiTestEnv struct {
	store  *Store
	dev    *fakeGNOIDevice
	caCert *x509.Certificate
	caKey  any
	server *tls.Certificate
	allow  []*net.IPNet
	target string
	fp     string
}

func newGNOITestEnv(t *testing.T, dev *fakeGNOIDevice) *gnoiTestEnv {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(st, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000}); err != nil {
		t.Fatal(err)
	}
	caCert, caKey, err := loadCA(st, caRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	// Device server cert issued by the NetAnchor root, for loopback.
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "device"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, caCert, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srvCert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{*srvCert}})))
	gnoicert.RegisterCertificateManagementServer(srv, dev)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	allow, err := parseGNOIAllow("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	return &gnoiTestEnv{store: st, dev: dev, caCert: caCert, caKey: caKey, server: srvCert, allow: allow, target: lis.Addr().String(), fp: sha256Of(der)}
}

func sha256Of(der []byte) string {
	sum := sha256.Sum256(der)
	return hexColons(sum[:])
}

func (e *gnoiTestEnv) request(t *testing.T) gnoiPushRequest {
	t.Helper()
	tpl, ok := builtinByName("TLS-Server")
	if !ok {
		t.Fatal("missing builtin profile")
	}
	return gnoiPushRequest{
		Target: e.target, Username: testDevUser, Password: testDevPass, Verify: gnoiVerifyCA, CAID: caRoot,
		Template: tpl, CommonName: "switch.example.net", Country: "NL", State: "Zuid-Holland", Organization: "Example",
		DNSNames: []string{"switch.example.net"}, IPs: []net.IP{net.ParseIP("192.0.2.10")},
		CertID: "netanchor-test", ValidDays: tpl.ValidDays, Admin: "tester",
	}
}

// certRecords returns the leaf certificates (the root CA record is excluded).
func certRecords(t *testing.T, st *Store) []CertRecord {
	t.Helper()
	recs, err := st.Records()
	if err != nil {
		t.Fatal(err)
	}
	var out []CertRecord
	for _, r := range recs {
		if r.Kind == "csr" {
			out = append(out, r)
		}
	}
	return out
}

func stepNames(steps []gnoiStep) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.Name+"="+s.Status)
	}
	return out
}

func TestGNOIPushHappyPath(t *testing.T) {
	dev := &fakeGNOIDevice{}
	e := newGNOITestEnv(t, dev)
	req := e.request(t)

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	steps, err := gnoiPush(context.Background(), e.store, e.allow, req)
	if err != nil {
		t.Fatalf("push failed: %v (steps %v)", err, stepNames(steps))
	}
	want := "connect=ok auth=ok capabilities=ok generate=ok sign=ok install=ok verify=ok"
	if got := strings.Join(stepNames(steps), " "); got != want {
		t.Fatalf("steps = %q, want %q", got, want)
	}
	d := dev.snap()
	if d.loads != 1 || d.chain != 1 {
		t.Fatalf("device got %d loads and %d CA certs, want 1 and 1 (root only)", d.loads, d.chain)
	}

	recs, _ := e.store.Records()
	var rec CertRecord
	for _, r := range recs {
		if r.Kind == "csr" {
			rec = r
		}
	}
	if rec.Serial == "" || len(rec.Pushes) != 1 {
		t.Fatalf("record %+v: want one push", rec)
	}
	if skew := time.Since(rec.NotBefore); skew < 23*time.Hour || skew > 25*time.Hour {
		t.Fatalf("NotBefore is %v in the past, want about 24h to tolerate device clock skew", skew)
	}
	if rec.Pushes[0].Outcome != "installed and verified" || rec.Pushes[0].Target != e.target || rec.Pushes[0].Admin != "tester" {
		t.Fatalf("push record = %+v", rec.Pushes[0])
	}

	block, _ := pem.Decode(d.cert)
	if block == nil {
		t.Fatal("device received no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(e.caCert); err != nil {
		t.Fatalf("certificate not signed by the selected CA: %v", err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "switch.example.net" {
		t.Fatalf("DNS SANs = %v, want the form value only", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("IP SANs = %v, want the form value only", cert.IPAddresses)
	}
	if cert.Subject.CommonName != "switch.example.net" || len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "NL" {
		t.Fatalf("subject = %v", cert.Subject)
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || pub.N.Cmp(d.pub.N) != 0 {
		t.Fatal("certificate key is not the device-generated key")
	}

	if strings.Contains(logs.String(), testDevPass) {
		t.Fatal("device password appeared in logs")
	}
	index, err := os.ReadFile(filepath.Join(e.store.dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(index, []byte(testDevPass)) || bytes.Contains(index, []byte(testDevUser)) {
		t.Fatal("credentials appeared in index.json")
	}
}

func TestGNOIAcceptsSHA1DeviceCSR(t *testing.T) {
	dev := &fakeGNOIDevice{csrAlg: x509.SHA1WithRSA}
	e := newGNOITestEnv(t, dev)
	if _, err := gnoiPush(context.Background(), e.store, e.allow, e.request(t)); err != nil {
		t.Fatalf("SHA-1 device CSR rejected: %v", err)
	}
}

func TestGNOIRefusesExistingCertID(t *testing.T) {
	dev := &fakeGNOIDevice{existing: []string{"netanchor-test"}}
	e := newGNOITestEnv(t, dev)
	steps, err := gnoiPush(context.Background(), e.store, e.allow, e.request(t))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want existing-id refusal", err)
	}
	if got := stepNames(steps); got[len(got)-1] != "auth=failed" {
		t.Fatalf("steps = %v", got)
	}
	if dev.snap().loads != 0 {
		t.Fatal("device was asked to install over an existing id")
	}
	if recs := certRecords(t, e.store); len(recs) != 0 {
		t.Fatalf("refused push left %d records", len(recs))
	}
}

func TestGNOIRequiresSubjectFieldsBeforeContactingDevice(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	for name, mutate := range map[string]func(*gnoiPushRequest){
		"country":      func(r *gnoiPushRequest) { r.Country = "" },
		"state":        func(r *gnoiPushRequest) { r.State = "" },
		"organization": func(r *gnoiPushRequest) { r.Organization = "" },
	} {
		req := e.request(t)
		mutate(&req)
		steps, err := gnoiPush(context.Background(), e.store, e.allow, req)
		if err == nil || len(steps) != 0 {
			t.Fatalf("missing %s: err=%v steps=%v, want immediate refusal", name, err, stepNames(steps))
		}
	}
	if e.dev.snap().getCalls != 0 {
		t.Fatal("device was contacted for an invalid request")
	}
}

func TestGNOIDeviceErrorMidInstallIsRecorded(t *testing.T) {
	dev := &fakeGNOIDevice{loadMode: "error"}
	e := newGNOITestEnv(t, dev)
	steps, err := gnoiPush(context.Background(), e.store, e.allow, e.request(t))
	if err == nil || errors.Is(err, errGNOIUnverified) {
		t.Fatalf("err = %v, want a failed push", err)
	}
	if got := stepNames(steps); got[len(got)-1] != "install=failed" {
		t.Fatalf("steps = %v", got)
	}
	recs := certRecords(t, e.store)
	if len(recs) != 1 || len(recs[0].Pushes) != 1 || !strings.HasPrefix(recs[0].Pushes[0].Outcome, "failed at install") {
		t.Fatalf("records = %+v", recs)
	}
}

func TestGNOIVerifyRetriesThenReportsUnverified(t *testing.T) {
	defer func(w, i time.Duration) { gnoiVerifyWindow, gnoiVerifyInterval = w, i }(gnoiVerifyWindow, gnoiVerifyInterval)
	gnoiVerifyWindow, gnoiVerifyInterval = 400*time.Millisecond, 50*time.Millisecond

	dev := &fakeGNOIDevice{loadMode: "silent"}
	e := newGNOITestEnv(t, dev)
	steps, err := gnoiPush(context.Background(), e.store, e.allow, e.request(t))
	if !errors.Is(err, errGNOIUnverified) {
		t.Fatalf("err = %v, want installed-could-not-verify", err)
	}
	if got := stepNames(steps); got[len(got)-1] != "verify=unconfirmed" {
		t.Fatalf("steps = %v", got)
	}
	if n := dev.snap().getCalls; n < 3 {
		t.Fatalf("verify made %d GetCertificates calls, want retries", n)
	}
	recs := certRecords(t, e.store)
	if len(recs) != 1 || len(recs[0].Pushes) != 1 || recs[0].Pushes[0].Outcome != errGNOIUnverified.Error() {
		t.Fatalf("records = %+v", recs)
	}
}

func TestGNOIInstallResetStillVerifies(t *testing.T) {
	dev := &fakeGNOIDevice{loadMode: "reset"}
	e := newGNOITestEnv(t, dev)
	steps, err := gnoiPush(context.Background(), e.store, e.allow, e.request(t))
	if err != nil {
		t.Fatalf("err = %v, steps %v", err, stepNames(steps))
	}
}

func TestGNOIAllowlist(t *testing.T) {
	if got, err := parseGNOIAllow(""); err != nil || len(got) != 0 {
		t.Fatalf("empty allowlist = %v, %v", got, err)
	}
	if _, err := parseGNOIAllow("192.0.2.10"); err == nil {
		t.Fatal("bare address accepted without a prefix")
	}
	allow, err := parseGNOIAllow(" 10.0.0.0/8, 192.0.2.10/32 ")
	if err != nil || len(allow) != 2 {
		t.Fatalf("allow = %v, %v", allow, err)
	}
	if _, _, _, err := gnoiResolve(context.Background(), nil, "192.0.2.10:57400"); err == nil || !strings.Contains(err.Error(), "NETANCHOR_GNOI_ALLOW") {
		t.Fatalf("empty allowlist: err = %v, want refusal", err)
	}
	if _, _, _, err := gnoiResolve(context.Background(), allow, "192.0.2.10:57400"); err != nil {
		t.Fatalf("CIDR match refused: %v", err)
	}
	if _, _, _, err := gnoiResolve(context.Background(), allow, "192.0.2.11:57400"); err == nil {
		t.Fatal("address outside the CIDR accepted")
	}
	// Every resolved address must be allowed, not just the first.
	mixed := []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("203.0.113.5")}
	if _, err := gnoiCheckAllowed(allow, "switch.example.net", mixed); err == nil {
		t.Fatal("one disallowed address among resolved IPs was accepted")
	}
	ip, err := gnoiCheckAllowed(allow, "switch.example.net", mixed[:1])
	if err != nil || ip.String() != "192.0.2.10" {
		t.Fatalf("checked ip = %v, %v", ip, err)
	}
	if _, _, _, err := gnoiResolve(context.Background(), allow, "192.0.2.10"); err == nil {
		t.Fatal("target without a port accepted")
	}
}

func TestGNOIFingerprintModePinsProbedCertificate(t *testing.T) {
	dev := &fakeGNOIDevice{}
	e := newGNOITestEnv(t, dev)
	fp, err := gnoiProbe(context.Background(), e.allow, e.target)
	if err != nil {
		t.Fatal(err)
	}
	if normalizeFingerprint(fp) != normalizeFingerprint(e.fp) {
		t.Fatalf("probe fingerprint %s, want %s", fp, e.fp)
	}
	req := e.request(t)
	req.Verify, req.Fingerprint = gnoiVerifyFingerprint, fp
	if _, err := gnoiPush(context.Background(), e.store, e.allow, req); err != nil {
		t.Fatalf("push with confirmed fingerprint: %v", err)
	}

	bad := e.request(t)
	bad.Verify, bad.Fingerprint = gnoiVerifyFingerprint, "00:11:22"
	steps, err := gnoiPush(context.Background(), e.store, e.allow, bad)
	if err == nil || len(steps) != 1 || steps[0].Name != "connect" {
		t.Fatalf("wrong fingerprint: err=%v steps=%v, want connect failure", err, stepNames(steps))
	}
}

func TestGNOIValidateRequestRules(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	base := e.request(t)
	cases := map[string]func(*gnoiPushRequest){
		"no certid":        func(r *gnoiPushRequest) { r.CertID = "" },
		"bad certid":       func(r *gnoiPushRequest) { r.CertID = "a/b" },
		"no password":      func(r *gnoiPushRequest) { r.Password = "" },
		"unpinned fp":      func(r *gnoiPushRequest) { r.Verify = gnoiVerifyFingerprint },
		"bad verify":       func(r *gnoiPushRequest) { r.Verify = "maybe" },
		"no SANs for TLS":  func(r *gnoiPushRequest) { r.DNSNames, r.IPs = nil, nil },
		"profile no RSA2k": func(r *gnoiPushRequest) { r.Template.AllowedAlgos = []keyAlgo{algoECP256} },
	}
	for name, mutate := range cases {
		req := base
		mutate(&req)
		if err := validateGNOIRequest(req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validateGNOIRequest(base); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
}

func TestGNOIPageNeverEchoesPasswordAndRecordsPush(t *testing.T) {
	dev := &fakeGNOIDevice{}
	e := newGNOITestEnv(t, dev)
	auth, err := NewAuth(e.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.store, auth)
	srv.gnoiAllow = e.allow

	form := url.Values{
		"target": {e.target}, "username": {testDevUser}, "password": {testDevPass},
		"verify": {gnoiVerifyUnverified}, "ca": {caRoot}, "template": {"builtin:TLS-Server"},
		"cn": {"switch.example.net"}, "country": {"NL"}, "state": {"Zuid"}, "org": {"Example"},
		"dns_sans": {"switch.example.net"}, "rebind_ack": {"on"}, // unverified_ack missing on purpose
	}
	post := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/gnoi/push", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://"+req.Host)
		form.Set("csrf", srv.backupToken(req))
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	rec := post(form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), testDevPass) {
		t.Fatal("password echoed in page")
	}
	if !strings.Contains(rec.Body.String(), "unverified connections") {
		t.Fatal("missing unverified acknowledgement not reported")
	}

	form.Set("unverified_ack", "on")
	form.Set("verify", gnoiVerifyCA)
	rec = post(form)
	if !strings.Contains(rec.Body.String(), "Installed and verified") {
		t.Fatalf("push did not report success: %s", rec.Body.String())
	}
	recs := certRecords(t, e.store)
	if len(recs) != 1 {
		t.Fatalf("want one certificate record, got %d", len(recs))
	}
	serial := recs[0].Serial
	det := httptest.NewRecorder()
	dreq := httptest.NewRequest(http.MethodGet, "/cert/"+serial, nil)
	dreq.SetPathValue("serial", serial)
	srv.handleCertDetails(det, dreq)
	if det.Code != http.StatusOK || !strings.Contains(det.Body.String(), "Pushed to "+e.target) {
		t.Fatalf("details page lacks push line (status %d)", det.Code)
	}
	if strings.Contains(det.Body.String(), testDevPass) {
		t.Fatal("password leaked into details page")
	}
}

func TestParseGNOIAllowErrorsOnBadEntry(t *testing.T) {
	if _, err := parseGNOIAllow("10.0.0.0/8,nonsense"); err == nil || !strings.Contains(err.Error(), "nonsense") {
		t.Fatalf("err = %v", err)
	}
}

func TestGNOIRejectsMissingCSRFOrOrigin(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	auth, err := NewAuth(e.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.store, auth)
	srv.gnoiAllow = e.allow
	for name, mod := range map[string]func(*http.Request, url.Values){
		"no token":  func(r *http.Request, f url.Values) { r.Header.Set("Origin", "http://"+r.Host) },
		"no origin": func(r *http.Request, f url.Values) { f.Set("csrf", srv.backupToken(r)) },
		"other origin": func(r *http.Request, f url.Values) {
			f.Set("csrf", srv.backupToken(r))
			r.Header.Set("Origin", "http://evil.example")
		},
	} {
		for _, action := range []string{"push", "fingerprint"} {
			form := url.Values{"target": {e.target}}
			req := httptest.NewRequest(http.MethodPost, "/admin/gnoi/"+action, nil)
			mod(req, form)
			req.Body = io.NopCloser(strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			srv.Routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s/%s: status %d, want 403", name, action, rec.Code)
			}
		}
	}
}

// Browsers send "Origin: null" on form POSTs from pages served with
// Referrer-Policy no-referrer, which the CSRF check rejects.
func TestGNOIPageKeepsOriginForSameSitePosts(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	auth, err := NewAuth(e.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.store, auth)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/gnoi", nil))
	if got := rec.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q, want same-origin", got)
	}
}

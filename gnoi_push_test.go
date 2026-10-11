package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gnoicert "github.com/openconfig/gnoi/cert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// startFakeGNOI serves dev on loopback with a server certificate from the test root.
// It returns the host:port and the server certificate DER.
func startFakeGNOI(t *testing.T, dev *fakeGNOIDevice, caCert *x509.Certificate, caKey any) (string, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "device"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, caCert, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})))
	gnoicert.RegisterCertificateManagementServer(srv, dev)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), der
}

// testDevice is an unsaved device on target, verified against the test root.
func testDevice(t *testing.T, target, name string) Device {
	t.Helper()
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return Device{Name: name, ManagementIP: host, Port: p, Platform: "IOS-XE", Verify: gnoiVerifyCA, CAID: caRoot}
}

// testDefinition saves the definition the push tests use.
func testDefinition(t *testing.T, st *Store) (CertDefinition, CertTemplate) {
	t.Helper()
	tpl, ok := builtinByName("TLS-Server")
	if !ok {
		t.Fatal("missing builtin profile")
	}
	def := CertDefinition{Name: "switch-tls", CAID: caRoot, Profile: tpl.Name, Country: "NL", State: "Zuid-Holland", Organization: "Example", ValidDays: tpl.ValidDays, CertID: "netanchor-switch"}
	if err := st.SaveDefinition(&def); err != nil {
		t.Fatal(err)
	}
	return def, tpl
}

// saveTestDevice stores d and returns it with its ID.
func saveTestDevice(t *testing.T, st *Store, d Device) Device {
	t.Helper()
	if err := st.SaveDevice(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

// pushAll pushes def to devs with the test device credentials, as the page does for devices without stored ones.
func pushAll(t *testing.T, e *gnoiTestEnv, def CertDefinition, tpl CertTemplate, devs ...Device) []devicePushResult {
	t.Helper()
	return pushDefinitionToDevices(context.Background(), e.store, e.allow, def, tpl, devs, deviceCreds{Username: testDevUser, Password: testDevPass}, "", "tester")
}

func TestPushDefinitionContinuesAfterFailure(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	good1, good2, bad := &fakeGNOIDevice{}, &fakeGNOIDevice{}, &fakeGNOIDevice{loadMode: "error"}
	badTarget, _ := startFakeGNOI(t, bad, e.caCert, e.caKey)
	goodTarget, _ := startFakeGNOI(t, good2, e.caCert, e.caKey)
	good1Target, _ := startFakeGNOI(t, good1, e.caCert, e.caKey)
	def, tpl := testDefinition(t, e.store)

	var devs []Device
	for i, target := range []string{good1Target, badTarget, goodTarget} {
		devs = append(devs, saveTestDevice(t, e.store, testDevice(t, target, "switch"+strconv.Itoa(i))))
	}
	results := pushAll(t, e, def, tpl, devs...)
	want := []string{"ok", "failed", "ok"}
	for i, r := range results {
		if r.Status != want[i] {
			t.Fatalf("device %d: status %q (%s), want %q", i, r.Status, r.Outcome, want[i])
		}
	}
	if good1.snap().loads != 1 || good2.snap().loads != 1 {
		t.Fatal("devices after the failure were not pushed")
	}
}

func TestPushSkipsDeviceWithExistingCertID(t *testing.T) {
	dev := &fakeGNOIDevice{existing: []string{"netanchor-switch"}}
	e := newGNOITestEnv(t, dev)
	def, tpl := testDefinition(t, e.store)
	d := saveTestDevice(t, e.store, testDevice(t, e.target, "switch"))

	results := pushAll(t, e, def, tpl, d)
	if results[0].Status != "skipped" || !strings.Contains(results[0].Outcome, "renewal comes with Rotate") {
		t.Fatalf("result = %+v, want skipped with renewal note", results[0])
	}
	if dev.snap().loads != 0 {
		t.Fatal("device was asked to install over an existing id")
	}
	if recs := certRecords(t, e.store); len(recs) != 0 {
		t.Fatalf("skipped push left %d records", len(recs))
	}
}

func TestPushRepinsFingerprintDeviceAfterInstall(t *testing.T) {
	dev := &fakeGNOIDevice{}
	e := newGNOITestEnv(t, dev)
	def, tpl := testDefinition(t, e.store)
	d := testDevice(t, e.target, "switch")
	d.Verify, d.Pin = gnoiVerifyFingerprint, e.fp
	d = saveTestDevice(t, e.store, d)

	results := pushAll(t, e, def, tpl, d)
	if results[0].Status != "ok" {
		t.Fatalf("push: %+v", results[0])
	}
	got, _, err := e.store.GetDevice(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(dev.snap().cert)
	if block == nil {
		t.Fatal("device received no certificate")
	}
	if normalizeFingerprint(got.Pin) != normalizeFingerprint(sha256Of(block.Bytes)) {
		t.Fatalf("pin %s, want the installed certificate %s", got.Pin, sha256Of(block.Bytes))
	}
	if got.PinAddress != e.target {
		t.Fatalf("pin address %q, want %q", got.PinAddress, e.target)
	}
}

func TestPushReportsUnverifiedStatus(t *testing.T) {
	defer func(w, i time.Duration) { gnoiVerifyWindow, gnoiVerifyInterval = w, i }(gnoiVerifyWindow, gnoiVerifyInterval)
	gnoiVerifyWindow, gnoiVerifyInterval = 400*time.Millisecond, 50*time.Millisecond

	e := newGNOITestEnv(t, &fakeGNOIDevice{loadMode: "silent"})
	def, tpl := testDefinition(t, e.store)
	d := saveTestDevice(t, e.store, testDevice(t, e.target, "switch"))
	results := pushAll(t, e, def, tpl, d)
	if results[0].Status != "unverified" {
		t.Fatalf("status %q (%s), want unverified", results[0].Status, results[0].Outcome)
	}
}

func TestPushDeviceCertificateSANsAndSubject(t *testing.T) {
	dev := &fakeGNOIDevice{}
	e := newGNOITestEnv(t, dev)
	def, tpl := testDefinition(t, e.store)
	def.ExtraSANs = []string{"alt.example.net", "192.0.2.99"}
	if err := e.store.SaveDefinition(&def); err != nil {
		t.Fatal(err)
	}
	d := testDevice(t, e.target, "switch")
	d.FQDN, d.ManagementIP = "switch.example.net", "127.0.0.1"
	d = saveTestDevice(t, e.store, d)

	if results := pushAll(t, e, def, tpl, d); results[0].Status != "ok" {
		t.Fatalf("push: %+v", results[0])
	}
	block, _ := pem.Decode(dev.snap().cert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "switch.example.net" {
		t.Fatalf("CN = %q, want the device FQDN", cert.Subject.CommonName)
	}
	if strings.Join(cert.DNSNames, ",") != "switch.example.net,alt.example.net" {
		t.Fatalf("DNS SANs = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 || cert.IPAddresses[0].String() != "127.0.0.1" || cert.IPAddresses[1].String() != "192.0.2.99" {
		t.Fatalf("IP SANs = %v", cert.IPAddresses)
	}
}

func TestPushPageNeverEchoesSecretsAndShowsPushOnDevice(t *testing.T) {
	dev := &fakeGNOIDevice{}
	e := newGNOITestEnv(t, dev)
	auth, err := NewAuth(e.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.store, auth)
	srv.gnoiAllow = e.allow
	def, _ := testDefinition(t, e.store)
	d := saveTestDevice(t, e.store, testDevice(t, e.target, "switch"))

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	const caPass = "ca-passphrase-s3cret"
	form := url.Values{
		"definition": {def.ID}, "device": {d.ID}, "username": {testDevUser}, "password": {testDevPass},
		"ca_passphrase": {caPass}, "rebind_ack": {"on"},
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://"+req.Host)
		form.Set("csrf", srv.backupToken(req))
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	rec := post("/push", form)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "1 installed") {
		t.Fatalf("status %d, body lacks the summary", rec.Code)
	}
	for _, secret := range []string{testDevPass, caPass} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("%q echoed in page", secret)
		}
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("%q appeared in logs", secret)
		}
		index, err := os.ReadFile(filepath.Join(e.store.dir, "index.json"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(index, []byte(secret)) {
			t.Fatalf("%q appeared in index.json", secret)
		}
	}
	if recs := certRecords(t, e.store); len(recs) != 1 || len(recs[0].Pushes) != 1 {
		t.Fatalf("want one certificate with one push, got %+v", recs)
	}

	devPage := deviceGet(srv, "/devices/"+d.ID)
	if devPage.Code != http.StatusOK || !strings.Contains(devPage.Body.String(), "netanchor-switch") {
		t.Fatalf("device page lacks the push (status %d)", devPage.Code)
	}
}

func TestPushPageRequiresUnverifiedAcknowledgement(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	auth, err := NewAuth(e.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.store, auth)
	srv.gnoiAllow = e.allow
	def, _ := testDefinition(t, e.store)
	d := testDevice(t, e.target, "switch")
	d.Verify = gnoiVerifyUnverified
	d = saveTestDevice(t, e.store, d)

	form := url.Values{"definition": {def.ID}, "device": {d.ID}, "username": {testDevUser}, "password": {testDevPass}, "rebind_ack": {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/push", nil)
	req.Header.Set("Origin", "http://"+req.Host)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form.Set("csrf", srv.backupToken(req))
	req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "unverified connections") {
		t.Fatal("missing unverified acknowledgement not reported")
	}
	if recs := certRecords(t, e.store); len(recs) != 0 {
		t.Fatal("push ran without the acknowledgement")
	}
}

func TestPushRejectsMissingCSRFOrOrigin(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	auth, err := NewAuth(e.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.store, auth)
	for name, mod := range map[string]func(*http.Request, url.Values){
		"no token":  func(r *http.Request, f url.Values) { r.Header.Set("Origin", "http://"+r.Host) },
		"no origin": func(r *http.Request, f url.Values) { f.Set("csrf", srv.backupToken(r)) },
		"other origin": func(r *http.Request, f url.Values) {
			f.Set("csrf", srv.backupToken(r))
			r.Header.Set("Origin", "http://evil.example")
		},
	} {
		form := url.Values{"device": {"x"}}
		req := httptest.NewRequest(http.MethodPost, "/push", nil)
		mod(req, form)
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", name, rec.Code)
		}
	}
}

// Browsers send "Origin: null" on form POSTs from pages served with
// Referrer-Policy no-referrer, which the CSRF check rejects.
func TestPushPageKeepsOriginForSameSitePosts(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	auth, err := NewAuth(e.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.store, auth)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/push", nil))
	if got := rec.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q, want same-origin", got)
	}
}

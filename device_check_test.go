package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testDeviceCertPEM returns a self-signed certificate with the given subject and expiry.
func testDeviceCertPEM(t *testing.T, subject pkix.Name, notBefore, notAfter time.Time) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: subject, Issuer: subject, NotBefore: notBefore, NotAfter: notAfter}, &x509.Certificate{Subject: subject, SerialNumber: big.NewInt(1)}, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// deviceForEnv saves a device that points at the fake gNOI server, pinned to its certificate.
func deviceForEnv(t *testing.T, env *gnoiTestEnv, withCreds bool) Device {
	t.Helper()
	host, portStr, err := net.SplitHostPort(env.target)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	dev := Device{Name: "lab-" + portStr, FQDN: "lab-" + portStr + ".example.net", ManagementIP: host, Port: port, Platform: devicePlatformIOSXE, Pin: env.fp}
	if withCreds {
		dev.Credentials, err = env.store.sealCredentials(deviceCreds{Username: testDevUser, Password: testDevPass})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := env.store.SaveDevice(&dev); err != nil {
		t.Fatal(err)
	}
	return dev
}

func TestDeviceTestConnectionFillsModelAndSerial(t *testing.T) {
	dev := &fakeGNOIDevice{sudi: testDeviceCertPEM(t, pkix.Name{CommonName: "Cisco", SerialNumber: "PID:C9300-24P SN:FCW2345A0BC"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))}
	env := newGNOITestEnv(t, dev)
	d := deviceForEnv(t, env, true)
	creds, err := env.store.openCredentials(d.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	rep, steps, err := gnoiInspect(context.Background(), env.store, env.allow, d, creds, false, "test")
	if err != nil {
		t.Fatalf("inspect: %v (steps %v)", err, stepNames(steps))
	}
	if rep.Model != "C9300-24P" || rep.Serial != "FCW2345A0BC" {
		t.Fatalf("model/serial = %q/%q", rep.Model, rep.Serial)
	}
	if rep.Served != nil {
		t.Fatal("test connection must not read the served certificate")
	}
	if got := stepNames(steps); strings.Join(got, ",") != "connect=ok,auth=ok,identity=ok" {
		t.Fatalf("steps = %v", got)
	}
}

func TestDeviceTestConnectionWithoutSUDI(t *testing.T) {
	env := newGNOITestEnv(t, &fakeGNOIDevice{})
	d := deviceForEnv(t, env, true)
	creds := deviceCreds{Username: testDevUser, Password: testDevPass}
	rep, steps, err := gnoiInspect(context.Background(), env.store, env.allow, d, creds, false, "test")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if rep.Model != "" || rep.Serial != "" {
		t.Fatalf("expected no model/serial, got %q/%q", rep.Model, rep.Serial)
	}
	if steps[len(steps)-1].Name != "identity" || steps[len(steps)-1].Status != "ok" {
		t.Fatalf("steps = %v", stepNames(steps))
	}
}

func TestDeviceCheckAuthFailure(t *testing.T) {
	env := newGNOITestEnv(t, &fakeGNOIDevice{})
	d := deviceForEnv(t, env, false)
	_, steps, err := gnoiInspect(context.Background(), env.store, env.allow, d, deviceCreds{Username: testDevUser, Password: "wrong"}, false, "test")
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if got := stepNames(steps); strings.Join(got, ",") != "connect=ok,auth=failed" {
		t.Fatalf("steps = %v", got)
	}
}

func TestDeviceCheckPinMismatchStopsAtConnect(t *testing.T) {
	env := newGNOITestEnv(t, &fakeGNOIDevice{})
	d := deviceForEnv(t, env, false)
	d.Pin = "00:" + strings.Repeat("11:", 31) + "11"
	_, steps, err := gnoiInspect(context.Background(), env.store, env.allow, d, deviceCreds{Username: testDevUser, Password: testDevPass}, false, "test")
	if err == nil {
		t.Fatal("expected connect failure on pin mismatch")
	}
	if got := stepNames(steps); strings.Join(got, ",") != "connect=failed" {
		t.Fatalf("steps = %v", got)
	}
}

func TestDeviceRefreshStoresSnapshotAndHighlightsExpiry(t *testing.T) {
	now := time.Now()
	expired := testDeviceCertPEM(t, pkix.Name{CommonName: "old.example.net"}, now.Add(-48*time.Hour), now.Add(-time.Hour))
	dev := &fakeGNOIDevice{installed: map[string][]byte{"netanchor-old": expired}}
	env := newGNOITestEnv(t, dev)
	d := deviceForEnv(t, env, true)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	st := env.store
	auth, err := NewAuth(st, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, auth)
	srv.gnoiAllow = env.allow

	rec := devicePost(srv, "/devices/"+d.ID+"/refresh", url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status %d: %s", rec.Code, rec.Body.String())
	}
	got, ok, err := st.GetDevice(d.ID)
	if err != nil || !ok || got.Snapshot == nil {
		t.Fatalf("snapshot not stored: ok=%v err=%v", ok, err)
	}
	if got.Snapshot.Served == nil || got.Snapshot.Served.Fingerprint != env.fp {
		t.Fatalf("served certificate not recorded: %+v", got.Snapshot.Served)
	}
	if len(got.Snapshot.Certs) != 1 || got.Snapshot.Certs[0].CertID != "netanchor-old" {
		t.Fatalf("certs = %+v", got.Snapshot.Certs)
	}

	page := deviceGet(srv, "/devices/"+d.ID)
	body := page.Body.String()
	if !strings.Contains(body, "netanchor-old") || !strings.Contains(body, `class="pill bad"`) {
		t.Fatalf("snapshot not rendered with expired highlight")
	}
	if strings.Contains(body, testDevPass) || strings.Contains(logs.String(), testDevPass) {
		t.Fatal("device password appeared in page or logs")
	}
}

func TestDeviceCheckRejectsMissingCSRF(t *testing.T) {
	env := newGNOITestEnv(t, &fakeGNOIDevice{})
	d := deviceForEnv(t, env, true)
	auth, err := NewAuth(env.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(env.store, auth)
	srv.gnoiAllow = env.allow
	req, _ := http.NewRequest(http.MethodPost, "/devices/"+d.ID+"/test", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestDeviceExpiryClass(t *testing.T) {
	now := time.Now()
	cases := []struct {
		want string
		when time.Time
	}{
		{"", time.Time{}},
		{"bad", now.Add(-time.Second)},
		{"warn", now.Add(10 * 24 * time.Hour)},
		{"lock", now.Add(90 * 24 * time.Hour)},
	}
	for _, c := range cases {
		if got := deviceExpiryClass(c.when, now); got != c.want {
			t.Errorf("deviceExpiryClass(%v) = %q, want %q", c.when, got, c.want)
		}
	}
}

func TestReadableDN(t *testing.T) {
	in := "CN=C9300L-24P-4X_FOC2602Y6K3_sdn-network-infra-iwan,1.2.840.113549.1.9.2=#131969626b2d6c61622d737739392e6e74736c61622e6c6f63616c"
	want := "CN=C9300L-24P-4X_FOC2602Y6K3_sdn-network-infra-iwan,unstructuredName=ibk-lab-sw99.ntslab.local"
	if got := readableDN(in); got != want {
		t.Fatalf("readableDN = %q, want %q", got, want)
	}
	if got := readableDN("CN=x,1.2.3=#zz"); got != "CN=x,1.2.3=#zz" {
		t.Fatalf("undecodable value changed: %q", got)
	}
}

func TestSnapshotViewMarksGRPCCertificate(t *testing.T) {
	now := time.Now()
	a := DeviceCert{CertID: "a", Fingerprint: "AA"}
	b := DeviceCert{CertID: "b", Fingerprint: "BB"}
	rows, served := deviceSnapshotView(&DeviceSnapshot{Certs: []DeviceCert{a, b}, Served: &b}, now)
	if served != nil || rows[0].GRPC || !rows[1].GRPC {
		t.Fatalf("listed served cert: rows=%+v served=%+v", rows, served)
	}
	other := DeviceCert{CertID: "", Fingerprint: "CC"}
	rows, served = deviceSnapshotView(&DeviceSnapshot{Certs: []DeviceCert{a}, Served: &other}, now)
	if served == nil || rows[0].GRPC {
		t.Fatalf("unlisted served cert must show separately: rows=%+v served=%+v", rows, served)
	}
}

func TestTimeLeft(t *testing.T) {
	now := time.Now()
	for want, when := range map[string]time.Time{
		"":               {},
		"expired":        now.Add(-time.Hour),
		"1 day left":     now.Add(36 * time.Hour),
		"10 days left":   now.Add(10*24*time.Hour + time.Hour),
		"2.0 years left": now.Add(2 * 365 * 24 * time.Hour),
	} {
		if got := timeLeft(when, now); got != want {
			t.Errorf("timeLeft(%v) = %q, want %q", when, got, want)
		}
	}
}

// setLegacyVerify rewrites a stored device the way an older release saved it: with
// a verify mode and CA id, and no pin.
func setLegacyVerify(t *testing.T, st *Store, id, mode string) {
	t.Helper()
	b, err := os.ReadFile(st.devicesPath())
	backupCheck(t, err)
	var recs []map[string]any
	backupCheck(t, json.Unmarshal(b, &recs))
	for _, r := range recs {
		if r["id"] == id {
			r["verify"], r["ca_id"] = mode, "0a1b2c"
			delete(r, "pin")
			delete(r, "pin_address")
		}
	}
	b, err = json.Marshal(recs)
	backupCheck(t, err)
	backupCheck(t, os.WriteFile(st.devicesPath(), b, 0o600))
}

// A device saved with the removed unverified or CA mode, and no pin, never
// connects: test, refresh and push fail before the device is dialed.
func TestLegacyVerifyDeviceWithoutPinNeverConnects(t *testing.T) {
	for _, mode := range []string{"unverified", "ca"} {
		env := newGNOITestEnv(t, &fakeGNOIDevice{})
		saved := deviceForEnv(t, env, true)
		setLegacyVerify(t, env.store, saved.ID, mode)
		d, ok, err := env.store.GetDevice(saved.ID)
		backupCheck(t, err)
		if !ok || d.Pin != "" {
			t.Fatalf("%s: device = %+v, want loaded without a pin", mode, d)
		}
		creds, err := env.store.openCredentials(d.Credentials)
		backupCheck(t, err)

		for _, refresh := range []bool{false, true} {
			_, steps, err := gnoiInspect(context.Background(), env.store, env.allow, d, creds, refresh, "test")
			if err == nil || !strings.Contains(err.Error(), "no fingerprint pinned") {
				t.Fatalf("%s: inspect err = %v, want the pin message", mode, err)
			}
			if got := stepNames(steps); strings.Join(got, ",") != "connect=failed" {
				t.Fatalf("%s: steps = %v", mode, got)
			}
		}

		def, tpl := testDefinition(t, env.store)
		res := pushAll(t, env, def, tpl, d)
		if res[0].Status != "failed" || !strings.Contains(res[0].Outcome, "no fingerprint pinned") {
			t.Fatalf("%s: push = %+v, want the pin message", mode, res[0])
		}
		if n := env.dev.snap().getCalls; n != 0 {
			t.Fatalf("%s: device was contacted %d times", mode, n)
		}
		if n := env.dev.snap().loads; n != 0 {
			t.Fatalf("%s: certificate pushed to an unpinned device", mode)
		}
	}
}

// Editing such a device works as before: fetching and saving the fingerprint sets the pin.
func TestLegacyVerifyDeviceGetsPinOnEdit(t *testing.T) {
	env, srv := deviceAddEnv(t, &fakeGNOIDevice{})
	saved := deviceForEnv(t, env, true)
	setLegacyVerify(t, env.store, saved.ID, "unverified")
	edit := deviceForm1("legacy", env)
	edit.Set("id", saved.ID)
	if rec := devicePost(srv, "/devices/save", edit); rec.Code != http.StatusSeeOther {
		t.Fatalf("edit: status %d: %s", rec.Code, rec.Body.String())
	}
	if d, _, _ := env.store.GetDevice(saved.ID); d.Pin != env.fp {
		t.Fatalf("pin = %q, want %q", d.Pin, env.fp)
	}
}

// selfSignedRSAPEM returns a self-signed RSA certificate PEM and its key, for a fake gRPC server.
func selfSignedRSAPEM(t *testing.T, cn string) ([]byte, *rsa.PrivateKey, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), k, der
}

// revokeForm is the revoke POST body; devicePost adds the CSRF token.
func revokeForm(certID string, confirm bool) url.Values {
	f := url.Values{"cert_id": {certID}}
	if confirm {
		f.Set("confirm", "on")
	}
	return f
}

func TestDeviceRevokeRemovesListedCertificateAndRefreshes(t *testing.T) {
	now := time.Now()
	expired := testDeviceCertPEM(t, pkix.Name{CommonName: "old.example.net"}, now.Add(-48*time.Hour), now.Add(-time.Hour))
	dev := &fakeGNOIDevice{installed: map[string][]byte{"netanchor-old": expired}}
	env := newGNOITestEnv(t, dev)
	d := deviceForEnv(t, env, true)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	auth, err := NewAuth(env.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(env.store, auth)
	srv.gnoiAllow = env.allow
	rec := devicePost(srv, "/devices/"+d.ID+"/certificates/revoke", revokeForm("netanchor-old", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status %d: %s", rec.Code, rec.Body.String())
	}
	if got := dev.revoked(); len(got) != 1 || got[0] != "netanchor-old" {
		t.Fatalf("RevokeCertificates ids = %v, want [netanchor-old]", got)
	}
	if !strings.Contains(rec.Body.String(), "Removed netanchor-old from the switch.") || !strings.Contains(rec.Body.String(), "Certificates refreshed: 0 listed.") {
		t.Fatalf("result not shown: %s", rec.Body.String())
	}
	got, _, _ := env.store.GetDevice(d.ID)
	if got.Snapshot == nil || len(got.Snapshot.Certs) != 0 {
		t.Fatalf("snapshot not refreshed after revoke: %+v", got.Snapshot)
	}
	if strings.Contains(logs.String(), testDevPass) {
		t.Fatal("device password appeared in logs")
	}
}

func TestDeviceRevokeRefusesGRPCCertificate(t *testing.T) {
	grpcPEM, k, der := selfSignedRSAPEM(t, "switch-grpc")
	dev := &fakeGNOIDevice{installed: map[string][]byte{"netanchor-grpc": grpcPEM}, lastCert: grpcPEM, rebind: true, devKey: k}
	env := newGNOITestEnv(t, dev)
	d := deviceForEnv(t, env, true)
	// The port now presents the rebound certificate, so pin that one.
	if err := env.store.UpdateDevice(d.ID, func(x *Device) { x.Pin = sha256Of(der) }); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth(env.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(env.store, auth)
	srv.gnoiAllow = env.allow
	rec := devicePost(srv, "/devices/"+d.ID+"/certificates/revoke", revokeForm("netanchor-grpc", true))
	if !strings.Contains(rec.Body.String(), "Failed at check") || !strings.Contains(rec.Body.String(), "the gRPC port presents this certificate") {
		t.Fatalf("gRPC certificate not refused for the gRPC reason: %s", rec.Body.String())
	}
	if got := dev.revoked(); len(got) != 0 {
		t.Fatalf("RevokeCertificates called for the gRPC certificate: %v", got)
	}
	if _, ok := dev.installed["netanchor-grpc"]; !ok {
		t.Fatal("gRPC certificate removed from the device")
	}
}

func TestDeviceRevokeRefusesSUDIUnknownAndUnconfirmed(t *testing.T) {
	now := time.Now()
	sudi := testDeviceCertPEM(t, pkix.Name{CommonName: "sudi"}, now.Add(-time.Hour), now.Add(time.Hour))
	normal := testDeviceCertPEM(t, pkix.Name{CommonName: "normal"}, now.Add(-time.Hour), now.Add(time.Hour))
	dev := &fakeGNOIDevice{sudi: sudi, installed: map[string][]byte{"netanchor-a": normal}}
	env := newGNOITestEnv(t, dev)
	d := deviceForEnv(t, env, true)
	auth, err := NewAuth(env.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(env.store, auth)
	srv.gnoiAllow = env.allow

	cases := []struct {
		id      string
		confirm bool
		want    string
	}{
		{"CISCO_IDEVID_SUDI", true, "Failed at check"},
		{"nope", true, "Failed at check"},
		{"netanchor-a", false, "tick the confirmation box"},
	}
	for _, c := range cases {
		rec := devicePost(srv, "/devices/"+d.ID+"/certificates/revoke", revokeForm(c.id, c.confirm))
		if !strings.Contains(rec.Body.String(), c.want) {
			t.Fatalf("%s confirm=%v: want %q in %s", c.id, c.confirm, c.want, rec.Body.String())
		}
	}
	if got := dev.revoked(); len(got) != 0 {
		t.Fatalf("RevokeCertificates called: %v", got)
	}
}

func TestDeviceRevokeRejectsMissingCSRF(t *testing.T) {
	dev := &fakeGNOIDevice{installed: map[string][]byte{"netanchor-a": testDeviceCertPEM(t, pkix.Name{CommonName: "a"}, time.Now(), time.Now().Add(time.Hour))}}
	env := newGNOITestEnv(t, dev)
	d := deviceForEnv(t, env, true)
	auth, err := NewAuth(env.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(env.store, auth)
	srv.gnoiAllow = env.allow
	req := httptest.NewRequest(http.MethodPost, "/devices/"+d.ID+"/certificates/revoke", strings.NewReader(url.Values{"cert_id": {"netanchor-a"}, "confirm": {"on"}}.Encode()))
	req.Header.Set("Origin", "http://"+req.Host)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if got := dev.revoked(); len(got) != 0 {
		t.Fatalf("revoke sent without CSRF: %v", got)
	}
}

func TestDeviceRevokeViewerForbidden(t *testing.T) {
	dev := &fakeGNOIDevice{installed: map[string][]byte{"netanchor-a": testDeviceCertPEM(t, pkix.Name{CommonName: "a"}, time.Now(), time.Now().Add(time.Hour))}}
	env := newGNOITestEnv(t, dev)
	d := deviceForEnv(t, env, true)
	auth, err := NewAuth(env.store, false, true)
	if err != nil {
		t.Fatal(err)
	}
	backupCheck(t, auth.AddUser("viewer", "viewer password", RoleViewer))
	viewer := httptest.NewRecorder()
	auth.issueSession(viewer, "viewer")
	cookie := viewer.Result().Cookies()[0].String()
	srv := NewServer(env.store, auth)
	srv.gnoiAllow = env.allow
	routes := auth.Middleware(srv.Routes())

	req := httptest.NewRequest(http.MethodPost, "/devices/"+d.ID+"/certificates/revoke", strings.NewReader(revokeForm("netanchor-a", true).Encode()))
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Origin", "http://"+req.Host)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer status %d, want 403", rec.Code)
	}
	if got := dev.revoked(); len(got) != 0 {
		t.Fatalf("viewer revoked: %v", got)
	}
}

func TestDevicePageDeleteControlOnlyForDeletableRows(t *testing.T) {
	now := time.Now()
	grpcPEM := testDeviceCertPEM(t, pkix.Name{CommonName: "grpc"}, now.Add(-time.Hour), now.Add(time.Hour))
	grpcDER, _ := pem.Decode(grpcPEM)
	dev := &fakeGNOIDevice{}
	env := newGNOITestEnv(t, dev)
	d := deviceForEnv(t, env, true)
	grpcFP := sha256Of(grpcDER.Bytes)
	snap := &DeviceSnapshot{Taken: now, Served: &DeviceCert{Fingerprint: grpcFP}, Certs: []DeviceCert{
		{CertID: "netanchor-a", Fingerprint: "AA"},
		{CertID: "CISCO_IDEVID_SUDI", Fingerprint: "BB"},
		{CertID: "netanchor-grpc", Fingerprint: grpcFP},
	}}
	if err := env.store.UpdateDevice(d.ID, func(x *Device) { x.Snapshot = snap }); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth(env.store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(env.store, auth)
	body := deviceGet(srv, "/devices/"+d.ID).Body.String()

	action := `action="/devices/` + d.ID + `/certificates/revoke`
	if n := strings.Count(body, action); n != 1 {
		t.Fatalf("delete forms = %d, want 1 (only netanchor-a)", n)
	}
	if !strings.Contains(body, `name="cert_id" value="netanchor-a"`) {
		t.Fatal("deletable row has no delete form")
	}
	if !strings.Contains(body, "protected: gRPC server") || !strings.Contains(body, "protected: Cisco SUDI") {
		t.Fatal("protected rows not marked")
	}
}

func TestDeviceRevokeRejectsMissingCertID(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth(st, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, auth)
	d := Device{Name: "sw", ManagementIP: "192.0.2.10", Port: 57400, Platform: devicePlatformIOSXE, Pin: "AA"}
	if err := st.SaveDevice(&d); err != nil {
		t.Fatal(err)
	}
	rec := devicePost(srv, "/devices/"+d.ID+"/certificates/revoke", revokeForm("", true))
	if !strings.Contains(rec.Body.String(), "no certificate was chosen") {
		t.Fatalf("empty cert id not refused: %s", rec.Body.String())
	}
}

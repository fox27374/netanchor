package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	dev := Device{Name: "lab-" + portStr, ManagementIP: host, Port: port, Platform: devicePlatformIOSXE, Pin: env.fp}
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
		{"", now.Add(90 * 24 * time.Hour)},
	}
	for _, c := range cases {
		if got := deviceExpiryClass(c.when, now); got != c.want {
			t.Errorf("deviceExpiryClass(%v) = %q, want %q", c.when, got, c.want)
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

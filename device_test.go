package main

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testDeviceKeyBytes = "0123456789abcdef0123456789abcdef" // 32 bytes

func deviceTestStore(t *testing.T, withKey bool) (*Store, *Server) {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	backupCheck(t, err)
	if withKey {
		key := filepath.Join(t.TempDir(), "device.key")
		backupCheck(t, os.WriteFile(key, []byte(testDeviceKeyBytes), 0o600))
		backupCheck(t, st.LoadDeviceKey(key))
	}
	auth, err := NewAuth(st, false, false)
	backupCheck(t, err)
	return st, NewServer(st, auth)
}

// devicePost posts a form with a valid Origin and CSRF token (auth disabled, trusted-local identity).
func devicePost(srv *Server, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Origin", "http://"+req.Host)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form.Set("csrf", srv.backupToken(req))
	req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func deviceGet(srv *Server, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func deviceForm1(name string) url.Values {
	return url.Values{
		"name": {name}, "management_ip": {"192.0.2.10"}, "port": {"57400"}, "platform": {"IOS-XE"},
		"verify": {gnoiVerifyUnverified}, "unverified_ack": {"on"},
	}
}

func TestDeviceCRUDAndNameUniqueness(t *testing.T) {
	st, srv := deviceTestStore(t, false)

	rec := devicePost(srv, "/devices/save", deviceForm1("sw1"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: status %d: %s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/devices/")
	if id == "" {
		t.Fatal("create: no redirect to the device")
	}

	dup := devicePost(srv, "/devices/save", deviceForm1("sw1"))
	if dup.Code != http.StatusOK || !strings.Contains(dup.Body.String(), "already exists") {
		t.Fatalf("duplicate name not refused: status %d", dup.Code)
	}

	if rec := deviceGet(srv, "/devices/"+id); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sw1") {
		t.Fatalf("details: status %d", rec.Code)
	}
	if rec := deviceGet(srv, "/devices"); !strings.Contains(rec.Body.String(), "192.0.2.10:57400") {
		t.Fatal("list does not show the device address")
	}

	edit := deviceForm1("sw1")
	edit.Set("id", id)
	edit.Set("site", "lab-east")
	if rec := devicePost(srv, "/devices/save", edit); rec.Code != http.StatusSeeOther {
		t.Fatalf("edit: status %d: %s", rec.Code, rec.Body.String())
	}
	if dev, ok, _ := st.GetDevice(id); !ok || dev.Site != "lab-east" {
		t.Fatalf("edit not stored: %+v", dev)
	}

	if rec := devicePost(srv, "/devices/"+id+"/delete", url.Values{}); !strings.Contains(rec.Body.String(), "tick the confirmation") {
		t.Fatal("delete without confirmation was not refused")
	}
	if rec := devicePost(srv, "/devices/"+id+"/delete", url.Values{"confirm_delete": {"on"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: status %d", rec.Code)
	}
	if rec := deviceGet(srv, "/devices/"+id); rec.Code != http.StatusNotFound {
		t.Fatalf("deleted device still served: %d", rec.Code)
	}
}

func TestDeviceCredentialsEncryptedAtRest(t *testing.T) {
	st, srv := deviceTestStore(t, true)
	form := deviceForm1("sw2")
	form.Set("username", testDevUser)
	form.Set("password", testDevPass)
	rec := devicePost(srv, "/devices/save", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: status %d: %s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/devices/")

	raw, err := os.ReadFile(filepath.Join(st.dir, "devices.json"))
	backupCheck(t, err)
	if bytes.Contains(raw, []byte(testDevPass)) || bytes.Contains(raw, []byte(testDevUser)) {
		t.Fatal("devices.json holds the device credentials in clear")
	}

	dev, _, _ := st.GetDevice(id)
	c, err := st.openCredentials(dev.Credentials)
	backupCheck(t, err)
	if c.Username != testDevUser || c.Password != testDevPass {
		t.Fatal("credentials did not round-trip")
	}

	for _, path := range []string{"/devices/" + id, "/devices/" + id + "/edit"} {
		if body := deviceGet(srv, path).Body.String(); strings.Contains(body, testDevPass) {
			t.Fatalf("%s renders the password", path)
		}
	}

	// Blank username and password on edit keep the stored credentials.
	before := append([]byte(nil), dev.Credentials...)
	edit := deviceForm1("sw2")
	edit.Set("id", id)
	if rec := devicePost(srv, "/devices/save", edit); rec.Code != http.StatusSeeOther {
		t.Fatalf("edit: status %d: %s", rec.Code, rec.Body.String())
	}
	if dev, _, _ = st.GetDevice(id); !bytes.Equal(dev.Credentials, before) {
		t.Fatal("blank edit changed the stored credentials")
	}
}

func TestDeviceWithoutKeyStoresNothing(t *testing.T) {
	st, srv := deviceTestStore(t, false)
	form := deviceForm1("sw3")
	form.Set("username", testDevUser)
	form.Set("password", testDevPass)
	rec := devicePost(srv, "/devices/save", form)
	if !strings.Contains(rec.Body.String(), "NETANCHOR_DEVICE_KEY_FILE") {
		t.Fatalf("no explanation without a key file: status %d", rec.Code)
	}
	if devs, _ := st.ListDevices(); len(devs) != 0 {
		t.Fatalf("device stored although credentials could not be: %d", len(devs))
	}
	if strings.Contains(deviceGet(srv, "/devices/new").Body.String(), testDevPass) {
		t.Fatal("password rendered")
	}
}

func TestDeviceCredentialsNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	_, srv := deviceTestStore(t, true)
	form := deviceForm1("sw6")
	form.Set("username", testDevUser)
	form.Set("password", testDevPass)
	rec := devicePost(srv, "/devices/save", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: status %d: %s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/devices/")
	edit := deviceForm1("sw6")
	edit.Set("id", id)
	edit.Set("username", testDevUser)
	edit.Set("password", "another-"+testDevPass)
	devicePost(srv, "/devices/save", edit)
	devicePost(srv, "/devices/"+id+"/delete", url.Values{"confirm_delete": {"on"}})

	for _, secret := range []string{testDevPass, "another-" + testDevPass} {
		if strings.Contains(buf.String(), secret) {
			t.Fatal("device password written to the log")
		}
	}
}

func TestLoadDeviceKeyRejectsBadFiles(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	backupCheck(t, err)
	if err := st.LoadDeviceKey(""); err != nil || st.CredentialsAvailable() {
		t.Fatalf("empty path should leave credential storage off: %v", err)
	}
	if err := st.LoadDeviceKey(filepath.Join(t.TempDir(), "missing.key")); err == nil || st.CredentialsAvailable() {
		t.Fatalf("missing key file accepted: %v", err)
	}
	short := filepath.Join(t.TempDir(), "short.key")
	backupCheck(t, os.WriteFile(short, []byte(testDeviceKeyBytes[:31]), 0o600))
	if err := st.LoadDeviceKey(short); err == nil || st.CredentialsAvailable() {
		t.Fatalf("31-byte key file accepted: %v", err)
	}
}

func TestDevicePinRules(t *testing.T) {
	st, srv := deviceTestStore(t, false)
	r := httptest.NewRequest(http.MethodPost, "/devices/save", nil)
	const fp = "AA:BB:CC:DD"
	base := url.Values{
		"name": {"sw4"}, "management_ip": {"192.0.2.20"}, "port": {"57400"}, "platform": {"IOS-XE"},
		"verify": {gnoiVerifyFingerprint}, "fingerprint": {fp},
	}
	parse := func(v url.Values) deviceForm {
		r.PostForm = v
		return deviceFormFromPost(r)
	}

	if _, err := srv.deviceFromForm(r, parse(base)); err == nil {
		t.Fatal("pin saved without a fetched fingerprint")
	}

	probed := cloneValues(base)
	probed.Set("probed_target", "192.0.2.20:57400")
	probed.Set("probed_fingerprint", fp)
	dev, err := srv.deviceFromForm(r, parse(probed))
	if err != nil || dev.PinAddress != "192.0.2.20:57400" {
		t.Fatalf("confirmed pin refused: %v", err)
	}
	backupCheck(t, st.SaveDevice(&dev))
	devs, err := st.ListDevices()
	backupCheck(t, err)
	if len(devs) != 1 {
		t.Fatalf("want one device, got %d", len(devs))
	}
	saved := devs[0]

	changed := cloneValues(base)
	changed.Set("id", saved.ID)
	changed.Set("port", "57401")
	if _, err := srv.deviceFromForm(r, parse(changed)); err == nil {
		t.Fatal("port change kept the old pin without a new fetch")
	}

	same := cloneValues(base)
	same.Set("id", saved.ID)
	if _, err := srv.deviceFromForm(r, parse(same)); err != nil {
		t.Fatalf("unchanged address and pin refused: %v", err)
	}
}

func TestDeviceRolesAndCSRF(t *testing.T) {
	st, a := backupFixture(t)
	srv := NewServer(st, a)
	backupCheck(t, a.AddUser("viewer", "viewer password", RoleViewer))
	viewer := httptest.NewRecorder()
	a.issueSession(viewer, "viewer")
	cookie := viewer.Result().Cookies()[0].String()
	routes := a.Middleware(srv.Routes())

	get := httptest.NewRequest(http.MethodGet, "/devices", nil)
	get.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Devices") {
		t.Fatalf("viewer cannot read devices: %d", rec.Code)
	}

	if rec := deviceGetWithCookie(routes, "/devices/new", cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET /devices/new: status %d, want 403", rec.Code)
	}
	for _, path := range []string{"/devices/save", "/devices/probe"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(deviceForm1("x").Encode()))
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer POST %s: status %d, want 403", path, rec.Code)
		}
	}

	// Without a CSRF token the admin-side POST is refused even with a valid origin.
	bad := httptest.NewRequest(http.MethodPost, "/devices/save", strings.NewReader(deviceForm1("sw5").Encode()))
	bad.Header.Set("Origin", "http://"+bad.Host)
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, bad)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token: status %d, want 403", rec.Code)
	}
	if devs, _ := st.ListDevices(); len(devs) != 0 {
		t.Fatal("device stored despite a missing CSRF token")
	}
}

func TestDeviceNavLink(t *testing.T) {
	st, a := backupFixture(t)
	srv := NewServer(st, a)
	admin := httptest.NewRecorder()
	a.issueSession(admin, "admin")
	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	req.Header.Set("Cookie", admin.Result().Cookies()[0].String())
	rec := httptest.NewRecorder()
	a.Middleware(srv.Routes()).ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `href="/devices"`) {
		t.Fatal("Devices link missing from the Device Management group")
	}
}

func TestDeviceProbeRespectsAllowlist(t *testing.T) {
	e := newGNOITestEnv(t, &fakeGNOIDevice{})
	_, srv := deviceTestStore(t, false)
	host, port, err := net.SplitHostPort(e.target)
	backupCheck(t, err)
	form := url.Values{"name": {"sw6"}, "management_ip": {host}, "port": {port}, "platform": {"IOS-XE"}, "verify": {gnoiVerifyFingerprint}}

	srv.gnoiAllow = nil
	if rec := devicePost(srv, "/devices/probe", form); strings.Contains(rec.Body.String(), "Fingerprint fetched") || !strings.Contains(rec.Body.String(), "NETANCHOR_GNOI_ALLOW") {
		t.Fatal("probe not refused with an empty allowlist")
	}

	allow, err := parseGNOIAllow("0.0.0.0/0,::/0")
	backupCheck(t, err)
	srv.gnoiAllow = allow
	rec := devicePost(srv, "/devices/probe", form)
	if !strings.Contains(rec.Body.String(), "Fingerprint fetched") || !strings.Contains(rec.Body.String(), e.fp) {
		t.Fatalf("probe refused with 0.0.0.0/0,::/0: %s", rec.Body.String())
	}
}

func deviceGetWithCookie(h http.Handler, path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

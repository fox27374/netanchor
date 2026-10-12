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

func deviceTestStore(t *testing.T) (*Store, *Server) {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	backupCheck(t, err)
	backupCheck(t, st.loadOrCreateDeviceKey())
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

// deviceForm1 is a valid fingerprint-pinned form aimed at the fake device. The
// fetched fingerprint is posted as probed for the same address, so the pin rule passes.
func deviceForm1(name string, env *gnoiTestEnv) url.Values {
	host, port, err := net.SplitHostPort(env.target)
	if err != nil {
		panic(err)
	}
	return url.Values{
		"name": {name}, "management_ip": {host}, "port": {port}, "platform": {"IOS-XE"},
		"fingerprint": {env.fp}, "probed_target": {env.target}, "probed_fingerprint": {env.fp},
	}
}

func TestDeviceCRUDAndNameUniqueness(t *testing.T) {
	env, srv := deviceAddEnv(t, &fakeGNOIDevice{})
	st := env.store

	rec := devicePost(srv, "/devices/save", deviceAddForm(t, env, "sw1"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: status %d: %s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/devices/")
	if id == "" {
		t.Fatal("create: no redirect to the device")
	}

	dup := devicePost(srv, "/devices/save", deviceAddForm(t, env, "sw1"))
	if dup.Code != http.StatusOK || !strings.Contains(dup.Body.String(), "already exists") {
		t.Fatalf("duplicate name not refused: status %d", dup.Code)
	}

	if rec := deviceGet(srv, "/devices/"+id); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sw1") {
		t.Fatalf("details: status %d", rec.Code)
	}
	if rec := deviceGet(srv, "/devices"); !strings.Contains(rec.Body.String(), env.target) {
		t.Fatal("list does not show the device address")
	}

	edit := deviceForm1("sw1", env)
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
	env, srv := deviceAddEnv(t, &fakeGNOIDevice{})
	st := env.store
	form := deviceAddForm(t, env, "sw2")
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
	edit := deviceForm1("sw2", env)
	edit.Set("id", id)
	if rec := devicePost(srv, "/devices/save", edit); rec.Code != http.StatusSeeOther {
		t.Fatalf("edit: status %d: %s", rec.Code, rec.Body.String())
	}
	if dev, _, _ = st.GetDevice(id); !bytes.Equal(dev.Credentials, before) {
		t.Fatal("blank edit changed the stored credentials")
	}
}

func TestDeviceCredentialsNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	env, srv := deviceAddEnv(t, &fakeGNOIDevice{})
	form := deviceAddForm(t, env, "sw6")
	form.Set("username", testDevUser)
	form.Set("password", testDevPass)
	rec := devicePost(srv, "/devices/save", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: status %d: %s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/devices/")
	edit := deviceForm1("sw6", env)
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

// A fresh data dir gets auth/device.key (32 bytes); a restart reuses it so the
// stored credentials still decrypt.
func TestDeviceKeyCreatedOnFirstStart(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	backupCheck(t, err)
	backupCheck(t, st.loadOrCreateDeviceKey())
	b, err := os.ReadFile(filepath.Join(dir, "auth", "device.key"))
	backupCheck(t, err)
	if len(b) != deviceKeySize {
		t.Fatalf("device.key is %d bytes", len(b))
	}
	blob, err := st.sealCredentials(deviceCreds{Username: testDevUser, Password: testDevPass})
	backupCheck(t, err)

	restarted, err := OpenStore(dir)
	backupCheck(t, err)
	backupCheck(t, restarted.loadOrCreateDeviceKey())
	c, err := restarted.openCredentials(blob)
	backupCheck(t, err)
	if c.Username != testDevUser || c.Password != testDevPass {
		t.Fatal("credentials did not survive a restart")
	}
}

// A device.key of the wrong length stops startup and is never replaced.
func TestDeviceKeyWrongLengthIsAnError(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	backupCheck(t, err)
	short := filepath.Join(dir, "auth", "device.key")
	backupCheck(t, os.WriteFile(short, []byte(testDeviceKeyBytes[:31]), 0o600))
	if err := st.loadOrCreateDeviceKey(); err == nil {
		t.Fatal("31-byte device.key accepted")
	}
	b, err := os.ReadFile(short)
	backupCheck(t, err)
	if len(b) != 31 {
		t.Fatal("malformed device.key was replaced")
	}
}

func TestDevicePinRules(t *testing.T) {
	st, srv := deviceTestStore(t)
	r := httptest.NewRequest(http.MethodPost, "/devices/save", nil)
	const fp = "AA:BB:CC:DD"
	base := url.Values{
		"name": {"sw4"}, "management_ip": {"192.0.2.20"}, "port": {"57400"}, "platform": {"IOS-XE"},
		"fingerprint": {fp},
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
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"name": {"x"}}.Encode()))
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer POST %s: status %d, want 403", path, rec.Code)
		}
	}

	// Without a CSRF token the admin-side POST is refused even with a valid origin.
	bad := httptest.NewRequest(http.MethodPost, "/devices/save", strings.NewReader(url.Values{"name": {"sw5"}}.Encode()))
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
	_, srv := deviceTestStore(t)
	host, port, err := net.SplitHostPort(e.target)
	backupCheck(t, err)
	form := url.Values{"name": {"sw6"}, "management_ip": {host}, "port": {port}, "platform": {"IOS-XE"}}

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

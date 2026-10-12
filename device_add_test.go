package main

import (
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// deviceAddEnv starts a fake gNOI device and a server whose allowlist covers it.
func deviceAddEnv(t *testing.T, dev *fakeGNOIDevice) (*gnoiTestEnv, *Server) {
	t.Helper()
	env := newGNOITestEnv(t, dev)
	auth, err := NewAuth(env.store, false, false)
	backupCheck(t, err)
	srv := NewServer(env.store, auth)
	srv.gnoiAllow = env.allow
	return env, srv
}

// deviceAddForm is an add form aimed at the fake device, with unverified TLS so no pin is needed.
func deviceAddForm(t *testing.T, env *gnoiTestEnv, name string) url.Values {
	t.Helper()
	host, port, err := net.SplitHostPort(env.target)
	backupCheck(t, err)
	f := deviceForm1(name)
	f.Set("management_ip", host)
	f.Set("port", port)
	f.Set("username", testDevUser)
	f.Set("password", testDevPass)
	return f
}

func TestDeviceAddStoresAfterSuccessfulTest(t *testing.T) {
	sudi := testDeviceCertPEM(t, pkix.Name{CommonName: "Cisco", SerialNumber: "PID:C9300-24P SN:FCW2345A0BC"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	dev := &fakeGNOIDevice{sudi: sudi}
	env, srv := deviceAddEnv(t, dev)

	rec := devicePost(srv, "/devices/save", deviceAddForm(t, env, "sw7"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add: status %d: %s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/devices/")
	if id == "" {
		t.Fatal("no redirect to the device page")
	}
	got, ok, err := env.store.GetDevice(id)
	backupCheck(t, err)
	if !ok || got.Credentials == nil {
		t.Fatal("device or credentials not stored")
	}
	c, err := env.store.openCredentials(got.Credentials)
	backupCheck(t, err)
	if c.Username != testDevUser || c.Password != testDevPass {
		t.Fatal("stored credentials do not match the form")
	}
	if got.Snapshot == nil || got.Snapshot.Served == nil || got.Snapshot.Served.Fingerprint != env.fp {
		t.Fatalf("snapshot with served certificate not stored: %+v", got.Snapshot)
	}
	if got.Model != "C9300-24P" || got.Serial != "FCW2345A0BC" {
		t.Fatalf("model/serial = %q/%q", got.Model, got.Serial)
	}
}

func TestDeviceAddFailedTestStoresNothing(t *testing.T) {
	env, srv := deviceAddEnv(t, &fakeGNOIDevice{})
	form := deviceAddForm(t, env, "sw8")
	form.Set("password", "wrong-"+testDevPass)
	rec := devicePost(srv, "/devices/save", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("failed add: status %d, want 200 re-render", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Failed at auth") || !strings.Contains(body, "Connection test") {
		t.Fatal("check outcome not shown in the form")
	}
	if !strings.Contains(body, `value="sw8"`) || !strings.Contains(body, `value="`+testDevUser+`"`) {
		t.Fatal("entered values not kept in the form")
	}
	if strings.Contains(body, testDevPass) || strings.Contains(body, "wrong-"+testDevPass) {
		t.Fatal("password echoed back in the form")
	}
	if devs, _ := env.store.ListDevices(); len(devs) != 0 {
		t.Fatalf("device stored after a failed test: %d", len(devs))
	}
}

func TestDeviceAddOutsideAllowlistBlocksSave(t *testing.T) {
	env, srv := deviceAddEnv(t, &fakeGNOIDevice{})
	srv.gnoiAllow = nil
	rec := devicePost(srv, "/devices/save", deviceAddForm(t, env, "sw9"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Failed at connect") {
		t.Fatalf("allowlist refusal not shown: status %d", rec.Code)
	}
	if devs, _ := env.store.ListDevices(); len(devs) != 0 {
		t.Fatal("device stored although the address is outside the allowlist")
	}
}

func TestDeviceAddRequiresCredentials(t *testing.T) {
	env, srv := deviceAddEnv(t, &fakeGNOIDevice{})
	for _, drop := range []string{"username", "password"} {
		form := deviceAddForm(t, env, "sw10")
		form.Del(drop)
		rec := devicePost(srv, "/devices/save", form)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "username and password are required") {
			t.Fatalf("missing %s: status %d, want validation error", drop, rec.Code)
		}
	}
	if devs, _ := env.store.ListDevices(); len(devs) != 0 {
		t.Fatal("device stored without credentials")
	}
	if n := env.dev.snap().getCalls; n != 0 {
		t.Fatalf("device contacted %d times for a form with missing credentials", n)
	}
}

func TestDeviceEditDoesNotRunTest(t *testing.T) {
	env, srv := deviceAddEnv(t, &fakeGNOIDevice{})
	d := deviceForEnv(t, env, true)
	edit := deviceForm1("renamed")
	edit.Set("id", d.ID)
	edit.Set("management_ip", d.ManagementIP)
	edit.Set("username", testDevUser)
	edit.Set("password", "not-checked-"+testDevPass)
	rec := devicePost(srv, "/devices/save", edit)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit: status %d: %s", rec.Code, rec.Body.String())
	}
	if n := env.dev.snap().getCalls; n != 0 {
		t.Fatalf("edit contacted the device %d times", n)
	}
	if got, _, _ := env.store.GetDevice(d.ID); got.Name != "renamed" {
		t.Fatalf("edit not stored: %+v", got)
	}
}

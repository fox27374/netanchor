package main

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// logTo sends the standard logger to w for the rest of the test.
func logTo(t *testing.T, w *bytes.Buffer) {
	t.Helper()
	old := log.Writer()
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(old) })
}

func TestAppLogRotatesAndStaysBounded(t *testing.T) {
	dir := t.TempDir()
	a, err := openAppLog(dir)
	backupCheck(t, err)
	defer func() { a.f.Close() }()
	logDir := appLogDir(dir)
	if info, err := os.Stat(logDir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("logs dir perms: %v %v", info, err)
	}
	if info, err := os.Stat(a.path()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("log file perms: %v %v", info, err)
	}

	// Write about 12 MiB in 100-byte lines: two rotations, so .1 is overwritten.
	const total = 12 << 20
	written, last := 0, ""
	for i := 0; written < total; i++ {
		last = fmt.Sprintf("line %09d", i)
		line := last + strings.Repeat("x", 100-len(last)-1) + "\n"
		if _, err := a.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		written += len(line)
	}
	cur, err := os.ReadFile(a.path())
	backupCheck(t, err)
	prev, err := os.ReadFile(a.path() + ".1")
	backupCheck(t, err)
	if len(cur) == 0 || len(cur) > appLogMax {
		t.Fatalf("current file size %d, cap %d", len(cur), appLogMax)
	}
	if len(prev) == 0 || len(prev) > appLogMax {
		t.Fatalf("rotated file size %d, cap %d", len(prev), appLogMax)
	}
	if !strings.Contains(string(cur), last) {
		t.Fatal("newest line missing from the current file")
	}
	if strings.Contains(string(cur)+string(prev), "line 000000000x") {
		t.Fatal("oldest line survived two rotations; .1 should have been overwritten")
	}
}

func TestAppLogTailSpansRotatedFile(t *testing.T) {
	dir := t.TempDir()
	logDir := appLogDir(dir)
	backupCheck(t, os.MkdirAll(logDir, 0o700))
	backupCheck(t, os.WriteFile(filepath.Join(logDir, "netanchor.log.1"), []byte("p1\np2\np3\np4\np5\np6\np7\np8\np9\np10\n"), 0o600))
	backupCheck(t, os.WriteFile(filepath.Join(logDir, "netanchor.log"), []byte("c1\nc2\nc3\n"), 0o600))

	got, err := appLogLines(logDir, 5)
	backupCheck(t, err)
	if want := "p9,p10,c1,c2,c3"; strings.Join(got, ",") != want {
		t.Fatalf("tail 5 = %v, want %s", got, want)
	}
	got, err = appLogLines(logDir, 100)
	backupCheck(t, err)
	if len(got) != 13 || got[0] != "p1" || got[12] != "c3" {
		t.Fatalf("tail 100 = %v", got)
	}
	empty, err := appLogLines(t.TempDir(), 10)
	backupCheck(t, err)
	if len(empty) != 0 {
		t.Fatalf("no files should give no lines, got %v", empty)
	}
}

func TestLogsPagesAdminOnly(t *testing.T) {
	s, a := backupFixture(t)
	srv := NewServer(s, a)
	routes := a.Middleware(srv.Routes())
	backupCheck(t, a.AddUser("viewer", "viewer password", RoleViewer))
	backupCheck(t, os.MkdirAll(appLogDir(s.dir), 0o700))
	backupCheck(t, os.WriteFile(filepath.Join(appLogDir(s.dir), "netanchor.log"), []byte("startup known-line-xyz\n"), 0o600))

	admin := httptest.NewRecorder()
	a.issueSession(admin, "admin")
	viewer := httptest.NewRecorder()
	a.issueSession(viewer, "viewer")
	get := func(path, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		return w
	}
	adminCookie := admin.Result().Cookies()[0].String()
	viewerCookie := viewer.Result().Cookies()[0].String()

	for _, path := range []string{"/logs", "/logs.txt"} {
		if w := get(path, viewerCookie); w.Code != http.StatusForbidden {
			t.Errorf("viewer GET %s = %d, want 403", path, w.Code)
		}
		w := get(path, adminCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("admin GET %s = %d", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "known-line-xyz") {
			t.Errorf("admin GET %s does not show the log line", path)
		}
		if path == "/logs.txt" {
			if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Errorf("/logs.txt content type %q", ct)
			}
			if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("/logs.txt cache control %q", cc)
			}
		}
	}
}

func TestHealthzIsNotLogged(t *testing.T) {
	s, a := backupFixture(t)
	routes := NewServer(s, a).Routes()
	var buf bytes.Buffer
	logTo(t, &buf)
	routes.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/healthz", nil))
	if buf.Len() != 0 {
		t.Fatalf("healthz was logged: %q", buf.String())
	}
	routes.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/logo.svg", nil))
	if !strings.Contains(buf.String(), "GET /logo.svg") {
		t.Fatalf("other requests must still be logged, got %q", buf.String())
	}
}

func TestGNOIStepsLoggedWithoutPassword(t *testing.T) {
	sudi := testDeviceCertPEM(t, pkix.Name{CommonName: "Cisco", SerialNumber: "PID:C9300-24P SN:FCW2345A0BC"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	env, srv := deviceAddEnv(t, &fakeGNOIDevice{sudi: sudi})
	dataDir := t.TempDir()
	al, err := openAppLog(dataDir)
	backupCheck(t, err)
	defer al.f.Close()
	old := log.Writer()
	log.SetOutput(al)
	t.Cleanup(func() { log.SetOutput(old) })

	rec := devicePost(srv, "/devices/save", deviceAddForm(t, env, "sw7"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add: status %d: %s", rec.Code, rec.Body.String())
	}
	log.SetOutput(old)

	b, err := os.ReadFile(al.path())
	backupCheck(t, err)
	text := string(b)
	for _, want := range []string{"gnoi device=sw7 op=add step=connect status=ok", "step=auth status=ok"} {
		if !strings.Contains(text, want) {
			t.Errorf("log missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, testDevPass) {
		t.Fatalf("device password written to the log:\n%s", text)
	}
}

func TestBackupExcludesLogsDir(t *testing.T) {
	if backupPath("logs/netanchor.log") {
		t.Fatal("logs/ must not be a backup path")
	}
	src, _ := backupFixture(t)
	snap, err := snapshotBackup(src)
	backupCheck(t, err)

	// A restore into a live dir that already has logs/ must still activate and validate.
	dst, _ := backupFixture(t)
	backupCheck(t, os.MkdirAll(appLogDir(dst.dir), 0o700))
	backupCheck(t, os.WriteFile(filepath.Join(appLogDir(dst.dir), "netanchor.log"), []byte("keep me\n"), 0o600))
	stage, err := stageBackup(dst.dir, snap, false)
	backupCheck(t, err)
	backupCheck(t, activateBackup(dst.dir, stage, durableRename))
	backupCheck(t, recoverRestore(dst.dir))
	backupCheck(t, validateBackup(dst.dir))
	if _, err := os.Stat(filepath.Join(appLogDir(dst.dir), "netanchor.log")); err != nil {
		t.Fatalf("restore touched logs/: %v", err)
	}
}

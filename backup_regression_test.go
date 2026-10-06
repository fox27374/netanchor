package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBackupCanceledBehindUnfinishedLogin(t *testing.T) {
	s, a := backupFixture(t)
	app := NewServer(s, a)
	loginStarted := make(chan struct{})
	backupStarted := make(chan struct{})
	backupFinished := make(chan struct{})
	routes := app.Routes()
	ts := httptest.NewServer(a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			close(loginStarted)
		}
		if r.URL.Path == "/admin/backup" {
			close(backupStarted)
			defer close(backupFinished)
		}
		routes.ServeHTTP(w, r)
	})))
	defer ts.Close()
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	backupCheck(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "POST /login HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000\r\n\r\nusername=admin&", ts.Listener.Addr())
	backupCheck(t, err)
	<-loginStarted
	w := httptest.NewRecorder()
	a.issueSession(w, "admin")
	cookie := w.Result().Cookies()[0]
	r := httptest.NewRequest("POST", ts.URL+"/admin/backup", nil)
	r.AddCookie(cookie)
	form := url.Values{"csrf": {app.backupToken(r)}, "password": {testBackupPassword}, "password_confirm": {testBackupPassword}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err = http.NewRequestWithContext(ctx, "POST", ts.URL+"/admin/backup", strings.NewReader(form.Encode()))
	backupCheck(t, err)
	r.AddCookie(cookie)
	r.Header.Set("Origin", ts.URL)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		resp, err := ts.Client().Do(r)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-backupStarted
	time.Sleep(50 * time.Millisecond)
	client := &http.Client{Timeout: time.Second}
	// Waiting for exclusivity must not queue a writer that blocks new readers.
	resp, err := client.Get(ts.URL + "/healthz")
	backupCheck(t, err)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("waiting backup blocked new GUI requests")
	}
	cancel()
	<-clientDone
	select {
	case <-backupFinished:
	case <-time.After(time.Second):
		t.Fatal("canceled backup still waits behind unfinished login")
	}
	resp, err = client.Get(ts.URL + "/healthz")
	backupCheck(t, err)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("canceled backup left readers blocked")
	}
	scepServer := httptest.NewServer(app.scep.Routes())
	defer scepServer.Close()
	resp, err = client.Get(scepServer.URL + "/scep?operation=GetCACaps")
	backupCheck(t, err)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("canceled backup blocked SCEP listener")
	}
}

func TestBackupWaitTimeoutAndReadDeadline(t *testing.T) {
	s, a := backupFixture(t)
	// Keep the body/acquisition budgets short, but allow race-instrumented
	// PBKDF2 encryption in the subsequent successful backup to finish. Slow
	// response writes have their own independent short-deadline test below.
	s.operationLimits = operationLimits{read: 750 * time.Millisecond, write: 10 * time.Second, exclusiveWait: 80 * time.Millisecond}
	app := NewServer(s, a)
	started, finished := make(chan struct{}), make(chan struct{})
	routes := app.Routes()
	ts := httptest.NewServer(a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			close(started)
			defer close(finished)
		}
		routes.ServeHTTP(w, r)
	})))
	defer ts.Close()
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	backupCheck(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "POST /login HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000\r\n\r\nusername=", ts.Listener.Addr())
	backupCheck(t, err)
	<-started
	w := httptest.NewRecorder()
	a.issueSession(w, "admin")
	cookie := w.Result().Cookies()[0]
	r := httptest.NewRequest("POST", ts.URL+"/admin/backup", nil)
	r.AddCookie(cookie)
	form := url.Values{"csrf": {app.backupToken(r)}, "password": {testBackupPassword}, "password_confirm": {testBackupPassword}}
	r, err = http.NewRequest("POST", ts.URL+"/admin/backup", strings.NewReader(form.Encode()))
	backupCheck(t, err)
	r.AddCookie(cookie)
	r.Header.Set("Origin", ts.URL)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(r)
	backupCheck(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("busy snapshot status = %d; want 503", resp.StatusCode)
	}
	select {
	case <-finished:
		t.Fatal("backup did not time out before the unfinished login")
	default:
	}
	resp, err = client.Get(ts.URL + "/healthz")
	backupCheck(t, err)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("timed out backup blocked readers")
	}
	// Do not close the offending socket: the server's read deadline must release
	// the lease itself, without client cooperation.
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("unfinished login ignored request read deadline")
	}
	// Cancellation/timeout must leave the maintenance path usable too.
	r, err = http.NewRequest("POST", ts.URL+"/admin/backup", strings.NewReader(form.Encode()))
	backupCheck(t, err)
	r.AddCookie(cookie)
	r.Header.Set("Origin", ts.URL)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(r)
	backupCheck(t, err)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("backup after read timeout = %d", resp.StatusCode)
	}
}

func TestOperationWriteDeadlineReleasesLease(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	backupCheck(t, err)
	s.operationLimits = operationLimits{read: 20 * time.Millisecond, write: 150 * time.Millisecond}
	done := make(chan error, 1)
	ts := httptest.NewServer(s.operations(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 32<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				done <- err
				return
			}
		}
	})))
	defer ts.Close()
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	backupCheck(t, err)
	defer conn.Close()
	backupCheck(t, conn.(*net.TCPConn).SetReadBuffer(1024))
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", ts.Listener.Addr())
	backupCheck(t, err)
	// Never consume the response: the kernel send buffer must eventually fill.
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected write timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled response held operation lease indefinitely")
	}
	deadline := time.Now().Add(time.Second)
	for !s.operationsMu.TryLock() {
		if time.Now().After(deadline) {
			t.Fatal("write timeout did not release lease")
		}
		time.Sleep(time.Millisecond)
	}
	s.operationsMu.Unlock()
}

func TestBackupLegacyProfileRoundTrip(t *testing.T) {
	s, _ := backupFixture(t)
	legacy := []byte(`[{"name":"legacy","description":"preserve","algo":"ecp256","valid_days":90,"profile":"server"}]`)
	backupCheck(t, os.WriteFile(s.templatesPath(), legacy, 0600))
	plain, err := snapshotBackup(s)
	backupCheck(t, err)
	encrypted, err := sealBackup(plain, testBackupPassword)
	backupCheck(t, err)
	plain, err = openBackup(encrypted, testBackupPassword)
	backupCheck(t, err)
	destination := t.TempDir()
	stage, err := stageBackup(destination, plain, false)
	backupCheck(t, err)
	defer os.RemoveAll(stage)
	backupCheck(t, activateBackup(destination, stage, durableRename))
	for _, dir := range []string{s.dir, destination} {
		var profiles []CertTemplate
		backupCheck(t, backupJSON((&Store{dir: dir}).templatesPath(), &profiles))
		if len(profiles) != 1 || profiles[0].MaxDays != 365 || len(profiles[0].AllowedAlgos) != 4 || profiles[0].Description != "preserve" {
			t.Fatalf("migration not persisted in %s: %+v", dir, profiles)
		}
	}
}

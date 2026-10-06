package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testBackupPassword = "a long unique backup password"

func backupCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func backupRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	backupCheck(t, err)
	return b
}
func backupFixture(t *testing.T) (*Store, *Auth) {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	backupCheck(t, err)
	a, err := NewAuth(s, false, true)
	backupCheck(t, err)
	backupCheck(t, a.AddUser("admin", "admin password", RoleAdmin))
	_, err = CreateCA(s, CAParams{CommonName: "backup root", Algo: algoECP256, ValidDays: 3650})
	backupCheck(t, err)
	_, _, _, err = ensureServerCert(s, []string{"source.example"}, "")
	backupCheck(t, err)
	return s, a
}

func TestBackupFullRoundTrip(t *testing.T) {
	f := newSCEPFixture(t)
	s := f.e.store
	a, err := NewAuth(s, false, true)
	backupCheck(t, err)
	backupCheck(t, a.AddUser("restored-admin", "admin password", RoleAdmin))
	_, _, _, err = ensureServerCert(s, []string{"source.example"}, "")
	backupCheck(t, err)
	profile, _ := builtinByName("TLS-Server")
	profile.Name = "custom-server"
	profile.Builtin = false
	backupCheck(t, s.AddTemplate(profile))
	leaf, err := IssueCert(s, IssueParams{CommonName: "trash.example", Algo: algoECP256, IssuerID: caRoot, ValidDays: 10, Profile: profileServer})
	backupCheck(t, err)
	backupCheck(t, s.DeleteCert(leaf.Serial))
	raw, pending := pendingSCEP(t, f)
	unused := f.challenge(t) // also reconciles the prior committed issuance
	// Include a revoked challenge too: neither may reactivate after restore.
	revoked := f.challenge(t)
	backupCheck(t, f.e.revoke(hashSCEP([]byte(revoked))))
	backupCheck(t, os.WriteFile(filepath.Join(s.dir, "external-secret"), []byte("not included"), 0600))
	backupCheck(t, os.WriteFile(filepath.Join(s.dir, "auth", ".netanchor-abandoned"), []byte("not included"), 0600))
	plain, err := snapshotBackup(s)
	backupCheck(t, err)
	if bytes.Contains(plain, []byte("external-secret")) || bytes.Contains(plain, []byte("abandoned")) {
		t.Fatal("temporary/external files included")
	}
	sealed, err := sealBackup(plain, testBackupPassword)
	backupCheck(t, err)
	if bytes.Contains(sealed, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext key in encrypted backup")
	}
	decoded, err := openBackup(sealed, testBackupPassword)
	backupCheck(t, err)
	if !bytes.Equal(plain, decoded) {
		t.Fatal("encryption roundtrip changed archive")
	}
	oldSession := httptest.NewRecorder()
	a.issueSession(oldSession, "restored-admin")
	for _, regenerate := range []bool{false, true} {
		t.Run(fmt.Sprint("regenerate=", regenerate), func(t *testing.T) {
			t.Setenv("NETANCHOR_TLS_HOSTS", "destination.example,192.0.2.44")
			dst, auth := backupFixture(t)
			backupCheck(t, os.WriteFile(filepath.Join(dst.dir, "external-secret"), []byte("destination only"), 0600))
			stage, err := stageBackup(dst.dir, decoded, regenerate)
			backupCheck(t, err)
			backupCheck(t, activateBackup(dst.dir, stage, durableRename))
			backupCheck(t, recoverRestore(dst.dir))
			backupCheck(t, validateBackup(dst.dir))
			newAuth, err := NewAuth(dst, false, true)
			backupCheck(t, err)
			if _, ok := newAuth.findUser("admin"); ok {
				t.Fatal("temporary admin survived replacement")
			}
			if _, ok := newAuth.findUser("restored-admin"); !ok {
				t.Fatal("restored admin missing")
			}
			req := httptest.NewRequest("GET", "/", nil)
			req.AddCookie(oldSession.Result().Cookies()[0])
			if _, ok := newAuth.currentUser(req); ok {
				t.Fatal("source browser session survived")
			}
			if bytes.Equal(newAuth.sessionKey, auth.sessionKey) || bytes.Equal(newAuth.sessionKey, a.sessionKey) {
				t.Fatal("session key not fresh")
			}
			if string(backupRead(t, filepath.Join(dst.dir, "external-secret"))) != "destination only" {
				t.Fatal("external configuration replaced")
			}
			var archive backupArchive
			backupCheck(t, json.Unmarshal(decoded, &archive))
			for _, file := range archive.Files {
				if file.Path == "auth/session.key" || file.Path == "scep.json" || (regenerate && strings.HasPrefix(file.Path, "tls/")) {
					continue
				}
				if !bytes.Equal(file.Data, backupRead(t, filepath.Join(dst.dir, file.Path))) {
					t.Fatalf("changed %s", file.Path)
				}
			}
			cert, err := parseCertPEM(backupRead(t, dst.tlsCertPath()))
			backupCheck(t, err)
			if regenerate {
				backupCheck(t, cert.VerifyHostname("destination.example"))
			} else {
				backupCheck(t, cert.VerifyHostname("source.example"))
			}
			e := newSCEPService(dst)
			backupCheck(t, e.startup(""))
			if e.key != nil {
				t.Fatal("restored SCEP automatically unlocked")
			}
			backupCheck(t, e.selectCA(f.ca, "test-pass"))
			st, err := e.load()
			backupCheck(t, err)
			for _, c := range st.Challenges {
				if c.Used.IsZero() && !c.Revoked {
					t.Fatal("unused challenge survived")
				}
			}
			old := f.e
			f.e = e
			defer func() { f.e = old }()
			b, status := e.enroll(raw)
			got := f.response(t, b, status, true)
			if !bytes.Equal(got.Raw, pending.Challenges[0].DER) {
				t.Fatal("used issuance changed")
			}
			for _, secret := range []string{unused, revoked} {
				req := f.request(t, f.csr(t, secret, nil))
				b, status = e.enroll(req.Raw)
				f.response(t, b, status, false)
			}
		})
	}
}

func TestBackupAuthenticationAndBounds(t *testing.T) {
	b, err := sealBackup([]byte("secret data"), testBackupPassword)
	backupCheck(t, err)
	if _, err = openBackup(b, "wrong password long enough"); err == nil {
		t.Fatal("wrong password accepted")
	}
	for _, i := range []int{0, len(backupMagic), len(backupMagic) + 16, len(b) - 1} {
		damaged := bytes.Clone(b)
		damaged[i] ^= 1
		if _, err = openBackup(damaged, testBackupPassword); err == nil {
			t.Fatal("tampering accepted")
		}
	}
	if _, err = sealBackup(nil, "short"); err == nil {
		t.Fatal("weak password accepted")
	}
	if _, err = openBackup(make([]byte, backupLimit+100), testBackupPassword); err == nil {
		t.Fatal("oversize ciphertext accepted")
	}
	if _, err = stageBackup(t.TempDir(), make([]byte, backupLimit+1), false); err == nil {
		t.Fatal("oversize plaintext accepted")
	}
}

func TestBackupPendingAndDeletedSCEP(t *testing.T) {
	f := newSCEPFixture(t)
	_, pending := pendingSCEP(t, f)
	// Collect the authoritative pending journal without snapshot reconciliation,
	// as might be present in a supported archive produced after a failed publish.
	plain, err := snapshotBackup(f.e.store)
	backupCheck(t, err)
	var a backupArchive
	backupCheck(t, json.Unmarshal(plain, &a))
	serial := pending.Challenges[0].Record.Serial
	files := a.Files[:0]
	for _, file := range a.Files {
		if file.Path == "certs/"+serial+"-cert.pem" {
			continue
		}
		if file.Path == "index.json" {
			var recs []CertRecord
			backupCheck(t, json.Unmarshal(file.Data, &recs))
			kept := recs[:0]
			for _, r := range recs {
				if r.Serial != serial {
					kept = append(kept, r)
				}
			}
			file.Data, _ = json.Marshal(kept)
		}
		if file.Path == "scep.json" {
			file.Data, _ = json.Marshal(pending)
		}
		files = append(files, file)
	}
	a.Files = files
	plain, err = json.Marshal(a)
	backupCheck(t, err)
	for _, mutate := range []func(*scepState){
		func(st *scepState) { st.Challenges[0].Record.Serial = "../escape" },
		func(st *scepState) { st.Challenges[0].Used = time.Time{} },
		func(st *scepState) { st.Challenges[0].Record.TemplatePolicy.Profile = profileClient },
	} {
		var bad backupArchive
		backupCheck(t, json.Unmarshal(plain, &bad))
		for i, f := range bad.Files {
			if f.Path == "scep.json" {
				var st scepState
				backupCheck(t, json.Unmarshal(f.Data, &st))
				mutate(&st)
				bad.Files[i].Data, _ = json.Marshal(st)
			}
		}
		b, err := json.Marshal(bad)
		backupCheck(t, err)
		if _, err = stageBackup(t.TempDir(), b, false); err == nil {
			t.Fatal("inconsistent SCEP journal accepted")
		}
	}
	stage, err := stageBackup(t.TempDir(), plain, false)
	backupCheck(t, err)
	defer os.RemoveAll(stage)
	s := &Store{dir: stage}
	st, err := newSCEPService(s).load()
	backupCheck(t, err)
	if !st.Challenges[0].Published || !bytes.Equal(backupRead(t, s.certPath(serial)), encodeCertPEM(pending.Challenges[0].DER)) {
		t.Fatal("pending journal not reconciled")
	}
	if _, ok := s.RecordBySerial(serial); !ok {
		t.Fatal("pending index not recovered")
	}
	backupCheck(t, f.e.store.DeleteCert(serial))
	plain, err = snapshotBackup(f.e.store)
	backupCheck(t, err)
	stage2, err := stageBackup(t.TempDir(), plain, false)
	backupCheck(t, err)
	defer os.RemoveAll(stage2)
	if _, err = os.Stat(filepath.Join(stage2, "certs", serial+"-cert.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted SCEP certificate resurrected")
	}
}

func TestBackupRecoveryDecisionsAndStagingFailure(t *testing.T) {
	s, _ := backupFixture(t)
	before, err := snapshotBackup(s)
	backupCheck(t, err)
	// Failure to create staging cannot alter logical data.
	block := filepath.Join(s.dir, "blocked")
	backupCheck(t, os.WriteFile(block, []byte("file"), 0600))
	if _, err = stageBackup(block, before, false); err == nil {
		t.Fatal("staging storage error ignored")
	}
	after, err := snapshotBackup(s)
	backupCheck(t, err)
	assertBackupFilesEqual(t, before, after)
	// A durable committed journal must keep new data and discard old material.
	tx := filepath.Join(s.dir, ".restore")
	backupCheck(t, os.MkdirAll(filepath.Join(tx, "old", "auth"), 0700))
	backupCheck(t, os.WriteFile(filepath.Join(tx, "old", "auth", "session.key"), []byte("old"), 0600))
	j := restoreJournal{Version: 1, Committed: true, Present: map[string]bool{}}
	for _, root := range backupRoots {
		j.Present[root], err = exists(filepath.Join(s.dir, root))
		backupCheck(t, err)
	}
	b, _ := json.Marshal(j)
	backupCheck(t, durableWrite(filepath.Join(tx, "journal.json"), b))
	orphan := filepath.Join(s.dir, ".backup-stage-orphan")
	backupCheck(t, os.Mkdir(orphan, 0700))
	backupCheck(t, os.WriteFile(filepath.Join(orphan, "secret"), []byte("decrypted"), 0600))
	backupCheck(t, recoverRestore(s.dir))
	backupCheck(t, recoverRestore(s.dir))
	after, err = snapshotBackup(s)
	backupCheck(t, err)
	assertBackupFilesEqual(t, before, after)
	if present, _ := exists(orphan); present {
		t.Fatal("abandoned plaintext not cleaned")
	}
	// Unknown recovery versions fail closed, without changing logical data.
	backupCheck(t, os.Mkdir(tx, 0700))
	j.Version = 2
	b, _ = json.Marshal(j)
	backupCheck(t, durableWrite(filepath.Join(tx, "journal.json"), b))
	if err = recoverRestore(s.dir); err == nil {
		t.Fatal("future journal accepted")
	}
	after, err = snapshotBackup(s)
	backupCheck(t, err)
	assertBackupFilesEqual(t, before, after)
}

func TestBackupRejectsInvalidArchives(t *testing.T) {
	s, _ := backupFixture(t)
	plain, err := snapshotBackup(s)
	backupCheck(t, err)
	for name, mutate := range map[string]func(*backupArchive){
		"future format":    func(a *backupArchive) { a.Format = 2 },
		"traversal":        func(a *backupArchive) { a.Files[0].Path = "../escaped" },
		"absolute":         func(a *backupArchive) { a.Files[0].Path = "/auth/users.json" },
		"unexpected":       func(a *backupArchive) { a.Files[0].Path = "compose.yaml" },
		"recovery journal": func(a *backupArchive) { a.Files[0].Path = ".restore/journal.json" },
		"duplicate":        func(a *backupArchive) { a.Files = append(a.Files, a.Files[0]) },
		"size":             func(a *backupArchive) { a.Files[0].Data = make([]byte, backupFileLimit+1) },
		"missing key": func(a *backupArchive) {
			for i, f := range a.Files {
				if f.Path == "cas/root/key.pem" {
					a.Files = append(a.Files[:i], a.Files[i+1:]...)
					break
				}
			}
		},
		"key mismatch": func(a *backupArchive) {
			var key []byte
			for _, f := range a.Files {
				if f.Path == "tls/server-key.pem" {
					key = f.Data
				}
			}
			for i := range a.Files {
				if a.Files[i].Path == "cas/root/key.pem" {
					a.Files[i].Data = key
				}
			}
		},
		"index mismatch": func(a *backupArchive) {
			for i, f := range a.Files {
				if f.Path == "index.json" {
					var recs []CertRecord
					json.Unmarshal(f.Data, &recs)
					recs[0].Serial = "abc"
					a.Files[i].Data, _ = json.Marshal(recs)
				}
			}
		},
		"user KDF bound": func(a *backupArchive) {
			for i, f := range a.Files {
				if f.Path == "auth/users.json" {
					a.Files[i].Data = bytes.Replace(f.Data, []byte("600000"), []byte("999999999"), 1)
				}
			}
		},
		"HTTPS mismatch": func(a *backupArchive) {
			for i, f := range a.Files {
				if f.Path == "tls/server-key.pem" {
					a.Files[i].Data = []byte("bad key")
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var a backupArchive
			backupCheck(t, json.Unmarshal(plain, &a))
			mutate(&a)
			b, err := json.Marshal(a)
			backupCheck(t, err)
			dir := t.TempDir()
			if _, err = stageBackup(dir, b, false); err == nil {
				t.Fatal("invalid archive accepted")
			}
			entries, err := os.ReadDir(dir)
			backupCheck(t, err)
			if len(entries) != 0 {
				t.Fatal("failed validation left decrypted staging material")
			}
		})
	}
	for _, b := range [][]byte{[]byte(`{"Format":1,"Format":2}`), []byte(`{"Format":1,"unknown":true}`), append(bytes.Clone(plain), []byte(` {}`)...)} {
		if _, err = stageBackup(t.TempDir(), b, false); err == nil {
			t.Fatal("invalid schema accepted")
		}
	}
	backupCheck(t, os.Symlink(s.caKeyPath(caRoot), filepath.Join(s.dir, "certs", "a-key.pem")))
	if _, err = snapshotBackup(s); err == nil {
		t.Fatal("symlink exported")
	}
}

func restoreRequest(t *testing.T, s *Server, archive []byte, token, confirm string) *http.Request {
	t.Helper()
	var b bytes.Buffer
	m := multipart.NewWriter(&b)
	for k, v := range map[string]string{"csrf": token, "password": testBackupPassword, "confirm": confirm} {
		backupCheck(t, m.WriteField(k, v))
	}
	f, err := m.CreateFormFile("archive", "backup.nab")
	backupCheck(t, err)
	_, err = f.Write(archive)
	backupCheck(t, err)
	backupCheck(t, m.Close())
	r := httptest.NewRequest("POST", "http://netanchor.test/admin/restore", &b)
	r.Header.Set("Content-Type", m.FormDataContentType())
	r.Header.Set("Origin", "https://netanchor.test")
	return r
}

func TestBackupHTTPAuthorizationRestoreAndBootstrap(t *testing.T) {
	s, a := backupFixture(t)
	srv := NewServer(s, a)
	routes := a.Middleware(srv.Routes())
	backupCheck(t, a.AddUser("viewer", "viewer password", RoleViewer))
	admin := httptest.NewRecorder()
	a.issueSession(admin, "admin")
	cookie := admin.Result().Cookies()[0]
	viewer := httptest.NewRecorder()
	a.issueSession(viewer, "viewer")
	for _, path := range []string{"/admin/backup", "/admin/restore"} {
		for _, method := range []string{"GET", "POST"} {
			r := httptest.NewRequest(method, path, nil)
			r.AddCookie(viewer.Result().Cookies()[0])
			w := httptest.NewRecorder()
			routes.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("viewer access %s %s = %d", method, path, w.Code)
			}
		}
	}
	for _, handler := range []http.HandlerFunc{srv.handleBackupPage, srv.handleBackup, srv.handleRestore} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("POST", "/admin/backup", nil))
		if w.Code != 403 {
			t.Fatal("handler omitted admin check")
		}
	}
	r := httptest.NewRequest("GET", "http://netanchor.test/admin/backup", nil)
	r.AddCookie(cookie)
	token := srv.backupToken(r)
	form := url.Values{"csrf": {token}, "password": {testBackupPassword}, "password_confirm": {testBackupPassword}}
	var archive []byte
	for _, origin := range []string{"", "null", "https://attacker.test", "https://netanchor.test"} {
		r := httptest.NewRequest("POST", "http://netanchor.test/admin/backup", strings.NewReader(form.Encode()))
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		if origin != "https://netanchor.test" {
			if w.Code != 403 {
				t.Fatal("cross-origin backup allowed")
			}
		} else {
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			archive = w.Body.Bytes()
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("download cached")
			}
		}
	}
	for _, tc := range []struct{ token, confirm string }{{"wrong", "REPLACE"}, {token, ""}} {
		r := restoreRequest(t, srv, archive, tc.token, tc.confirm)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 403 {
			t.Fatal("unconfirmed/CSRF restore allowed")
		}
	}
	before, err := snapshotBackup(s)
	backupCheck(t, err)
	damaged := bytes.Clone(archive)
	damaged[len(damaged)-1] ^= 1
	r = restoreRequest(t, srv, damaged, token, "REPLACE")
	r.AddCookie(cookie)
	bad := httptest.NewRecorder()
	routes.ServeHTTP(bad, r)
	if bad.Code != 400 {
		t.Fatal("damaged archive accepted")
	}
	after, err := snapshotBackup(s)
	backupCheck(t, err)
	assertBackupFilesEqual(t, before, after)
	// Fresh instance: setup lands on management, no CA needed to restore.
	dst, err := OpenStore(t.TempDir())
	backupCheck(t, err)
	da, err := NewAuth(dst, false, true)
	backupCheck(t, err)
	ds := NewServer(dst, da)
	dr := da.Middleware(ds.Routes())
	setup := url.Values{"username": {"temporary"}, "password": {"temporary password"}, "password_confirm": {"temporary password"}}
	r = httptest.NewRequest("POST", "/setup", strings.NewReader(setup.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	dr.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/users" || dst.HasCA(caRoot) {
		t.Fatal("bad fresh bootstrap path")
	}
	tempCookie := w.Result().Cookies()[0]
	r = httptest.NewRequest("GET", "/admin/backup", nil)
	r.AddCookie(tempCookie)
	token = ds.backupToken(r)
	r = restoreRequest(t, ds, archive, token, "REPLACE")
	r.AddCookie(tempCookie)
	w = httptest.NewRecorder()
	dr.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "restart required") {
		t.Fatal(w.Body.String())
	}
	select {
	case <-ds.restart:
	default:
		t.Fatal("shutdown not requested")
	}
	for _, handler := range []http.Handler{dr, ds.scep.Routes()} {
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/scep?operation=GetCACaps", nil))
		if w.Code != 503 {
			t.Fatal("stale process still serving")
		}
	}
	backupCheck(t, recoverRestore(dst.dir))
	newAuth, err := NewAuth(dst, false, true)
	backupCheck(t, err)
	if _, ok := newAuth.findUser("temporary"); ok {
		t.Fatal("temporary user remained")
	}
	if _, ok := newAuth.findUser("admin"); !ok {
		t.Fatal("restored user missing")
	}
}

func TestBackupBarrierWaitsWholeOperationsAndResumes(t *testing.T) {
	s, a := backupFixture(t)
	a.enabled = false
	srv := NewServer(s, a)
	started := make(chan struct{})
	release := make(chan struct{})
	writerDone := make(chan struct{})
	// Deliberately split a real issuance across PEM and metadata writes.
	rec, err := IssueCert(s, IssueParams{CommonName: "split", Algo: algoECP256, IssuerID: caRoot, ValidDays: 2})
	backupCheck(t, err)
	cert := backupRead(t, s.certPath(rec.Serial))
	key := backupRead(t, s.keyPath(rec.Serial))
	backupCheck(t, s.DeleteCert(rec.Serial))
	writer := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.SaveCert(rec.Serial, cert, key); err != nil {
			t.Error(err)
		}
		close(started)
		<-release
		if err := s.AddRecord(rec); err != nil {
			t.Error(err)
		}
	}))
	go func() {
		defer close(writerDone)
		writer.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/issue", nil))
	}()
	<-started
	result := make(chan error, 1)
	reader := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result <- srv.backupExclusive(r, func() error {
			plain, err := snapshotBackup(s)
			if err != nil {
				return err
			}
			stage, err := stageBackup(s.dir, plain, false)
			if stage != "" {
				os.RemoveAll(stage)
			}
			return err
		})
	}))
	go reader.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/admin/backup", nil))
	select {
	case err := <-result:
		t.Fatalf("snapshot passed incomplete writer: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-writerDone
	backupCheck(t, <-result)
	// SCEP-only listener must wait for the same exclusive barrier.
	s.operationsMu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.scep.Routes().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/scep?operation=GetCACaps", nil))
	}()
	select {
	case <-done:
		t.Fatal("SCEP bypassed barrier")
	case <-time.After(30 * time.Millisecond):
	}
	s.operationsMu.Unlock()
	<-done
	// A failed snapshot automatically releases exclusivity, including malformed journal.
	backupCheck(t, os.WriteFile(filepath.Join(s.dir, "scep.json"), []byte("bad JSON"), 0600))
	r := httptest.NewRequest("POST", "http://netanchor.test/admin/backup", nil)
	form := url.Values{"csrf": {srv.backupToken(r)}, "password": {testBackupPassword}, "password_confirm": {testBackupPassword}}
	r = httptest.NewRequest("POST", "http://netanchor.test/admin/backup", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://netanchor.test")
	w := httptest.NewRecorder()
	a.Middleware(srv.Routes()).ServeHTTP(w, r)
	if w.Code != 500 {
		t.Fatal("expected snapshot failure")
	}
	w = httptest.NewRecorder()
	a.Middleware(srv.Routes()).ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatal("failure did not resume serving")
	}
}

func TestBackupRollbackEveryComponent(t *testing.T) {
	s, _ := backupFixture(t)
	plain, err := snapshotBackup(s)
	backupCheck(t, err)
	for failAt := 1; failAt <= 10; failAt++ {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			dst, _ := backupFixture(t)
			before, err := snapshotBackup(dst)
			backupCheck(t, err)
			stage, err := stageBackup(dst.dir, plain, false)
			backupCheck(t, err)
			count := 0
			err = activateBackup(dst.dir, stage, func(from, to string) error {
				count++
				if count == failAt {
					return errors.New("injected storage failure")
				}
				return durableRename(from, to)
			})
			if err == nil {
				t.Fatal("failure injection missed")
			}
			backupCheck(t, recoverRestore(dst.dir))
			after, err := snapshotBackup(dst)
			backupCheck(t, err)
			assertBackupFilesEqual(t, before, after)
		})
	}
}

func TestBackupRollbackAbsentAndRemovedComponents(t *testing.T) {
	source, err := OpenStore(t.TempDir())
	backupCheck(t, err)
	_, err = NewAuth(source, false, false)
	backupCheck(t, err)
	profile, _ := builtinByName("TLS-Server")
	profile.Name = "restored-profile"
	profile.Builtin = false
	backupCheck(t, source.AddTemplate(profile))
	backupCheck(t, newSCEPService(source).save(scepState{}))
	plain, err := snapshotBackup(source)
	backupCheck(t, err)
	dst, _ := backupFixture(t)
	leaf, err := IssueCert(dst, IssueParams{CommonName: "deleted", Algo: algoECP256, IssuerID: caRoot, ValidDays: 1})
	backupCheck(t, err)
	backupCheck(t, dst.DeleteCert(leaf.Serial))
	before, err := snapshotBackup(dst)
	backupCheck(t, err)
	for n := 1; n <= 12; n++ {
		stage, err := stageBackup(dst.dir, plain, false)
		backupCheck(t, err)
		count := 0
		err = activateBackup(dst.dir, stage, func(from, to string) error {
			// Return an error AFTER rename, modeling a failed subsequent fsync.
			err := durableRename(from, to)
			count++
			if count == n {
				return errors.New("post-rename failure")
			}
			return err
		})
		if err == nil {
			t.Fatalf("failure point %d missed", n)
		}
		backupCheck(t, recoverRestore(dst.dir))
		after, err := snapshotBackup(dst)
		backupCheck(t, err)
		assertBackupFilesEqual(t, before, after)
	}
	stage, err := stageBackup(dst.dir, plain, false)
	backupCheck(t, err)
	backupCheck(t, activateBackup(dst.dir, stage, durableRename))
	if dst.HasCA(caRoot) {
		t.Fatal("destination CA retained")
	}
	for _, root := range []string{"index.json", "trash"} {
		if present, _ := exists(filepath.Join(dst.dir, root)); present {
			t.Fatal("old optional component retained")
		}
	}
	for _, root := range []string{"templates.json", "scep.json"} {
		if present, _ := exists(filepath.Join(dst.dir, root)); !present {
			t.Fatal("new component missing")
		}
	}
}

func assertBackupFilesEqual(t *testing.T, a, b []byte) {
	t.Helper()
	var aa, bb backupArchive
	backupCheck(t, json.Unmarshal(a, &aa))
	backupCheck(t, json.Unmarshal(b, &bb))
	x, _ := json.Marshal(aa.Files)
	y, _ := json.Marshal(bb.Files)
	if !bytes.Equal(x, y) {
		t.Fatal("rollback changed original logical files")
	}
}

// This helper runs the real main/shutdown path and transaction code in a child
// process. Exit points simulate abrupt death without deferred cleanup.
func TestBackupProcessHelper(t *testing.T) {
	mode := os.Getenv("NETANCHOR_BACKUP_TEST_MODE")
	if mode == "" {
		return
	}
	dir := os.Getenv("NETANCHOR_BACKUP_TEST_DIR")
	if mode == "serve" {
		flag.CommandLine = flag.NewFlagSet("netanchor", flag.ExitOnError)
		os.Args = []string{"netanchor", "-data", dir, "-addr", os.Getenv("NETANCHOR_BACKUP_TEST_ADDR")}
		main()
		os.Exit(0)
	}
	n, _ := strconv.Atoi(os.Getenv("NETANCHOR_BACKUP_TEST_CRASH"))
	count := 0
	err := activateBackup(dir, os.Getenv("NETANCHOR_BACKUP_TEST_STAGE"), func(from, to string) error {
		err := durableRename(from, to)
		count++
		if count == n {
			os.Exit(73)
		}
		return err
	})
	if err != nil {
		os.Exit(74)
	}
	os.Exit(0)
}

func TestBackupCrashRecovery(t *testing.T) {
	s, _ := backupFixture(t)
	plain, err := snapshotBackup(s)
	backupCheck(t, err)
	for n := 1; n <= 10; n++ {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			dst, _ := backupFixture(t)
			before, err := snapshotBackup(dst)
			backupCheck(t, err)
			stage, err := stageBackup(dst.dir, plain, false)
			backupCheck(t, err)
			cmd := exec.Command(os.Args[0], "-test.run=^TestBackupProcessHelper$")
			cmd.Env = append(os.Environ(), "NETANCHOR_BACKUP_TEST_MODE=crash", "NETANCHOR_BACKUP_TEST_DIR="+dst.dir, "NETANCHOR_BACKUP_TEST_STAGE="+stage, "NETANCHOR_BACKUP_TEST_CRASH="+strconv.Itoa(n))
			err = cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("child crash: %v", err)
			}
			backupCheck(t, recoverRestore(dst.dir))
			backupCheck(t, recoverRestore(dst.dir))
			after, err := snapshotBackup(dst)
			backupCheck(t, err)
			assertBackupFilesEqual(t, before, after)
		})
	}
}

func TestBackupRealProcessShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess server")
	}
	s, _ := backupFixture(t)
	plain, err := snapshotBackup(s)
	backupCheck(t, err)
	encrypted, err := sealBackup(plain, testBackupPassword)
	backupCheck(t, err)
	destination, originalAuth := backupFixture(t)
	dir := destination.dir
	// Simulate death after moving auth away. Startup must recover it before
	// NewAuth creates or caches a replacement signing key.
	tx := filepath.Join(dir, ".restore")
	backupCheck(t, os.MkdirAll(filepath.Join(tx, "old"), 0700))
	j := restoreJournal{Version: 1, Present: map[string]bool{}}
	for _, root := range backupRoots {
		j.Present[root], err = exists(filepath.Join(dir, root))
		backupCheck(t, err)
	}
	journal, _ := json.Marshal(j)
	backupCheck(t, durableWrite(filepath.Join(tx, "journal.json"), journal))
	backupCheck(t, durableRename(filepath.Join(dir, "auth"), filepath.Join(tx, "old", "auth")))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	backupCheck(t, err)
	addr := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBackupProcessHelper$")
	cmd.Env = append(os.Environ(), "NETANCHOR_BACKUP_TEST_MODE=serve", "NETANCHOR_BACKUP_TEST_DIR="+dir, "NETANCHOR_BACKUP_TEST_ADDR="+addr, "NETANCHOR_TLS=off", "NETANCHOR_DISABLE_AUTH=1", "NETANCHOR_SCEP_ADDR=", "NETANCHOR_SCEP_SECRET_FILE=")
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	backupCheck(t, cmd.Start())
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	client := &http.Client{Timeout: 2 * time.Second}
	base := "http://" + addr
	var page []byte
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		resp, err := client.Get(base + "/admin/backup")
		if err == nil {
			page, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	match := regexp.MustCompile(`name="csrf" value="([a-f0-9]+)"`).FindSubmatch(page)
	if len(match) != 2 {
		t.Fatal("server not ready")
	}
	if string(match[1]) != originalAuth.sign("backup-csrf-v1|trusted-local") {
		t.Fatal("startup cached authentication before restore recovery")
	}
	r := restoreRequest(t, nil, encrypted, string(match[1]), "REPLACE")
	r.URL, _ = url.Parse(base + "/admin/restore")
	r.Host = addr
	r.RequestURI = ""
	r.Header.Set("Origin", base)
	resp, err := client.Do(r)
	backupCheck(t, err)
	body, err := io.ReadAll(resp.Body)
	backupCheck(t, err)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("Restore complete")) {
		t.Fatalf("restore response: %d %s", resp.StatusCode, body)
	}
	backupCheck(t, cmd.Wait())
	if !strings.Contains(logs.String(), "Restore requires restart") {
		t.Fatal("missing manual restart log")
	}
	backupCheck(t, recoverRestore(dir))
	backupCheck(t, validateBackup(dir))
}

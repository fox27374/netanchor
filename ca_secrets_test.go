package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSecret(t *testing.T, dir, id, passphrase string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, id), []byte(passphrase), 0o600); err != nil {
		t.Fatal(err)
	}
}

// secretsStore returns a reopened data dir with an encrypted root and an encrypted,
// non-SCEP intermediate "ops". Nothing is unlocked.
func secretsStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(s, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000, Passphrase: "root-pass"}); err != nil {
		t.Fatal(err)
	}
	ops, err := CreateIntermediate(s, IntermediateParams{CommonName: "Ops", Algo: algoECP256, ValidDays: 500, ParentID: caRoot, ParentPassphrase: "root-pass", Passphrase: "ops-pass"})
	if err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, ops.CAID
}

// Startup with a secrets dir unlocks the SCEP CA, and enrollment works with no UI unlock.
func TestCASecretsUnlockSCEPAtStartup(t *testing.T) {
	f := newSCEPFixture(t)
	secrets := t.TempDir()
	writeSecret(t, secrets, f.ca, "test-pass\n")
	restarted, err := OpenStore(f.e.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted.unlockSecrets(secrets)
	f.e = newSCEPService(restarted)
	if err := f.e.startup(); err != nil {
		t.Fatal(err)
	}
	if restarted.CALocked(f.ca) {
		t.Fatal("SCEP CA stayed locked despite its passphrase file")
	}
	secret := f.challenge(t)
	req := f.request(t, f.csr(t, secret, []string{"switch.example.net"}))
	raw, status := f.e.enroll(req.Raw, "")
	f.response(t, raw, status, true)
}

// A passphrase file that does not decrypt the key leaves the CA locked; startup still succeeds.
func TestCASecretsWrongPassphraseStaysLocked(t *testing.T) {
	f := newSCEPFixture(t)
	secrets := t.TempDir()
	writeSecret(t, secrets, f.ca, "not-the-passphrase")
	restarted, err := OpenStore(f.e.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted.unlockSecrets(secrets)
	if !restarted.CALocked(f.ca) {
		t.Fatal("wrong passphrase unlocked the CA")
	}
	f.e = newSCEPService(restarted)
	if err := f.e.startup(); err != nil {
		t.Fatalf("startup failed on a wrong passphrase file: %v", err)
	}
	if err := f.e.selectCA(f.ca); err == nil {
		t.Fatal("locked CA selected for SCEP")
	}
	secret := f.challenge(t)
	req := f.request(t, f.csr(t, secret, []string{"switch.example.net"}))
	if _, status := f.e.enroll(req.Raw, ""); status != 503 {
		t.Fatalf("locked SCEP CA answered with status %d", status)
	}

	srv := NewServer(restarted, mustAuth(t, restarted))
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, httptest.NewRequest("GET", "/ca", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `>locked<`) {
		t.Fatalf("CA page does not show a locked badge (status %d)", w.Code)
	}
}

// Issuing with an unlocked non-SCEP CA needs no passphrase form value.
func TestCASecretsIssueReusesUnlockedCA(t *testing.T) {
	s, ops := secretsStore(t)
	secrets := t.TempDir()
	writeSecret(t, secrets, caRoot, "root-pass\n")
	writeSecret(t, secrets, ops, "ops-pass\n")
	s.unlockSecrets(secrets)
	if s.CALocked(ops) || s.CALocked(caRoot) {
		t.Fatal("CAs stayed locked despite their passphrase files")
	}
	if _, _, err := loadCA(s, ops, ""); err != nil {
		t.Fatalf("push path cannot reuse the unlocked CA: %v", err)
	}

	srv := NewServer(s, mustAuth(t, s))
	form := url.Values{"common_name": {"switch.example.net"}, "issuer": {ops}, "template": {"builtin:TLS-Server"}, "dns_sans": {"switch.example.net"}}
	req := httptest.NewRequest("POST", "/issue", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("issue with unlocked CA: status %d: %s", w.Code, w.Body.String())
	}
}

// A locked CA with a one-off passphrase signs once and stays locked afterwards.
func TestCASecretsOneOffPassphraseNotRetained(t *testing.T) {
	s, _ := secretsStore(t)
	if !s.CALocked(caRoot) {
		t.Fatal("root unexpectedly unlocked")
	}
	p := IssueParams{CommonName: "one-off.example.net", SANs: []string{"one-off.example.net"}, Algo: algoECP256, ValidDays: 30, Profile: profileServer, IssuerID: caRoot}
	if _, err := IssueCert(s, p); err == nil {
		t.Fatal("locked CA issued without a passphrase")
	}
	p.CAPassphrase = "root-pass"
	if _, err := IssueCert(s, p); err != nil {
		t.Fatalf("one-off passphrase rejected: %v", err)
	}
	if !s.CALocked(caRoot) {
		t.Fatal("one-off passphrase unlocked the CA")
	}
}

func mustAuth(t *testing.T, s *Store) *Auth {
	t.Helper()
	a, err := NewAuth(s, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// passphraseStore opens a fresh data dir with an administrator and no CAs.
func passphraseStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuth(s, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddUser("admin", "admin password", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	return s
}

// Creating an encrypted intermediate writes its passphrase (0600) to the default
// directory, and a restart unlocks both CAs from it.
func TestCASecretsCreateWritesPassphraseFile(t *testing.T) {
	t.Setenv("NETANCHOR_CA_SECRETS_DIR", "")
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(s, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000, Passphrase: "root-pass"}); err != nil {
		t.Fatal(err)
	}
	ops, err := CreateIntermediate(s, IntermediateParams{CommonName: "Ops", Algo: algoECP256, ValidDays: 500, ParentID: caRoot, ParentPassphrase: "root-pass", Passphrase: "ops-pass"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca-secrets", ops.CAID)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("passphrase file mode %v", info.Mode().Perm())
	}
	if b := backupRead(t, path); string(b) != "ops-pass" {
		t.Fatalf("passphrase file content %q", b)
	}
	if s.CALocked(ops.CAID) || s.CALocked(caRoot) {
		t.Fatal("created CAs locked in this process")
	}
	if note := s.passphraseNote(ops.CAID); !strings.Contains(note, "was saved to "+path) {
		t.Fatalf("note %q", note)
	}

	restarted, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted.unlockSecrets(restarted.caSecretsDir())
	if restarted.CALocked(ops.CAID) || restarted.CALocked(caRoot) {
		t.Fatal("CAs stayed locked after restart despite passphrase files")
	}
}

// An unwritable secrets dir does not fail creation; the CA is unlocked until restart and the message warns.
func TestCASecretsUnwritableDirWarnsButCreates(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETANCHOR_CA_SECRETS_DIR", blocker)
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(s, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000, Passphrase: "root-pass"}); err != nil {
		t.Fatalf("creation failed on unwritable secrets dir: %v", err)
	}
	if s.CALocked(caRoot) {
		t.Fatal("root locked until restart despite creation with passphrase")
	}
	if note := s.passphraseNote(caRoot); !strings.Contains(note, "could not be saved") || !strings.Contains(note, filepath.Join(blocker, caRoot)) {
		t.Fatalf("note does not warn and name the file: %q", note)
	}

	// The create-root handler shows the same warning in its flash message.
	h, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(h, mustAuth(t, h))
	form := url.Values{"common_name": {"root"}, "algo": {"ecp256"}, "valid_days": {"1000"}, "passphrase": {"root-pass"}, "passphrase_confirm": {"root-pass"}}
	req := httptest.NewRequest("POST", "/ca/root", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create root: status %d: %s", w.Code, w.Body.String())
	}
	page := httptest.NewRequest("GET", "/ca", nil)
	for _, c := range w.Result().Cookies() {
		page.AddCookie(c)
	}
	pw := httptest.NewRecorder()
	srv.Routes().ServeHTTP(pw, page)
	if !strings.Contains(pw.Body.String(), "could not be saved") {
		t.Fatal("CA page does not show the passphrase save warning")
	}
}

// Deleting an intermediate moves its passphrase file into the same trash entry as its key.
func TestCASecretsDeleteMovesPassphraseToTrash(t *testing.T) {
	t.Setenv("NETANCHOR_CA_SECRETS_DIR", "")
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(s, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000, Passphrase: "root-pass"}); err != nil {
		t.Fatal(err)
	}
	ops, err := CreateIntermediate(s, IntermediateParams{CommonName: "Ops", Algo: algoECP256, ValidDays: 500, ParentID: caRoot, ParentPassphrase: "root-pass", Passphrase: "ops-pass"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCA(ops.CAID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-secrets", ops.CAID)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("passphrase file left in live dir: %v", err)
	}
	trashed, _ := filepath.Glob(filepath.Join(dir, "trash", "*", "ca-secrets", ops.CAID))
	if len(trashed) != 1 {
		t.Fatalf("passphrase file not in trash: %v", trashed)
	}
	if b := backupRead(t, trashed[0]); string(b) != "ops-pass" {
		t.Fatalf("trashed passphrase content %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-secrets", caRoot)); err != nil {
		t.Fatalf("root passphrase file disturbed: %v", err)
	}
}

// Backups carry the live CAs' passphrase files; restore with regenerate unlocks the staged root
// from them, and after activation the restored root unlocks at startup.
func TestCASecretsBackupRestoreRoundTrip(t *testing.T) {
	t.Setenv("NETANCHOR_CA_SECRETS_DIR", "")
	t.Setenv("NETANCHOR_TLS_HOSTS", "destination.example")
	src := passphraseStore(t)
	if _, err := CreateCA(src, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000, Passphrase: "root-pass"}); err != nil {
		t.Fatal(err)
	}
	plain, err := snapshotBackup(src)
	if err != nil {
		t.Fatal(err)
	}
	var arc backupArchive
	if err := json.Unmarshal(plain, &arc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range arc.Files {
		if f.Path == "ca-secrets/"+caRoot {
			found = string(f.Data) == "root-pass"
		}
	}
	if !found {
		t.Fatal("backup lacks the root passphrase file")
	}

	dst := passphraseStore(t)
	stage, err := stageBackup(dst.dir, plain, true)
	if err != nil {
		t.Fatalf("staging with regenerate needs the restored passphrase: %v", err)
	}
	if err := activateBackup(dst.dir, stage, durableRename); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dst.dir, "ca-secrets", caRoot))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("restored passphrase mode %v", info.Mode().Perm())
	}
	restarted, err := OpenStore(dst.dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted.unlockSecrets(restarted.caSecretsDir())
	if restarted.CALocked(caRoot) {
		t.Fatal("restored root stayed locked after restart")
	}
}

// With an external secrets dir the backup reads passphrases from that dir, not <data>/ca-secrets.
func TestCASecretsBackupReadsExternalDir(t *testing.T) {
	external := t.TempDir()
	t.Setenv("NETANCHOR_CA_SECRETS_DIR", external)
	src := passphraseStore(t)
	if _, err := CreateCA(src, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000, Passphrase: "root-pass"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(external, caRoot)); err != nil {
		t.Fatalf("passphrase not written to external dir: %v", err)
	}
	plain, err := snapshotBackup(src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), "ca-secrets/root") {
		t.Fatal("backup does not include the external passphrase file")
	}
}

// Validation rejects a ca-secrets entry whose name is not a CA in the backup.
func TestCASecretsValidationRejectsUnknownCA(t *testing.T) {
	t.Setenv("NETANCHOR_CA_SECRETS_DIR", "")
	src := passphraseStore(t)
	if _, err := CreateCA(src, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000, Passphrase: "root-pass"}); err != nil {
		t.Fatal(err)
	}
	plain, err := snapshotBackup(src)
	if err != nil {
		t.Fatal(err)
	}
	var arc backupArchive
	if err := json.Unmarshal(plain, &arc); err != nil {
		t.Fatal(err)
	}
	arc.Files = append(arc.Files, backupFile{Path: "ca-secrets/0123456789abcdef", Data: []byte("unknown-pass")})
	bad, err := json.Marshal(arc)
	if err != nil {
		t.Fatal(err)
	}
	_, err = stageBackup(passphraseStore(t).dir, bad, false)
	if err == nil || !strings.Contains(err.Error(), "CA passphrase file") {
		t.Fatalf("backup with a passphrase file for an unknown CA: err %v", err)
	}
}

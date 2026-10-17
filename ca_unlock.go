package main

import (
	"crypto"
	"crypto/x509"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// caSecretLimit bounds one passphrase file, in bytes, in backups and on disk reads.
const caSecretLimit = 1 << 10

// caSecretsRoot is the backup root and default directory name for passphrase files.
const caSecretsRoot = "ca-secrets"

// unlockedCA is an encrypted CA whose key is decrypted in memory for this process.
// passFile and saveErr are set only for a CA created in this process with a passphrase.
type unlockedCA struct {
	cert     *x509.Certificate
	key      crypto.Signer
	passFile string
	saveErr  error
}

// caKeyring holds the unlocked CAs by ID. It is never persisted. SCEP, push,
// issue, sign and the HTTPS certificate all read keys through loadCA.
// ponytail: unlocked keys are re-read from disk only at startup; no reload.
type caKeyring struct {
	mu  sync.Mutex
	cas map[string]unlockedCA
}

func (k *caKeyring) get(id string) (unlockedCA, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	u, ok := k.cas[id]
	return u, ok
}

func (k *caKeyring) put(id string, u unlockedCA) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cas == nil {
		k.cas = map[string]unlockedCA{}
	}
	k.cas[id] = u
}

func (k *caKeyring) drop(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.cas, id)
}

// caSecretsDir is the effective passphrase directory: NETANCHOR_CA_SECRETS_DIR if
// set, otherwise <data>/ca-secrets. It is not created here.
func (s *Store) caSecretsDir() string {
	if d := os.Getenv("NETANCHOR_CA_SECRETS_DIR"); d != "" {
		return d
	}
	return filepath.Join(s.dir, caSecretsRoot)
}

// CALocked reports whether CA id has an encrypted key that is not unlocked.
func (s *Store) CALocked(id string) bool {
	_, ok := s.unlocked.get(id)
	return !ok && s.CAKeyEncrypted(id)
}

// unlockSecrets unlocks every encrypted CA whose file in dir (named by CA ID,
// content = passphrase) decrypts the key. It runs once at startup with the
// effective directory, and during restore on the staged copy before the HTTPS
// certificate is issued. A missing file leaves the CA locked silently; anything
// else is logged.
func (s *Store) unlockSecrets(dir string) {
	cas, err := s.CAs()
	if err != nil {
		log.Printf("CA secrets: listing CAs: %v", err)
		return
	}
	ids := map[string]bool{}
	for _, ca := range cas {
		ids[ca.ID] = true
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		entries = nil
	} else if err != nil {
		log.Printf("CA secrets: reading %s: %v", dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !ids[e.Name()] {
			log.Printf("CA secrets: ignoring %s: no CA with that ID", e.Name())
		}
	}
	for _, ca := range cas {
		if !s.CAKeyEncrypted(ca.ID) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, ca.ID))
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("CA %s stays locked: no passphrase file", ca.ID)
			continue
		}
		if err != nil {
			log.Printf("CA %s stays locked: reading passphrase file: %v", ca.ID, err)
			continue
		}
		cert, key, err := loadCA(s, ca.ID, strings.TrimRight(string(b), "\r\n"))
		if err != nil {
			log.Printf("CA %s stays locked: %v", ca.ID, err)
			continue
		}
		s.unlocked.put(ca.ID, unlockedCA{cert: cert, key: key})
		log.Printf("CA %s unlocked from passphrase file", ca.ID)
	}
}

// keepUnlocked keeps a CA created in this process unlocked until restart and
// saves its passphrase to the effective directory. A save failure does not fail
// the creation; passphraseNote reports it.
func (s *Store) keepUnlocked(id string, der []byte, key crypto.Signer, passphrase string) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	path, saveErr := s.savePassphrase(id, passphrase)
	if saveErr != nil {
		log.Printf("CA %s passphrase not saved to %s: %v", id, path, saveErr)
	}
	s.unlocked.put(id, unlockedCA{cert: cert, key: key, passFile: path, saveErr: saveErr})
	return nil
}

// savePassphrase writes the passphrase to <effective dir>/<id> with mode 0600.
func (s *Store) savePassphrase(id, passphrase string) (string, error) {
	dir := s.caSecretsDir()
	path := filepath.Join(dir, id)
	if strings.HasSuffix(passphrase, "\n") || strings.HasSuffix(passphrase, "\r") {
		return path, errors.New("passphrase ends in a line break, which the file format cannot keep")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return path, err
	}
	return path, durableWrite(path, []byte(passphrase))
}

// passphraseNote tells the admin what happened to the passphrase file of a CA
// created in this process with a passphrase. It is empty for other CAs.
func (s *Store) passphraseNote(id string) string {
	u, ok := s.unlocked.get(id)
	if !ok || u.passFile == "" {
		return ""
	}
	if u.saveErr != nil {
		return "It stays unlocked until NetAnchor restarts, then it will be locked: the passphrase could not be saved to " + u.passFile + " (" + u.saveErr.Error() + "). To keep it unlocked after a restart, create that file containing the passphrase, mode 0600."
	}
	return "The passphrase was saved to " + u.passFile + ", so it stays unlocked after a restart."
}

// readStagedSecrets returns the passphrase files of a staged backup keyed by CA ID.
func readStagedSecrets(stage string) (map[string][]byte, error) {
	dir := filepath.Join(stage, caSecretsRoot)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = b
	}
	return out, nil
}

// writeSecretFiles writes passphrase files into dir with mode 0600.
func writeSecretFiles(dir string, files map[string][]byte) error {
	if len(files) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for id, b := range files {
		if err := durableWrite(filepath.Join(dir, id), b); err != nil {
			return err
		}
	}
	return nil
}

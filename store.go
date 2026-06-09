package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// CA identifiers. The root is always "root"; an optional single intermediate is
// "intermediate".
const (
	caRoot         = "root"
	caIntermediate = "intermediate"
)

// CertRecord is the metadata we keep about each certificate.
type CertRecord struct {
	Serial     string    `json:"serial"`
	CommonName string    `json:"common_name"`
	Kind       string    `json:"kind"`      // "root", "intermediate", "issued", "csr"
	IssuerID   string    `json:"issuer_id"` // which CA signed it: "root" or "intermediate"
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	HasKey     bool      `json:"has_key"`
	KeyEnc     bool      `json:"key_encrypted"`
	CreatedAt  time.Time `json:"created_at"`
}

// Store is a tiny file-backed persistence layer.
//
//	<dir>/cas/<id>/cert.pem , key.pem   -- the CA(s)
//	<dir>/certs/<serial>-cert.pem, -key.pem
//	<dir>/index.json                    -- metadata
type Store struct {
	dir string
	mu  sync.Mutex
}

func OpenStore(dir string) (*Store, error) {
	for _, sub := range []string{"", "cas", "certs", "auth", "tls"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir}, nil
}

func (s *Store) usersPath() string      { return filepath.Join(s.dir, "auth", "users.json") }
func (s *Store) sessionKeyPath() string { return filepath.Join(s.dir, "auth", "session.key") }
func (s *Store) tlsCertPath() string    { return filepath.Join(s.dir, "tls", "server-cert.pem") }
func (s *Store) tlsKeyPath() string     { return filepath.Join(s.dir, "tls", "server-key.pem") }
func (s *Store) templatesPath() string  { return filepath.Join(s.dir, "templates.json") }

func (s *Store) caDir(id string) string      { return filepath.Join(s.dir, "cas", id) }
func (s *Store) caCertPath(id string) string { return filepath.Join(s.caDir(id), "cert.pem") }
func (s *Store) caKeyPath(id string) string  { return filepath.Join(s.caDir(id), "key.pem") }
func (s *Store) indexPath() string           { return filepath.Join(s.dir, "index.json") }

func (s *Store) certPath(serial string) string {
	return filepath.Join(s.dir, "certs", serial+"-cert.pem")
}
func (s *Store) keyPath(serial string) string {
	return filepath.Join(s.dir, "certs", serial+"-key.pem")
}

// HasCA reports whether the CA with the given id exists.
func (s *Store) HasCA(id string) bool {
	_, err := os.Stat(s.caCertPath(id))
	return err == nil
}

func (s *Store) SaveCA(id string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(s.caDir(id), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(s.caCertPath(id), certPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(s.caKeyPath(id), keyPEM, 0o600)
}

func (s *Store) LoadCACertPEM(id string) ([]byte, error) { return os.ReadFile(s.caCertPath(id)) }
func (s *Store) LoadCAKeyPEM(id string) ([]byte, error)  { return os.ReadFile(s.caKeyPath(id)) }

// CAKeyEncrypted reports whether a CA's stored key is passphrase-protected.
func (s *Store) CAKeyEncrypted(id string) bool {
	pemBytes, err := s.LoadCAKeyPEM(id)
	if err != nil {
		return false
	}
	return isEncryptedKeyPEM(pemBytes)
}

// IssuerChainPEM returns the certificate chain for a signing CA: the CA's own
// certificate followed by any ancestors, so the result is a complete path up to
// the root.
func (s *Store) IssuerChainPEM(issuerID string) ([]byte, error) {
	switch issuerID {
	case caIntermediate:
		ic, err := s.LoadCACertPEM(caIntermediate)
		if err != nil {
			return nil, err
		}
		rc, err := s.LoadCACertPEM(caRoot)
		if err != nil {
			return nil, err
		}
		return append(ensureTrailingNewline(ic), rc...), nil
	default:
		return s.LoadCACertPEM(caRoot)
	}
}

// SaveCert writes a leaf certificate (and optionally its private key).
func (s *Store) SaveCert(serial string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(s.certPath(serial), certPEM, 0o600); err != nil {
		return err
	}
	if keyPEM != nil {
		if err := os.WriteFile(s.keyPath(serial), keyPEM, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) LoadCertPEM(serial string) ([]byte, error) { return os.ReadFile(s.certPath(serial)) }
func (s *Store) LoadKeyPEM(serial string) ([]byte, error)  { return os.ReadFile(s.keyPath(serial)) }

// --- index.json handling -------------------------------------------------

func (s *Store) loadIndex() ([]CertRecord, error) {
	data, err := os.ReadFile(s.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []CertRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func (s *Store) saveIndex(recs []CertRecord) error {
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.indexPath(), data, 0o600)
}

// AddRecord appends a record, replacing any existing record for the same CA id
// (so re-creating the root or intermediate updates rather than duplicates).
func (s *Store) AddRecord(rec CertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.loadIndex()
	if err != nil {
		return err
	}
	if rec.Kind == caRoot || rec.Kind == caIntermediate {
		filtered := recs[:0]
		for _, r := range recs {
			if r.Kind != rec.Kind {
				filtered = append(filtered, r)
			}
		}
		recs = filtered
	}
	recs = append(recs, rec)
	return s.saveIndex(recs)
}

// Records returns all records sorted newest-first.
func (s *Store) Records() ([]CertRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.loadIndex()
	if err != nil {
		return nil, err
	}
	sort.Slice(recs, func(i, j int) bool {
		return recs[i].CreatedAt.After(recs[j].CreatedAt)
	})
	return recs, nil
}

// RecordBySerial looks up a single record.
func (s *Store) RecordBySerial(serial string) (CertRecord, bool) {
	recs, err := s.Records()
	if err != nil {
		return CertRecord{}, false
	}
	for _, r := range recs {
		if r.Serial == serial {
			return r, true
		}
	}
	return CertRecord{}, false
}

// --- certificate templates -----------------------------------------------

func (s *Store) LoadTemplates() ([]CertTemplate, error) {
	data, err := os.ReadFile(s.templatesPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tmpls []CertTemplate
	if err := json.Unmarshal(data, &tmpls); err != nil {
		return nil, err
	}
	return tmpls, nil
}

func (s *Store) saveTemplates(tmpls []CertTemplate) error {
	data, err := json.MarshalIndent(tmpls, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.templatesPath(), data, 0o600)
}

func (s *Store) GetTemplate(name string) (CertTemplate, bool) {
	tmpls, err := s.LoadTemplates()
	if err != nil {
		return CertTemplate{}, false
	}
	for _, t := range tmpls {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return CertTemplate{}, false
}

// AddTemplate stores a new template, rejecting duplicate names.
func (s *Store) AddTemplate(t CertTemplate) error {
	if err := t.normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tmpls, err := s.LoadTemplates()
	if err != nil {
		return err
	}
	for _, e := range tmpls {
		if strings.EqualFold(e.Name, t.Name) {
			return errors.New("a template with that name already exists")
		}
	}
	t.CreatedAt = time.Now()
	return s.saveTemplates(append(tmpls, t))
}

// UpdateTemplate replaces the template identified by name (the name itself is
// immutable here, keeping edit URLs stable).
func (s *Store) UpdateTemplate(name string, t CertTemplate) error {
	t.Name = name
	if err := t.normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tmpls, err := s.LoadTemplates()
	if err != nil {
		return err
	}
	for i := range tmpls {
		if strings.EqualFold(tmpls[i].Name, name) {
			t.CreatedAt = tmpls[i].CreatedAt
			tmpls[i] = t
			return s.saveTemplates(tmpls)
		}
	}
	return errors.New("template not found")
}

func (s *Store) DeleteTemplate(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tmpls, err := s.LoadTemplates()
	if err != nil {
		return err
	}
	kept := make([]CertTemplate, 0, len(tmpls))
	for _, t := range tmpls {
		if !strings.EqualFold(t.Name, name) {
			kept = append(kept, t)
		}
	}
	if len(kept) == len(tmpls) {
		return errors.New("template not found")
	}
	return s.saveTemplates(kept)
}

func ensureTrailingNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] != '\n' {
		return append(b, '\n')
	}
	return b
}

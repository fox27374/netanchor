package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
	Serial         string       `json:"serial"`
	CommonName     string       `json:"common_name"`
	Kind           string       `json:"kind"`            // "root", "intermediate", "issued", "csr"
	IssuerID       string       `json:"issuer_id"`       // which CA signed it: "root" or "intermediate" or other CA id
	CAID           string       `json:"ca_id,omitempty"` // CA id for intermediates (serial hex for new, empty for legacy)
	AllowSubCA     bool         `json:"allow_sub_ca"`    // for intermediates: if true, can sign other CAs; if false, leaf-only
	NotBefore      time.Time    `json:"not_before"`
	NotAfter       time.Time    `json:"not_after"`
	HasKey         bool         `json:"has_key"`
	KeyEnc         bool         `json:"key_encrypted"`
	CreatedAt      time.Time    `json:"created_at"`
	TemplateName   string       `json:"template_name,omitempty"`
	TemplatePolicy CertTemplate `json:"template_policy,omitempty"`
	Provenance     string       `json:"provenance,omitempty"`
}

// Store is a tiny file-backed persistence layer.
//
//	<dir>/cas/<id>/cert.pem , key.pem   -- the CA(s)
//	<dir>/certs/<serial>-cert.pem, -key.pem
//	<dir>/index.json                    -- metadata
type Store struct {
	dir    string
	mu     sync.Mutex
	scepMu sync.Mutex // serializes SCEP commits with CA/certificate deletion
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
// the root. It walks the CA tree via IssuerID, guarding against loops.
func (s *Store) IssuerChainPEM(issuerID string) ([]byte, error) {
	var chain [][]byte
	currentID := issuerID
	seen := make(map[string]bool)

	for {
		if seen[currentID] {
			return nil, fmt.Errorf("CA chain loop detected at %s", currentID)
		}
		seen[currentID] = true

		certPEM, err := s.LoadCACertPEM(currentID)
		if err != nil {
			return nil, fmt.Errorf("loading CA %s: %w", currentID, err)
		}
		chain = append(chain, certPEM)

		if currentID == caRoot {
			break
		}

		rec := s.findCARecord(currentID)
		if rec == nil {
			return nil, fmt.Errorf("CA %s has no record", currentID)
		}
		if rec.IssuerID == "" {
			return nil, fmt.Errorf("CA %s has no issuer", currentID)
		}
		currentID = rec.IssuerID
	}

	var result []byte
	for _, c := range chain {
		result = append(result, ensureTrailingNewline(c)...)
	}
	return result, nil
}

// CAPath returns the CA records from the root down to caID, walking the CA
// tree via IssuerID and guarding against loops.
func (s *Store) CAPath(caID string) ([]CertRecord, error) {
	var path []CertRecord
	seen := make(map[string]bool)
	for id := caID; ; {
		if seen[id] {
			return nil, fmt.Errorf("CA chain loop detected at %s", id)
		}
		seen[id] = true
		rec := s.findCARecord(id)
		if rec == nil {
			return nil, fmt.Errorf("CA %s has no record", id)
		}
		path = append([]CertRecord{*rec}, path...)
		if id == caRoot {
			return path, nil
		}
		id = rec.IssuerID
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
	return durableWrite(s.indexPath(), data)
}

// AddRecord appends a record, replacing any existing record for the root CA
// (so re-creating the root updates rather than duplicates). All other records
// (intermediates and leaf certs) are appended (no dedup).
func (s *Store) AddRecord(rec CertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.loadIndex()
	if err != nil {
		return err
	}
	if rec.Kind == caRoot {
		filtered := recs[:0]
		for _, r := range recs {
			if r.Kind != caRoot {
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

// findCARecord looks up a CA record by CA id (or Kind for legacy).
// It returns a pointer to the record found, or nil.
func (s *Store) findCARecord(caID string) *CertRecord {
	recs, err := s.Records()
	if err != nil {
		return nil
	}
	for i := range recs {
		rec := &recs[i]
		// Match by CAID (for serial-based intermediates) or legacy intermediate
		if rec.Kind == caIntermediate {
			if rec.CAID == caID {
				return rec
			}
			// Legacy: empty CAID + ID "intermediate" matches caID "intermediate"
			if rec.CAID == "" && caID == caIntermediate && rec.IssuerID == caRoot {
				return rec
			}
		} else if rec.Kind == caRoot && caID == caRoot {
			return rec
		}
	}
	return nil
}

// CAInfo describes a CA with its hierarchical path.
type CAInfo struct {
	ID           string // "root", "intermediate" (legacy), or serial hex
	Record       *CertRecord
	ParentID     string // issuer ID
	Path         string // e.g. "Root › A › B"
	CanSignSubCA bool   // whether this CA can sign other CAs
}

// CAs returns info for all CAs in tree order (sorted by path, root first).
func (s *Store) CAs() ([]CAInfo, error) {
	recs, err := s.Records()
	if err != nil {
		return nil, err
	}

	idToRec := make(map[string]*CertRecord)
	for i := range recs {
		rec := &recs[i]
		if rec.Kind == caRoot {
			idToRec[caRoot] = rec
		} else if rec.Kind == caIntermediate {
			caID := rec.CAID
			if caID == "" {
				caID = caIntermediate
			}
			idToRec[caID] = rec
		}
	}

	var result []CAInfo
	for i := range recs {
		rec := &recs[i]
		if rec.Kind != caRoot && rec.Kind != caIntermediate {
			continue
		}

		var caID string
		if rec.Kind == caRoot {
			caID = caRoot
		} else {
			caID = rec.CAID
			if caID == "" {
				caID = caIntermediate
			}
		}

		var pathParts []string
		walkID := caID
		seen := make(map[string]bool)
		for {
			if seen[walkID] {
				break
			}
			seen[walkID] = true

			walkedRec := idToRec[walkID]
			if walkedRec == nil {
				break
			}
			pathParts = append([]string{walkedRec.CommonName}, pathParts...)

			if walkID == caRoot {
				break
			}
			walkID = walkedRec.IssuerID
		}

		path := strings.Join(pathParts, " › ")
		canSignSubCA := rec.Kind == caRoot || rec.AllowSubCA

		result = append(result, CAInfo{
			ID:           caID,
			Record:       rec,
			ParentID:     rec.IssuerID,
			Path:         path,
			CanSignSubCA: canSignSubCA,
		})
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

// ValidSerial guards against path traversal: serials are always lowercase hex.
func ValidSerial(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ValidCAID reports whether a CA id is valid and exists.
func (s *Store) ValidCAID(id string) bool {
	if id == caRoot || id == caIntermediate {
		return s.HasCA(id)
	}
	if ValidSerial(id) {
		return s.HasCA(id)
	}
	return false
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
	migrated := migrateTemplates(tmpls)
	if len(migrated) > 0 {
		old, _ := json.Marshal(tmpls)
		next, _ := json.Marshal(migrated)
		if string(old) != string(next) {
			if err := s.saveTemplates(migrated); err != nil {
				return nil, err
			}
		}
	}
	return migrated, nil
}

func migrateTemplates(in []CertTemplate) []CertTemplate {
	for i := range in {
		if in[i].MaxDays == 0 {
			max := in[i].ValidDays
			for _, b := range builtinTemplates() {
				if b.Profile == in[i].Profile && b.MaxDays > max {
					max = b.MaxDays
				}
			}
			in[i].MaxDays = max
		}
		if len(in[i].AllowedAlgos) == 0 {
			in[i].AllowedAlgos = []keyAlgo{algoRSA2048, algoRSA4096, algoECP256, algoECP384}
		}
	}
	return in
}

func (s *Store) saveTemplates(tmpls []CertTemplate) error {
	data, err := json.MarshalIndent(tmpls, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.templatesPath(), data, 0o600)
}

func (s *Store) validateTemplateIssuers(t CertTemplate) error {
	for _, id := range t.AllowedIssuers {
		if !s.ValidCAID(id) {
			return fmt.Errorf("issuer CA %q does not exist", id)
		}
	}
	return nil
}

func (s *Store) GetTemplate(name string) (CertTemplate, bool) {
	if strings.HasPrefix(name, "builtin:") {
		return builtinByName(strings.TrimPrefix(name, "builtin:"))
	}
	tmpls, err := s.LoadTemplates()
	if err != nil {
		return CertTemplate{}, false
	}
	for _, t := range tmpls {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return builtinByName(name)
}

// AddTemplate stores a new template, rejecting duplicate names.
func (s *Store) AddTemplate(t CertTemplate) error {
	if err := t.normalize(); err != nil {
		return err
	}
	if err := s.validateTemplateIssuers(t); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tmpls, err := s.LoadTemplates()
	if err != nil {
		return err
	}
	if _, ok := builtinByName(t.Name); ok {
		return errors.New("built-in templates cannot be overwritten")
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
	if err := s.validateTemplateIssuers(t); err != nil {
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

// caIDOf returns the CA id a CA record is stored under.
func caIDOf(rec CertRecord) string {
	switch {
	case rec.Kind == caRoot:
		return caRoot
	case rec.CAID != "":
		return rec.CAID
	default:
		return caIntermediate // legacy single intermediate
	}
}

// CASubtree returns what deleting an intermediate CA removes: the CA itself
// (first) plus all descendant CAs, and every certificate any of them issued.
func (s *Store) CASubtree(id string) (cas, certs []CertRecord, err error) {
	recs, err := s.Records()
	if err != nil {
		return nil, nil, err
	}
	return caSubtree(recs, id)
}

func caSubtree(recs []CertRecord, id string) (cas, certs []CertRecord, err error) {
	if id == caRoot {
		return nil, nil, errors.New("the root CA cannot be deleted")
	}
	inTree := map[string]bool{}
	for _, r := range recs {
		if r.Kind == caIntermediate && caIDOf(r) == id {
			cas = append(cas, r)
			inTree[id] = true
		}
	}
	if len(cas) == 0 {
		return nil, nil, fmt.Errorf("CA %s not found", id)
	}
	// Breadth-first over children; cas grows while we walk it.
	for i := 0; i < len(cas); i++ {
		parent := caIDOf(cas[i])
		for _, r := range recs {
			if r.Kind == caIntermediate && r.IssuerID == parent && !inTree[caIDOf(r)] {
				inTree[caIDOf(r)] = true
				cas = append(cas, r)
			}
		}
	}
	for _, r := range recs {
		if (r.Kind == "issued" || r.Kind == "csr") && inTree[r.IssuerID] {
			certs = append(certs, r)
		}
	}
	return cas, certs, nil
}

// DeleteCA moves an intermediate CA, its descendant CAs and all certificates
// they issued to the trash.
func (s *Store) DeleteCA(id string) error {
	s.scepMu.Lock()
	defer s.scepMu.Unlock()
	if err := s.reconcileSCEP(); err != nil {
		return err
	}
	if !s.ValidCAID(id) {
		return fmt.Errorf("CA %s not found", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.loadIndex()
	if err != nil {
		return err
	}
	cas, certs, err := caSubtree(recs, id)
	if err != nil {
		return err
	}
	return s.trash(recs, append(cas, certs...))
}

// DeleteCert moves a single issued certificate (and its key) to the trash.
func (s *Store) DeleteCert(serial string) error {
	s.scepMu.Lock()
	defer s.scepMu.Unlock()
	// Finish committed SCEP projections before deletion so crash recovery cannot
	// mistake an intentionally deleted certificate for an unfinished issuance.
	if err := s.reconcileSCEP(); err != nil {
		return err
	}
	if !ValidSerial(serial) {
		return errors.New("invalid serial")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.loadIndex()
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Serial == serial && (r.Kind == "issued" || r.Kind == "csr") {
			return s.trash(recs, []CertRecord{r})
		}
	}
	return errors.New("certificate not found")
}

// trash moves the files of the removed records to <dir>/trash/<timestamp>/
// (same layout, plus an index.json of the removed records) and drops them from
// the index. Caller holds s.mu.
func (s *Store) trash(recs, removed []CertRecord) error {
	dst := filepath.Join(s.dir, "trash", time.Now().Format("20060102T150405.000000000"))
	for _, sub := range []string{"cas", "certs"} {
		if err := os.MkdirAll(filepath.Join(dst, sub), 0o700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(removed, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dst, "index.json"), data, 0o600); err != nil {
		return err
	}

	gone := map[string]bool{}
	for _, r := range removed {
		gone[r.Serial] = true
		if r.Kind == caIntermediate {
			id := caIDOf(r)
			if err := os.Rename(s.caDir(id), filepath.Join(dst, "cas", id)); err != nil {
				return err
			}
			continue
		}
		for _, p := range []string{s.certPath(r.Serial), s.keyPath(r.Serial)} {
			err := os.Rename(p, filepath.Join(dst, "certs", filepath.Base(p)))
			if err != nil && !errors.Is(err, os.ErrNotExist) { // CSR certs have no key
				return err
			}
		}
	}

	kept := recs[:0]
	for _, r := range recs {
		if !gone[r.Serial] {
			kept = append(kept, r)
		}
	}
	return s.saveIndex(kept)
}

func ensureTrailingNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] != '\n' {
		return append(b, '\n')
	}
	return b
}

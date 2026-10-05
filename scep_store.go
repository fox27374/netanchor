package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const scepRetention = 7 * 24 * time.Hour

// One atomically replaced journal is the authority for authorization and issuance.
// The ordinary certificate store is an idempotent projection of committed entries.
type scepState struct {
	CA         string
	Challenges []scepChallenge
}
type scepChallenge struct {
	Hash        string
	CA          string
	Profile     CertTemplate
	DNS         []string
	IPs         []net.IP
	Days        int
	Expires     time.Time
	Revoked     bool
	Used        time.Time
	Transaction string
	RequestHash string
	SignerHash  string
	DER         []byte
	Record      CertRecord
	Published   bool
}

func (c scepChallenge) Status() string {
	switch {
	case !c.Used.IsZero():
		return "used"
	case c.Revoked:
		return "revoked"
	case time.Now().After(c.Expires):
		return "expired"
	default:
		return "active"
	}
}

type SCEPService struct {
	store *Store
	cert  *x509.Certificate
	key   *rsa.PrivateKey
}

func durableWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".netanchor-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (e *SCEPService) path() string { return filepath.Join(e.store.dir, "scep.json") }
func (e *SCEPService) load() (scepState, error) {
	var st scepState
	b, err := os.ReadFile(e.path())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(b, &st)
	return st, err
}
func (e *SCEPService) save(st scepState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return durableWrite(e.path(), b)
}
func newSCEPService(s *Store) *SCEPService { return &SCEPService{store: s} }

func (e *SCEPService) ca(id string) (*x509.Certificate, error) {
	if id == caRoot || !e.store.ValidCAID(id) {
		return nil, errors.New("select an existing SCEP intermediate")
	}
	b, err := e.store.LoadCACertPEM(id)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("invalid CA PEM")
	}
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, err
	}
	ku := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	k, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok || k.N.BitLen() < 2048 || !c.IsCA || !c.MaxPathLenZero || c.KeyUsage&ku != ku {
		return nil, errors.New("SCEP requires a leaf-only RSA intermediate with certSign, crlSign, digitalSignature and keyEncipherment")
	}
	return c, nil
}
func (e *SCEPService) selectCA(id, password string) error {
	e.store.scepMu.Lock()
	defer e.store.scepMu.Unlock()
	st, err := e.load()
	if err != nil {
		return err
	}
	c, err := e.ca(id)
	if err != nil {
		return err
	}
	_, key, err := loadCA(e.store, id, password)
	if err != nil {
		return err
	}
	k, ok := key.(*rsa.PrivateKey)
	if !ok || !k.PublicKey.Equal(c.PublicKey) {
		return errors.New("CA key mismatch")
	}
	st.CA = id
	if err := e.save(st); err != nil {
		return err
	}
	e.cert, e.key = c, k
	return nil
}
func (e *SCEPService) startup(secretFile string) error {
	e.store.scepMu.Lock()
	st, err := e.load()
	if err == nil {
		err = e.recover(&st)
	}
	e.store.scepMu.Unlock()
	if err != nil {
		return err
	}
	if secretFile == "" || st.CA == "" {
		return nil
	}
	b, err := os.ReadFile(secretFile)
	if err != nil {
		return err
	}
	return e.selectCA(st.CA, strings.TrimRight(string(b), "\r\n"))
}
func (e *SCEPService) ready(st scepState) (*x509.Certificate, error) {
	c, err := e.ca(st.CA)
	if err != nil {
		e.cert, e.key = nil, nil
		return nil, err
	}
	if e.cert == nil || e.key == nil || !bytes.Equal(c.Raw, e.cert.Raw) {
		return nil, errors.New("SCEP CA is locked")
	}
	// Include ancestor expiry and reject incomplete/deleted chains.
	chain, err := e.store.IssuerChainPEM(st.CA)
	if err != nil {
		return nil, err
	}
	for len(chain) > 0 {
		p, rest := pem.Decode(chain)
		if p == nil {
			return nil, errors.New("invalid CA chain")
		}
		chain = rest
		a, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}
		if time.Now().Before(a.NotBefore) || !time.Now().Before(a.NotAfter) {
			return nil, errors.New("CA chain not currently valid")
		}
		if a.NotAfter.Before(c.NotAfter) {
			c.NotAfter = a.NotAfter
		}
	}
	return c, nil
}
func hashSCEP(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (e *SCEPService) challenge(profile string, identities []string, days, hours int) (string, error) {
	e.store.scepMu.Lock()
	defer e.store.scepMu.Unlock()
	st, err := e.load()
	if err != nil {
		return "", err
	}
	if _, err := e.ca(st.CA); err != nil {
		return "", err
	}
	e.store.mu.Lock()
	t, ok := e.store.GetTemplate(profile)
	e.store.mu.Unlock()
	if !ok || t.Profile != profileServer {
		return "", errors.New("select a TLS server profile")
	}
	if days == 0 {
		days = 365
	}
	if days < 1 || days > 36500 {
		return "", errors.New("invalid certificate lifetime")
	}
	if days > t.MaxDays {
		days = t.MaxDays
	}
	if err := policyBasics(t, st.CA, days); err != nil {
		return "", err
	}
	if hours == 0 {
		hours = 24
	}
	if hours < 1 || hours > 168 {
		return "", errors.New("challenge lifetime must be 1–168 hours")
	}
	dns, ips := splitSANs(identities)
	if len(dns)+len(ips) == 0 || len(dns)+len(ips) > 100 {
		return "", errors.New("supply 1–100 authorized DNS/IP identities")
	}
	for _, d := range dns {
		if len(d) > 253 || strings.ContainsAny(d, "* /:@\t\r\n") {
			return "", fmt.Errorf("invalid DNS identity %q", d)
		}
		for _, label := range strings.Split(d, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", errors.New("invalid DNS label")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
					return "", errors.New("invalid DNS label")
				}
			}
		}
	}
	if err := e.recover(&st); err != nil {
		return "", err
	}
	pruneSCEP(&st)
	if len(st.Challenges) >= 10000 {
		return "", errors.New("SCEP challenge capacity reached; wait for retention cleanup")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(b)
	st.Challenges = append(st.Challenges, scepChallenge{Hash: hashSCEP([]byte(secret)), CA: st.CA, Profile: t, DNS: dns, IPs: ips, Days: days, Expires: time.Now().Add(time.Duration(hours) * time.Hour)})
	if err := e.save(st); err != nil {
		return "", err
	}
	return secret, nil
}
func pruneSCEP(st *scepState) {
	kept := st.Challenges[:0]
	for _, c := range st.Challenges {
		until := c.Expires.Add(scepRetention)
		if !c.Used.IsZero() {
			until = c.Used.Add(scepRetention)
		}
		if time.Now().Before(until) || (!c.Used.IsZero() && !c.Published) {
			kept = append(kept, c)
		}
	}
	st.Challenges = kept
}

// Caller holds scepMu. Never resurrect deleted CAs or published/deleted certs.
func (e *SCEPService) recover(st *scepState) error {
	dirty := false
	for i := range st.Challenges {
		c := &st.Challenges[i]
		if c.Used.IsZero() || c.Published {
			continue
		}
		dirty = true
		// Absence is not a deletion record: a missing mount, permission error,
		// or incomplete restore must never discard committed issuance. Deletion
		// reconciles all pending projections before removing any CA files.
		if _, err := e.ca(c.CA); err != nil {
			return fmt.Errorf("recovering SCEP issuance %s: %w", c.Record.Serial, err)
		}
		if err := durableWrite(e.store.certPath(c.Record.Serial), encodeCertPEM(c.DER)); err != nil {
			return err
		}
		e.store.mu.Lock()
		recs, err := e.store.loadIndex()
		if err == nil {
			found := false
			for _, r := range recs {
				if r.Serial == c.Record.Serial {
					found = true
				}
			}
			if !found {
				err = e.store.saveIndex(append(recs, c.Record))
			}
		}
		e.store.mu.Unlock()
		if err != nil {
			return err
		}
		c.Published = true
	}
	if dirty {
		return e.save(*st)
	}
	return nil
}

// Caller holds scepMu, but not mu. A deletion must include every committed
// certificate, even one whose PEM was written before its index update failed.
// Failure aborts deletion before it moves any files.
func (s *Store) reconcileSCEP() error {
	e := newSCEPService(s)
	st, err := e.load()
	if err != nil {
		return err
	}
	return e.recover(&st)
}

func (e *SCEPService) lock() {
	e.store.scepMu.Lock()
	defer e.store.scepMu.Unlock()
	e.cert, e.key = nil, nil
}

func (e *SCEPService) revoke(hash string) error {
	e.store.scepMu.Lock()
	defer e.store.scepMu.Unlock()
	st, err := e.load()
	if err != nil {
		return err
	}
	for i := range st.Challenges {
		c := &st.Challenges[i]
		if c.Hash == hash {
			if !c.Used.IsZero() {
				return errors.New("challenge already used; certificate revocation is not supported")
			}
			c.Revoked = true
			return e.save(st)
		}
	}
	return errors.New("challenge not found")
}

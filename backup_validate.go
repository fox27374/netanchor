package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

func backupJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return strictJSON(b, v)
}

func validateBackup(dir string) error {
	s := &Store{dir: dir}
	var users []User
	if err := backupJSON(s.usersPath(), &users); err != nil {
		return err
	}
	if len(users) > 10000 {
		return errors.New("too many users")
	}
	names := map[string]bool{}
	admins := 0
	for _, u := range users {
		name := strings.ToLower(u.Username)
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "|\r\n") || names[name] || (u.Role != RoleAdmin && u.Role != RoleViewer) {
			return errors.New("invalid user record")
		}
		names[name] = true
		if u.Role == RoleAdmin {
			admins++
		}
		p := strings.Split(u.PasswordHash, "$")
		if len(p) != 4 || p[0] != "pbkdf2" {
			return errors.New("invalid password hash")
		}
		n, err := strconv.Atoi(p[1])
		if err != nil || n < 1 || n > pwIter {
			return errors.New("unsupported password KDF")
		}
		salt, e1 := base64.RawStdEncoding.DecodeString(p[2])
		hash, e2 := base64.RawStdEncoding.DecodeString(p[3])
		if e1 != nil || e2 != nil || len(salt) != 16 || len(hash) != 32 {
			return errors.New("invalid password hash")
		}
	}
	if len(users) > 0 && admins == 0 {
		return errors.New("backup has no administrator")
	}
	if b, err := os.ReadFile(s.sessionKeyPath()); err == nil && len(b) != 32 {
		return errors.New("invalid session key")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	certPEM, ce := os.ReadFile(s.tlsCertPath())
	keyPEM, ke := os.ReadFile(s.tlsKeyPath())
	if !errors.Is(ce, os.ErrNotExist) || !errors.Is(ke, os.ErrNotExist) {
		if ce != nil || ke != nil {
			return errors.New("incomplete HTTPS identity")
		}
		if len(keyPEM) > 64<<10 || len(certPEM) > 1<<20 {
			return errors.New("HTTPS identity too large")
		}
		if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
			return fmt.Errorf("invalid HTTPS identity: %w", err)
		}
		chain, err := parseCertsPEM(certPEM)
		if err != nil || len(chain) == 0 || chain[0].IsCA {
			return errors.New("invalid HTTPS certificate chain")
		}
		for i := 0; i+1 < len(chain); i++ {
			if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
				return errors.New("HTTPS chain signature mismatch")
			}
		}
	}
	var recs []CertRecord
	if err := backupJSON(s.indexPath(), &recs); err != nil {
		return err
	}
	cas := map[string]*x509.Certificate{}
	records := map[string]CertRecord{}
	certs := map[string]*x509.Certificate{}
	if err := validateRecords(dir, recs, cas, records, certs, true); err != nil {
		return err
	}
	for _, r := range recs {
		c := certs[r.Serial]
		if r.Kind == caRoot {
			if err := c.CheckSignatureFrom(c); err != nil {
				return errors.New("invalid root signature")
			}
			continue
		}
		issuer := cas[r.IssuerID]
		if issuer == nil || c.CheckSignatureFrom(issuer) != nil {
			return errors.New("missing or mismatched issuer")
		}
		id := r.IssuerID
		for depth := 0; id != caRoot; depth++ {
			if depth >= 64 || cas[id] == nil {
				return errors.New("invalid or excessively deep CA chain")
			}
			id = records[serialString(cas[id].SerialNumber)].IssuerID
		}
	}
	var templates []CertTemplate
	if err := backupJSON(s.templatesPath(), &templates); err != nil {
		return err
	}
	if len(templates) > 10000 {
		return errors.New("too many profiles")
	}
	names = map[string]bool{}
	for _, t := range templates {
		if names[strings.ToLower(t.Name)] || t.Builtin {
			return errors.New("invalid custom profiles")
		}
		names[strings.ToLower(t.Name)] = true
		if err := t.normalize(); err != nil {
			return err
		}
		// Deleted CA restrictions may legitimately remain on a profile.
		for _, id := range t.AllowedIssuers {
			if !backupCAID(id) {
				return errors.New("invalid profile issuer")
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "trash"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	historyCerts := map[string]*x509.Certificate{}
	historyCAs := map[string][]*x509.Certificate{}
	var historyRecords []CertRecord
	for id, c := range cas {
		historyCAs[id] = append(historyCAs[id], c)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return errors.New("invalid trash")
		}
		var removed []CertRecord
		p := filepath.Join(dir, "trash", entry.Name())
		if err := backupJSON(filepath.Join(p, "index.json"), &removed); err != nil {
			return err
		}
		if len(removed) == 0 {
			return errors.New("trash without index")
		}
		tc := map[string]*x509.Certificate{}
		tca := map[string]*x509.Certificate{}
		if err := validateRecords(p, removed, tca, map[string]CertRecord{}, tc, false); err != nil {
			return err
		}
		for serial, c := range tc {
			if prior := historyCerts[serial]; prior != nil && !bytes.Equal(prior.Raw, c.Raw) {
				return errors.New("conflicting trash certificates")
			}
			historyCerts[serial] = c
		}
		for id, c := range tca {
			historyCAs[id] = append(historyCAs[id], c)
		}
		historyRecords = append(historyRecords, removed...)
	}
	for _, r := range historyRecords {
		issuers := historyCAs[r.IssuerID]
		if len(issuers) > 0 {
			valid := false
			for _, issuer := range issuers {
				if historyCerts[r.Serial].CheckSignatureFrom(issuer) == nil {
					valid = true
					break
				}
			}
			if !valid {
				return errors.New("trash certificate issuer mismatch")
			}
		}
	}
	var st scepState
	if err := backupJSON(filepath.Join(dir, "scep.json"), &st); err != nil {
		return err
	}
	if st.CA != "" && !backupCAID(st.CA) {
		return errors.New("invalid SCEP selection")
	}
	if st.CA == caRoot {
		return errors.New("invalid SCEP root selection")
	}
	if cas[st.CA] != nil {
		if _, err := newSCEPService(s).ca(st.CA); err != nil {
			return err
		}
	}
	if len(st.Challenges) > 10000 {
		return errors.New("too many SCEP challenges")
	}
	names = map[string]bool{}
	for _, c := range st.Challenges {
		if len(c.Hash) != 64 || !ValidSerial(c.Hash) || names[c.Hash] || !backupCAID(c.CA) || c.CA == caRoot {
			return errors.New("invalid SCEP challenge")
		}
		names[c.Hash] = true
		if c.Expires.IsZero() || c.Days < 1 || c.Days > 36500 || len(c.DNS)+len(c.IPs) < 1 || len(c.DNS)+len(c.IPs) > 100 || c.Profile.Profile != profileServer {
			return errors.New("invalid SCEP authorization")
		}
		if err := c.Profile.normalize(); err != nil {
			return err
		}
		for _, ip := range c.IPs {
			if ip.To16() == nil {
				return errors.New("invalid SCEP IP")
			}
		}
		for _, dns := range c.DNS {
			if len(dns) > 253 {
				return errors.New("invalid SCEP DNS identity")
			}
			for _, label := range strings.Split(dns, ".") {
				if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
					return errors.New("invalid SCEP DNS label")
				}
				for _, ch := range label {
					if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
						return errors.New("invalid SCEP DNS label")
					}
				}
			}
		}
		if c.Used.IsZero() {
			if len(c.DER) != 0 || c.Record.Serial != "" || c.Published || c.Transaction != "" || c.RequestHash != "" || c.SignerHash != "" {
				return errors.New("inconsistent unused SCEP challenge")
			}
			continue
		}
		if len(c.RequestHash) != 64 || !ValidSerial(c.RequestHash) || len(c.SignerHash) != 64 || !ValidSerial(c.SignerHash) || len(c.Transaction) < 1 || len(c.Transaction) > 256 {
			return errors.New("invalid SCEP history")
		}
		cert, err := x509.ParseCertificate(c.DER)
		if err != nil || c.Record.Serial != serialString(cert.SerialNumber) || c.Record.IssuerID != c.CA || c.Record.Kind != "csr" || c.Record.Provenance != "scep" || c.Record.HasKey || c.Record.KeyEnc {
			return errors.New("inconsistent SCEP issuance")
		}
		if cert.IsCA || cert.NotBefore.Unix() != c.Record.NotBefore.Unix() || cert.NotAfter.Unix() != c.Record.NotAfter.Unix() || !reflect.DeepEqual(c.Profile, c.Record.TemplatePolicy) || c.Record.TemplateName != c.Profile.Name {
			return errors.New("SCEP policy/metadata mismatch")
		}
		if issuer := cas[c.CA]; issuer != nil {
			if cert.CheckSignatureFrom(issuer) != nil {
				return errors.New("SCEP issuer mismatch")
			}
		} else if c.Published {
			if historical := historyCerts[c.Record.Serial]; historical == nil || !bytes.Equal(historical.Raw, c.DER) {
				return errors.New("published SCEP certificate missing from live data and trash")
			}
		} else {
			return errors.New("pending SCEP issuer missing")
		}
		if r, ok := records[c.Record.Serial]; ok {
			if !reflect.DeepEqual(r, c.Record) || !bytes.Equal(certs[r.Serial].Raw, c.DER) {
				return errors.New("SCEP projection mismatch")
			}
		} else if !c.Published {
			// A committed journal may have a PEM but no index yet. It is recovered
			// only in staging, after every journal record has been validated.
			if b, err := os.ReadFile(s.certPath(c.Record.Serial)); err == nil && !bytes.Equal(b, encodeCertPEM(c.DER)) {
				return errors.New("pending SCEP PEM mismatch")
			}
		}
	}
	return nil
}

func backupCAID(id string) bool { return id == caRoot || id == caIntermediate || ValidSerial(id) }

func validateRecords(dir string, recs []CertRecord, cas map[string]*x509.Certificate, records map[string]CertRecord, certs map[string]*x509.Certificate, live bool) error {
	if len(recs) > 10000 {
		return errors.New("too many certificate records")
	}
	expected := map[string]bool{}
	for _, r := range recs {
		if !ValidSerial(r.Serial) || records[r.Serial].Serial != "" {
			return errors.New("invalid or duplicate certificate serial")
		}
		var cp, kp string
		switch r.Kind {
		case caRoot, caIntermediate:
			id := caIDOf(r)
			if !backupCAID(id) || cas[id] != nil || !r.HasKey {
				return errors.New("invalid CA record")
			}
			if r.Kind == caRoot && (r.CAID != "" || r.IssuerID != "") {
				return errors.New("invalid root metadata")
			}
			if r.Kind == caIntermediate && (id == caRoot || !backupCAID(r.IssuerID) || id == r.IssuerID || (r.CAID != "" && r.CAID != r.Serial)) {
				return errors.New("invalid intermediate metadata")
			}
			cp = filepath.Join("cas", id, "cert.pem")
			kp = filepath.Join("cas", id, "key.pem")
		case "issued", "csr":
			if !backupCAID(r.IssuerID) || (r.Kind == "csr" && r.HasKey) || (r.Kind == "issued" && !r.HasKey) || r.KeyEnc {
				return errors.New("invalid leaf record")
			}
			cp = filepath.Join("certs", r.Serial+"-cert.pem")
			kp = filepath.Join("certs", r.Serial+"-key.pem")
		default:
			return errors.New("unsupported certificate kind")
		}
		b, err := os.ReadFile(filepath.Join(dir, cp))
		if err != nil {
			return err
		}
		if len(b) > 1<<20 {
			return errors.New("certificate too large")
		}
		c, err := parseCertPEM(b)
		if err != nil {
			return err
		}
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("invalid certificate PEM framing")
		}
		if serialString(c.SerialNumber) != r.Serial || c.NotBefore.Unix() != r.NotBefore.Unix() || c.NotAfter.Unix() != r.NotAfter.Unix() || c.IsCA != (r.Kind == caRoot || r.Kind == caIntermediate) {
			return errors.New("certificate/index mismatch")
		}
		if r.Kind == caIntermediate && r.AllowSubCA == c.MaxPathLenZero {
			return errors.New("CA path length metadata mismatch")
		}
		if r.Provenance != "" && r.Provenance != "scep" {
			return errors.New("unsupported certificate provenance")
		}
		if r.TemplatePolicy.Name != "" {
			policy := r.TemplatePolicy
			if err := policy.normalize(); err != nil {
				return err
			}
		}
		expected[cp] = true
		if r.HasKey {
			b, err := os.ReadFile(filepath.Join(dir, kp))
			if err != nil {
				return err
			}
			if err := validateBackupKey(b, c, r.KeyEnc); err != nil {
				return err
			}
			expected[kp] = true
		}
		records[r.Serial] = r
		certs[r.Serial] = c
		if c.IsCA {
			cas[caIDOf(r)] = c
		}
	}
	for _, root := range []string{"cas", "certs"} {
		err := filepath.WalkDir(filepath.Join(dir, root), func(p string, d os.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			if !expected[rel] {
				// Unpublished SCEP PEMs are checked against the authoritative journal.
				if live && root == "certs" && strings.HasSuffix(p, "-cert.pem") {
					var st scepState
					if err := backupJSON(filepath.Join(dir, "scep.json"), &st); err != nil {
						return err
					}
					for _, c := range st.Challenges {
						if !c.Used.IsZero() && !c.Published && rel == filepath.Join("certs", c.Record.Serial+"-cert.pem") {
							b, err := os.ReadFile(p)
							if err == nil && bytes.Equal(b, encodeCertPEM(c.DER)) {
								return nil
							}
						}
					}
				}
				return fmt.Errorf("unindexed certificate/key: %s", rel)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func validateBackupKey(b []byte, c *x509.Certificate, encrypted bool) error {
	if len(b) > 64<<10 {
		return errors.New("private key too large")
	}
	p, rest := pem.Decode(b)
	if p == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid key PEM")
	}
	if encrypted {
		// Ciphertext cannot prove a public/private key match without the original
		// CA passphrase. Validate the envelope, preserve it byte-for-byte, and let
		// normal unlock authenticate it later; backup never asks for CA secrets.
		if p.Type != encKeyType || p.Headers["KDF"] != "PBKDF2-SHA256" || p.Headers["Cipher"] != "AES-256-GCM" || p.Headers["Iterations"] != strconv.Itoa(pbkdf2Iter) || len(p.Bytes) < 44 {
			return errors.New("invalid encrypted CA key envelope")
		}
		return nil
	}
	if p.Type != plainKeyType {
		return errors.New("invalid unencrypted key")
	}
	k, err := unmarshalKey(b, "")
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, c.RawSubjectPublicKeyInfo) {
		return errors.New("certificate/private key mismatch")
	}
	return nil
}

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

// keyAlgo identifies the public-key algorithm to generate.
type keyAlgo string

const (
	algoRSA2048 keyAlgo = "rsa2048"
	algoRSA4096 keyAlgo = "rsa4096"
	algoECP256  keyAlgo = "ecp256"
	algoECP384  keyAlgo = "ecp384"
)

// generateKey produces a fresh private key for the chosen algorithm. The result
// implements crypto.Signer, which is all x509.CreateCertificate needs, so the
// rest of the code can stay algorithm-agnostic.
func generateKey(algo keyAlgo) (crypto.Signer, error) {
	switch algo {
	case algoRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case algoRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case algoECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case algoECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		return nil, fmt.Errorf("unknown key algorithm %q", algo)
	}
}

// randSerial returns a random 128-bit positive serial number.
func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// serialString renders a serial number as lowercase hex without separators, so
// it is safe to use as a filename.
func serialString(serial *big.Int) string {
	return strings.ToLower(serial.Text(16))
}

func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// loadCA reads a stored CA certificate and its (possibly encrypted) private key.
func loadCA(s *Store, id, passphrase string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := s.LoadCACertPEM(id)
	if err != nil {
		return nil, nil, fmt.Errorf("loading %s CA certificate: %w", id, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("%s CA certificate PEM is invalid", id)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := s.LoadCAKeyPEM(id)
	if err != nil {
		return nil, nil, fmt.Errorf("loading %s CA key: %w", id, err)
	}
	key, err := unmarshalKey(keyPEM, passphrase)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// CAParams holds the inputs for creating the root CA.
type CAParams struct {
	CommonName   string
	Organization string
	Country      string
	Algo         keyAlgo
	ValidDays    int
	Passphrase   string // optional; encrypts the CA private key at rest
}

// CreateCA generates a new self-signed root CA and persists it. The root is left
// path-length unconstrained so it can optionally sign an intermediate later.
func CreateCA(s *Store, p CAParams) (CertRecord, error) {
	if p.CommonName == "" {
		return CertRecord{}, errors.New("common name is required")
	}
	key, err := generateKey(p.Algo)
	if err != nil {
		return CertRecord{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return CertRecord{}, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(p.CommonName, p.Organization, p.Country),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, p.ValidDays),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return CertRecord{}, err
	}
	keyPEM, err := marshalKey(key, p.Passphrase)
	if err != nil {
		return CertRecord{}, err
	}
	if err := s.SaveCA(caRoot, encodeCertPEM(der), keyPEM); err != nil {
		return CertRecord{}, err
	}

	rec := CertRecord{
		Serial:     serialString(serial),
		CommonName: p.CommonName,
		Kind:       caRoot,
		NotBefore:  tmpl.NotBefore,
		NotAfter:   tmpl.NotAfter,
		HasKey:     true,
		KeyEnc:     p.Passphrase != "",
		CreatedAt:  now,
	}
	return rec, s.AddRecord(rec)
}

// IntermediateParams holds the inputs for creating an intermediate CA.
type IntermediateParams struct {
	CommonName       string
	Organization     string
	Country          string
	Algo             keyAlgo
	ValidDays        int
	ParentID         string // which CA signed it: "root" or other intermediate id
	ParentPassphrase string // unlocks the parent key if it is encrypted
	Passphrase       string // optional; encrypts the new intermediate key at rest
	AllowSubCAs      bool   // if true, MaxPathLen = -1 (unconstrained); if false, MaxPathLen = 0
	SCEP             bool   // dedicated RSA, encryption-capable, leaf-only intermediate
}

// CreateIntermediate creates an intermediate CA signed by a parent (root or another intermediate).
// The intermediate can optionally allow sub-CAs (AllowSubCAs=false => MaxPathLen=0 => leaf-only;
// AllowSubCAs=true => MaxPathLen=-1 => unconstrained).
func CreateIntermediate(s *Store, p IntermediateParams) (CertRecord, error) {
	if p.SCEP && (p.AllowSubCAs || (p.Algo != algoRSA2048 && p.Algo != algoRSA4096)) {
		return CertRecord{}, errors.New("SCEP requires a leaf-only RSA intermediate")
	}
	if p.CommonName == "" {
		return CertRecord{}, errors.New("common name is required")
	}

	// Normalize parent ID: accept any valid CA id, fall back to root
	parentID := normalizeIssuer(s, p.ParentID)

	// Verify parent exists and can have sub-CAs
	if !s.HasCA(parentID) {
		return CertRecord{}, fmt.Errorf("parent CA %s does not exist", parentID)
	}
	parentCert, parentKey, err := loadCA(s, parentID, p.ParentPassphrase)
	if err != nil {
		return CertRecord{}, err
	}

	// Check if parent allows sub-CAs: if parentCert.MaxPathLenZero=true, parent cannot have children
	if parentCert.MaxPathLenZero && parentID != caRoot {
		return CertRecord{}, fmt.Errorf("parent CA %s does not allow sub-CAs (path length is 0)", parentID)
	}
	// Root always allows sub-CAs

	key, err := generateKey(p.Algo)
	if err != nil {
		return CertRecord{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return CertRecord{}, err
	}

	now := time.Now()
	notAfter := now.AddDate(0, 0, p.ValidDays)
	if notAfter.After(parentCert.NotAfter) {
		notAfter = parentCert.NotAfter // never outlive the parent
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(p.CommonName, p.Organization, p.Country),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            map[bool]int{true: -1, false: 0}[p.AllowSubCAs],
		MaxPathLenZero:        !p.AllowSubCAs,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	if p.SCEP {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		return CertRecord{}, err
	}
	keyPEM, err := marshalKey(key, p.Passphrase)
	if err != nil {
		return CertRecord{}, err
	}

	// Use serial hex as CA ID for new intermediates
	caID := serialString(serial)
	if err := s.SaveCA(caID, encodeCertPEM(der), keyPEM); err != nil {
		return CertRecord{}, err
	}

	rec := CertRecord{
		Serial:     caID,
		CommonName: p.CommonName,
		Kind:       caIntermediate,
		IssuerID:   parentID,
		CAID:       caID,
		AllowSubCA: p.AllowSubCAs,
		NotBefore:  tmpl.NotBefore,
		NotAfter:   tmpl.NotAfter,
		HasKey:     true,
		KeyEnc:     p.Passphrase != "",
		CreatedAt:  now,
	}
	return rec, s.AddRecord(rec)
}

// IssueParams holds the inputs for issuing a leaf certificate (key generated by us).
type IssueParams struct {
	CommonName             string
	Organization           string
	Country                string
	SANs                   []string // DNS names and IPs, mixed
	Algo                   keyAlgo
	ValidDays              int
	Profile                certProfile
	Template               CertTemplate
	TemplateName           string
	DNSNames, Emails, URIs []string
	IPs                    []net.IP
	IssuerID               string // "root" or "intermediate"
	CAPassphrase           string // unlocks the signing CA key if encrypted
}

type certProfile string

const (
	profileServer certProfile = "server"
	profileClient certProfile = "client"
	profileBoth   certProfile = "both"
	profileCode   certProfile = "code"
	profileEmail  certProfile = "email"
)

func extKeyUsage(p certProfile) []x509.ExtKeyUsage {
	switch p {
	case profileClient:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case profileBoth:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case profileCode:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	case profileEmail:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
}

// splitSANs separates host strings into DNS names and IP addresses.
func splitSANs(sans []string) (dns []string, ips []net.IP) {
	for _, raw := range sans {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, h)
		}
	}
	return dns, ips
}

func parsePolicyURIs(values []string) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(values))
	for _, v := range values {
		u, err := url.Parse(strings.TrimSpace(v))
		if err != nil || u == nil || !u.IsAbs() || u.Opaque != "" || ((u.Scheme == "http" || u.Scheme == "https") && u.Host == "") {
			return nil, fmt.Errorf("invalid URI SAN %q", v)
		}
		out = append(out, u)
	}
	return out, nil
}

// IssueCert generates a key pair, signs a leaf certificate with the chosen CA,
// and stores both.
func IssueCert(s *Store, p IssueParams) (CertRecord, error) {
	if p.CommonName == "" && p.Template.Name == "" {
		return CertRecord{}, errors.New("common name is required")
	}
	if p.IssuerID == "" || !s.ValidCAID(p.IssuerID) {
		return CertRecord{}, errors.New("select a valid issuing CA")
	}
	issuer := normalizeIssuer(s, p.IssuerID)
	caCert, caKey, err := loadCA(s, issuer, p.CAPassphrase)
	if err != nil {
		return CertRecord{}, err
	}

	key, err := generateKey(p.Algo)
	if err != nil {
		return CertRecord{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return CertRecord{}, err
	}

	dns, ips := splitSANs(p.SANs)
	dns = append(dns, p.DNSNames...)
	ips = append(ips, p.IPs...)
	if p.Template.Name != "" {
		if p.Organization == "" {
			p.Organization = p.Template.Organization
		}
		if p.Country == "" {
			p.Country = p.Template.Country
		}
		if err := validateIssuePolicy(p.Template, issuer, p.ValidDays, p.Algo, p.CommonName, dns, ips, p.Emails, p.URIs); err != nil {
			return CertRecord{}, err
		}
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(p.CommonName, p.Organization, p.Country),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, p.ValidDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage(p.Profile),
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
		EmailAddresses:        p.Emails,
	}
	if p.Template.Name != "" {
		tmpl.URIs, err = parsePolicyURIs(p.URIs)
		if err != nil {
			return CertRecord{}, err
		}
		tmpl.ExtKeyUsage = extKeyUsage(p.Template.Profile)
		tmpl.KeyUsage = profileKeyUsage(p.Template.Profile, p.Algo)
	}
	if tmpl.NotAfter.After(caCert.NotAfter) {
		return CertRecord{}, errors.New("requested validity exceeds issuing CA expiration")
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, key.Public(), caKey)
	if err != nil {
		return CertRecord{}, err
	}
	// Leaf keys are stored as standard, unencrypted PKCS#8 so they're usable
	// directly by other tooling (nginx, openssl, ...) after download.
	keyPEM, err := marshalKey(key, "")
	if err != nil {
		return CertRecord{}, err
	}
	ser := serialString(serial)
	if err := s.SaveCert(ser, encodeCertPEM(der), keyPEM); err != nil {
		return CertRecord{}, err
	}

	rec := CertRecord{
		Serial:       ser,
		CommonName:   p.CommonName,
		Kind:         "issued",
		IssuerID:     issuer,
		NotBefore:    tmpl.NotBefore,
		NotAfter:     tmpl.NotAfter,
		HasKey:       true,
		CreatedAt:    now,
		TemplateName: p.TemplateName, TemplatePolicy: p.Template,
	}
	return rec, s.AddRecord(rec)
}

// SignCSRParams holds the inputs for signing an externally generated CSR.
type SignCSRParams struct {
	CSRPEM       []byte
	ValidDays    int
	Profile      certProfile
	IssuerID     string
	CAPassphrase string
	Template     CertTemplate
	TemplateName string
}

// SignCSR validates a PEM-encoded CSR and issues a certificate for it signed by
// the chosen CA. No private key is stored, since the requester keeps their own.
func SignCSR(s *Store, p SignCSRParams) (CertRecord, error) {
	block, _ := pem.Decode(p.CSRPEM)
	if block == nil {
		return CertRecord{}, errors.New("could not decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return CertRecord{}, fmt.Errorf("parsing CSR: %w", err)
	}
	if p.IssuerID == "" || !s.ValidCAID(p.IssuerID) {
		return CertRecord{}, errors.New("select a valid issuing CA")
	}
	caCert, caKey, err := loadCA(s, p.IssuerID, p.CAPassphrase)
	if err != nil {
		return CertRecord{}, err
	}
	rec, der, err := signCSRWithoutPersistence(csr, p, caCert, caKey, false)
	if err != nil {
		return CertRecord{}, err
	}
	if err := s.SaveCert(rec.Serial, encodeCertPEM(der), nil); err != nil {
		return CertRecord{}, err
	}
	return rec, s.AddRecord(rec)
}

// signCSRWithoutPersistence validates and signs the supplied CSR fields. It does
// not load a key, replace identities, or write storage. Callers own authorization
// and persistence: the UI saves immediately; SCEP explicitly substitutes its
// authorized SANs on a copy and commits DER + metadata in its durable journal.
func signCSRWithoutPersistence(csr *x509.CertificateRequest, p SignCSRParams, caCert *x509.Certificate, caKey crypto.Signer, boundExpiry bool) (CertRecord, []byte, error) {
	if caCert == nil || caKey == nil || csr == nil {
		return CertRecord{}, nil, errors.New("CSR, issuing certificate and key are required")
	}
	if err := csr.CheckSignature(); err != nil {
		return CertRecord{}, nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}
	if p.Template.Name != "" {
		if err := validateCSRPolicy(csr, p.Template, p.IssuerID, p.ValidDays); err != nil {
			return CertRecord{}, nil, err
		}
	}
	if p.Template.Name != "" {
		a, ok := publicKeyAlgo(csr.PublicKey)
		if !ok || !allowedAlgo(p.Template, a) {
			return CertRecord{}, nil, errors.New("CSR public-key algorithm is not allowed by this template")
		}
	}
	serial, err := randSerial()
	if err != nil {
		return CertRecord{}, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, p.ValidDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage(p.Profile),
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
	}
	if p.Template.Name != "" {
		tmpl.ExtKeyUsage = extKeyUsage(p.Template.Profile)
		tmpl.KeyUsage = profileKeyUsage(p.Template.Profile, publicKeyAlgoValue(csr.PublicKey))
		if boundExpiry && tmpl.NotAfter.After(caCert.NotAfter) {
			tmpl.NotAfter = caCert.NotAfter
		}
		if tmpl.NotAfter.After(caCert.NotAfter) {
			return CertRecord{}, nil, errors.New("requested validity exceeds issuing CA expiration")
		}
		if !tmpl.NotAfter.After(now) {
			return CertRecord{}, nil, errors.New("issuing CA has expired")
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return CertRecord{}, nil, err
	}
	ser := serialString(serial)
	cn := csr.Subject.CommonName
	if cn == "" && len(csr.DNSNames) > 0 {
		cn = csr.DNSNames[0]
	}
	rec := CertRecord{
		Serial:       ser,
		CommonName:   cn,
		Kind:         "csr",
		IssuerID:     p.IssuerID,
		NotBefore:    tmpl.NotBefore,
		NotAfter:     tmpl.NotAfter,
		HasKey:       false,
		CreatedAt:    now,
		TemplateName: p.TemplateName, TemplatePolicy: p.Template,
	}
	return rec, der, nil
}

// normalizeIssuer validates a CA id (root, legacy intermediate, or serial hex).
// Falls back to root if the id is not valid.
func normalizeIssuer(s *Store, id string) string {
	if id == "" || !s.ValidCAID(id) {
		return caRoot
	}
	return id
}

func subject(cn, org, country string) pkix.Name {
	name := pkix.Name{CommonName: cn}
	if org != "" {
		name.Organization = []string{org}
	}
	if country != "" {
		name.Country = []string{country}
	}
	return name
}

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

// IntermediateParams holds the inputs for creating an optional intermediate CA
// signed by the root.
type IntermediateParams struct {
	CommonName     string
	Organization   string
	Country        string
	Algo           keyAlgo
	ValidDays      int
	RootPassphrase string // unlocks the root key if it is encrypted
	Passphrase     string // optional; encrypts the new intermediate key at rest
}

// CreateIntermediate creates an intermediate CA signed by the root. The
// intermediate is path-length 0, so it may only issue leaf certificates.
func CreateIntermediate(s *Store, p IntermediateParams) (CertRecord, error) {
	if p.CommonName == "" {
		return CertRecord{}, errors.New("common name is required")
	}
	if !s.HasCA(caRoot) {
		return CertRecord{}, errors.New("create the root CA first")
	}
	rootCert, rootKey, err := loadCA(s, caRoot, p.RootPassphrase)
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

	now := time.Now()
	notAfter := now.AddDate(0, 0, p.ValidDays)
	if notAfter.After(rootCert.NotAfter) {
		notAfter = rootCert.NotAfter // never outlive the root
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(p.CommonName, p.Organization, p.Country),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // may only issue leaf certs
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, key.Public(), rootKey)
	if err != nil {
		return CertRecord{}, err
	}
	keyPEM, err := marshalKey(key, p.Passphrase)
	if err != nil {
		return CertRecord{}, err
	}
	if err := s.SaveCA(caIntermediate, encodeCertPEM(der), keyPEM); err != nil {
		return CertRecord{}, err
	}

	rec := CertRecord{
		Serial:     serialString(serial),
		CommonName: p.CommonName,
		Kind:       caIntermediate,
		IssuerID:   caRoot,
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
	CommonName   string
	Organization string
	SANs         []string // DNS names and IPs, mixed
	Algo         keyAlgo
	ValidDays    int
	Profile      certProfile
	IssuerID     string // "root" or "intermediate"
	CAPassphrase string // unlocks the signing CA key if encrypted
}

type certProfile string

const (
	profileServer certProfile = "server"
	profileClient certProfile = "client"
	profileBoth   certProfile = "both"
)

func extKeyUsage(p certProfile) []x509.ExtKeyUsage {
	switch p {
	case profileClient:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case profileBoth:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
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

// IssueCert generates a key pair, signs a leaf certificate with the chosen CA,
// and stores both.
func IssueCert(s *Store, p IssueParams) (CertRecord, error) {
	if p.CommonName == "" {
		return CertRecord{}, errors.New("common name is required")
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
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(p.CommonName, p.Organization, ""),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, p.ValidDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage(p.Profile),
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
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
		Serial:     ser,
		CommonName: p.CommonName,
		Kind:       "issued",
		IssuerID:   issuer,
		NotBefore:  tmpl.NotBefore,
		NotAfter:   tmpl.NotAfter,
		HasKey:     true,
		CreatedAt:  now,
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
	if err := csr.CheckSignature(); err != nil {
		return CertRecord{}, fmt.Errorf("CSR signature is invalid: %w", err)
	}

	issuer := normalizeIssuer(s, p.IssuerID)
	caCert, caKey, err := loadCA(s, issuer, p.CAPassphrase)
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

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return CertRecord{}, err
	}
	ser := serialString(serial)
	if err := s.SaveCert(ser, encodeCertPEM(der), nil); err != nil {
		return CertRecord{}, err
	}

	cn := csr.Subject.CommonName
	if cn == "" && len(csr.DNSNames) > 0 {
		cn = csr.DNSNames[0]
	}
	rec := CertRecord{
		Serial:     ser,
		CommonName: cn,
		Kind:       "csr",
		IssuerID:   issuer,
		NotBefore:  tmpl.NotBefore,
		NotAfter:   tmpl.NotAfter,
		HasKey:     false,
		CreatedAt:  now,
	}
	return rec, s.AddRecord(rec)
}

// normalizeIssuer falls back to the root unless a usable intermediate is asked for.
func normalizeIssuer(s *Store, id string) string {
	if id == caIntermediate && s.HasCA(caIntermediate) {
		return caIntermediate
	}
	return caRoot
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

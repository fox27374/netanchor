package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// CertInfo is a fully-rendered, template-friendly view of an x509 certificate.
type CertInfo struct {
	CommonName     string
	Subject        string
	Issuer         string
	SerialHex      string
	NotBefore      string
	NotAfter       string
	Expired        bool
	DaysLeft       int
	IsCA           bool
	MaxPathLen     string
	PublicKey      string
	SignatureAlgo  string
	KeyUsages      []string
	ExtKeyUsages   []string
	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	URIs           []string
	SHA256         string
	SHA1           string
}

// parseCertPEM decodes the first CERTIFICATE block from PEM bytes.
func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseCertsPEM decodes every CERTIFICATE block from PEM bytes, in order.
func parseCertsPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificates found")
	}
	return certs, nil
}

func describeCert(cert *x509.Certificate) CertInfo {
	now := time.Now()
	info := CertInfo{
		CommonName:     cert.Subject.CommonName,
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialHex:      serialString(cert.SerialNumber),
		NotBefore:      cert.NotBefore.Format("2006-01-02 15:04 MST"),
		NotAfter:       cert.NotAfter.Format("2006-01-02 15:04 MST"),
		Expired:        now.After(cert.NotAfter),
		DaysLeft:       int(time.Until(cert.NotAfter).Hours() / 24),
		IsCA:           cert.IsCA,
		PublicKey:      describePublicKey(cert.PublicKey),
		SignatureAlgo:  cert.SignatureAlgorithm.String(),
		KeyUsages:      keyUsageStrings(cert.KeyUsage),
		ExtKeyUsages:   extKeyUsageStrings(cert.ExtKeyUsage),
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
	}
	if cert.IsCA && cert.MaxPathLenZero {
		info.MaxPathLen = "0 (leaf certificates only)"
	} else if cert.IsCA {
		info.MaxPathLen = "unconstrained"
	}
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	sum256 := sha256.Sum256(cert.Raw)
	info.SHA256 = hexColons(sum256[:])
	sum1 := sha1.Sum(cert.Raw)
	info.SHA1 = hexColons(sum1[:])
	return info
}

func describePublicKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

func keyUsageStrings(ku x509.KeyUsage) []string {
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	var out []string
	for _, p := range pairs {
		if ku&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}

func extKeyUsageStrings(eku []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "Any",
		x509.ExtKeyUsageServerAuth:      "TLS Web Server Authentication",
		x509.ExtKeyUsageClientAuth:      "TLS Web Client Authentication",
		x509.ExtKeyUsageCodeSigning:     "Code Signing",
		x509.ExtKeyUsageEmailProtection: "Email Protection",
		x509.ExtKeyUsageOCSPSigning:     "OCSP Signing",
		x509.ExtKeyUsageTimeStamping:    "Time Stamping",
	}
	var out []string
	for _, u := range eku {
		if n, ok := names[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, "Other")
		}
	}
	return out
}

func hexColons(b []byte) string {
	const hexd = "0123456789ABCDEF"
	buf := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexd[c>>4], hexd[c&0x0f])
	}
	return string(buf)
}

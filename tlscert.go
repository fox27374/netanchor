package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"time"
)

// ensureServerCert makes sure a usable TLS server certificate and key exist on
// disk, generating them if missing or expired. When an (unlocked) root CA is
// available the server certificate is issued by it — so importing the root makes
// the GUI trusted — otherwise it falls back to a self-signed certificate.
//
// It returns the cert file, key file, and a short human description of how the
// certificate was produced.
func ensureServerCert(store *Store, hosts []string, caPassphrase string) (certFile, keyFile, descr string, err error) {
	certFile = store.tlsCertPath()
	keyFile = store.tlsKeyPath()

	if serverCertValid(certFile, keyFile) {
		return certFile, keyFile, "existing certificate", nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	serial, err := randSerial()
	if err != nil {
		return "", "", "", err
	}

	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1"}
	}
	dns, ips := splitSANs(hosts)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, 825),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}

	var certPEM []byte
	descr = "self-signed"

	// Prefer issuing from the root CA when we can unlock it.
	if store.HasCA(caRoot) {
		if caCert, caKey, lerr := loadCA(store, caRoot, caPassphrase); lerr == nil {
			if der, cerr := x509.CreateCertificate(rand.Reader, tmpl, caCert, key.Public(), caKey); cerr == nil {
				// Present a full chain: server leaf followed by the root.
				rootPEM, _ := store.LoadCACertPEM(caRoot)
				certPEM = append(ensureTrailingNewline(encodeCertPEM(der)), rootPEM...)
				descr = "issued by root CA"
			}
		}
	}

	if certPEM == nil {
		der, serr := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if serr != nil {
			return "", "", "", serr
		}
		certPEM = encodeCertPEM(der)
	}

	keyPEM, err := marshalKey(key, "")
	if err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", "", err
	}
	return certFile, keyFile, descr, nil
}

// serverCertValid reports whether both files exist and the certificate is not
// expired (and not about to expire within a day).
func serverCertValid(certFile, keyFile string) bool {
	if _, err := os.Stat(keyFile); err != nil {
		return false
	}
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return false
	}
	cert, err := parseCertPEM(pemBytes)
	if err != nil {
		return false
	}
	return time.Now().Add(24 * time.Hour).Before(cert.NotAfter)
}

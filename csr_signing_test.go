package main

import (
	"crypto/x509"
	"os"
	"testing"
)

func TestCSRSigningWithoutPersistence(t *testing.T) {
	f := newSCEPFixture(t)
	csr := f.csr(t, "test-challenge", []string{"switch.example.net"})
	profile, _ := builtinByName("TLS-Server")
	p := SignCSRParams{IssuerID: f.ca, ValidDays: 365, Template: profile, TemplateName: profile.Name}
	rec, der, err := signCSRWithoutPersistence(csr, p, f.e.cert, f.e.key, true)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if serialString(cert.SerialNumber) != rec.Serial || rec.Kind != "csr" {
		t.Fatal("DER/metadata mismatch")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != csr.DNSNames[0] {
		t.Fatal("signing helper replaced identities")
	}
	if _, ok := f.e.store.RecordBySerial(rec.Serial); ok {
		t.Fatal("signing helper persisted metadata")
	}
	if _, err := os.Stat(f.e.store.certPath(rec.Serial)); !os.IsNotExist(err) {
		t.Fatal("signing helper persisted PEM")
	}
	csr.Signature[0] ^= 1
	if _, _, err := signCSRWithoutPersistence(csr, p, f.e.cert, f.e.key, true); err == nil {
		t.Fatal("helper skipped CSR signature verification")
	}
}

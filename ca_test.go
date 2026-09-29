package main

import (
	"crypto/x509"
	"testing"
)

func TestNestedIntermediateChain(t *testing.T) {
	// Create a temporary store
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}

	// Create root CA
	rootRec, err := CreateCA(s, CAParams{
		CommonName:   "Test Root CA",
		Organization: "Test",
		Algo:         algoECP256,
		ValidDays:    3650,
		Passphrase:   "",
	})
	if err != nil {
		t.Fatalf("CreateCA (root): %v", err)
	}

	// Create intermediate A (allows sub-CAs)
	aRec, err := CreateIntermediate(s, IntermediateParams{
		CommonName:       "Test Intermediate A",
		Organization:     "Test",
		Algo:             algoECP256,
		ValidDays:        1825,
		ParentID:         "root",
		ParentPassphrase: "",
		AllowSubCAs:      true, // Allow sub-CAs
	})
	if err != nil {
		t.Fatalf("CreateIntermediate (A): %v", err)
	}
	if !aRec.AllowSubCA {
		t.Errorf("aRec.AllowSubCA = false, want true")
	}

	// Create intermediate B (no sub-CAs), signed by A
	bRec, err := CreateIntermediate(s, IntermediateParams{
		CommonName:       "Test Intermediate B",
		Organization:     "Test",
		Algo:             algoECP256,
		ValidDays:        1825,
		ParentID:         aRec.Serial, // Use A's serial as parent
		ParentPassphrase: "",
		AllowSubCAs:      false, // No sub-CAs (leaf-only)
	})
	if err != nil {
		t.Fatalf("CreateIntermediate (B): %v", err)
	}
	if bRec.AllowSubCA {
		t.Errorf("bRec.AllowSubCA = true, want false")
	}

	// Issue a certificate from B
	leafRec, err := IssueCert(s, IssueParams{
		CommonName:   "test.example.com",
		SANs:         []string{"test.example.com"},
		Algo:         algoECP256,
		ValidDays:    365,
		Profile:      profileServer,
		IssuerID:     bRec.Serial, // Use B's serial as issuer
		CAPassphrase: "",
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Test IssuerChainPEM for B: should return B + A + root chain
	chainPEM, err := s.IssuerChainPEM(bRec.Serial)
	if err != nil {
		t.Fatalf("IssuerChainPEM(%s): %v", bRec.Serial, err)
	}

	// Parse the chain
	certs, err := parseCertsPEM(chainPEM)
	if err != nil {
		t.Fatalf("parseCertsPEM: %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("len(certs) = %d, want 3 (B + A + root)", len(certs))
	}

	// Verify the chain by subject CN
	if len(certs) >= 3 {
		if certs[0].Subject.CommonName != "Test Intermediate B" {
			t.Errorf("certs[0].Subject.CommonName = %q, want %q", certs[0].Subject.CommonName, "Test Intermediate B")
		}
		if certs[1].Subject.CommonName != "Test Intermediate A" {
			t.Errorf("certs[1].Subject.CommonName = %q, want %q", certs[1].Subject.CommonName, "Test Intermediate A")
		}
		if certs[2].Subject.CommonName != "Test Root CA" {
			t.Errorf("certs[2].Subject.CommonName = %q, want %q", certs[2].Subject.CommonName, "Test Root CA")
		}
	}

	// Load the leaf cert and verify it chains correctly
	leafPEM, err := s.LoadCertPEM(leafRec.Serial)
	if err != nil {
		t.Fatalf("LoadCertPEM: %v", err)
	}
	leaf, err := parseCertPEM(leafPEM)
	if err != nil {
		t.Fatalf("parseCertPEM (leaf): %v", err)
	}

	// Build trust pool with root
	rootPEM, err := s.LoadCACertPEM(caRoot)
	if err != nil {
		t.Fatalf("LoadCACertPEM (root): %v", err)
	}
	root, err := parseCertPEM(rootPEM)
	if err != nil {
		t.Fatalf("parseCertPEM (root): %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	// Build intermediates pool (A and B)
	intermediates := x509.NewCertPool()
	for _, c := range certs {
		intermediates.AddCert(c)
	}

	// Verify the leaf with the chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, err = leaf.Verify(opts)
	if err != nil {
		t.Errorf("leaf.Verify: %v", err)
	}

	// Test that creating a sub-CA under B should fail (MaxPathLenZero)
	_, err = CreateIntermediate(s, IntermediateParams{
		CommonName:       "Test Intermediate C",
		Organization:     "Test",
		Algo:             algoECP256,
		ValidDays:        1825,
		ParentID:         bRec.Serial, // Try to use B (no sub-CAs) as parent
		ParentPassphrase: "",
		AllowSubCAs:      true,
	})
	if err == nil {
		t.Errorf("CreateIntermediate (C under B) succeeded, want error (B does not allow sub-CAs)")
	}

	// Test legacy intermediate: create one with old-style ID and check it resolves
	// First, manually create a legacy intermediate entry
	legacyRec := CertRecord{
		Serial:     "deadbeef",
		CommonName: "Legacy Intermediate",
		Kind:       caIntermediate,
		IssuerID:   caRoot,
		CAID:       "", // Empty CAID means legacy
		AllowSubCA: false,
		HasKey:     true,
		KeyEnc:     false,
		CreatedAt:  rootRec.CreatedAt,
	}

	// Create a dummy cert for the legacy intermediate
	// For testing, we'll just copy the root cert
	rootCertPEM, _ := s.LoadCACertPEM(caRoot)
	rootKeyPEM, _ := s.LoadCAKeyPEM(caRoot)
	if err := s.SaveCA(caIntermediate, rootCertPEM, rootKeyPEM); err != nil {
		t.Fatalf("SaveCA (legacy): %v", err)
	}
	if err := s.AddRecord(legacyRec); err != nil {
		t.Fatalf("AddRecord (legacy): %v", err)
	}

	// Verify that IssuerChainPEM("intermediate") works (legacy)
	legacyChain, err := s.IssuerChainPEM(caIntermediate)
	if err != nil {
		t.Errorf("IssuerChainPEM(intermediate): %v", err)
	}
	legacyCerts, err := parseCertsPEM(legacyChain)
	if err != nil {
		t.Errorf("parseCertsPEM (legacy chain): %v", err)
	}
	if len(legacyCerts) < 1 {
		t.Errorf("len(legacyCerts) = %d, want >= 1", len(legacyCerts))
	}
}

func TestLegacyIntermediateStillWorks(t *testing.T) {
	// Test that legacy intermediates still work after new ones are created
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}

	// Create root
	rootRec, err := CreateCA(s, CAParams{
		CommonName: "Root",
		Algo:       algoECP256,
		ValidDays:  3650,
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	// Add a legacy intermediate manually
	legacyRec := CertRecord{
		Serial:     "legacy",
		CommonName: "Legacy Intermediate",
		Kind:       caIntermediate,
		IssuerID:   caRoot,
		CAID:       "",
		AllowSubCA: false,
		HasKey:     true,
		CreatedAt:  rootRec.CreatedAt,
	}
	rootCertPEM, _ := s.LoadCACertPEM(caRoot)
	rootKeyPEM, _ := s.LoadCAKeyPEM(caRoot)
	s.SaveCA(caIntermediate, rootCertPEM, rootKeyPEM)
	s.AddRecord(legacyRec)

	// Create a new intermediate under root
	_, err = CreateIntermediate(s, IntermediateParams{
		CommonName:  "New Intermediate",
		Algo:        algoECP256,
		ValidDays:   1825,
		ParentID:    "root",
		AllowSubCAs: false,
	})
	if err != nil {
		t.Fatalf("CreateIntermediate: %v", err)
	}

	// Verify legacy intermediate still exists and its chain still works
	legacyChain, err := s.IssuerChainPEM(caIntermediate)
	if err != nil {
		t.Errorf("IssuerChainPEM(intermediate) after new intermediate created: %v", err)
	}
	legacyCerts, err := parseCertsPEM(legacyChain)
	if err != nil {
		t.Errorf("parseCertsPEM (legacy chain): %v", err)
	}
	if len(legacyCerts) < 2 {
		t.Errorf("len(legacyCerts) = %d, want >= 2 (intermediate + root)", len(legacyCerts))
	}
}

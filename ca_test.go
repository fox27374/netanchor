package main

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestDeleteCA(t *testing.T) {
	// Test cascading CA deletion
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}

	// Create root CA
	_, err = CreateCA(s, CAParams{
		CommonName:   "Test Root CA",
		Organization: "Test",
		Algo:         algoECP256,
		ValidDays:    3650,
	})
	if err != nil {
		t.Fatalf("CreateCA (root): %v", err)
	}

	// Create intermediate A (allows sub-CAs)
	aRec, err := CreateIntermediate(s, IntermediateParams{
		CommonName:   "Intermediate A",
		Organization: "Test",
		Algo:         algoECP256,
		ValidDays:    1825,
		ParentID:     "root",
		AllowSubCAs:  true,
	})
	if err != nil {
		t.Fatalf("CreateIntermediate (A): %v", err)
	}

	// Create intermediate B under A
	bRec, err := CreateIntermediate(s, IntermediateParams{
		CommonName:   "Intermediate B",
		Organization: "Test",
		Algo:         algoECP256,
		ValidDays:    1825,
		ParentID:     aRec.Serial,
		AllowSubCAs:  false,
	})
	if err != nil {
		t.Fatalf("CreateIntermediate (B): %v", err)
	}

	// Issue a cert from A
	leafARecords, err := IssueCert(s, IssueParams{
		CommonName:   "test-a.example.com",
		SANs:         []string{"test-a.example.com"},
		Algo:         algoECP256,
		ValidDays:    365,
		Profile:      profileServer,
		IssuerID:     aRec.Serial,
		CAPassphrase: "",
	})
	if err != nil {
		t.Fatalf("IssueCert (from A): %v", err)
	}

	// Issue a cert from B
	leafBRec, err := IssueCert(s, IssueParams{
		CommonName:   "test-b.example.com",
		SANs:         []string{"test-b.example.com"},
		Algo:         algoECP256,
		ValidDays:    365,
		Profile:      profileServer,
		IssuerID:     bRec.Serial,
		CAPassphrase: "",
	})
	if err != nil {
		t.Fatalf("IssueCert (from B): %v", err)
	}

	// Issue a cert from root
	leafRootRec, err := IssueCert(s, IssueParams{
		CommonName:   "test-root.example.com",
		SANs:         []string{"test-root.example.com"},
		Algo:         algoECP256,
		ValidDays:    365,
		Profile:      profileServer,
		IssuerID:     caRoot,
		CAPassphrase: "",
	})
	if err != nil {
		t.Fatalf("IssueCert (from root): %v", err)
	}

	// Verify all records exist before deletion
	recs, _ := s.Records()
	if len(recs) != 7 { // root, A, B, leafA, leafB, leafRoot, + root itself as CA
		t.Logf("Initial records: %d (expected 7: root CA, A, B, leafA, leafB, leafRoot)", len(recs))
	}

	// Delete intermediate A (should cascade to B and both leaves)
	if err := s.DeleteCA(aRec.Serial); err != nil {
		t.Fatalf("DeleteCA(A): %v", err)
	}

	// Verify records after deletion
	recs, _ = s.Records()
	for _, r := range recs {
		if r.Serial == aRec.Serial || r.Serial == bRec.Serial ||
			r.Serial == leafARecords.Serial || r.Serial == leafBRec.Serial {
			t.Errorf("Record still exists after deletion: %s (%s)", r.CommonName, r.Serial)
		}
	}

	// Root and its leaf should still exist
	rootFound := false
	leafRootFound := false
	for _, r := range recs {
		if r.Kind == caRoot {
			rootFound = true
		}
		if r.Serial == leafRootRec.Serial {
			leafRootFound = true
		}
	}
	if !rootFound {
		t.Errorf("Root CA was deleted!")
	}
	if !leafRootFound {
		t.Errorf("Leaf from root was deleted!")
	}

	// Verify trash directory was created and contains the deleted records
	trashBaseDir := filepath.Join(dir, "trash")
	trashDirs, err := filepath.Glob(filepath.Join(trashBaseDir, "*"))
	if err != nil || len(trashDirs) == 0 {
		t.Errorf("No trash directory created")
	} else {
		// Should have one trash timestamp directory
		trashDir := trashDirs[0]
		indexPath := filepath.Join(trashDir, "index.json")
		data, err := os.ReadFile(indexPath)
		if err != nil {
			t.Errorf("Could not read trash index.json: %v", err)
		}
		var trashedRecs []CertRecord
		if err := json.Unmarshal(data, &trashedRecs); err != nil {
			t.Errorf("Could not parse trash index.json: %v", err)
		}
		if len(trashedRecs) != 4 {
			t.Errorf("Trash index has %d records, want 4 (A, B, leafA, leafB)", len(trashedRecs))
		}

		// Verify CA files were moved
		aPath := filepath.Join(trashDir, "cas", aRec.Serial)
		if _, err := os.Stat(filepath.Join(aPath, "cert.pem")); err != nil {
			t.Errorf("A's cert.pem not in trash: %v", err)
		}

		bPath := filepath.Join(trashDir, "cas", bRec.Serial)
		if _, err := os.Stat(filepath.Join(bPath, "cert.pem")); err != nil {
			t.Errorf("B's cert.pem not in trash: %v", err)
		}

		// Verify CA files were removed from original location
		if s.HasCA(aRec.Serial) {
			t.Errorf("A's cert still exists at original location")
		}
		if s.HasCA(bRec.Serial) {
			t.Errorf("B's cert still exists at original location")
		}
	}
}

func TestDeleteCert(t *testing.T) {
	// Test certificate deletion
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}

	// Create root CA
	_, err = CreateCA(s, CAParams{
		CommonName: "Test Root CA",
		Algo:       algoECP256,
		ValidDays:  3650,
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	// Issue a cert
	certRec, err := IssueCert(s, IssueParams{
		CommonName:   "test.example.com",
		SANs:         []string{"test.example.com"},
		Algo:         algoECP256,
		ValidDays:    365,
		Profile:      profileServer,
		IssuerID:     caRoot,
		CAPassphrase: "",
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Verify cert exists
	_, ok := s.RecordBySerial(certRec.Serial)
	if !ok {
		t.Fatalf("Cert record not found before deletion")
	}

	// Delete the cert
	if err := s.DeleteCert(certRec.Serial); err != nil {
		t.Fatalf("DeleteCert: %v", err)
	}

	// Verify cert record is gone
	_, ok = s.RecordBySerial(certRec.Serial)
	if ok {
		t.Errorf("Cert record still exists after deletion")
	}

	// Verify files are in trash
	trashBaseDir := filepath.Join(dir, "trash")
	trashDirs, err := filepath.Glob(filepath.Join(trashBaseDir, "*"))
	if err != nil || len(trashDirs) == 0 {
		t.Errorf("No trash directory created")
	} else {
		trashDir := trashDirs[0]
		certPath := filepath.Join(trashDir, "certs", certRec.Serial+"-cert.pem")
		if _, err := os.Stat(certPath); err != nil {
			t.Errorf("Cert not in trash: %v", err)
		}
		keyPath := filepath.Join(trashDir, "certs", certRec.Serial+"-key.pem")
		if _, err := os.Stat(keyPath); err != nil {
			t.Errorf("Key not in trash: %v", err)
		}
	}
}

func TestDeleteRootCA(t *testing.T) {
	// Test that root CA cannot be deleted
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}

	// Create root CA
	_, err = CreateCA(s, CAParams{
		CommonName: "Test Root CA",
		Algo:       algoECP256,
		ValidDays:  3650,
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	// Try to delete root - should fail
	if err := s.DeleteCA(caRoot); err == nil {
		t.Errorf("DeleteCA(root) succeeded, want error")
	}
}

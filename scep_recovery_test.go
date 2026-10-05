package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Commit an issuance while its PEM/index projection is unavailable.
func pendingSCEP(t *testing.T, f *scepFixture) ([]byte, scepState) {
	t.Helper()
	r := f.request(t, f.csr(t, f.challenge(t), nil))
	dir := filepath.Join(f.e.store.dir, "certs")
	if err := os.Rename(dir, dir+".offline"); err != nil {
		t.Fatal(err)
	}
	if _, status := f.e.enroll(r.Raw); status != 503 {
		t.Fatalf("projection failure status: %d", status)
	}
	if err := os.Rename(dir+".offline", dir); err != nil {
		t.Fatal(err)
	}
	st, err := f.e.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Challenges) != 1 || st.Challenges[0].Published || st.Challenges[0].Used.IsZero() {
		t.Fatal("expected pending durable issuance")
	}
	return r.Raw, st
}

func TestSCEPRecoveryPreservesUnavailableCA(t *testing.T) {
	for _, mode := range []string{"missing", "not-directory"} {
		t.Run(mode, func(t *testing.T) {
			f := newSCEPFixture(t)
			raw, st := pendingSCEP(t, f)
			before, err := os.ReadFile(f.e.path())
			if err != nil {
				t.Fatal(err)
			}
			dir := f.e.store.caDir(f.ca)
			if err := os.Rename(dir, dir+".offline"); err != nil {
				t.Fatal(err)
			}
			if mode == "not-directory" {
				if err := os.WriteFile(dir, []byte("unavailable mount"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.e.recover(&st); err == nil {
				t.Error("unavailable CA was treated as deliberate deletion")
			}
			after, err := os.ReadFile(f.e.path())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Error("storage outage permanently changed pending commit")
			}
			if mode == "not-directory" {
				if err := os.Remove(dir); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(dir+".offline", dir); err != nil {
				t.Fatal(err)
			}
			f.e = newSCEPService(f.e.store)
			if err := f.e.startup(""); err != nil {
				t.Fatal(err)
			}
			if err := f.e.selectCA(f.ca, "test-pass"); err != nil {
				t.Fatal(err)
			}
			b, status := f.e.enroll(raw)
			c := f.response(t, b, status, true)
			if !bytes.Equal(c.Raw, st.Challenges[0].DER) {
				t.Fatal("recovery changed committed certificate")
			}
		})
	}
}

func TestSCEPDeleteCAReconcilesUnindexedPEM(t *testing.T) {
	f := newSCEPFixture(t)
	_, st := pendingSCEP(t, f)
	serial := st.Challenges[0].Record.Serial
	index := f.e.store.indexPath()
	if err := os.Rename(index, index+".offline"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(index, 0700); err != nil {
		t.Fatal(err)
	}
	// Recovery writes the PEM, then fails to read/write the metadata index.
	if err := f.e.recover(&st); err == nil {
		t.Fatal("expected index outage")
	}
	if _, err := os.Stat(f.e.store.certPath(serial)); err != nil {
		t.Fatalf("PEM was not written: %v", err)
	}
	if err := f.e.store.DeleteCA(f.ca); err == nil {
		t.Fatal("deletion accepted unavailable index")
	}
	if !f.e.store.HasCA(f.ca) {
		t.Fatal("failed reconciliation removed CA")
	}
	if err := os.Remove(index); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(index+".offline", index); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.e.store.RecordBySerial(serial); ok {
		t.Fatal("test requires unindexed PEM")
	}
	if err := f.e.store.DeleteCA(f.ca); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.e.store.certPath(serial)); !os.IsNotExist(err) {
		t.Errorf("unindexed committed PEM left outside trash: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(f.e.store.dir, "trash", "*", "certs", serial+"-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("committed certificate missing from trash: %v", files)
	}
	f.e = newSCEPService(f.e.store)
	if err := f.e.startup(""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.e.store.RecordBySerial(serial); ok {
		t.Fatal("deleted issuance resurrected on restart")
	}
}

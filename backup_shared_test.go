package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

// Shared challenges, with an issuance, must survive backup and restore, and
// inconsistent shared journals must be refused.
func TestBackupSharedChallengeRoundTrip(t *testing.T) {
	f, secret := newSharedFixture(t, []string{"example.net"})
	_, err := f.e.sharedChallenge("builtin:TLS-Server", []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}, nil, 0, 7)
	backupCheck(t, err)
	stubLookup(t, nil)
	b, status := f.enrollAt(t, f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "switch"}}), "192.0.2.10:1")
	issued := f.response(t, b, status, true)
	serial := serialString(issued.SerialNumber)

	plain, err := snapshotBackup(f.e.store)
	backupCheck(t, err)
	var a backupArchive
	backupCheck(t, json.Unmarshal(plain, &a))
	for _, mutate := range []func(*scepState){
		func(st *scepState) { st.Shared[0].Issuances[0].Source = netip.MustParseAddr("10.9.9.9") },
		func(st *scepState) { st.Shared[0].Suffixes = []string{"EXAMPLE.net"} },
		func(st *scepState) { st.Shared[0].Ranges = nil },
		func(st *scepState) { st.Shared[0].Issuances[0].Identity = "" },
	} {
		var bad backupArchive
		backupCheck(t, json.Unmarshal(plain, &bad))
		for i, file := range bad.Files {
			if file.Path == "scep.json" {
				var st scepState
				backupCheck(t, json.Unmarshal(file.Data, &st))
				mutate(&st)
				bad.Files[i].Data, _ = json.Marshal(st)
			}
		}
		b, err := json.Marshal(bad)
		backupCheck(t, err)
		if _, err = stageBackup(t.TempDir(), b, false); err == nil {
			t.Fatal("inconsistent shared SCEP journal accepted")
		}
	}

	stage, err := stageBackup(t.TempDir(), plain, false)
	backupCheck(t, err)
	defer os.RemoveAll(stage)
	s := &Store{dir: stage}
	st, err := newSCEPService(s).load()
	backupCheck(t, err)
	if len(st.Shared) != 2 || len(st.Shared[0].Issuances) != 1 || st.Shared[0].Issuances[0].Source != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("shared challenges not restored: %+v", st.Shared)
	}
	if _, ok := s.RecordBySerial(serial); !ok {
		t.Fatal("shared issuance missing from restored index")
	}
	if !st.Shared[0].Issuances[0].Published || !bytes.Equal(backupRead(t, s.certPath(serial)), encodeCertPEM(st.Shared[0].Issuances[0].DER)) {
		t.Fatal("shared issuance not published")
	}
}

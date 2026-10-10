package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A device with credentials and a snapshot survives backup and restore. The
// credentials stay encrypted in the archive and decrypt with the same key.
func TestDeviceBackupRoundTripAndKeyMismatch(t *testing.T) {
	s, _ := backupFixture(t)
	key := []byte(testDeviceKeyBytes)
	s.deviceKey = key
	blob, err := s.sealCredentials(deviceCreds{Username: "admin", Password: "device password"})
	backupCheck(t, err)
	d := Device{
		Name: "lab-1", ManagementIP: "192.0.2.10", Port: 57400, Platform: devicePlatformIOSXE,
		Verify: gnoiVerifyUnverified, Credentials: blob,
		Snapshot: &DeviceSnapshot{Taken: time.Now().UTC(), Certs: []DeviceCert{{CertID: "netanchor-x"}}},
	}
	backupCheck(t, s.SaveDevice(&d))

	plain, err := snapshotBackup(s)
	backupCheck(t, err)
	sealed, err := sealBackup(plain, testBackupPassword)
	backupCheck(t, err)
	opened, err := openBackup(sealed, testBackupPassword)
	backupCheck(t, err)

	stage, err := stageBackup(t.TempDir(), opened, false)
	backupCheck(t, err)
	dropped, err := dropUndecryptableCredentials(stage, key)
	backupCheck(t, err)
	if len(dropped) != 0 {
		t.Fatalf("same key dropped credentials of %v", dropped)
	}
	restored, err := (&Store{dir: stage, deviceKey: key}).ListDevices()
	backupCheck(t, err)
	if len(restored) != 1 || restored[0].ID != d.ID || restored[0].Snapshot == nil || restored[0].Snapshot.Certs[0].CertID != "netanchor-x" {
		t.Fatalf("restored devices = %+v", restored)
	}
	c, err := (&Store{dir: stage, deviceKey: key}).openCredentials(restored[0].Credentials)
	backupCheck(t, err)
	if c.Username != "admin" || c.Password != "device password" {
		t.Fatal("restored credentials do not match")
	}

	for name, otherKey := range map[string][]byte{"no key": nil, "other key": []byte("ffffffffffffffffffffffffffffffff")} {
		stage, err := stageBackup(t.TempDir(), opened, false)
		backupCheck(t, err)
		dropped, err := dropUndecryptableCredentials(stage, otherKey)
		backupCheck(t, err)
		if len(dropped) != 1 || dropped[0] != "lab-1" {
			t.Fatalf("%s: dropped = %v", name, dropped)
		}
		kept, err := (&Store{dir: stage}).ListDevices()
		backupCheck(t, err)
		if len(kept) != 1 || kept[0].ID != d.ID || kept[0].Credentials != nil || kept[0].Snapshot == nil {
			t.Fatalf("%s: device not kept without credentials: %+v", name, kept)
		}
	}
}

func TestValidateDevicesRejectsBadRecords(t *testing.T) {
	good := Device{ID: "1", Name: "a", ManagementIP: "192.0.2.1", Port: 57400, Platform: devicePlatformIOSXE, Verify: gnoiVerifyUnverified}
	bad := map[string][]Device{
		"duplicate name": {good, {ID: "2", Name: "a", ManagementIP: "192.0.2.2", Port: 57400, Platform: devicePlatformIOSXE, Verify: gnoiVerifyUnverified}},
		"bad platform":   {{ID: "1", Name: "a", ManagementIP: "192.0.2.1", Port: 57400, Platform: "JUNOS", Verify: gnoiVerifyUnverified}},
		"bad port":       {{ID: "1", Name: "a", ManagementIP: "192.0.2.1", Port: 0, Platform: devicePlatformIOSXE, Verify: gnoiVerifyUnverified}},
	}
	for name, devs := range bad {
		dir := t.TempDir()
		b, err := json.Marshal(devs)
		backupCheck(t, err)
		backupCheck(t, os.WriteFile(filepath.Join(dir, "devices.json"), b, 0o600))
		if validateDevices(dir) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	dir := t.TempDir()
	b, err := json.Marshal([]Device{good})
	backupCheck(t, err)
	backupCheck(t, os.WriteFile(filepath.Join(dir, "devices.json"), b, 0o600))
	backupCheck(t, validateDevices(dir))
}

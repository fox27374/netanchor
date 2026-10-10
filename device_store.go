package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const deviceKeySize = 32

var (
	errDeviceNameTaken      = errors.New("a device with this name already exists")
	errDeviceNotFound       = errors.New("device not found")
	errCredentialsDisabled  = errors.New("credentials are not stored: NETANCHOR_DEVICE_KEY_FILE is not set")
	errCredentialsMalformed = errors.New("stored credentials are malformed")
)

// Device is one network device NetAnchor can push certificates to. Credentials
// are a sealed JSON blob (AES-256-GCM); the password is never stored in clear.
type Device struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	FQDN         string          `json:"fqdn,omitempty"`
	ManagementIP string          `json:"management_ip"`
	Port         int             `json:"port"`
	Platform     string          `json:"platform"`
	Site         string          `json:"site,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	Notes        string          `json:"notes,omitempty"`
	Model        string          `json:"model,omitempty"`
	Serial       string          `json:"serial,omitempty"`
	Verify       string          `json:"verify"`                // gnoiVerifyCA, gnoiVerifyFingerprint or gnoiVerifyUnverified
	CAID         string          `json:"ca_id,omitempty"`       // trusted NetAnchor CA when Verify is ca
	Pin          string          `json:"pin,omitempty"`         // SHA-256 fingerprint of the device server certificate
	PinAddress   string          `json:"pin_address,omitempty"` // host:port the pin was confirmed for
	Credentials  []byte          `json:"credentials,omitempty"` // nonce || AES-256-GCM(JSON deviceCreds)
	Snapshot     *DeviceSnapshot `json:"snapshot,omitempty"`    // last "Refresh certificates" result
	Created      time.Time       `json:"created"`
	Updated      time.Time       `json:"updated"`
}

// DeviceSnapshot is what the device reported on the last refresh.
type DeviceSnapshot struct {
	Taken  time.Time    `json:"taken"`
	Certs  []DeviceCert `json:"certs"`
	Served *DeviceCert  `json:"served,omitempty"` // certificate the gRPC port presents
}

// DeviceCert is one certificate as the device reports it. Fields are empty
// when the device returned something that does not parse as X.509.
type DeviceCert struct {
	CertID      string    `json:"cert_id,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

type deviceCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Store) devicesPath() string { return filepath.Join(s.dir, "devices.json") }

// LoadDeviceKey reads the credential key from path. An empty path leaves
// credential storage off. The file must hold exactly 32 random bytes.
func (s *Store) LoadDeviceKey(path string) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading device key file: %w", err)
	}
	if len(b) != deviceKeySize {
		return fmt.Errorf("device key file must contain exactly %d random bytes (for example: head -c 32 /dev/urandom > key)", deviceKeySize)
	}
	s.deviceKey = b
	return nil
}

// CredentialsAvailable reports whether a device key is loaded.
func (s *Store) CredentialsAvailable() bool { return s.deviceKey != nil }

func (s *Store) deviceGCM() (cipher.AEAD, error) {
	if s.deviceKey == nil {
		return nil, errCredentialsDisabled
	}
	block, err := aes.NewCipher(s.deviceKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) sealCredentials(c deviceCreds) ([]byte, error) {
	gcm, err := s.deviceGCM()
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func (s *Store) openCredentials(blob []byte) (deviceCreds, error) {
	var c deviceCreds
	gcm, err := s.deviceGCM()
	if err != nil {
		return c, err
	}
	if len(blob) < gcm.NonceSize() {
		return c, errCredentialsMalformed
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	if err != nil {
		return c, errors.New("stored credentials cannot be decrypted with the current device key")
	}
	if err := json.Unmarshal(plain, &c); err != nil {
		return c, errCredentialsMalformed
	}
	return c, nil
}

func (s *Store) loadDevices() ([]Device, error) {
	b, err := os.ReadFile(s.devicesPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var devs []Device
	err = json.Unmarshal(b, &devs)
	return devs, err
}

func (s *Store) saveDevices(devs []Device) error {
	b, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		return err
	}
	return durableWrite(s.devicesPath(), b)
}

// ListDevices returns all devices sorted by name.
func (s *Store) ListDevices() ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	devs, err := s.loadDevices()
	sort.Slice(devs, func(i, j int) bool { return strings.ToLower(devs[i].Name) < strings.ToLower(devs[j].Name) })
	return devs, err
}

// GetDevice returns the device with the given id.
func (s *Store) GetDevice(id string) (Device, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	devs, err := s.loadDevices()
	if err != nil {
		return Device{}, false, err
	}
	for _, d := range devs {
		if d.ID == id {
			return d, true, nil
		}
	}
	return Device{}, false, nil
}

// SaveDevice creates the device when d.ID is empty, otherwise replaces the
// device with that id. Names must stay unique.
func (s *Store) SaveDevice(d *Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	devs, err := s.loadDevices()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	d.Updated = now
	for _, o := range devs {
		if o.Name == d.Name && o.ID != d.ID {
			return errDeviceNameTaken
		}
	}
	if d.ID == "" {
		id, err := newDeviceID()
		if err != nil {
			return err
		}
		d.ID, d.Created = id, now
		devs = append(devs, *d)
	} else {
		i := -1
		for j := range devs {
			if devs[j].ID == d.ID {
				i = j
			}
		}
		if i < 0 {
			return errDeviceNotFound
		}
		d.Created = devs[i].Created
		devs[i] = *d
	}
	return s.saveDevices(devs)
}

// UpdateDevice applies fn to the stored device under the store lock. Unlike
// SaveDevice it keeps Updated: it is for device-reported data, not admin edits.
func (s *Store) UpdateDevice(id string, fn func(d *Device)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	devs, err := s.loadDevices()
	if err != nil {
		return err
	}
	for i := range devs {
		if devs[i].ID == id {
			fn(&devs[i])
			return s.saveDevices(devs)
		}
	}
	return errDeviceNotFound
}

// DeleteDevice removes the device and its stored credentials.
func (s *Store) DeleteDevice(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	devs, err := s.loadDevices()
	if err != nil {
		return err
	}
	out := devs[:0]
	found := false
	for _, d := range devs {
		if d.ID == id {
			found = true
			continue
		}
		out = append(out, d)
	}
	if !found {
		return errDeviceNotFound
	}
	return s.saveDevices(out)
}

// dropUndecryptableCredentials runs on a staged restore before activation. Devices
// are kept; credentials the live key (nil when unset) cannot open are cleared.
// It returns the names of the devices that lost their credentials.
func dropUndecryptableCredentials(dir string, key []byte) ([]string, error) {
	s := &Store{dir: dir, deviceKey: key}
	devs, err := s.loadDevices()
	if err != nil {
		return nil, err
	}
	var dropped []string
	for i := range devs {
		if devs[i].Credentials == nil {
			continue
		}
		if _, err := s.openCredentials(devs[i].Credentials); err != nil {
			dropped = append(dropped, devs[i].Name)
			devs[i].Credentials = nil
		}
	}
	if len(dropped) == 0 {
		return nil, nil
	}
	return dropped, s.saveDevices(devs)
}

func newDeviceID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

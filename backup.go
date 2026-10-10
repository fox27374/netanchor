package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Format 1 fixes the KDF cost, cipher and size limits; no attacker-controlled
// KDF parameters or compression are accepted. The complete header is AAD.
const backupMagic = "NETANCHOR-BACKUP-1\n"
const backupLimit = 64 << 20
const backupFileLimit = 16 << 20

var backupRoots = []string{"cas", "certs", "auth", "tls", "trash", "index.json", "templates.json", "scep.json", "devices.json"}

type backupFile struct {
	Path string
	Data []byte
}
type backupArchive struct {
	Format      int
	Application string
	Created     time.Time
	Files       []backupFile
}

func backupPassword(p string) error {
	if len(p) < 12 || len(p) > 1024 || strings.TrimSpace(p) == "" {
		return errors.New("use a backup password of 12–1024 bytes (a long, unique passphrase is recommended)")
	}
	return nil
}

func sealBackup(plain []byte, password string) ([]byte, error) {
	if err := backupPassword(password); err != nil {
		return nil, err
	}
	if len(plain) > backupLimit {
		return nil, errors.New("backup exceeds 64 MiB archive limit")
	}
	header := append([]byte(backupMagic), make([]byte, 28)...)
	if _, err := rand.Read(header[len(backupMagic):]); err != nil {
		return nil, err
	}
	g, err := gcmFromPassphrase(password, header[len(backupMagic):len(backupMagic)+16], pbkdf2Iter)
	if err != nil {
		return nil, err
	}
	return g.Seal(header, header[len(backupMagic)+16:], plain, header), nil
}

func openBackup(data []byte, password string) ([]byte, error) {
	if err := backupPassword(password); err != nil {
		return nil, err
	}
	n := len(backupMagic) + 28
	if len(data) < n+16 || len(data) > backupLimit+n+16 || !bytes.HasPrefix(data, []byte(backupMagic)) {
		return nil, errors.New("unsupported or oversized backup")
	}
	g, err := gcmFromPassphrase(password, data[len(backupMagic):len(backupMagic)+16], pbkdf2Iter)
	if err != nil {
		return nil, err
	}
	b, err := g.Open(nil, data[len(backupMagic)+16:n], data[n:], data[:n])
	if err != nil {
		return nil, errors.New("incorrect password or damaged backup")
	}
	return b, nil
}

func backupPath(p string) bool {
	if p == "" || len(p) > 256 || strings.Contains(p, "\\") || strings.HasPrefix(p, "/") || filepath.ToSlash(filepath.Clean(p)) != p {
		return false
	}
	v := strings.Split(p, "/")
	if v[0] == "trash" {
		if len(v) < 3 {
			return false
		}
		if _, err := time.Parse("20060102T150405.000000000", v[1]); err != nil {
			return false
		}
		v = v[2:]
		if v[0] != "cas" && v[0] != "certs" && strings.Join(v, "/") != "index.json" {
			return false
		}
	}
	switch v[0] {
	case "index.json", "templates.json", "scep.json", "devices.json":
		return len(v) == 1
	case "auth":
		return len(v) == 2 && (v[1] == "users.json" || v[1] == "session.key")
	case "tls":
		return len(v) == 2 && (v[1] == "server-cert.pem" || v[1] == "server-key.pem")
	case "cas":
		return len(v) == 3 && (v[1] == caRoot || v[1] == caIntermediate || ValidSerial(v[1])) && (v[2] == "cert.pem" || v[2] == "key.pem")
	case "certs":
		if len(v) != 2 {
			return false
		}
		for _, suffix := range []string{"-cert.pem", "-key.pem"} {
			if strings.HasSuffix(v[1], suffix) && ValidSerial(strings.TrimSuffix(v[1], suffix)) {
				return true
			}
		}
	}
	return false
}

// Caller holds the operation barrier. Reconcile committed SCEP projections before
// collecting files, without needing to unlock any CA key.
func snapshotBackup(s *Store) ([]byte, error) {
	s.scepMu.Lock()
	err := s.reconcileSCEP()
	s.scepMu.Unlock()
	if err != nil {
		return nil, err
	}
	// Normalize the application's known legacy profile representation before
	// emitting format 1. Future schemas are never inferred during restore.
	if _, err := s.LoadTemplates(); err != nil {
		return nil, err
	}
	a := backupArchive{Format: 1, Application: version, Created: time.Now().UTC()}
	total := 0
	for _, root := range backupRoots {
		err = filepath.WalkDir(filepath.Join(s.dir, root), func(path string, d fs.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) && path == filepath.Join(s.dir, root) {
				return nil
			}
			if err != nil {
				return err
			}
			if strings.HasPrefix(d.Name(), ".netanchor-") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return errors.New("nonregular data file")
			}
			rel, err := filepath.Rel(s.dir, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if !backupPath(rel) {
				return fmt.Errorf("unexpected data file %s", rel)
			}
			if info.Size() > backupFileLimit || info.Size() > int64(48<<20-total) || len(a.Files) >= 10000 {
				return errors.New("backup file/count/size limit exceeded")
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			total += len(b)
			a.Files = append(a.Files, backupFile{rel, b})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(a)
}

// Reject unknown fields, duplicate JSON object keys, trailing values and deeply
// nested objects before decoding into the schema.
func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			seen := map[string]bool{}
			for d.More() {
				if delim == '{' {
					k, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := k.(string)
					key = strings.ToLower(key)
					if !ok || seen[key] {
						return errors.New("duplicate JSON field")
					}
					seen[key] = true
				}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

func stageBackup(dir string, plain []byte, regenerate bool) (string, error) {
	var a backupArchive
	if len(plain) > backupLimit {
		return "", errors.New("archive too large")
	}
	if err := strictJSON(plain, &a); err != nil {
		return "", err
	}
	if a.Format != 1 || a.Application == "" || len(a.Application) > 128 || a.Created.IsZero() || len(a.Files) > 10000 {
		return "", errors.New("unsupported backup manifest")
	}
	stage, err := os.MkdirTemp(dir, ".backup-stage-")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(stage)
		}
	}()
	seen := map[string]bool{}
	total := 0
	for _, f := range a.Files {
		total += len(f.Data)
		if !backupPath(f.Path) || seen[f.Path] || len(f.Data) > backupFileLimit || total > 48<<20 {
			return "", errors.New("invalid archive path, duplicate or size")
		}
		seen[f.Path] = true
		p := filepath.Join(stage, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return "", err
		}
		if err := durableWrite(p, f.Data); err != nil {
			return "", err
		}
	}
	if err := validateBackup(stage); err != nil {
		return "", err
	}
	s, err := OpenStore(stage)
	if err != nil {
		return "", err
	}
	e := newSCEPService(s)
	st, err := e.load()
	if err != nil {
		return "", err
	}
	if err = e.recover(&st); err != nil {
		return "", err
	}
	for i := range st.Challenges {
		if st.Challenges[i].Used.IsZero() {
			st.Challenges[i].Revoked = true
		}
	}
	if seen["scep.json"] {
		if err = e.save(st); err != nil {
			return "", err
		}
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return "", err
	}
	if err = durableWrite(s.sessionKeyPath(), key); err != nil {
		return "", err
	}
	if regenerate {
		if err = os.RemoveAll(filepath.Join(stage, "tls")); err != nil {
			return "", err
		}
		if err = os.Mkdir(filepath.Join(stage, "tls"), 0700); err != nil {
			return "", err
		}
		if _, _, _, err = ensureServerCert(s, splitComma(envOr("NETANCHOR_TLS_HOSTS", "localhost,127.0.0.1")), envOr("NETANCHOR_CA_PASSPHRASE", "")); err != nil {
			return "", err
		}
	}
	if err = syncTree(stage); err != nil {
		return "", err
	}
	ok = true
	return stage, nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func syncTree(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return syncDir(p)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	})
}

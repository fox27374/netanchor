package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// appLogMax is the size at which netanchor.log moves to netanchor.log.1.
const appLogMax = 5 << 20

// appLogTail is how many lines the Logs page and /logs.txt show.
const appLogTail = 2000

// appLog writes NetAnchor's log to <data>/logs/netanchor.log. Once the file would
// pass appLogMax it is renamed to netanchor.log.1, which is overwritten each time.
// ponytail: one global mutex; fine for a log line rate, not for high-volume writers.
type appLog struct {
	mu   sync.Mutex
	dir  string
	f    *os.File
	size int64
}

func appLogDir(dataDir string) string { return filepath.Join(dataDir, "logs") }

func openAppLog(dataDir string) (*appLog, error) {
	dir := appLogDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	a := &appLog{dir: dir}
	if err := a.open(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *appLog) path() string { return filepath.Join(a.dir, "netanchor.log") }

func (a *appLog) open() error {
	f, err := os.OpenFile(a.path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	a.f, a.size = f, info.Size()
	return nil
}

func (a *appLog) rotate() error {
	a.f.Close()
	err := os.Rename(a.path(), a.path()+".1")
	if oerr := a.open(); oerr != nil {
		return oerr
	}
	return err
}

func (a *appLog) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.size > 0 && a.size+int64(len(p)) > appLogMax {
		if err := a.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := a.f.Write(p)
	a.size += int64(n)
	return n, err
}

// appLogLines returns the last n lines: the tail of netanchor.log.1 first when
// netanchor.log is short, then netanchor.log. Missing files count as empty.
// ponytail: reads both files whole (at most ~10 MiB); seek from the end if that gets slow.
func appLogLines(dir string, n int) ([]string, error) {
	cur, err := readLogLines(filepath.Join(dir, "netanchor.log"))
	if err != nil {
		return nil, err
	}
	if len(cur) >= n {
		return cur[len(cur)-n:], nil
	}
	prev, err := readLogLines(filepath.Join(dir, "netanchor.log.1"))
	if err != nil {
		return nil, err
	}
	if need := n - len(cur); len(prev) > need {
		prev = prev[len(prev)-need:]
	}
	return append(prev, cur...), nil
}

func readLogLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil, nil
	}
	return strings.Split(s, "\n"), nil
}

// handleLogs shows the recent log on an admin page.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	lines, err := appLogLines(appLogDir(s.store.dir), appLogTail)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := s.base(r, "Logs", "logs")
	d.Data = strings.Join(lines, "\n")
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "logs", d)
}

// handleLogsText serves the same lines as plain text.
func (s *Server) handleLogsText(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	lines, err := appLogLines(appLogDir(s.store.dir), appLogTail)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if len(lines) > 0 {
		w.Write([]byte(strings.Join(lines, "\n") + "\n"))
	}
}

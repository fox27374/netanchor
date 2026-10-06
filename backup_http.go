package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type operationKey struct{}
type operationLease struct {
	store *Store
	held  bool
}

const (
	operationReadTimeout   = 30 * time.Second
	operationWriteTimeout  = 2 * time.Minute
	restoreReadTimeout     = 2 * time.Minute
	maintenanceWaitTimeout = 5 * time.Second
)

// Immutable after listeners start. Zero fields select production defaults;
// per-store overrides let real-network deadline tests use short intervals.
type operationLimits struct{ read, write, exclusiveWait time.Duration }

func (lease *operationLease) release() {
	if lease.held {
		lease.held = false
		lease.store.operationsMu.RUnlock()
	}
}

// The barrier surrounds authentication AND the whole handler, not individual
// file writes. The context lease prevents recursive RLock on GUI SCEP routes.
func (s *Store) operations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lease, ok := r.Context().Value(operationKey{}).(*operationLease); ok && lease.store == s {
			next.ServeHTTP(w, r)
			return
		}
		readLimit, writeLimit := s.operationLimits.read, s.operationLimits.write
		if readLimit == 0 {
			readLimit = operationReadTimeout
			if r.Method == http.MethodPost && r.URL.Path == "/admin/restore" {
				readLimit = restoreReadTimeout
			}
		}
		if writeLimit == 0 {
			writeLimit = operationWriteTimeout
		}
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(readLimit))
		_ = controller.SetWriteDeadline(time.Now().Add(readLimit + writeLimit))
		s.operationsMu.RLock()
		lease := &operationLease{store: s, held: true}
		defer lease.release()
		if s.stopped {
			http.Error(w, "Instance restored or recovery required. Restart NetAnchor, then sign in again.", 503)
			return
		}
		ctx := context.WithValue(r.Context(), operationKey{}, lease)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) backupExclusive(r *http.Request, fn func() error) error {
	lease, ok := r.Context().Value(operationKey{}).(*operationLease)
	if !ok || lease.store != s.store || !lease.held {
		return errors.New("operation barrier missing")
	}
	// Maintenance consumes its read lease. After this call handlers use only
	// copied snapshot/result data, never live storage. In particular cancellation
	// must not reacquire a read lock or leave a goroutine queued for exclusivity.
	lease.release()
	limit := s.store.operationLimits.exclusiveWait
	if limit == 0 {
		limit = maintenanceWaitTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), limit)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Unlike Lock, TryLock does not block new readers while waiting for a
		// slow body/response to finish. Busy instances fail after the wait budget.
		if s.store.operationsMu.TryLock() {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	defer s.store.operationsMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.store.stopped {
		return errors.New("restart required")
	}
	// Another request could delete/demote this account while we waited.
	if s.auth.enabled {
		u, ok := s.auth.currentUser(r)
		if !ok || u.Role != RoleAdmin {
			return errors.New("administrator required")
		}
	}
	return fn()
}

func (s *Server) backupToken(r *http.Request) string {
	identity := "trusted-local"
	if c, err := r.Cookie(sessionCookie); err == nil && s.auth.enabled {
		identity = c.Value
	}
	return s.auth.sign("backup-csrf-v1|" + identity)
}

func (s *Server) backupCSRF(r *http.Request) bool {
	// Match browser authority rather than upstream scheme, supporting HTTPS
	// termination without trusting arbitrary X-Forwarded-* headers. Proxies must
	// preserve Host. Missing/null Origin is rejected for these browser actions.
	u, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host != r.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.backupToken(r))) == 1
}

func (s *Server) handleBackupPage(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	d := s.base(r, "Backup & Restore", "backup")
	d.Data = s.backupToken(r)
	s.render(w, "backup", d)
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.backupMu.TryLock() {
		http.Error(w, "Another backup or restore is running.", 409)
		return
	}
	defer s.backupMu.Unlock()
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", 403)
		return
	}
	p := r.PostForm.Get("password")
	if err := backupPassword(p); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if p != r.PostForm.Get("password_confirm") {
		http.Error(w, "passwords do not match", 400)
		return
	}
	var plain []byte
	err := s.backupExclusive(r, func() error { var err error; plain, err = snapshotBackup(s.store); return err })
	if err != nil {
		http.Error(w, "Snapshot failed: "+err.Error(), maintenanceStatus(err))
		return
	}
	defer clear(plain)
	b, err := sealBackup(plain, p)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	serveBytes(w, "application/octet-stream", "netanchor-"+time.Now().UTC().Format("20060102T150405Z")+".nab", b)
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.backupMu.TryLock() {
		http.Error(w, "Another backup or restore is running.", 409)
		return
	}
	defer s.backupMu.Unlock()
	r.Body = http.MaxBytesReader(w, r.Body, backupLimit+1<<20)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		if r.MultipartForm != nil {
			r.MultipartForm.RemoveAll()
		}
		http.Error(w, "Invalid upload (maximum 64 MiB archive).", 400)
		return
	}
	defer r.MultipartForm.RemoveAll()
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", 403)
		return
	}
	if r.FormValue("confirm") != "REPLACE" {
		http.Error(w, "Type REPLACE to confirm full replacement.", 400)
		return
	}
	f, _, err := r.FormFile("archive")
	if err != nil {
		http.Error(w, "backup file required", 400)
		return
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, backupLimit+128))
	if err != nil {
		http.Error(w, "reading backup failed", 400)
		return
	}
	plain, err := openBackup(b, r.FormValue("password"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer clear(plain)
	stage, err := stageBackup(s.store.dir, plain, r.FormValue("regenerate") == "on")
	if err != nil {
		http.Error(w, "Backup validation/staging failed: "+err.Error(), 400)
		return
	}
	defer os.RemoveAll(stage)
	stopped := false
	err = s.backupExclusive(r, func() error {
		err := activateBackup(s.store.dir, stage, durableRename)
		if err == nil {
			s.store.stopped = true
		} else {
			// Any unresolved transaction is fail-closed, including uncertain fsync.
			present, e := exists(filepath.Join(s.store.dir, ".restore"))
			if present || e != nil {
				s.store.stopped = true
			}
		}
		stopped = s.store.stopped
		return err
	})
	if stopped {
		defer s.restartOnce.Do(func() { close(s.restart) })
	}
	if err != nil {
		message := "Restore failed: " + err.Error()
		if stopped {
			message += ". Serving is blocked; repair storage and restart NetAnchor to recover."
		}
		http.Error(w, message, maintenanceStatus(err))
		return
	}
	s.auth.clearSession(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Restore complete</title><h1>Restore complete — restart required</h1><p>All instance data was replaced. Browser sessions and unused SCEP challenges were invalidated.</p><p>NetAnchor is shutting down now. A container with restart: unless-stopped restarts automatically. If running a standalone binary, start it again manually.</p><p>After restart, <a href="/login">sign in with an account from the backup</a>. Your temporary account has been replaced. The HTTPS identity may have changed; verify it before accepting any browser warning. SCEP needs unlock unless a matching startup secret is configured.</p></html>`)
}

func maintenanceStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusServiceUnavailable
	}
	if errors.Is(err, context.Canceled) {
		return http.StatusRequestTimeout
	}
	return http.StatusInternalServerError
}

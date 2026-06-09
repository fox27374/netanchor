package main

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Role is a coarse permission level.
type Role string

const (
	RoleAdmin  Role = "admin"  // full control: CAs, issuing, signing, keys, users
	RoleViewer Role = "viewer" // read-only: view + download public certificates
)

// User is an account that can log in.
type User struct {
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"password_hash"` // pbkdf2$iter$salt$hash (base64)
	CreatedAt    time.Time `json:"created_at"`
}

const (
	pwIter        = 600_000
	sessionTTL    = 12 * time.Hour
	sessionCookie = "netanchor_session"
)

// Auth holds authentication state and policy.
type Auth struct {
	store      *Store
	enabled    bool
	secure     bool // mark cookies Secure (set when serving over HTTPS)
	sessionKey []byte
	mu         sync.Mutex // guards users.json read/modify/write
}

// NewAuth loads (or creates) the cookie-signing key.
func NewAuth(store *Store, secure, enabled bool) (*Auth, error) {
	a := &Auth{store: store, enabled: enabled, secure: secure}
	key, err := loadOrCreateKey(store.sessionKeyPath())
	if err != nil {
		return nil, err
	}
	a.sessionKey = key
	return a, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) >= 32 {
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// --- password hashing -----------------------------------------------------

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pwIter, 32)
	if err != nil {
		return "", err
	}
	return "pbkdf2$" + strconv.Itoa(pwIter) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(dk), nil
}

func verifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- user store -----------------------------------------------------------

func (a *Auth) loadUsers() ([]User, error) {
	data, err := os.ReadFile(a.store.usersPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (a *Auth) saveUsers(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.store.usersPath(), data, 0o600)
}

// HasUsers reports whether any account exists (drives first-run setup).
func (a *Auth) HasUsers() bool {
	users, err := a.loadUsers()
	return err == nil && len(users) > 0
}

func (a *Auth) findUser(username string) (User, bool) {
	users, err := a.loadUsers()
	if err != nil {
		return User{}, false
	}
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			return u, true
		}
	}
	return User{}, false
}

// AddUser creates a new account.
func (a *Auth) AddUser(username, password string, role Role) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return errors.New("username and password are required")
	}
	if role != RoleAdmin && role != RoleViewer {
		return errors.New("invalid role")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	users, err := a.loadUsers()
	if err != nil {
		return err
	}
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			return errors.New("a user with that name already exists")
		}
	}
	users = append(users, User{
		Username:     username,
		Role:         role,
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	})
	return a.saveUsers(users)
}

// DeleteUser removes an account, refusing to remove the last admin.
func (a *Auth) DeleteUser(username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	users, err := a.loadUsers()
	if err != nil {
		return err
	}
	admins := 0
	for _, u := range users {
		if u.Role == RoleAdmin {
			admins++
		}
	}
	kept := make([]User, 0, len(users))
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			if u.Role == RoleAdmin && admins <= 1 {
				return errors.New("cannot delete the last administrator")
			}
			continue
		}
		kept = append(kept, u)
	}
	if len(kept) == len(users) {
		return errors.New("user not found")
	}
	return a.saveUsers(kept)
}

// --- sessions (signed cookies) -------------------------------------------

// issueSession sets a signed session cookie for the user. The cookie carries
// only the username and an expiry; the role is always looked up fresh from the
// store so changes/deletions take effect immediately.
func (a *Auth) issueSession(w http.ResponseWriter, username string) {
	exp := time.Now().Add(sessionTTL).Unix()
	payload := username + "|" + strconv.FormatInt(exp, 10)
	value := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + a.sign(payload)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(exp, 0),
	})
}

func (a *Auth) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (a *Auth) sign(payload string) string {
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// currentUser validates the session cookie and returns the live user record.
func (a *Auth) currentUser(r *http.Request) (User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return User{}, false
	}
	enc, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return User{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return User{}, false
	}
	payload := string(raw)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(a.sign(payload))) != 1 {
		return User{}, false
	}
	username, expStr, ok := strings.Cut(payload, "|")
	if !ok {
		return User{}, false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return User{}, false
	}
	return a.findUser(username)
}

// --- request context ------------------------------------------------------

type ctxKey int

const userCtxKey ctxKey = 0

func userFromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userCtxKey).(User)
	return u, ok
}

// --- middleware -----------------------------------------------------------

// Middleware enforces authentication and role-based access.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		// First-run: force creation of the initial admin.
		if !a.HasUsers() {
			if r.URL.Path == "/setup" {
				next.ServeHTTP(w, r)
				return
			}
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}

		if r.URL.Path == "/login" || r.URL.Path == "/setup" {
			next.ServeHTTP(w, r)
			return
		}

		user, ok := a.currentUser(r)
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				http.Error(w, "authentication required", http.StatusUnauthorized)
			}
			return
		}

		if requiresAdmin(r.Method, r.URL.Path) && user.Role != RoleAdmin {
			http.Error(w, "forbidden: administrator role required", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requiresAdmin reports whether a request needs the admin role. Everything that
// changes state, plus private-key downloads, is admin-only; read views are open
// to any authenticated user.
func requiresAdmin(method, path string) bool {
	// Managing certificate templates is admin-only.
	if strings.HasPrefix(path, "/templates") {
		return true
	}
	// Private key downloads: /download/<serial>/key (but not /download/ca/...).
	if method == http.MethodGet &&
		strings.HasPrefix(path, "/download/") &&
		strings.HasSuffix(path, "/key") &&
		!strings.HasPrefix(path, "/download/ca/") {
		return true
	}
	// PKCS#12 export bundles the private key.
	if strings.HasPrefix(path, "/download/") && strings.HasSuffix(path, "/p12") {
		return true
	}
	switch path {
	case "/issue", "/sign", "/users":
		return true // both the form (GET) and the action (POST)
	case "/ca/root", "/ca/intermediate", "/users/delete", "/users/add":
		return true
	}
	return false
}

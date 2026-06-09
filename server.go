package main

import (
	"crypto/x509"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

//go:embed templates/*.html
var templateFS embed.FS

// Server wires the store and auth to the HTTP handlers and parsed templates.
type Server struct {
	store     *Store
	auth      *Auth
	templates map[string]*template.Template
}

func NewServer(store *Store, auth *Auth) *Server {
	pages := []string{"dashboard", "ca", "issue", "sign", "details", "message", "login", "setup", "users", "templates", "template_edit"}
	tpls := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		tpls[p] = template.Must(template.New(p).ParseFS(
			templateFS, "templates/layout.html", "templates/"+p+".html"))
	}
	return &Server{store: store, auth: auth, templates: tpls}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /ca", s.handleCA)
	mux.HandleFunc("POST /ca/root", s.handleCreateRoot)
	mux.HandleFunc("POST /ca/intermediate", s.handleCreateIntermediate)
	mux.HandleFunc("GET /ca/view/{id}", s.handleCADetails)
	mux.HandleFunc("GET /issue", s.handleIssueForm)
	mux.HandleFunc("POST /issue", s.handleIssue)
	mux.HandleFunc("GET /sign", s.handleSignForm)
	mux.HandleFunc("POST /sign", s.handleSign)
	mux.HandleFunc("GET /cert/{serial}", s.handleCertDetails)
	mux.HandleFunc("GET /download/ca/{id}/{what}", s.handleDownloadCA)
	mux.HandleFunc("GET /download/{serial}/{what}", s.handleDownload)
	mux.HandleFunc("POST /download/{serial}/p12", s.handleExportP12)

	// Certificate templates (issuance presets).
	mux.HandleFunc("GET /templates", s.handleTemplates)
	mux.HandleFunc("POST /templates/add", s.handleTemplateAdd)
	mux.HandleFunc("GET /templates/edit/{name}", s.handleTemplateEditForm)
	mux.HandleFunc("POST /templates/edit/{name}", s.handleTemplateEdit)
	mux.HandleFunc("POST /templates/delete", s.handleTemplateDelete)

	// Auth & account management.
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /setup", s.handleSetupForm)
	mux.HandleFunc("POST /setup", s.handleSetup)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /users", s.handleUsers)
	mux.HandleFunc("POST /users/add", s.handleUserAdd)
	mux.HandleFunc("POST /users/delete", s.handleUserDelete)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	return logRequests(mux)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) render(w http.ResponseWriter, page string, data any) {
	tpl, ok := s.templates[page]
	if !ok {
		http.Error(w, "unknown page: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

// pageData is the common envelope passed to every template.
type pageData struct {
	Title           string
	HasCA           bool
	HasIntermediate bool
	Active          string
	Error           string
	Message         string
	Data            any

	// Identity / access.
	AuthEnabled   bool
	Authenticated bool
	Username      string
	Role          string
	IsAdmin       bool

	Version string
}

func (s *Server) base(r *http.Request, title, active string) pageData {
	d := pageData{
		Title:           title,
		Active:          active,
		HasCA:           s.store.HasCA(caRoot),
		HasIntermediate: s.store.HasCA(caIntermediate),
		AuthEnabled:     s.auth.enabled,
		Version:         version,
	}
	if !s.auth.enabled {
		d.Authenticated = true
		d.IsAdmin = true
		return d
	}
	if u, ok := userFromContext(r.Context()); ok {
		d.Authenticated = true
		d.Username = u.Username
		d.Role = string(u.Role)
		d.IsAdmin = u.Role == RoleAdmin
	}
	return d
}

// isAdmin reports whether the current request is from an admin (or auth is off).
func (s *Server) isAdmin(r *http.Request) bool {
	if !s.auth.enabled {
		return true
	}
	u, ok := userFromContext(r.Context())
	return ok && u.Role == RoleAdmin
}

// --- dashboard -----------------------------------------------------------

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	recs, err := s.store.Records()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := s.base(r, "Dashboard", "dashboard")
	d.Data = recs
	s.render(w, "dashboard", d)
}

// --- CA management -------------------------------------------------------

type caViewData struct {
	Root                  *CertRecord
	RootEncrypted         bool
	Intermediate          *CertRecord
	IntermediateEncrypted bool
}

func (s *Server) caData() caViewData {
	recs, _ := s.store.Records()
	var data caViewData
	for i := range recs {
		rec := recs[i]
		switch rec.Kind {
		case caRoot:
			data.Root = &rec
		case caIntermediate:
			data.Intermediate = &rec
		}
	}
	data.RootEncrypted = s.store.CAKeyEncrypted(caRoot)
	data.IntermediateEncrypted = s.store.CAKeyEncrypted(caIntermediate)
	return data
}

func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, "Certificate Authority", "ca")
	d.Data = s.caData()
	s.render(w, "ca", d)
}

func (s *Server) handleCreateRoot(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	pass := r.FormValue("passphrase")
	if pass != r.FormValue("passphrase_confirm") {
		s.caError(w, r, "Passphrases do not match.")
		return
	}
	p := CAParams{
		CommonName:   strings.TrimSpace(r.FormValue("common_name")),
		Organization: strings.TrimSpace(r.FormValue("organization")),
		Country:      strings.TrimSpace(r.FormValue("country")),
		Algo:         keyAlgo(r.FormValue("algo")),
		ValidDays:    atoiDefault(r.FormValue("valid_days"), 3650),
		Passphrase:   pass,
	}
	if _, err := CreateCA(s.store, p); err != nil {
		s.caError(w, r, err.Error())
		return
	}
	s.message(w, r, "Root CA created", "Your root CA is ready. You can now issue certificates, sign CSRs, and optionally create an intermediate CA.")
}

func (s *Server) handleCreateIntermediate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	pass := r.FormValue("passphrase")
	if pass != r.FormValue("passphrase_confirm") {
		s.caError(w, r, "Passphrases do not match.")
		return
	}
	p := IntermediateParams{
		CommonName:     strings.TrimSpace(r.FormValue("common_name")),
		Organization:   strings.TrimSpace(r.FormValue("organization")),
		Country:        strings.TrimSpace(r.FormValue("country")),
		Algo:           keyAlgo(r.FormValue("algo")),
		ValidDays:      atoiDefault(r.FormValue("valid_days"), 1825),
		RootPassphrase: r.FormValue("root_passphrase"),
		Passphrase:     pass,
	}
	if _, err := CreateIntermediate(s.store, p); err != nil {
		s.caError(w, r, err.Error())
		return
	}
	s.message(w, r, "Intermediate CA created", "Your intermediate CA is ready. You can now choose it as the issuer when creating certificates or signing CSRs.")
}

func (s *Server) caError(w http.ResponseWriter, r *http.Request, msg string) {
	d := s.base(r, "Certificate Authority", "ca")
	d.Error = msg
	d.Data = s.caData()
	s.render(w, "ca", d)
}

// --- issue ---------------------------------------------------------------

func (s *Server) handleIssueForm(w http.ResponseWriter, r *http.Request) {
	if !s.store.HasCA(caRoot) {
		s.needCA(w, r)
		return
	}
	s.render(w, "issue", s.formBase(r, "Issue Certificate", "issue"))
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	if !s.store.HasCA(caRoot) {
		s.needCA(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	p := IssueParams{
		CommonName:   strings.TrimSpace(r.FormValue("common_name")),
		Organization: strings.TrimSpace(r.FormValue("organization")),
		SANs:         splitLines(r.FormValue("sans")),
		Algo:         keyAlgo(r.FormValue("algo")),
		ValidDays:    atoiDefault(r.FormValue("valid_days"), 365),
		Profile:      certProfile(r.FormValue("profile")),
		IssuerID:     r.FormValue("issuer"),
		CAPassphrase: r.FormValue("ca_passphrase"),
	}
	rec, err := IssueCert(s.store, p)
	if err != nil {
		d := s.formBase(r, "Issue Certificate", "issue")
		d.Error = err.Error()
		s.render(w, "issue", d)
		return
	}
	s.message(w, r, "Certificate issued",
		fmt.Sprintf("Issued certificate for %q (serial %s). View or download it from the dashboard.",
			rec.CommonName, rec.Serial))
}

// --- sign ----------------------------------------------------------------

func (s *Server) handleSignForm(w http.ResponseWriter, r *http.Request) {
	if !s.store.HasCA(caRoot) {
		s.needCA(w, r)
		return
	}
	s.render(w, "sign", s.formBase(r, "Sign CSR", "sign"))
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if !s.store.HasCA(caRoot) {
		s.needCA(w, r)
		return
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		if err := r.ParseForm(); err != nil {
			s.fail(w, r, err)
			return
		}
	}

	csrPEM := []byte(strings.TrimSpace(r.FormValue("csr")))
	if len(csrPEM) == 0 {
		if file, _, err := r.FormFile("csr_file"); err == nil {
			defer file.Close()
			buf := make([]byte, 1<<20)
			n, _ := file.Read(buf)
			csrPEM = buf[:n]
		}
	}
	if len(csrPEM) == 0 {
		d := s.formBase(r, "Sign CSR", "sign")
		d.Error = "Please paste a CSR or upload a .csr/.pem file."
		s.render(w, "sign", d)
		return
	}

	p := SignCSRParams{
		CSRPEM:       csrPEM,
		ValidDays:    atoiDefault(r.FormValue("valid_days"), 365),
		Profile:      certProfile(r.FormValue("profile")),
		IssuerID:     r.FormValue("issuer"),
		CAPassphrase: r.FormValue("ca_passphrase"),
	}
	rec, err := SignCSR(s.store, p)
	if err != nil {
		d := s.formBase(r, "Sign CSR", "sign")
		d.Error = err.Error()
		s.render(w, "sign", d)
		return
	}
	s.message(w, r, "CSR signed",
		fmt.Sprintf("Signed certificate for %q (serial %s). View or download it from the dashboard.",
			rec.CommonName, rec.Serial))
}

// --- details -------------------------------------------------------------

type detailsPage struct {
	Info     CertInfo
	KindTag  string
	IsCAView bool
	CAID     string
	Serial   string
	HasKey   bool
	CanChain bool
	CertPEM  string // inline, copy-paste
	KeyPEM   string // inline, admin only
}

func (s *Server) handleCertDetails(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if !validSerial(serial) {
		http.Error(w, "bad serial", http.StatusBadRequest)
		return
	}
	pemBytes, err := s.store.LoadCertPEM(serial)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cert, err := parseCertPEM(pemBytes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rec, _ := s.store.RecordBySerial(serial)
	dp := detailsPage{
		Info:     describeCert(cert),
		KindTag:  kindTag(rec.Kind),
		Serial:   serial,
		HasKey:   rec.HasKey,
		CanChain: rec.IssuerID == caIntermediate,
		CertPEM:  string(pemBytes),
	}
	if rec.HasKey && s.isAdmin(r) {
		if keyPEM, err := s.store.LoadKeyPEM(serial); err == nil {
			dp.KeyPEM = string(keyPEM)
		}
	}
	d := s.base(r, "Certificate Details", "")
	d.Data = dp
	s.render(w, "details", d)
}

func (s *Server) handleCADetails(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id != caRoot && id != caIntermediate {
		http.NotFound(w, r)
		return
	}
	pemBytes, err := s.store.LoadCACertPEM(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cert, err := parseCertPEM(pemBytes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	dp := detailsPage{
		Info:     describeCert(cert),
		KindTag:  kindTag(id),
		IsCAView: true,
		CAID:     id,
		CanChain: id == caIntermediate,
		CertPEM:  string(pemBytes),
	}
	d := s.base(r, "CA Details", "ca")
	d.Data = dp
	s.render(w, "details", d)
}

func kindTag(kind string) string {
	switch kind {
	case caRoot:
		return "Root CA"
	case caIntermediate:
		return "Intermediate CA"
	case "issued":
		return "Issued"
	case "csr":
		return "Signed CSR"
	default:
		return kind
	}
}

// --- downloads -----------------------------------------------------------

func (s *Server) handleDownloadCA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id != caRoot && id != caIntermediate {
		http.Error(w, "unknown CA", http.StatusNotFound)
		return
	}
	switch r.PathValue("what") {
	case "cert":
		pemBytes, err := s.store.LoadCACertPEM(id)
		if err != nil {
			http.Error(w, "CA not found", http.StatusNotFound)
			return
		}
		servePEM(w, id+"-cert.pem", pemBytes)
	case "der":
		pemBytes, err := s.store.LoadCACertPEM(id)
		if err != nil {
			http.Error(w, "CA not found", http.StatusNotFound)
			return
		}
		cert, err := parseCertPEM(pemBytes)
		if err != nil {
			http.Error(w, "bad CA certificate", http.StatusInternalServerError)
			return
		}
		serveBytes(w, "application/pkix-cert", id+"-cert.der", cert.Raw)
	case "p7b":
		pemBytes, err := s.store.IssuerChainPEM(id)
		if err != nil {
			http.Error(w, "CA not found", http.StatusNotFound)
			return
		}
		certs, err := parseCertsPEM(pemBytes)
		if err != nil {
			http.Error(w, "bad CA certificate", http.StatusInternalServerError)
			return
		}
		p7, err := encodePKCS7Certs(certs)
		if err != nil {
			http.Error(w, "could not build PKCS#7", http.StatusInternalServerError)
			return
		}
		serveBytes(w, "application/x-pkcs7-certificates", id+"-cert.p7b", p7)
	case "chain":
		pemBytes, err := s.store.IssuerChainPEM(id)
		if err != nil {
			http.Error(w, "chain not available", http.StatusNotFound)
			return
		}
		servePEM(w, id+"-chain.pem", pemBytes)
	default:
		http.Error(w, "unknown download", http.StatusBadRequest)
	}
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if !validSerial(serial) {
		http.Error(w, "bad serial", http.StatusBadRequest)
		return
	}
	switch r.PathValue("what") {
	case "cert":
		pemBytes, err := s.store.LoadCertPEM(serial)
		if err != nil {
			http.Error(w, "certificate not found", http.StatusNotFound)
			return
		}
		servePEM(w, serial+"-cert.pem", pemBytes)
	case "der":
		cert, err := s.loadCert(serial)
		if err != nil {
			http.Error(w, "certificate not found", http.StatusNotFound)
			return
		}
		serveBytes(w, "application/pkix-cert", serial+"-cert.der", cert.Raw)
	case "p7b":
		certs, err := s.leafChainCerts(serial)
		if err != nil {
			http.Error(w, "certificate not found", http.StatusNotFound)
			return
		}
		p7, err := encodePKCS7Certs(certs)
		if err != nil {
			http.Error(w, "could not build PKCS#7", http.StatusInternalServerError)
			return
		}
		serveBytes(w, "application/x-pkcs7-certificates", serial+"-cert.p7b", p7)
	case "key":
		pemBytes, err := s.store.LoadKeyPEM(serial)
		if err != nil {
			http.Error(w, "private key not available", http.StatusNotFound)
			return
		}
		servePEM(w, serial+"-key.pem", pemBytes)
	case "chain":
		s.serveLeafChain(w, serial)
	default:
		http.Error(w, "unknown download", http.StatusBadRequest)
	}
}

// loadCert loads and parses a stored leaf certificate.
func (s *Server) loadCert(serial string) (*x509.Certificate, error) {
	pemBytes, err := s.store.LoadCertPEM(serial)
	if err != nil {
		return nil, err
	}
	return parseCertPEM(pemBytes)
}

// leafChainCerts returns the leaf certificate followed by its issuing CA chain.
func (s *Server) leafChainCerts(serial string) ([]*x509.Certificate, error) {
	leafPEM, err := s.store.LoadCertPEM(serial)
	if err != nil {
		return nil, err
	}
	leaf, err := parseCertPEM(leafPEM)
	if err != nil {
		return nil, err
	}
	certs := []*x509.Certificate{leaf}
	rec, _ := s.store.RecordBySerial(serial)
	if caPEM, err := s.store.IssuerChainPEM(rec.IssuerID); err == nil {
		if caCerts, err := parseCertsPEM(caPEM); err == nil {
			certs = append(certs, caCerts...)
		}
	}
	return certs, nil
}

// handleExportP12 builds a password-protected PKCS#12 bundle (cert + key + chain).
func (s *Server) handleExportP12(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if !validSerial(serial) {
		http.Error(w, "bad serial", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")

	keyPEM, err := s.store.LoadKeyPEM(serial)
	if err != nil {
		http.Error(w, "no private key available for this certificate", http.StatusNotFound)
		return
	}
	key, err := unmarshalKey(keyPEM, "")
	if err != nil {
		http.Error(w, "could not read private key", http.StatusInternalServerError)
		return
	}
	chain, err := s.leafChainCerts(serial)
	if err != nil || len(chain) == 0 {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	leaf := chain[0]
	caCerts := chain[1:]

	p12, err := pkcs12.Modern.Encode(key, leaf, caCerts, password)
	if err != nil {
		http.Error(w, "could not build PKCS#12: "+err.Error(), http.StatusInternalServerError)
		return
	}
	serveBytes(w, "application/x-pkcs12", serial+".p12", p12)
}

func (s *Server) serveLeafChain(w http.ResponseWriter, serial string) {
	leaf, err := s.store.LoadCertPEM(serial)
	if err != nil {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	rec, _ := s.store.RecordBySerial(serial)
	caChain, err := s.store.IssuerChainPEM(rec.IssuerID)
	if err != nil {
		http.Error(w, "chain not available", http.StatusNotFound)
		return
	}
	servePEM(w, serial+"-chain.pem", append(ensureTrailingNewline(leaf), caChain...))
}

// --- auth & account handlers ---------------------------------------------

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth.currentUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login", s.base(r, "Sign in", ""))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	user, ok := s.auth.findUser(username)
	if !ok || !verifyPassword(r.FormValue("password"), user.PasswordHash) {
		d := s.base(r, "Sign in", "")
		d.Error = "Invalid username or password."
		s.render(w, "login", d)
		return
	}
	s.auth.issueSession(w, user.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if s.auth.HasUsers() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, "setup", s.base(r, "Create administrator", ""))
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.auth.HasUsers() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	pw := r.FormValue("password")
	if pw != r.FormValue("password_confirm") {
		s.setupError(w, r, "Passwords do not match.")
		return
	}
	if err := s.auth.AddUser(username, pw, RoleAdmin); err != nil {
		s.setupError(w, r, err.Error())
		return
	}
	s.auth.issueSession(w, username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setupError(w http.ResponseWriter, r *http.Request, msg string) {
	d := s.base(r, "Create administrator", "")
	d.Error = msg
	s.render(w, "setup", d)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	s.usersPage(w, r, "")
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, errMsg string) {
	users, err := s.auth.loadUsers()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := s.base(r, "Users", "users")
	d.Error = errMsg
	d.Data = users
	s.render(w, "users", d)
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	pw := r.FormValue("password")
	if pw != r.FormValue("password_confirm") {
		s.usersPage(w, r, "Passwords do not match.")
		return
	}
	err := s.auth.AddUser(r.FormValue("username"), pw, Role(r.FormValue("role")))
	if err != nil {
		s.usersPage(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.auth.DeleteUser(r.FormValue("username")); err != nil {
		s.usersPage(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// --- certificate templates -----------------------------------------------

func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	s.templatesPage(w, r, "")
}

func (s *Server) templatesPage(w http.ResponseWriter, r *http.Request, errMsg string) {
	tmpls, err := s.store.LoadTemplates()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := s.base(r, "Templates", "templates")
	d.Error = errMsg
	d.Data = tmpls
	s.render(w, "templates", d)
}

func templateFromForm(r *http.Request) CertTemplate {
	return CertTemplate{
		Name:         strings.TrimSpace(r.FormValue("name")),
		Description:  strings.TrimSpace(r.FormValue("description")),
		Organization: strings.TrimSpace(r.FormValue("organization")),
		Country:      strings.TrimSpace(r.FormValue("country")),
		Algo:         keyAlgo(r.FormValue("algo")),
		ValidDays:    atoiDefault(r.FormValue("valid_days"), 365),
		Profile:      certProfile(r.FormValue("profile")),
	}
}

func (s *Server) handleTemplateAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.AddTemplate(templateFromForm(r)); err != nil {
		s.templatesPage(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

func (s *Server) handleTemplateEditForm(w http.ResponseWriter, r *http.Request) {
	t, ok := s.store.GetTemplate(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	d := s.base(r, "Edit template", "templates")
	d.Data = t
	s.render(w, "template_edit", d)
}

func (s *Server) handleTemplateEdit(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	t := templateFromForm(r)
	if err := s.store.UpdateTemplate(name, t); err != nil {
		t.Name = name
		d := s.base(r, "Edit template", "templates")
		d.Error = err.Error()
		d.Data = t
		s.render(w, "template_edit", d)
		return
	}
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

func (s *Server) handleTemplateDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.DeleteTemplate(r.FormValue("name")); err != nil {
		s.templatesPage(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

// formBase is like base but also loads templates for the issue/sign forms.
func (s *Server) formBase(r *http.Request, title, active string) pageData {
	d := s.base(r, title, active)
	tmpls, _ := s.store.LoadTemplates()
	d.Data = tmpls
	return d
}

// --- shared helpers ------------------------------------------------------

func (s *Server) message(w http.ResponseWriter, r *http.Request, title, body string) {
	d := s.base(r, title, "")
	d.Message = body
	d.Data = title
	s.render(w, "message", d)
}

func (s *Server) needCA(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, "No CA yet", "")
	d.Error = "You need to create a root CA before you can do this."
	d.Data = "No CA yet"
	s.render(w, "message", d)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	d := s.base(r, "Error", "")
	d.Error = err.Error()
	d.Data = "Error"
	s.render(w, "message", d)
}

func servePEM(w http.ResponseWriter, filename string, data []byte) {
	serveBytes(w, "application/x-pem-file", filename, data)
}

func serveBytes(w http.ResponseWriter, contentType, filename string, data []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Write(data)
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return def
}

func splitLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	})
}

// validSerial guards against path traversal: serials are always lowercase hex.
func validSerial(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

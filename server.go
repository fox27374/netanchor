package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed templates/logo.svg
var logoSVG []byte

// Server wires the store and auth to the HTTP handlers and parsed templates.
type Server struct {
	store       *Store
	auth        *Auth
	templates   map[string]*template.Template
	flashMu     sync.Mutex
	flashes     map[string]caFlash
	scep        *SCEPService
	gnoiAllow   []*net.IPNet // NETANCHOR_GNOI_ALLOW; empty refuses every device target
	backupMu    sync.Mutex
	restart     chan struct{}
	restartOnce sync.Once
}

const (
	caFlashCookie    = "netanchor_ca_flash"
	issueFlashCookie = "netanchor_issue_flash"
)

type caFlash struct {
	Title, Body string
	Expires     time.Time
}

func NewServer(store *Store, auth *Auth) *Server {
	pages := []string{"dashboard", "ca", "issue", "sign", "details", "message", "login", "setup", "users", "templates", "template_edit", "ca_delete_confirm", "cert_delete_confirm", "tools", "scep", "gnoi", "backup", "certificates", "devices", "device"}
	tpls := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		tpls[p] = template.Must(template.New(p).Funcs(template.FuncMap{"joinStrings": func(values []string) string { return strings.Join(values, ",") }, "hasAlgo": func(list []keyAlgo, value string) bool {
			for _, a := range list {
				if string(a) == value {
					return true
				}
			}
			return false
		}}).ParseFS(
			templateFS, "templates/layout.html", "templates/"+p+".html"))
	}
	return &Server{store: store, auth: auth, templates: tpls, flashes: make(map[string]caFlash), scep: newSCEPService(store), restart: make(chan struct{})}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/backup", s.handleBackupPage)
	mux.HandleFunc("POST /admin/backup", s.handleBackup)
	mux.HandleFunc("POST /admin/restore", s.handleRestore)
	for _, path := range scepPaths {
		mux.Handle(path, s.scep.Routes())
	}
	mux.HandleFunc("GET /admin/scep", s.handleSCEPAdmin)
	mux.HandleFunc("POST /admin/scep/{action}", s.handleSCEPAdmin)
	mux.HandleFunc("GET /admin/gnoi", s.handleGNOIAdmin)
	mux.HandleFunc("POST /admin/gnoi/{action}", s.handleGNOIAdmin)
	mux.HandleFunc("GET /devices", s.handleDevices)
	mux.HandleFunc("GET /devices/new", s.handleDeviceNew)
	mux.HandleFunc("POST /devices/save", s.handleDeviceSave)
	mux.HandleFunc("POST /devices/probe", s.handleDeviceProbe)
	mux.HandleFunc("GET /devices/{id}", s.handleDeviceDetail)
	mux.HandleFunc("GET /devices/{id}/edit", s.handleDeviceEdit)
	mux.HandleFunc("POST /devices/{id}/delete", s.handleDeviceDelete)
	mux.HandleFunc("POST /devices/{id}/test", s.handleDeviceTest)
	mux.HandleFunc("POST /devices/{id}/refresh", s.handleDeviceRefresh)
	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /certificates", s.handleCertificates)
	mux.HandleFunc("GET /tools", s.handleTools)
	mux.HandleFunc("POST /tools", s.handleToolsDecode)
	mux.HandleFunc("POST /tools/check-password", s.handleToolsPasswordCheck)
	mux.HandleFunc("GET /tools/{token}", s.handleToolsResult)
	mux.HandleFunc("POST /tools/{token}/download", s.handleToolsDownload)
	mux.HandleFunc("GET /ca", s.handleCA)
	mux.HandleFunc("POST /ca/root", s.handleCreateRoot)
	mux.HandleFunc("POST /ca/intermediate", s.handleCreateIntermediate)
	mux.HandleFunc("GET /ca/view/{id}", s.handleCADetails)
	mux.HandleFunc("GET /ca/delete/{id}", s.handleCADeleteForm)
	mux.HandleFunc("POST /ca/delete/{id}", s.handleCADeleteConfirm)
	mux.HandleFunc("GET /issue", s.handleIssueForm)
	mux.HandleFunc("POST /issue", s.handleIssue)
	mux.HandleFunc("GET /sign", s.handleSignForm)
	mux.HandleFunc("POST /sign", s.handleSign)
	mux.HandleFunc("GET /cert/{serial}", s.handleCertDetails)
	mux.HandleFunc("GET /cert/delete/{serial}", s.handleCertDeleteForm)
	mux.HandleFunc("POST /cert/delete/{serial}", s.handleCertDeleteConfirm)
	mux.HandleFunc("GET /download/ca/{id}/{what}", s.handleDownloadCA)
	mux.HandleFunc("GET /download/{serial}/{what}", s.handleDownload)
	mux.HandleFunc("POST /download/{serial}/p12", s.handleExportP12)

	// Certificate templates (issuance presets).
	mux.HandleFunc("GET /templates", s.handleTemplates)
	mux.HandleFunc("POST /templates/add", s.handleTemplateAdd)
	mux.HandleFunc("POST /templates/duplicate", s.handleTemplateDuplicate)
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
	// The logo doubles as the favicon; /favicon.ico covers browsers that ask
	// for it without reading the page's <link rel="icon">.
	serveLogo := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(logoSVG)
	}
	mux.HandleFunc("GET /logo.svg", serveLogo)
	mux.HandleFunc("GET /favicon.ico", serveLogo)
	return logRequests(mux)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/tools/") {
			path = "/tools/[result]"
		}
		log.Printf("%s %s", r.Method, path)
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
	Flash           *caFlash
	Data            any

	// For issue/sign forms: list of CAs that can issue certs (by CAID and DisplayPath)
	IssueCAs []caOptionData

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
		HasIntermediate: s.hasIntermediate(),
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

// hasIntermediate reports whether at least one intermediate CA exists (legacy or serial-based).
func (s *Server) hasIntermediate() bool {
	recs, err := s.store.Records()
	if err != nil {
		return false
	}
	for _, rec := range recs {
		if rec.Kind == caIntermediate {
			return true
		}
	}
	return false
}

// getIssueCAs returns all CAs that can issue certificates (all CAs).
func (s *Server) getIssueCAs() []caOptionData {
	cas, _ := s.store.CAs()
	var result []caOptionData
	for _, ca := range cas {
		if ca.Record.Kind == caRoot || ca.Record.Kind == caIntermediate {
			result = append(result, caOptionData{
				CAID:        ca.ID,
				DisplayPath: ca.Path,
				KeyEnc:      s.store.CAKeyEncrypted(ca.ID),
			})
		}
	}
	return result
}

// --- dashboard -----------------------------------------------------------

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	recs, err := s.store.Records()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	paths := map[string]string{}
	cas, _ := s.store.CAs()
	for _, ca := range cas {
		paths[ca.ID] = ca.Path
	}
	d := s.base(r, "Dashboard", "dashboard")
	d.Flash = s.takeFlash(w, r, issueFlashCookie, "/")
	d.Data = struct {
		Recs  []CertRecord
		Paths map[string]string // CA id -> "Root › A › B"
	}{recs, paths}
	s.render(w, "dashboard", d)
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	recs, err := s.store.Records()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	paths := map[string]string{}
	cas, _ := s.store.CAs()
	for _, ca := range cas {
		paths[ca.ID] = ca.Path
	}
	d := s.base(r, "Issued certificates", "certificates")
	d.Data = struct {
		Recs  []CertRecord
		Paths map[string]string // CA id -> "Root › A › B"
	}{recs, paths}
	s.render(w, "certificates", d)
}

// --- CA management -------------------------------------------------------

type caViewData struct {
	Root          *CertRecord
	RootEncrypted bool
	Intermediates []intermediateViewData
	ParentOptions []caOptionData
}

type intermediateViewData struct {
	CAID            string
	CommonName      string
	SignedBy        string // parent CA path
	NotAfter        time.Time
	KeyEnc          bool
	AllowSubCALabel string
}

type caOptionData struct {
	CAID        string
	DisplayPath string
	KeyEnc      bool // key is passphrase-protected, so signing needs the passphrase
}

func (s *Server) caData() caViewData {
	cas, _ := s.store.CAs()
	var data caViewData

	paths := map[string]string{}
	for _, ca := range cas {
		paths[ca.ID] = ca.Path
	}
	for _, ca := range cas {
		if ca.Record.Kind == caRoot {
			data.Root = ca.Record
			data.RootEncrypted = s.store.CAKeyEncrypted(caRoot)
		} else if ca.Record.Kind == caIntermediate {
			label := "No"
			if ca.Record.AllowSubCA {
				label = "Yes"
			}
			data.Intermediates = append(data.Intermediates, intermediateViewData{
				CAID:            ca.ID,
				CommonName:      ca.Record.CommonName,
				SignedBy:        paths[ca.ParentID],
				NotAfter:        ca.Record.NotAfter,
				KeyEnc:          ca.Record.KeyEnc,
				AllowSubCALabel: label,
			})
		}
	}

	for _, ca := range cas {
		if ca.CanSignSubCA {
			data.ParentOptions = append(data.ParentOptions, caOptionData{
				CAID:        ca.ID,
				DisplayPath: ca.Path,
				KeyEnc:      s.store.CAKeyEncrypted(ca.ID),
			})
		}
	}

	return data
}

func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, "Certificate Authority", "ca")
	d.Data = s.caData()
	d.Flash = s.takeFlash(w, r, caFlashCookie, "/ca")
	s.render(w, "ca", d)
}

// CA success messages stay server-side; the browser receives only an opaque,
// short-lived one-use token. This also keeps the deleted CA name out of URLs.
func (s *Server) redirectCASuccess(w http.ResponseWriter, r *http.Request, title, body string) {
	s.redirectSuccess(w, r, title, body, caFlashCookie, "/ca")
}

func (s *Server) redirectSuccess(w http.ResponseWriter, r *http.Request, title, body, cookieName, path string) {
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		s.fail(w, r, err)
		return
	}
	key := hex.EncodeToString(token)
	now := time.Now()
	s.flashMu.Lock()
	for k, flash := range s.flashes {
		if !now.Before(flash.Expires) || len(s.flashes) >= 128 {
			delete(s.flashes, k)
		}
	}
	s.flashes[key] = caFlash{Title: title, Body: body, Expires: now.Add(2 * time.Minute)}
	s.flashMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: key, Path: path, HttpOnly: true,
		Secure: s.auth.secure, SameSite: http.SameSiteLaxMode, MaxAge: 120,
	})
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request, cookieName, path string) *caFlash {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Path: path, HttpOnly: true,
		Secure: s.auth.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	s.flashMu.Lock()
	flash, ok := s.flashes[cookie.Value]
	delete(s.flashes, cookie.Value)
	s.flashMu.Unlock()
	if !ok || !time.Now().Before(flash.Expires) {
		return nil
	}
	return &flash
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
	s.redirectCASuccess(w, r, "Root CA created", "Your root CA is ready. You can now issue certificates, sign CSRs, and optionally create an intermediate CA.")
}

func (s *Server) handleCreateIntermediate(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	pass := r.FormValue("passphrase")
	if pass != r.FormValue("passphrase_confirm") {
		s.caError(w, r, "Passphrases do not match.")
		return
	}
	parentID := strings.TrimSpace(r.FormValue("parent"))
	if parentID == "" {
		parentID = caRoot
	}
	// Validate parent exists
	if !s.store.ValidCAID(parentID) {
		s.caError(w, r, fmt.Sprintf("Parent CA %s does not exist.", parentID))
		return
	}
	p := IntermediateParams{
		CommonName:       strings.TrimSpace(r.FormValue("common_name")),
		Organization:     strings.TrimSpace(r.FormValue("organization")),
		Country:          strings.TrimSpace(r.FormValue("country")),
		Algo:             keyAlgo(r.FormValue("algo")),
		ValidDays:        atoiDefault(r.FormValue("valid_days"), 1825),
		ParentID:         parentID,
		ParentPassphrase: r.FormValue("parent_passphrase"),
		Passphrase:       pass,
		AllowSubCAs:      r.FormValue("allow_sub") == "on",
		SCEP:             r.FormValue("scep") == "on",
	}
	if _, err := CreateIntermediate(s.store, p); err != nil {
		s.caError(w, r, err.Error())
		return
	}
	s.redirectCASuccess(w, r, "Intermediate CA created", "Your intermediate CA is ready. You can now choose it as the issuer when creating certificates or signing CSRs.")
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
		Country:      strings.TrimSpace(r.FormValue("country")),
		IssuerID:     r.FormValue("issuer"),
		CAPassphrase: r.FormValue("ca_passphrase"),
	}
	selected := strings.TrimSpace(r.FormValue("template"))
	t, ok := s.store.GetTemplate(selected)
	if !ok {
		s.issueError(w, r, "Select a valid certificate template.")
		return
	}
	p.Template = t
	p.TemplateName = t.Name
	p.Algo = keyAlgo(r.FormValue("algo"))
	if p.Algo == "" {
		p.Algo = t.Algo
	}
	days, provided, err := parseRequestedDays(r)
	if err != nil {
		s.issueError(w, r, err.Error())
		return
	}
	p.ValidDays = days
	if !provided {
		p.ValidDays = t.ValidDays
	}
	p.Profile = t.Profile
	p.DNSNames = splitLines(r.FormValue("dns_sans"))
	for _, v := range splitLines(r.FormValue("ip_sans")) {
		ip := net.ParseIP(v)
		if ip == nil {
			s.issueError(w, r, "Invalid IP SAN.")
			return
		}
		p.IPs = append(p.IPs, ip)
	}
	p.Emails = splitLines(r.FormValue("email_sans"))
	p.URIs = splitLines(r.FormValue("uri_sans"))
	rec, err := IssueCert(s.store, p)
	if err != nil {
		d := s.formBase(r, "Issue Certificate", "issue")
		d.Error = err.Error()
		s.render(w, "issue", d)
		return
	}
	s.redirectSuccess(w, r, "Certificate issued",
		fmt.Sprintf("Issued certificate for %q (serial %s). View or download it from the dashboard.",
			rec.CommonName, rec.Serial), issueFlashCookie, "/")
}

func (s *Server) issueError(w http.ResponseWriter, r *http.Request, msg string) {
	d := s.formBase(r, "Issue Certificate", "issue")
	d.Error = msg
	s.render(w, "issue", d)
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
		IssuerID:     r.FormValue("issuer"),
		CAPassphrase: r.FormValue("ca_passphrase"),
	}
	selected := strings.TrimSpace(r.FormValue("template"))
	t, ok := s.store.GetTemplate(selected)
	if !ok {
		d := s.formBase(r, "Sign CSR", "sign")
		d.Error = "Select a valid certificate template."
		s.render(w, "sign", d)
		return
	}
	p.Template = t
	p.TemplateName = t.Name
	days, provided, err := parseRequestedDays(r)
	if err != nil {
		d := s.formBase(r, "Sign CSR", "sign")
		d.Error = err.Error()
		s.render(w, "sign", d)
		return
	}
	p.ValidDays = days
	if !provided {
		p.ValidDays = t.ValidDays
	}
	p.Profile = t.Profile
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
	Info           CertInfo
	KindTag        string
	IsCAView       bool
	CAID           string
	Serial         string
	HasKey         bool
	CanChain       bool
	CertPEM        string // inline, copy-paste
	KeyPEM         string // inline, admin only
	Chain          []chainStep
	TemplateName   string
	TemplatePolicy CertTemplate
	Pushes         []DevicePush
}

// chainStep is one box in the chain schematic, root first. Href is empty for
// the certificate being viewed.
type chainStep struct {
	Name  string
	Href  string
	Valid bool   // inside its validity window right now
	Note  string // tooltip: why it is valid or not
}

// newChainStep builds a step and checks its validity window against now.
func newChainStep(name, href string, notBefore, notAfter time.Time) chainStep {
	st := chainStep{Name: name, Href: href}
	now := time.Now()
	switch {
	case now.Before(notBefore):
		st.Note = "not valid before " + notBefore.Format("2006-01-02")
	case now.After(notAfter):
		st.Note = "expired " + notAfter.Format("2006-01-02")
	default:
		st.Valid = true
		st.Note = "valid until " + notAfter.Format("2006-01-02")
	}
	return st
}

// caChain returns the chain steps from the root down to caID, or nil if the
// path cannot be resolved.
func (s *Server) caChain(caID string) []chainStep {
	path, err := s.store.CAPath(caID)
	if err != nil {
		return nil
	}
	steps := make([]chainStep, len(path))
	for i, rec := range path {
		steps[i] = newChainStep(rec.CommonName, "/ca/view/"+caIDOf(rec), rec.NotBefore, rec.NotAfter)
	}
	return steps
}

func (s *Server) handleCertDetails(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if !ValidSerial(serial) {
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
	// CanChain is true if issued by any CA that is not root (i.e., any intermediate)
	canChain := rec.IssuerID != "" && rec.IssuerID != caRoot
	dp := detailsPage{
		Info:         describeCert(cert),
		KindTag:      kindTag(rec.Kind),
		Serial:       serial,
		HasKey:       rec.HasKey,
		CanChain:     canChain,
		CertPEM:      string(pemBytes),
		TemplateName: rec.TemplateName, TemplatePolicy: rec.TemplatePolicy,
		Pushes: rec.Pushes,
	}
	if rec.IssuerID != "" {
		if chain := s.caChain(rec.IssuerID); chain != nil {
			dp.Chain = append(chain, newChainStep(dp.Info.CommonName, "", cert.NotBefore, cert.NotAfter))
		}
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
	if !s.store.ValidCAID(id) {
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
	kindStr := caRoot
	if id != caRoot {
		kindStr = caIntermediate
	}
	dp := detailsPage{
		Info:     describeCert(cert),
		KindTag:  kindTag(kindStr),
		IsCAView: true,
		CAID:     id,
		CanChain: id != caRoot,
		CertPEM:  string(pemBytes),
		Chain:    s.caChain(id),
	}
	if n := len(dp.Chain); n > 0 {
		dp.Chain[n-1].Href = ""
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

// --- CA deletion -----------------------------------------------------------

// deleteCAData holds info for the CA delete confirmation page.
type deleteCAData struct {
	CAID       string
	CommonName string
	SubCAs     []CertRecord
	SubCerts   []CertRecord
}

// renderCADelete shows the confirmation page listing everything that deleting
// the CA removes. It 404s for the root and unknown CAs.
func (s *Server) renderCADelete(w http.ResponseWriter, r *http.Request, id, errMsg string) {
	if !s.store.ValidCAID(id) {
		http.NotFound(w, r)
		return
	}
	cas, certs, err := s.store.CASubtree(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := s.base(r, "Delete CA", "ca")
	d.Error = errMsg
	d.Data = deleteCAData{
		CAID:       id,
		CommonName: cas[0].CommonName,
		SubCAs:     cas[1:],
		SubCerts:   certs,
	}
	s.render(w, "ca_delete_confirm", d)
}

func (s *Server) handleCADeleteForm(w http.ResponseWriter, r *http.Request) {
	s.renderCADelete(w, r, r.PathValue("id"), "")
}

func (s *Server) handleCADeleteConfirm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.store.ValidCAID(id) {
		http.NotFound(w, r)
		return
	}
	cas, _, err := s.store.CASubtree(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cn := cas[0].CommonName
	if strings.TrimSpace(r.FormValue("confirm_name")) != cn {
		s.renderCADelete(w, r, id, "The name you typed does not match. Nothing was deleted.")
		return
	}
	if err := s.store.DeleteCA(id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.redirectCASuccess(w, r, "CA deleted", fmt.Sprintf("%q, its sub-CAs and all certificates they issued were moved to the trash folder.", cn))
}

// --- certificate deletion --------------------------------------------------

func (s *Server) handleCertDeleteForm(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if !ValidSerial(serial) {
		http.Error(w, "bad serial", http.StatusBadRequest)
		return
	}
	rec, ok := s.store.RecordBySerial(serial)
	if !ok || (rec.Kind != "issued" && rec.Kind != "csr") {
		http.NotFound(w, r)
		return
	}

	d := s.base(r, "Delete Certificate - Confirm", "")
	d.Data = rec
	s.render(w, "cert_delete_confirm", d)
}

func (s *Server) handleCertDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if !ValidSerial(serial) {
		http.Error(w, "bad serial", http.StatusBadRequest)
		return
	}

	if err := s.store.DeleteCert(serial); err != nil {
		s.fail(w, r, err)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- downloads -----------------------------------------------------------

func (s *Server) handleDownloadCA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.store.ValidCAID(id) {
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
		servePKCS7(w, id+"-cert.p7b", []*x509.Certificate{cert})
	case "chain":
		pemBytes, err := s.store.IssuerChainPEM(id)
		if err != nil {
			http.Error(w, "chain not available", http.StatusNotFound)
			return
		}
		certs, err := parseCertsPEM(pemBytes)
		if err != nil {
			http.Error(w, "bad CA certificate", http.StatusInternalServerError)
			return
		}
		serveChain(w, r, id, certs)
	default:
		http.Error(w, "unknown download", http.StatusBadRequest)
	}
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if !ValidSerial(serial) {
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
		cert, err := s.loadCert(serial)
		if err != nil {
			http.Error(w, "certificate not found", http.StatusNotFound)
			return
		}
		servePKCS7(w, serial+"-cert.p7b", []*x509.Certificate{cert})
	case "key":
		pemBytes, err := s.store.LoadKeyPEM(serial)
		if err != nil {
			http.Error(w, "private key not available", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("format") != "der" {
			servePEM(w, serial+"-key.pem", pemBytes)
			return
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			http.Error(w, "could not read private key", http.StatusInternalServerError)
			return
		}
		serveBytes(w, "application/octet-stream", serial+"-key.der", block.Bytes)
	case "chain":
		certs, err := s.leafChainCerts(serial)
		if err != nil {
			http.Error(w, "certificate not found", http.StatusNotFound)
			return
		}
		serveChain(w, r, serial, certs)
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
	if !ValidSerial(serial) {
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
	if r.FormValue("noroot") != "" {
		chain = dropRoot(chain)
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

// serveChain sends certs (leaf first, root last) as PEM, or as PKCS#7 with
// ?format=p7b. With ?noroot=1 a trailing self-signed root is left out.
func serveChain(w http.ResponseWriter, r *http.Request, name string, certs []*x509.Certificate) {
	q := r.URL.Query()
	if q.Get("noroot") != "" {
		if trimmed := dropRoot(certs); len(trimmed) < len(certs) {
			certs = trimmed
			name += "-noroot"
		}
	}
	if q.Get("format") == "p7b" {
		servePKCS7(w, name+"-chain.p7b", certs)
		return
	}
	var out []byte
	for _, c := range certs {
		out = append(out, encodeCertPEM(c.Raw)...)
	}
	servePEM(w, name+"-chain.pem", out)
}

// dropRoot returns certs (leaf first, root last) without a trailing
// self-signed root. A lone certificate is never dropped.
func dropRoot(certs []*x509.Certificate) []*x509.Certificate {
	if n := len(certs); n > 1 && bytes.Equal(certs[n-1].RawIssuer, certs[n-1].RawSubject) {
		return certs[:n-1]
	}
	return certs
}

func servePKCS7(w http.ResponseWriter, filename string, certs []*x509.Certificate) {
	p7, err := encodePKCS7Certs(certs)
	if err != nil {
		http.Error(w, "could not build PKCS#7", http.StatusInternalServerError)
		return
	}
	serveBytes(w, "application/x-pkcs7-certificates", filename, p7)
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
	http.Redirect(w, r, "/users", http.StatusSeeOther)
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
	d.Data = struct{ Builtins, Custom []CertTemplate }{builtinTemplates(), tmpls}
	s.render(w, "templates", d)
}

func templateFromForm(r *http.Request) (CertTemplate, error) {
	valid, err := formInt(r, "valid_days", 365)
	if err != nil {
		return CertTemplate{}, err
	}
	max, err := formInt(r, "max_days", 365)
	if err != nil {
		return CertTemplate{}, err
	}
	return CertTemplate{
		Name:           strings.TrimSpace(r.FormValue("name")),
		Description:    strings.TrimSpace(r.FormValue("description")),
		Organization:   strings.TrimSpace(r.FormValue("organization")),
		Country:        strings.TrimSpace(r.FormValue("country")),
		Algo:           keyAlgo(r.FormValue("algo")),
		ValidDays:      valid,
		MaxDays:        max,
		Profile:        certProfile(r.FormValue("profile")),
		AllowedAlgos:   allowedAlgorithms(r),
		AllowedIssuers: splitLines(strings.Join(r.Form["allowed_issuers"], ",")),
	}, nil
}

func allowedAlgorithms(r *http.Request) []keyAlgo {
	var a []keyAlgo
	for _, v := range r.Form["allowed_algorithms"] {
		switch keyAlgo(v) {
		case algoRSA2048, algoRSA4096, algoECP256, algoECP384:
			a = append(a, keyAlgo(v))
		}
	}
	return a
}

func (s *Server) handleTemplateAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := templateFromForm(r)
	if err == nil {
		err = s.store.AddTemplate(t)
	}
	if err != nil {
		s.templatesPage(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

func (s *Server) handleTemplateDuplicate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, err)
		return
	}
	source, ok := builtinByName(r.FormValue("source"))
	if !ok {
		s.templatesPage(w, r, "Unknown built-in profile.")
		return
	}
	// Pick the first free "Copy-<name>" (then -2, -3, ...) so repeated duplicates don't collide.
	base := "Copy-" + source.Name
	source.Name = base
	for n := 2; ; n++ {
		if _, taken := s.store.GetTemplate(source.Name); !taken {
			break
		}
		source.Name = fmt.Sprintf("%s-%d", base, n)
	}
	source.Builtin = false
	if err := s.store.AddTemplate(source); err != nil {
		s.templatesPage(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

func (s *Server) handleTemplateEditForm(w http.ResponseWriter, r *http.Request) {
	t, ok := s.store.GetTemplate(r.PathValue("name"))
	if !ok || t.Builtin {
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
	t, err := templateFromForm(r)
	if err == nil {
		err = s.store.UpdateTemplate(name, t)
	}
	if err != nil {
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

// formBase is like base but also loads templates and CA options for the issue/sign forms.
func (s *Server) formBase(r *http.Request, title, active string) pageData {
	d := s.base(r, title, active)
	tmpls, _ := s.store.LoadTemplates()
	d.Data = struct{ Builtins, Custom []CertTemplate }{builtinTemplates(), tmpls}

	// Build list of CAs that can issue certs (all CAs except root if intermediates exist)
	// Actually, all CAs can issue: root, and all intermediates
	d.IssueCAs = s.getIssueCAs()

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

func formInt(r *http.Request, name string, def int) (int, error) {
	raw := strings.TrimSpace(r.FormValue(name))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive number", strings.ReplaceAll(name, "_", " "))
	}
	return n, nil
}
func parseRequestedDays(r *http.Request) (int, bool, error) {
	raw := strings.TrimSpace(r.FormValue("valid_days"))
	if raw == "" {
		return 0, false, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, true, fmt.Errorf("validity must be a positive number of days")
	}
	return n, true, nil
}

func splitLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	})
}

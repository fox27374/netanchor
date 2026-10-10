package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// definitionForm is the add/edit form. It echoes posted values as typed.
type definitionForm struct {
	ID, Name, CAID, Profile                string
	Country, State, Organization, City, OU string
	ValidDays, CertID, ExtraSANs           string
}

type definitionListPage struct {
	Defs []CertDefinition
	CSRF string
}

type definitionFormPage struct {
	Form     definitionForm
	CAs      []caOptionData
	Profiles []string
	CSRF     string
}

// definitionProfiles lists the templates a definition may use: server purpose
// with RSA 2048 allowed, since the device generates RSA 2048 keys only.
func (s *Server) definitionProfiles() []string {
	custom, _ := s.store.LoadTemplates()
	var names []string
	for _, t := range append(builtinTemplates(), custom...) {
		if t.Profile == profileServer && allowedAlgo(t, algoRSA2048) {
			names = append(names, t.Name)
		}
	}
	return names
}

func (s *Server) handleDefinitions(w http.ResponseWriter, r *http.Request) {
	deviceHeaders(w)
	d := s.base(r, "Device certificate definitions", "definitions")
	defs, err := s.store.ListDefinitions()
	if err != nil {
		d.Error = err.Error()
	}
	d.Data = definitionListPage{Defs: defs, CSRF: s.backupToken(r)}
	s.render(w, "definitions", d)
}

func (s *Server) handleDefinitionNew(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	s.renderDefinitionForm(w, r, definitionForm{ValidDays: "365"}, "")
}

func (s *Server) handleDefinitionEdit(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	def, ok, err := s.store.GetDefinition(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.renderDefinitionForm(w, r, definitionForm{
		ID: def.ID, Name: def.Name, CAID: def.CAID, Profile: def.Profile,
		Country: def.Country, State: def.State, Organization: def.Organization, City: def.City, OU: def.OU,
		ValidDays: strconv.Itoa(def.ValidDays), CertID: def.CertID, ExtraSANs: strings.Join(def.ExtraSANs, ", "),
	}, "")
}

func (s *Server) renderDefinitionForm(w http.ResponseWriter, r *http.Request, f definitionForm, errMsg string) {
	deviceHeaders(w)
	title := "Add device certificate definition"
	if f.ID != "" {
		title = "Edit device certificate definition"
	}
	d := s.base(r, title, "definitions")
	d.Error = errMsg
	d.Data = definitionFormPage{Form: f, CAs: s.getIssueCAs(), Profiles: s.definitionProfiles(), CSRF: s.backupToken(r)}
	s.render(w, "definition", d)
}

func (s *Server) handleDefinitionSave(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
		return
	}
	p := r.PostForm
	f := definitionForm{
		ID: strings.TrimSpace(p.Get("id")), Name: strings.TrimSpace(p.Get("name")), CAID: p.Get("ca"), Profile: strings.TrimSpace(p.Get("profile")),
		Country: strings.TrimSpace(p.Get("country")), State: strings.TrimSpace(p.Get("state")), Organization: strings.TrimSpace(p.Get("organization")),
		City: strings.TrimSpace(p.Get("city")), OU: strings.TrimSpace(p.Get("ou")),
		ValidDays: strings.TrimSpace(p.Get("valid_days")), CertID: strings.TrimSpace(p.Get("cert_id")), ExtraSANs: p.Get("extra_sans"),
	}
	def, err := s.definitionFromForm(f)
	if err == nil {
		err = s.store.SaveDefinition(&def)
	}
	if err != nil {
		s.renderDefinitionForm(w, r, f, err.Error())
		return
	}
	http.Redirect(w, r, "/definitions", http.StatusSeeOther)
}

// definitionFromForm validates the form against the profile, the issuing CA and
// the device rules. Nothing is stored here.
func (s *Server) definitionFromForm(f definitionForm) (CertDefinition, error) {
	var def CertDefinition
	def.ID = f.ID
	if !validTemplateName(f.Name) {
		return def, errors.New("name must be 1-64 chars: letters, digits, '-' or '_'")
	}
	if !s.store.ValidCAID(f.CAID) {
		return def, errors.New("select a valid issuing CA")
	}
	t, ok := s.store.GetTemplate(f.Profile)
	if !ok || t.Profile != profileServer || !allowedAlgo(t, algoRSA2048) {
		return def, errors.New("choose a server profile that allows RSA 2048 keys")
	}
	if f.Country == "" || f.State == "" || f.Organization == "" {
		return def, errors.New("country, state and organization are required by the device")
	}
	days, err := strconv.Atoi(f.ValidDays)
	if err != nil || days < 1 || days > t.MaxDays {
		return def, fmt.Errorf("validity must be between 1 and %d days", t.MaxDays)
	}
	cas, err := s.store.CAs()
	if err != nil {
		return def, err
	}
	for _, ca := range cas {
		if ca.ID == f.CAID && ca.Record != nil && time.Now().AddDate(0, 0, days).After(ca.Record.NotAfter) {
			return def, errors.New("validity runs past the issuing CA's expiry")
		}
	}
	certID := f.CertID
	if certID == "" {
		certID = sanitizeCertID("netanchor-" + f.Name)
	}
	if !validCertID(certID) {
		return def, errors.New("certificate id must be 1-64 letters, digits, '.', '-' or '_'")
	}
	var extra []string
	for _, san := range strings.Split(f.ExtraSANs, ",") {
		if san = strings.TrimSpace(san); san == "" {
			continue
		}
		if net.ParseIP(san) == nil && !validDNSName(san) {
			return def, fmt.Errorf("extra SAN %q is not a valid DNS name or IP address", san)
		}
		extra = append(extra, san)
	}
	def.Name, def.CAID, def.Profile = f.Name, f.CAID, t.Name
	def.Country, def.State, def.Organization, def.City, def.OU = f.Country, f.State, f.Organization, f.City, f.OU
	def.ValidDays, def.CertID, def.ExtraSANs = days, certID, extra
	return def, nil
}

// validDNSName accepts dot-separated labels of letters, digits and hyphens.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (s *Server) handleDefinitionDelete(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteDefinition(r.PathValue("id")); errors.Is(err, errDefinitionNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/definitions", http.StatusSeeOther)
}

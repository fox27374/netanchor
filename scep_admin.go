package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type scepAdminData struct {
	CA, Status, Fingerprint, Secret string
	CAs                             []caOptionData
	Profiles                        []CertTemplate
	Challenges                      []scepChallenge
}

func (s *Server) handleSCEPAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	var secret string
	var err error
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if err = r.ParseForm(); err != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		switch r.PathValue("action") {
		case "unlock":
			err = s.scep.selectCA(r.PostForm.Get("ca"), r.PostForm.Get("passphrase"))
		case "lock":
			s.scep.lock()
		case "revoke":
			err = s.scep.revoke(r.PostForm.Get("id"))
		case "challenge":
			var days, hours int
			days, err = scepFormInt(r.PostForm.Get("days"))
			if err == nil {
				hours, err = scepFormInt(r.PostForm.Get("hours"))
			}
			if err == nil {
				secret, err = s.scep.challenge(r.PostForm.Get("profile"), strings.FieldsFunc(r.PostForm.Get("sans"), func(c rune) bool { return c == ',' || c == '\n' || c == '\r' }), days, hours)
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err == nil && secret == "" {
			http.Redirect(w, r, "/admin/scep", http.StatusSeeOther)
			return
		}
	}
	d := s.base(r, "SCEP Enrollment", "scep")
	if err != nil {
		d.Error = err.Error()
	}
	v := scepAdminData{Secret: secret, Status: "locked / unavailable"}
	s.store.scepMu.Lock()
	st, loadErr := s.scep.load()
	if loadErr == nil {
		v.CA, v.Challenges = st.CA, st.Challenges
		if _, readyErr := s.scep.ready(st); readyErr == nil {
			v.Status = "unlocked"
		}
		if c, caErr := s.scep.ca(st.CA); caErr == nil {
			v.Fingerprint = hashSCEP(c.Raw)
		}
	}
	s.store.scepMu.Unlock()
	if loadErr != nil {
		d.Error = loadErr.Error()
	}
	for _, ca := range s.getIssueCAs() {
		if _, err := s.scep.ca(ca.CAID); err == nil {
			v.CAs = append(v.CAs, ca)
		}
	}
	s.store.mu.Lock()
	custom, loadErr := s.store.LoadTemplates()
	s.store.mu.Unlock()
	if loadErr != nil {
		d.Error = loadErr.Error()
	}
	for _, p := range append(builtinTemplates(), custom...) {
		if p.Profile == profileServer {
			v.Profiles = append(v.Profiles, p)
		}
	}
	d.Data = v
	s.render(w, "scep", d)
}

func scepFormInt(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("lifetimes must be positive whole numbers")
	}
	return n, nil
}

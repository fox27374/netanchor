package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type scepAdminData struct {
	CA, Status, Fingerprint, Secret string
	AllowDES                        bool
	CAs                             []caOptionData
	Profiles                        []CertTemplate
	Challenges                      []scepChallenge
	Shared                          []scepSharedChallenge
	URLs                            []string // enrollment URLs for the switch
}

// scepURLs lists the enrollment URLs, built from the host this page was reached on.
// The SCEP-only listener comes first. NETANCHOR_SCEP_PUBLIC_PORT is the port it is
// published on when that differs from the listener port (a container port mapping).
func scepURLs(r *http.Request) []string {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	var urls []string
	if addr := os.Getenv("NETANCHOR_SCEP_ADDR"); addr != "" {
		port := os.Getenv("NETANCHOR_SCEP_PUBLIC_PORT")
		if port == "" {
			_, port, _ = net.SplitHostPort(addr)
		}
		urls = append(urls, "http://"+net.JoinHostPort(host, port)+"/scep")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return append(urls, scheme+"://"+r.Host+"/scep")
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
		case "des":
			err = s.scep.setAllowDES(r.PostForm.Get("allow") == "on")
		case "revoke":
			err = s.scep.revoke(r.PostForm.Get("id"))
		case "challenge", "shared-challenge":
			// One create form; the kind radio picks per-device or shared.
			if r.PathValue("action") == "challenge" && r.PostForm.Get("kind") != "shared" {
				var days, hours int
				days, err = scepFormInt(r.PostForm.Get("days"))
				if err == nil {
					hours, err = scepFormInt(r.PostForm.Get("hours"))
				}
				if err == nil {
					secret, err = s.scep.challenge(r.PostForm.Get("profile"), strings.FieldsFunc(r.PostForm.Get("sans"), func(c rune) bool { return c == ',' || c == '\n' || c == '\r' }), days, hours)
				}
				break
			}
			var days, expiry int
			days, err = scepFormInt(r.PostForm.Get("days"))
			if err == nil {
				expiry, err = scepFormInt(r.PostForm.Get("expiry"))
			}
			var ranges []netip.Prefix
			if err == nil {
				ranges, err = parseSharedRanges(sharedFormList(r.PostForm.Get("ranges")))
			}
			if err == nil {
				secret, err = s.scep.sharedChallenge(r.PostForm.Get("profile"), ranges, sharedFormList(r.PostForm.Get("suffixes")), days, expiry)
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
	v := scepAdminData{Secret: secret, Status: "locked / unavailable", URLs: scepURLs(r)}
	s.store.scepMu.Lock()
	st, loadErr := s.scep.load()
	if loadErr == nil {
		v.CA, v.Challenges, v.Shared, v.AllowDES = st.CA, st.Challenges, st.Shared, st.AllowDES
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

// sharedFormList splits a textarea on commas and line breaks.
func sharedFormList(text string) []string {
	return strings.FieldsFunc(text, func(c rune) bool { return c == ',' || c == '\n' || c == '\r' })
}

// parseSharedRanges parses CIDR prefixes; bare addresses are refused so a /32 or /128 is explicit.
func parseSharedRanges(items []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR range %q: use address/length, for example 192.0.2.0/24", item)
		}
		out = append(out, p)
	}
	return out, nil
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

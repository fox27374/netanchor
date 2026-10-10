package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// gnoiPage is the data for templates/gnoi.html.
type gnoiPage struct {
	F        map[string]string // echoed form values; never the password or CA passphrase
	Builtins []CertTemplate
	Custom   []CertTemplate
	CAs      []caOptionData
	Steps    []gnoiStep
	Outcome  string // final line after a push attempt
	Class    string // alert class for Outcome: ok, warn or err
	CSRF     string // per-session token, same scheme as the backup page
}

func (s *Server) handleGNOIAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// no-referrer makes browsers send "Origin: null" on form POSTs, which backupCSRF rejects.
	w.Header().Set("Referrer-Policy", "same-origin")
	d := s.base(r, "Push to device (gNOI)", "gnoi")
	page := gnoiPage{F: map[string]string{}}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !s.backupCSRF(r) {
			http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
			return
		}
		page.F = gnoiEchoValues(r.PostForm)
		switch r.PathValue("action") {
		case "fingerprint":
			fp, err := gnoiProbe(r.Context(), s.gnoiAllow, strings.TrimSpace(r.PostForm.Get("target")))
			if err != nil {
				d.Error = err.Error()
			} else {
				page.F["fingerprint"] = fp
			}
		case "push":
			req, err := s.gnoiRequest(r, d.Username)
			if err != nil {
				d.Error = err.Error()
				break
			}
			ctx, cancel := context.WithTimeout(r.Context(), gnoiPushTimeout)
			steps, err := gnoiPush(ctx, s.store, s.gnoiAllow, req)
			cancel()
			page.Steps = steps
			switch {
			case err == nil:
				page.Class, page.Outcome = "ok", fmt.Sprintf("Installed and verified on %s as certificate %q.", req.Target, req.CertID)
			case errors.Is(err, errGNOIUnverified):
				page.Class, page.Outcome = "warn", errGNOIUnverified.Error()
			default:
				page.Class, page.Outcome = "err", "Push failed: "+err.Error()
			}
		default:
			http.NotFound(w, r)
			return
		}
	}
	page.CSRF = s.backupToken(r)
	page.Builtins = builtinTemplates()
	custom, err := s.store.LoadTemplates()
	if err != nil {
		d.Error = err.Error()
	}
	page.Custom = custom
	page.CAs = s.getIssueCAs()
	d.Data = page
	s.render(w, "gnoi", d)
}

// gnoiRequest validates the posted form and turns it into a push request. It
// does not contact the device.
func (s *Server) gnoiRequest(r *http.Request, admin string) (gnoiPushRequest, error) {
	req := gnoiPushRequest{
		Target:       strings.TrimSpace(r.PostForm.Get("target")),
		Username:     strings.TrimSpace(r.PostForm.Get("username")),
		Password:     r.PostForm.Get("password"),
		Verify:       r.PostForm.Get("verify"),
		Fingerprint:  r.PostForm.Get("fingerprint"),
		CAPassphrase: r.PostForm.Get("ca_passphrase"),
		CommonName:   strings.TrimSpace(r.PostForm.Get("cn")),
		Country:      strings.TrimSpace(r.PostForm.Get("country")),
		State:        strings.TrimSpace(r.PostForm.Get("state")),
		City:         strings.TrimSpace(r.PostForm.Get("city")),
		Organization: strings.TrimSpace(r.PostForm.Get("org")),
		Admin:        admin,
	}
	if req.Admin == "" {
		req.Admin = "(auth disabled)"
	}
	if r.PostForm.Get("rebind_ack") != "on" {
		return req, errors.New("confirm that this push may rebind the device's gRPC server")
	}
	if req.Verify == gnoiVerifyUnverified && r.PostForm.Get("unverified_ack") != "on" {
		return req, errors.New("confirm that unverified connections can expose the device credentials")
	}
	if !s.store.ValidCAID(r.PostForm.Get("ca")) {
		return req, errors.New("select a valid NetAnchor CA")
	}
	req.CAID = r.PostForm.Get("ca")
	t, ok := s.store.GetTemplate(strings.TrimSpace(r.PostForm.Get("template")))
	if !ok {
		return req, errors.New("select a valid certificate profile")
	}
	req.Template, req.ValidDays = t, t.ValidDays
	days, provided, err := parseRequestedDays(r)
	if err != nil {
		return req, err
	}
	if provided {
		req.ValidDays = days
	}
	req.DNSNames = splitLines(r.PostForm.Get("dns_sans"))
	for _, v := range splitLines(r.PostForm.Get("ip_sans")) {
		ip := net.ParseIP(v)
		if ip == nil {
			return req, errors.New("invalid IP SAN")
		}
		req.IPs = append(req.IPs, ip)
	}
	req.CertID = strings.TrimSpace(r.PostForm.Get("cert_id"))
	if req.CertID == "" {
		req.CertID = sanitizeCertID(req.CommonName)
	}
	return req, nil
}

// gnoiEchoValues copies the posted form for re-rendering, without secrets.
func gnoiEchoValues(v url.Values) map[string]string {
	out := map[string]string{}
	for k, vals := range v {
		if k == "password" || k == "ca_passphrase" || len(vals) == 0 {
			continue
		}
		out[k] = vals[0]
	}
	return out
}

// sanitizeCertID turns a common name into a default certificate id: ASCII
// letters, digits, '.', '-' and '_' only, at most 64 characters.
func sanitizeCertID(cn string) string {
	var b strings.Builder
	for _, c := range cn {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

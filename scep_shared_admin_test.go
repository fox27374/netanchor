package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSharedAdminFormValidationAndRender(t *testing.T) {
	f := newSCEPFixture(t)
	a, err := NewAuth(f.e.store, false, true)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(f.e.store, a)
	srv.scep = f.e
	admin := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		var r *http.Request
		if form == nil {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r = r.WithContext(context.WithValue(r.Context(), userCtxKey, User{Role: RoleAdmin}))
		w := httptest.NewRecorder()
		srv.Routes().ServeHTTP(w, r)
		return w
	}
	valid := func() url.Values {
		return url.Values{"profile": {"builtin:TLS-Server"}, "ranges": {"192.0.2.0/24"}, "suffixes": {"example.net"}, "days": {"365"}, "expiry": {"30"}}
	}
	bad := []struct {
		name, key, value, want string
	}{
		{"bare address", "ranges", "192.0.2.10", "CIDR range"},
		{"no ranges", "ranges", " , ", "at least one"},
		{"IPv4-mapped range", "ranges", "::ffff:192.0.2.0/120", "CIDR range"},
		{"leading dot suffix", "suffixes", ".example.net", "DNS suffix"},
		{"wildcard suffix", "suffixes", "*.example.net", "DNS suffix"},
		{"top-level suffix", "suffixes", "net", "DNS suffix"},
		{"zero expiry", "expiry", "0", "positive"},
		{"expiry over a year", "expiry", "366", "expiry must be 1"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			form := valid()
			form.Set(tc.key, tc.value)
			w := admin("POST", "/admin/scep/shared-challenge", form)
			if w.Code != 200 || !strings.Contains(w.Body.String(), tc.want) || strings.Contains(w.Body.String(), "Copy this challenge now") {
				t.Fatalf("status %d, body lacks %q", w.Code, tc.want)
			}
		})
	}
	st, _ := f.e.load()
	if len(st.Shared) != 0 {
		t.Fatal("invalid form created a shared challenge")
	}

	w := admin("POST", "/admin/scep/shared-challenge", valid())
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Copy this challenge now") {
		t.Fatalf("valid form: status %d", w.Code)
	}
	start := strings.Index(body, "<pre>") + 5
	end := strings.Index(body, "</pre>")
	if start < 5 || end < start {
		t.Fatal("missing shared secret")
	}
	secret := body[start:end]
	st, _ = f.e.load()
	if len(st.Shared) != 1 || st.Shared[0].Hash != hashSCEP([]byte(secret)) || st.Shared[0].Ranges[0].String() != "192.0.2.0/24" || st.Shared[0].Suffixes[0] != "example.net" {
		t.Fatalf("shared challenge not stored: %+v", st.Shared)
	}

	// One issuance, then the page must list it with a link and must not redisplay the secret.
	csr := f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "switch"}})
	der, status := f.enrollAt(t, csr, "192.0.2.10:1")
	issued := f.response(t, der, status, true)
	page := admin("GET", "/admin/scep", nil)
	html := page.Body.String()
	if page.Code != 200 || strings.Contains(html, secret) {
		t.Fatalf("page status %d or secret redisplayed", page.Code)
	}
	for _, want := range []string{"Shared · active", "192.0.2.0/24", "under example.net", "192.0.2.10", "/cert/" + serialString(issued.SerialNumber), "active"} {
		if !strings.Contains(html, want) {
			t.Errorf("SCEP page lacks %q", want)
		}
	}

	// Revoke through the existing revoke action; the page shows the challenge as revoked.
	w = admin("POST", "/admin/scep/revoke", url.Values{"id": {hashSCEP([]byte(secret))}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("revoke status %d: %s", w.Code, w.Body.String())
	}
	if html := admin("GET", "/admin/scep", nil).Body.String(); !strings.Contains(html, "revoked") {
		t.Fatal("revoked shared challenge not shown")
	}
}

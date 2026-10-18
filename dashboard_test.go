package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDashboardStatusFiltersAndTiles(t *testing.T) {
	now := time.Now() // handlers use the real clock
	for _, c := range []struct {
		notAfter time.Time
		want     string
	}{
		{now, "expired"},
		{now.Add(-time.Second), "expired"},
		{now.Add(time.Hour), "expiring"},
		{now.Add(deviceExpiryWarn), "expiring"},
		{now.Add(deviceExpiryWarn + time.Second), "valid"},
	} {
		if got := certStatus(c.notAfter, now); got != c.want {
			t.Errorf("certStatus(%v) = %q, want %q", c.notAfter.Sub(now), got, c.want)
		}
	}

	recs := []CertRecord{
		{Serial: "01", CommonName: "web.example", Kind: "issued", IssuerID: "root", TemplateName: "server", NotAfter: now.Add(400 * 24 * time.Hour)},
		{Serial: "02", CommonName: "Radius.example", Kind: "csr", IssuerID: "ab12", TemplateName: "radius", NotAfter: now.Add(10 * 24 * time.Hour)},
		{Serial: "03", CommonName: "sw99", Kind: "issued", IssuerID: "root", Provenance: "scep", NotAfter: now.Add(-time.Hour)},
		{Serial: "04", CommonName: "ca", Kind: "root", IssuerID: "root", NotAfter: now.Add(3000 * 24 * time.Hour)},
	}
	names := func(rows []certRow) string {
		var out []string
		for _, r := range rows {
			out = append(out, r.CommonName)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		name string
		f    certFilter
		want string
	}{
		{"none sorted soonest first, CAs excluded", certFilter{}, "sw99,Radius.example,web.example"},
		{"q is case-insensitive", certFilter{Q: "RADIUS"}, "Radius.example"},
		{"status", certFilter{Status: "expiring"}, "Radius.example"},
		{"issuer is direct only", certFilter{Issuer: "root"}, "sw99,web.example"},
		{"type csr", certFilter{Type: "csr"}, "Radius.example"},
		{"type scep", certFilter{Type: "scep"}, "sw99"},
		{"template", certFilter{Template: "server"}, "web.example"},
	} {
		if got := names(filterCerts(recs, c.f, now)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}

	s, a := backupFixture(t)
	for _, r := range recs[:3] {
		backupCheck(t, s.AddRecord(r))
	}
	routes := a.Middleware(NewServer(s, a).Routes())
	admin := httptest.NewRecorder()
	a.issueSession(admin, "admin")
	get := func(path string) string {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Cookie", admin.Result().Cookies()[0].String())
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("GET %s = %d", path, w.Code)
		}
		return w.Body.String()
	}

	body := get("/certificates?status=expired")
	if !strings.Contains(body, "sw99") || strings.Contains(body, "web.example") || strings.Contains(body, "Radius.example") {
		t.Errorf("status=expired should render only sw99")
	}
	if body := get("/certificates?status=expired&type=csr"); !strings.Contains(body, "No certificates match the filters.") {
		t.Errorf("empty filter result should say no match")
	}
	if body := get("/certificates?status=bogus"); !strings.Contains(body, "web.example") {
		t.Errorf("unknown status should not filter")
	}

	dash := get("/")
	for _, want := range []string{"Total</span><b>3</b>", "Valid</span><b>1</b>", "Expiring</span><b>1</b>", "Expired</span><b>1</b>"} {
		if !strings.Contains(dash, want) {
			t.Errorf("dashboard missing tile %q", want)
		}
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func definitionForm1(name string) url.Values {
	return url.Values{
		"name": {name}, "ca": {caRoot}, "profile": {"TLS-Server"}, "valid_days": {"90"},
		"country": {"NL"}, "state": {"Utrecht"}, "organization": {"Example Corp"},
	}
}

func TestDefinitionCRUD(t *testing.T) {
	st, srv := deviceTestStore(t, false)
	_, err := CreateCA(st, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 3650})
	backupCheck(t, err)

	rec := devicePost(srv, "/definitions/save", definitionForm1("core-tls"))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/definitions" {
		t.Fatalf("create: status %d: %s", rec.Code, rec.Body.String())
	}
	defs, err := st.ListDefinitions()
	backupCheck(t, err)
	if len(defs) != 1 || defs[0].CertID != "netanchor-core-tls" || defs[0].Profile != "TLS-Server" || defs[0].ValidDays != 90 {
		t.Fatalf("stored definitions = %+v", defs)
	}
	id := defs[0].ID

	if dup := devicePost(srv, "/definitions/save", definitionForm1("Core-TLS")); dup.Code != http.StatusOK || !strings.Contains(dup.Body.String(), "already exists") {
		t.Fatalf("case-insensitive duplicate name not refused: status %d", dup.Code)
	}

	edit := definitionForm1("core-tls")
	edit.Set("id", id)
	edit.Set("valid_days", "120")
	edit.Set("cert_id", "core.tls-1")
	edit.Set("extra_sans", "lb.example.net, 192.0.2.99")
	if rec := devicePost(srv, "/definitions/save", edit); rec.Code != http.StatusSeeOther {
		t.Fatalf("edit: status %d: %s", rec.Code, rec.Body.String())
	}
	got, ok, err := st.GetDefinition(id)
	backupCheck(t, err)
	if !ok || got.ValidDays != 120 || got.CertID != "core.tls-1" || len(got.ExtraSANs) != 2 || got.Created.IsZero() {
		t.Fatalf("after edit = %+v", got)
	}
	if rec := deviceGet(srv, "/definitions/"+id+"/edit"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "core-tls") {
		t.Fatalf("edit form: status %d", rec.Code)
	}

	if rec := devicePost(srv, "/definitions/"+id+"/delete", url.Values{}); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: status %d", rec.Code)
	}
	if defs, _ := st.ListDefinitions(); len(defs) != 0 {
		t.Fatal("definition not deleted")
	}
	if rec := devicePost(srv, "/definitions/"+id+"/delete", url.Values{}); rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing: status %d, want 404", rec.Code)
	}
}

func TestDefinitionValidation(t *testing.T) {
	st, srv := deviceTestStore(t, false)
	_, err := CreateCA(st, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 30})
	backupCheck(t, err)
	backupCheck(t, st.AddTemplate(CertTemplate{Name: "ec-only", Profile: profileServer, Algo: algoECP256, ValidDays: 90, MaxDays: 365, AllowedAlgos: []keyAlgo{algoECP256}}))

	cases := map[string]func(url.Values){
		"bad name":          func(v url.Values) { v.Set("name", "core tls") },
		"unknown CA":        func(v url.Values) { v.Set("ca", "nope") },
		"client profile":    func(v url.Values) { v.Set("profile", "TLS-Client") },
		"no RSA 2048":       func(v url.Values) { v.Set("profile", "ec-only") },
		"no organization":   func(v url.Values) { v.Set("organization", "") },
		"validity over max": func(v url.Values) { v.Set("valid_days", "366") },
		"validity zero":     func(v url.Values) { v.Set("valid_days", "0") },
		"past CA expiry":    func(v url.Values) { v.Set("valid_days", "90") },
		"bad cert id":       func(v url.Values) { v.Set("cert_id", "a/b") },
		"bad extra SAN":     func(v url.Values) { v.Set("extra_sans", "bad_name!") },
	}
	for name, mutate := range cases {
		f := definitionForm1("core")
		mutate(f)
		if rec := devicePost(srv, "/definitions/save", f); rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d, want 200 with an error", name, rec.Code)
		}
	}
	if defs, _ := st.ListDefinitions(); len(defs) != 0 {
		t.Fatalf("invalid definitions stored: %+v", defs)
	}

	// The CA lives 30 days, so a 20-day validity must be accepted.
	fit := definitionForm1("fits-ca")
	fit.Set("valid_days", "20")
	if rec := devicePost(srv, "/definitions/save", fit); rec.Code != http.StatusSeeOther {
		t.Fatalf("valid definition refused: %d %s", rec.Code, definitionErr(rec.Body.String()))
	}
}

func TestDefinitionRolesAndCSRF(t *testing.T) {
	st, a := backupFixture(t)
	srv := NewServer(st, a)
	backupCheck(t, a.AddUser("viewer", "viewer password", RoleViewer))
	viewer := httptest.NewRecorder()
	a.issueSession(viewer, "viewer")
	cookie := viewer.Result().Cookies()[0].String()
	routes := a.Middleware(srv.Routes())

	get := httptest.NewRequest(http.MethodGet, "/definitions", nil)
	get.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Device certificate definitions") {
		t.Fatalf("viewer cannot read definitions: %d", rec.Code)
	}
	if rec := deviceGetWithCookie(routes, "/definitions/new", cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET /definitions/new: status %d, want 403", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/definitions/save", strings.NewReader(definitionForm1("x").Encode()))
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	routes.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST save: status %d, want 403", rec.Code)
	}

	// Admin POST without a CSRF token is refused.
	bad := httptest.NewRequest(http.MethodPost, "/definitions/save", strings.NewReader(definitionForm1("y").Encode()))
	bad.Header.Set("Origin", "http://"+bad.Host)
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, bad)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token: status %d, want 403", rec.Code)
	}
	if defs, _ := st.ListDefinitions(); len(defs) != 0 {
		t.Fatal("definition stored despite a missing CSRF token")
	}
}

func TestDefinitionBackupRoundTrip(t *testing.T) {
	s, _ := backupFixture(t)
	d := CertDefinition{
		Name: "core-tls", CAID: caRoot, Profile: "TLS-Server", Country: "NL", State: "Utrecht", Organization: "Example",
		ValidDays: 90, CertID: "netanchor-core-tls", ExtraSANs: []string{"lb.example.net"}, Created: time.Now().UTC(),
	}
	backupCheck(t, s.SaveDefinition(&d))

	plain, err := snapshotBackup(s)
	backupCheck(t, err)
	sealed, err := sealBackup(plain, testBackupPassword)
	backupCheck(t, err)
	opened, err := openBackup(sealed, testBackupPassword)
	backupCheck(t, err)
	stage, err := stageBackup(t.TempDir(), opened, false)
	backupCheck(t, err)

	restored, err := (&Store{dir: stage}).ListDefinitions()
	backupCheck(t, err)
	if len(restored) != 1 || restored[0].ID != d.ID || restored[0].CertID != "netanchor-core-tls" || len(restored[0].ExtraSANs) != 1 {
		t.Fatalf("restored definitions = %+v", restored)
	}
}

func definitionErr(body string) string {
	m := regexp.MustCompile(`(?s)class="alert[^"]*"[^>]*>(.*?)</div>`).FindStringSubmatch(body)
	if m == nil {
		return "no alert in page"
	}
	return m[1]
}

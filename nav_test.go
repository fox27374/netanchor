package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCertificatesPageAndNavGroups(t *testing.T) {
	s, a := backupFixture(t)
	srv := NewServer(s, a)
	routes := a.Middleware(srv.Routes())
	backupCheck(t, a.AddUser("viewer", "viewer password", RoleViewer))
	admin := httptest.NewRecorder()
	a.issueSession(admin, "admin")
	viewer := httptest.NewRecorder()
	a.issueSession(viewer, "viewer")
	for _, tc := range []struct {
		name   string
		cookie string
		want   []string
		not    []string
	}{
		{"admin", admin.Result().Cookies()[0].String(), []string{"Certificate Management", "Device Management", "Issue Certificate", "Push (gNOI)", "Issued certificates"}, nil},
		{"viewer", viewer.Result().Cookies()[0].String(), []string{"Certificate Management", "Device Management", "Issued certificates", "SCEP"}, []string{"Issue Certificate", "Push (gNOI)"}},
	} {
		r := httptest.NewRequest("GET", "/certificates", nil)
		r.Header.Set("Cookie", tc.cookie)
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s GET /certificates = %d", tc.name, w.Code)
		}
		body := w.Body.String()
		for _, s := range tc.want {
			if !strings.Contains(body, s) {
				t.Errorf("%s: /certificates missing %q", tc.name, s)
			}
		}
		for _, s := range tc.not {
			if strings.Contains(body, s) {
				t.Errorf("%s: /certificates unexpectedly contains %q", tc.name, s)
			}
		}
	}
}

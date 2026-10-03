package main

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCASuccessRedirectAndOneTimeNotice(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth(store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(store, auth).Routes()

	post := func(path string, form url.Values, title, body, listed string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/ca" {
			t.Fatalf("POST %s: status %d, location %q, body %s", path, response.Code, response.Header().Get("Location"), response.Body.String())
		}
		var flash *http.Cookie
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == caFlashCookie {
				flash = cookie
			}
		}
		if flash == nil || !flash.HttpOnly || flash.Path != "/ca" || strings.Contains(flash.Value, title) || strings.Contains(flash.Value, listed) {
			t.Fatalf("POST %s: bad flash cookie: %+v", path, flash)
		}
		get := func(cookie *http.Cookie) *httptest.ResponseRecorder {
			t.Helper()
			r := httptest.NewRequest(http.MethodGet, "/ca", nil)
			if cookie != nil {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("GET /ca: status %d", w.Code)
			}
			return w
		}
		page := get(flash)
		for _, text := range []string{title, body, listed, "Dismiss notification"} {
			if !strings.Contains(html.UnescapeString(page.Body.String()), text) {
				t.Errorf("GET /ca missing %q", text)
			}
		}
		cleared := false
		for _, cookie := range page.Result().Cookies() {
			if cookie.Name == caFlashCookie && cookie.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Error("GET /ca did not clear flash cookie")
		}
		if again := get(flash); strings.Contains(again.Body.String(), "Dismiss notification") || strings.Contains(again.Body.String(), body) {
			t.Errorf("GET /ca replayed success notice")
		}
	}

	post("/ca/root", url.Values{"common_name": {"Test Root"}, "algo": {"ecp256"}},
		"Root CA created", "Your root CA is ready. You can now issue certificates, sign CSRs, and optionally create an intermediate CA.", "Test Root")
	post("/ca/intermediate", url.Values{"common_name": {"Test Intermediate"}, "algo": {"ecp256"}, "parent": {"root"}},
		"Intermediate CA created", "Your intermediate CA is ready. You can now choose it as the issuer when creating certificates or signing CSRs.", "Test Intermediate")
	cas, err := store.CAs()
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, ca := range cas {
		if ca.Record.CommonName == "Test Intermediate" {
			id = ca.ID
		}
	}
	if id == "" {
		t.Fatal("intermediate missing from listing")
	}
	post("/ca/delete/"+id, url.Values{"confirm_name": {"Test Intermediate"}},
		"CA deleted", `"Test Intermediate", its sub-CAs and all certificates they issued were moved to the trash folder.`, "Test Root")
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/ca", nil))
	if strings.Contains(page.Body.String(), "Test Intermediate") {
		t.Error("deleted CA remains in refreshed listing")
	}
}

func TestCAFailureAndForgedFlash(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth(store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(store, auth).Routes()
	req := httptest.NewRequest(http.MethodPost, "/ca/root", strings.NewReader("passphrase=a&passphrase_confirm=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Passphrases do not match.") || w.Header().Get("Location") != "" {
		t.Fatalf("failure changed: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/ca", nil)
	req.AddCookie(&http.Cookie{Name: caFlashCookie, Value: "forged"})
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "Dismiss notification") {
		t.Error("forged flash token displayed a notice")
	}
}

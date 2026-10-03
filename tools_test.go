package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func toolTestCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tool.example"}, Issuer: pkix.Name{CommonName: "Tool CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"tool.example"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}
func TestDecodeToolsPEMMultiAndWarnings(t *testing.T) {
	_, der := toolTestCert(t)
	input := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")})...)
	items, warn := decodeToolInput(input, "")
	if len(items) != 1 || len(warn) != 1 {
		t.Fatalf("items=%d warnings=%v", len(items), warn)
	}
	if items[0].Cert.Subject.CommonName != "tool.example" || len(items[0].Cert.DNSNames) != 1 {
		t.Fatal("certificate details not decoded")
	}
}
func TestDecodeToolsPKCS7RoundTrip(t *testing.T) {
	one, _ := toolTestCert(t)
	two, der := toolTestCert(t)
	two, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encodePKCS7Certs([]*x509.Certificate{one, two})
	if err != nil {
		t.Fatal(err)
	}
	items, warn := decodeToolInput(b, "")
	if len(items) != 2 || len(warn) != 0 {
		t.Fatalf("items=%d warnings=%v", len(items), warn)
	}
}

func TestDecodePKCS12TrustStore(t *testing.T) {
	cert, _ := toolTestCert(t)
	p12, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{cert}, "store password")
	if err != nil {
		t.Fatal(err)
	}
	items, warnings := decodeToolInput(p12, "store password")
	if len(items) != 1 || items[0].Cert == nil || len(warnings) != 0 {
		t.Fatalf("trust store: items=%v warnings=%v", items, warnings)
	}
}

func TestDecodeMixedPEMBlocksPreservesOrderAndWarnings(t *testing.T) {
	first, _ := toolTestCert(t)
	second, _ := toolTestCert(t)
	p7, err := encodePKCS7Certs([]*x509.Certificate{second})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(p7)
	input := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Raw}), pem.EncodeToMemory(block)...)
	input = append(input, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})...)
	items, warnings := decodeToolInput(input, "")
	if len(items) != 2 || len(warnings) != 1 {
		t.Fatalf("items=%d warnings=%v", len(items), warnings)
	}
	if !bytes.Equal(items[0].Cert.Raw, first.Raw) || !bytes.Equal(items[1].Cert.Raw, second.Raw) {
		t.Fatal("mixed certificate block ordering was not preserved")
	}
}

func TestDecodeOpenSSLExternalPKCS7(t *testing.T) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl unavailable")
	}
	cert, _ := toolTestCert(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	derPath := filepath.Join(dir, "bundle.der")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "crl2pkcs7", "-nocrl", "-certfile", certPath, "-outform", "DER", "-out", derPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl crl2pkcs7: %v: %s", err, out)
	}
	der, err := os.ReadFile(derPath)
	if err != nil {
		t.Fatal(err)
	}
	items, warn := decodeToolInput(der, "")
	if len(items) != 1 || len(warn) != 0 || items[0].Cert.Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("external PKCS#7 result: items=%d warnings=%v", len(items), warn)
	}
}
func TestDecodeToolsNoRecognized(t *testing.T) {
	items, warn := decodeToolInput([]byte("nonsense"), "")
	if len(items) != 0 || len(warn) == 0 || !strings.Contains(warn[0], "recognized") {
		t.Fatalf("items=%v warnings=%v", items, warn)
	}
}

func TestDecodeToolsDERCSRKeyAndPKCS12(t *testing.T) {
	cert, certDER := toolTestCert(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "request.example"}, DNSNames: []string{"request.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]struct {
		data []byte
		kind string
	}{"cert": {certDER, "Certificate"}, "csr": {csrDER, "CSR"}} {
		items, warn := decodeToolInput(value.data, "")
		if len(items) != 1 || items[0].Kind != value.kind || len(warn) != 0 {
			t.Fatalf("%s: items=%v warnings=%v", name, items, warn)
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	items, _ := decodeToolInput(keyDER, "")
	if len(items) != 1 || items[0].Key == nil {
		t.Fatal("PKCS8 DER key not decoded")
	}
	p12, err := pkcs12.Modern.Encode(key, cert, nil, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	items, warn := decodeToolInput(p12, "correct horse")
	if len(items) != 2 || len(warn) != 0 {
		t.Fatalf("PKCS12: %d items %v", len(items), warn)
	}
	items, warn = decodeToolInput(p12, "wrong")
	if len(items) != 0 || len(warn) == 0 || !strings.Contains(strings.ToLower(strings.Join(warn, " ")), "password") {
		t.Fatalf("wrong password feedback: %v", warn)
	}
}

func TestToolEntrySessionBindingAndExpiry(t *testing.T) {
	toolsCache.Lock()
	toolsCache.entries["testtoken"] = toolEntry{Owner: "alice", Expires: time.Now().Add(time.Minute)}
	toolsCache.entries["expiredtoken"] = toolEntry{Owner: "alice", Expires: time.Now().Add(-time.Minute)}
	toolsCache.Unlock()
	userReq := func(name string) *http.Request {
		r := httptest.NewRequest("GET", "/tools/testtoken", nil)
		r.SetPathValue("token", "testtoken")
		return r.WithContext(context.WithValue(r.Context(), userCtxKey, User{Username: name, Role: RoleViewer}))
	}
	if _, ok := toolEntryFor(userReq("alice")); !ok {
		t.Fatal("own result unavailable")
	}
	if _, ok := toolEntryFor(userReq("bob")); ok {
		t.Fatal("other user accessed result")
	}
	r := httptest.NewRequest("GET", "/tools/expiredtoken", nil).WithContext(context.WithValue(context.Background(), userCtxKey, User{Username: "alice"}))
	r.SetPathValue("token", "expiredtoken")
	if _, ok := toolEntryFor(r); ok {
		t.Fatal("expired result available")
	}
}

func TestViewerCannotAccessKeyExports(t *testing.T) {
	if requiresAdmin("POST", "/tools/abc/download") {
		t.Fatal("public tools downloads should pass middleware and enforce key policy in handler")
	}
	if requiresAdmin(http.MethodGet, "/tools/abc") {
		t.Fatal("viewer inspection should be allowed")
	}
}

func TestToolsViewerHTTPDownloadsAndSessionBinding(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth(store, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = auth.AddUser("alice", "pw", RoleViewer); err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, auth)
	cert, _ := toolTestCert(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	sw := httptest.NewRecorder()
	auth.issueSession(sw, "alice")
	cookie := sw.Result().Cookies()[0]
	const token = "http-test-token"
	toolsCache.Lock()
	toolsCache.entries[token] = toolEntry{Owner: "alice", Session: cookie.Value, Expires: time.Now().Add(time.Minute), Items: []toolItem{{Kind: "Certificate", Cert: cert, Match: -1}, {Kind: "Private key", Key: key, KeyDER: keyDER, Match: 0}}}
	toolsCache.Unlock()
	h := auth.Middleware(server.Routes())
	post := func(item, what, password string) *httptest.ResponseRecorder {
		v := url.Values{"item": {item}, "what": {what}, "password": {password}}
		r := httptest.NewRequest(http.MethodPost, "/tools/"+token+"/download", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://example.test")
		r.Host = "example.test"
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := post("0", "pem", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "CERTIFICATE") {
		t.Fatalf("viewer public download status=%d body=%s", w.Code, w.Body.String())
	}
	if w := post("1", "pem", ""); w.Code != http.StatusNotFound {
		t.Fatalf("viewer private key status=%d", w.Code)
	}
	if w := post("1", "p12", "export"); w.Code != http.StatusBadRequest {
		t.Fatalf("viewer PKCS12 status=%d", w.Code)
	}
	otherW := httptest.NewRecorder()
	time.Sleep(time.Second)
	auth.issueSession(otherW, "alice")
	r := httptest.NewRequest("GET", "/tools/"+token, nil)
	r.AddCookie(otherW.Result().Cookies()[0])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-session status=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader("pem=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.test")
	r.Host = "example.test"
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d", w.Code)
	}
}

func TestToolsBundleDoesNotRequireItemIndex(t *testing.T) {
	cert, _ := toolTestCert(t)
	toolsCache.Lock()
	toolsCache.entries["bundle-test"] = toolEntry{Owner: "admin:disabled", Expires: time.Now().Add(time.Minute), Items: []toolItem{{Cert: cert}}}
	toolsCache.Unlock()
	s := &Server{auth: &Auth{enabled: false}}
	r := httptest.NewRequest("POST", "/tools/bundle-test/download", strings.NewReader("what=bundle"))
	r.SetPathValue("token", "bundle-test")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://example.test")
	r.Host = "example.test"
	w := httptest.NewRecorder()
	s.handleToolsDownload(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("bundle status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestToolsPKCS12ExportRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "export.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	const token = "export-test"
	toolsCache.Lock()
	toolsCache.entries[token] = toolEntry{Owner: "admin:disabled", Expires: time.Now().Add(time.Minute), Items: []toolItem{
		{Kind: "Certificate", Cert: cert, Match: -1},
		{Kind: "Private key", Key: key, Match: 0},
	}}
	toolsCache.Unlock()
	s := &Server{auth: &Auth{enabled: false}}
	form := url.Values{"what": {"p12"}, "item": {"1"}, "password": {"new export password"}}
	r := httptest.NewRequest(http.MethodPost, "/tools/"+token+"/download", strings.NewReader(form.Encode()))
	r.SetPathValue("token", token)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://example.test")
	r.Host = "example.test"
	w := httptest.NewRecorder()
	s.handleToolsDownload(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", w.Code, w.Body.String())
	}
	items, warnings := decodeToolInput(w.Body.Bytes(), "new export password")
	if len(items) != 2 || len(warnings) != 0 || items[0].Key == nil || items[1].Cert.Subject.CommonName != "export.example" {
		t.Fatalf("exported PKCS#12 decode: items=%v warnings=%v", items, warnings)
	}
}

func TestToolsPasswordPreflight(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "preflight.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := pkcs12.Modern.Encode(key, cert, nil, "secret")
	if err != nil {
		t.Fatal(err)
	}
	passwordless, err := pkcs12.Passwordless.Encode(key, cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	trustStore, err := pkcs12.Passwordless.EncodeTrustStore([]*x509.Certificate{cert}, "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth(store, false, false)
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Middleware(NewServer(store, auth).Routes())
	for _, tc := range []struct {
		name, state string
		data        []byte
	}{
		{"protected", "required", protected},
		{"passwordless", "not-required", passwordless},
		{"passwordless-trust-store", "not-required", trustStore},
		{"invalid", "unknown", []byte("not a PKCS#12 file")},
		{"malformed-pfx-shaped", "unknown", []byte{0x30, 0x03, 0x02, 0x01, 0x03}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			file, err := mw.CreateFormFile("file", "input.p12")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(tc.data); err != nil {
				t.Fatal(err)
			}
			if err := mw.Close(); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/tools/check-password", &body)
			r.Header.Set("Content-Type", mw.FormDataContentType())
			r.Header.Set("Origin", "http://example.test")
			r.Host = "example.test"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"`+tc.state+`"`) {
				t.Fatalf("preflight status=%d body=%s, want %s", w.Code, w.Body.String(), tc.state)
			}
		})
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	file, err := mw.CreateFormFile("file", "protected.p12")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(protected); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/tools", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "http://example.test")
	r.Host = "example.test"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "This PKCS#12 file is password-protected") || strings.Contains(w.Body.String(), "DER input could not be decoded") {
		t.Fatalf("missing password status=%d body=%s", w.Code, w.Body.String())
	}
}

func multipartToolsRequest(t *testing.T, fileParts int, pasted string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if pasted != "" {
		if err := mw.WriteField("pem", pasted); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < fileParts; i++ {
		part, err := mw.CreateFormFile("file", fmt.Sprintf("input-%d.pem", i))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write([]byte("not a certificate"))
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/tools", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "http://example.test")
	r.Host = "example.test"
	return r
}

func TestToolsMultipartBoundsAndSingleFile(t *testing.T) {
	s := &Server{auth: &Auth{enabled: false}}
	_, der := toolTestCert(t)
	var r *http.Request
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	f, err := mw.CreateFormFile("file", "cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	_ = mw.Close()
	r = httptest.NewRequest(http.MethodPost, "/tools", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "http://example.test")
	r.Host = "example.test"
	w := httptest.NewRecorder()
	s.handleToolsDecode(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("multipart success status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Header().Get("Location"), " ") {
		t.Fatal("unexpected redirect")
	}
	r = multipartToolsRequest(t, 2, "")
	w = httptest.NewRecorder()
	s.handleToolsDecode(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "exactly one") {
		t.Fatalf("multiple upload status=%d body=%s", w.Code, w.Body.String())
	}
	r = multipartToolsRequest(t, 0, strings.Repeat("x", toolsMaxUpload+1))
	w = httptest.NewRecorder()
	s.handleToolsDecode(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "too large") {
		t.Fatalf("oversized paste status=%d", w.Code)
	}
	var huge bytes.Buffer
	mw = multipart.NewWriter(&huge)
	f, err = mw.CreateFormFile("file", "big.pem")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(f, strings.NewReader(strings.Repeat("x", toolsMaxUpload+1)))
	_ = mw.Close()
	r = httptest.NewRequest(http.MethodPost, "/tools", &huge)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "http://example.test")
	r.Host = "example.test"
	w = httptest.NewRecorder()
	s.handleToolsDecode(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "too large") {
		t.Fatalf("oversized upload status=%d body=%s", w.Code, w.Body.String())
	}
}

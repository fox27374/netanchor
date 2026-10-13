package main

import (
	"bytes"
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSCEPURLs(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://pki.example.net:8443/admin/scep", nil)
	r.TLS = &tls.ConnectionState{}
	t.Setenv("NETANCHOR_SCEP_ADDR", "0.0.0.0:8080")
	t.Setenv("NETANCHOR_SCEP_PUBLIC_PORT", "8085")
	got := strings.Join(scepURLs(r), " ")
	if got != "http://pki.example.net:8085/scep https://pki.example.net:8443/scep" {
		t.Fatalf("urls = %s", got)
	}
	os.Unsetenv("NETANCHOR_SCEP_PUBLIC_PORT")
	if got := scepURLs(r)[0]; got != "http://pki.example.net:8080/scep" {
		t.Fatalf("listener port url = %s", got)
	}
	os.Unsetenv("NETANCHOR_SCEP_ADDR")
	if got := strings.Join(scepURLs(r), " "); got != "https://pki.example.net:8443/scep" {
		t.Fatalf("gui only = %s", got)
	}
}

func TestLogSCEPRecordsOperationAndStatus(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	h := logSCEP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	r := httptest.NewRequest(http.MethodGet, "/scep/cgi-bin/pkiclient.exe?operation=GetCACert&message=x", nil)
	r.RemoteAddr = "172.24.80.240:51000"
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !strings.Contains(buf.String(), "scep GET /scep/cgi-bin/pkiclient.exe op=GetCACert from=172.24.80.240 status=503") {
		t.Fatalf("log = %q", buf.String())
	}
}

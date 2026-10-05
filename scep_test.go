package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

type scepFixture struct {
	e        *SCEPService
	ca       string
	key      *rsa.PrivateKey
	identity *x509.Certificate
}

func newSCEPFixture(t *testing.T) *scepFixture {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CreateCA(s, CAParams{CommonName: "root", Algo: algoECP256, ValidDays: 1000}); err != nil {
		t.Fatal(err)
	}
	r, err := CreateIntermediate(s, IntermediateParams{CommonName: "SCEP", Algo: algoRSA2048, ValidDays: 500, ParentID: caRoot, SCEP: true, Passphrase: "test-pass"})
	if err != nil {
		t.Fatal(err)
	}
	e := newSCEPService(s)
	if err = e.selectCA(r.CAID, "test-pass"); err != nil {
		t.Fatal(err)
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "switch"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &scepFixture{e: e, ca: r.CAID, key: k, identity: c}
}

func (f *scepFixture) challenge(t *testing.T) string {
	t.Helper()
	s, err := f.e.challenge("builtin:TLS-Server", []string{"switch.example.net", "192.0.2.10"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (f *scepFixture) csr(t *testing.T, secret string, dns []string) *x509.CertificateRequest {
	t.Helper()
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: "switch"}, DNSNames: dns, SignatureAlgorithm: x509.SHA256WithRSA}, ChallengePassword: secret}, f.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func (f *scepFixture) request(t *testing.T, csr *x509.CertificateRequest) *scep.PKIMessage {
	t.Helper()
	m, err := scep.NewCSRRequest(csr, &scep.PKIMessage{MessageType: scep.PKCSReq, Recipients: []*x509.Certificate{f.e.cert}, SignerCert: f.identity, SignerKey: f.key})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func (f *scepFixture) response(t *testing.T, raw []byte, status int, success bool) *x509.Certificate {
	t.Helper()
	if status != 200 {
		t.Fatalf("HTTP status %d", status)
	}
	p, err := pkcs7.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Signers) != 1 || !p.Signers[0].DigestAlgorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256) {
		t.Fatal("response is not SHA-256 signed")
	}
	m, err := scep.ParsePKIMessage(raw, scep.WithCACerts([]*x509.Certificate{f.e.cert}))
	if err != nil {
		t.Fatal(err)
	}
	if !success {
		if m.PKIStatus != scep.FAILURE {
			t.Fatalf("expected failure: %s", m.PKIStatus)
		}
		return nil
	}
	if m.PKIStatus != scep.SUCCESS {
		t.Fatalf("enrollment failed: %s", m.FailInfo)
	}
	if _, err = inspectEnvelope(p.Content); err != nil {
		t.Fatalf("response encryption: %v", err)
	}
	if err = m.DecryptPKIEnvelope(f.identity, f.key); err != nil {
		t.Fatal(err)
	}
	if err = m.Certificate.CheckSignatureFrom(f.e.cert); err != nil {
		t.Fatal(err)
	}
	return m.Certificate
}

func TestSCEPEnrollmentRetryRestartConcurrency(t *testing.T) {
	f := newSCEPFixture(t)
	secret := f.challenge(t)
	csr := f.csr(t, secret, nil) // Older clients omit SANs; authorization supplies them.
	req := f.request(t, csr)
	raw, status := f.e.enroll(req.Raw)
	cert := f.response(t, raw, status, true)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "switch.example.net" || len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("wrong authorized SANs: %+v", cert)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.IsCA {
		t.Fatal("wrong certificate purpose")
	}
	if cert.NotAfter.After(time.Now().AddDate(0, 0, 365)) || cert.NotAfter.Before(time.Now().AddDate(0, 0, 364)) {
		t.Fatal("wrong default validity")
	}
	m, err := scep.ParsePKIMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.TransactionID != req.TransactionID || !bytes.Equal(m.RecipientNonce, req.SenderNonce) {
		t.Fatal("response correlation mismatch")
	}
	// Re-encryption with a fresh nonce remains the same authenticated transaction.
	retry := f.request(t, csr)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, s := f.e.enroll(retry.Raw)
			c := f.response(t, b, s, true)
			if !bytes.Equal(c.Raw, cert.Raw) {
				t.Error("retry reissued certificate")
			}
		}()
	}
	wg.Wait()
	st, err := f.e.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Challenges) != 1 || st.Challenges[0].Hash == secret || !st.Challenges[0].Published {
		t.Fatal("bad durable state")
	}
	b, err := os.ReadFile(f.e.path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(secret)) {
		t.Fatal("plaintext challenge persisted")
	}
	recs, _ := f.e.store.Records()
	if len(recs) != 3 {
		t.Fatalf("duplicate issuance: %d records", len(recs))
	}
	rec, _ := f.e.store.RecordBySerial(serialString(cert.SerialNumber))
	if rec.Kind != "csr" || rec.Provenance != "scep" || rec.HasKey {
		t.Fatal("wrong provenance")
	}
	f.e = newSCEPService(f.e.store)
	if err := f.e.startup(""); err != nil {
		t.Fatal(err)
	}
	if _, s := f.e.enroll(req.Raw); s != 503 {
		t.Fatal("restart did not lock")
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("test-pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.e.startup(path); err != nil {
		t.Fatal(err)
	}
	raw, status = f.e.enroll(req.Raw)
	again := f.response(t, raw, status, true)
	if !bytes.Equal(again.Raw, cert.Raw) {
		t.Fatal("restart reissued")
	}
	other := f.request(t, f.csr(t, secret, []string{"switch.example.net"}))
	raw, status = f.e.enroll(other.Raw)
	f.response(t, raw, status, false)
	if err := f.e.store.DeleteCert(rec.Serial); err != nil {
		t.Fatal(err)
	}
	raw, status = f.e.enroll(req.Raw)
	f.response(t, raw, status, false)
	if err := f.e.startup(""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.e.store.RecordBySerial(rec.Serial); ok {
		t.Fatal("deleted certificate resurrected")
	}
}

func TestSCEPAuthorizationAndBounds(t *testing.T) {
	f := newSCEPFixture(t)
	secret := f.challenge(t)
	for _, names := range [][]string{{"other.example.net"}, {"switch.example.net", "extra.example.net"}} {
		r := f.request(t, f.csr(t, secret, names))
		b, s := f.e.enroll(r.Raw)
		f.response(t, b, s, false)
	}
	for _, args := range []struct {
		p           string
		ids         []string
		days, hours int
	}{
		{"builtin:TLS-Client", []string{"switch.example.net"}, 0, 0},
		{"builtin:TLS-Server", nil, 0, 0},
		{"builtin:TLS-Server", []string{"*.example.net"}, 0, 0},
		{"builtin:TLS-Server", []string{"switch.example.net"}, 0, 169},
		{"builtin:TLS-Server", []string{"switch.example.net"}, -1, 0},
	} {
		if _, err := f.e.challenge(args.p, args.ids, args.days, args.hours); err == nil {
			t.Fatalf("accepted %+v", args)
		}
	}
	if err := f.e.revoke(hashSCEP([]byte(secret))); err != nil {
		t.Fatal(err)
	}
	r := f.request(t, f.csr(t, secret, nil))
	b, s := f.e.enroll(r.Raw)
	f.response(t, b, s, false)
	secret = f.challenge(t)
	st, _ := f.e.load()
	st.Challenges[len(st.Challenges)-1].Expires = time.Now().Add(-time.Second)
	if err := f.e.save(st); err != nil {
		t.Fatal(err)
	}
	r = f.request(t, f.csr(t, secret, nil))
	b, s = f.e.enroll(r.Raw)
	f.response(t, b, s, false)
	secret = f.challenge(t)
	r = f.request(t, f.csr(t, secret, nil))
	f.e.lock()
	if _, s := f.e.enroll(r.Raw); s != 503 {
		t.Fatal("locked enrollment accepted")
	}
	if err := f.e.selectCA(f.ca, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := f.e.selectCA(f.ca, "test-pass"); err != nil {
		t.Fatal(err)
	}
	b, s = f.e.enroll(r.Raw)
	f.response(t, b, s, true)
	if err := f.e.store.DeleteCA(f.ca); err != nil {
		t.Fatal(err)
	}
	if _, s := f.e.enroll(r.Raw); s != 503 {
		t.Fatal("deleted CA accepted")
	}
}

// Sign custom CMS envelopes using the maintained library to test policy independently
// of the library's normal request builder (including validly signed malicious input).
func (f *scepFixture) signedEnvelope(t *testing.T, env []byte, digest asn1.ObjectIdentifier, extraCert bool, typ scep.MessageType) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(env)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(digest)
	if extraCert {
		sd.AddCertificate(f.e.cert)
	}
	attrs := []pkcs7.Attribute{
		{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}, Value: "transaction"},
		{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}, Value: typ},
		{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}, Value: make([]byte, 16)},
	}
	if err := sd.AddSigner(f.identity, f.key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attrs}); err != nil {
		t.Fatal(err)
	}
	b, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func marshalEnvelope(t *testing.T, e scepEnvelope) []byte {
	t.Helper()
	b, err := asn1.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	b, err = asn1.Marshal(p7ContentInfo{ContentType: pkcs7.OIDEnvelopedData, Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: b}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestSCEPAlgorithmAndMalformedSecurity(t *testing.T) {
	f := newSCEPFixture(t)
	secret := f.challenge(t)
	csr := f.csr(t, secret, nil)
	env, err := pkcs7.Encrypt(csr.Raw, []*x509.Certificate{f.e.cert})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"sha1", f.signedEnvelope(t, env, pkcs7.OIDDigestAlgorithmSHA1, false, scep.PKCSReq)},
		{"extra-recipient-cert", f.signedEnvelope(t, env, pkcs7.OIDDigestAlgorithmSHA256, true, scep.PKCSReq)},
		{"renewal", f.signedEnvelope(t, env, pkcs7.OIDDigestAlgorithmSHA256, false, scep.RenewalReq)},
		{"garbage", []byte("not CMS")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, s := f.e.enroll(tc.raw); s != 400 {
				t.Fatalf("accepted, status %d", s)
			}
		})
	}
	// Tests are deliberately nonparallel: library encryption defaults are global.
	for _, alg := range []int{pkcs7.EncryptionAlgorithmDESCBC, pkcs7.EncryptionAlgorithmAES256CBC, pkcs7.EncryptionAlgorithmAES128GCM} {
		pkcs7.ContentEncryptionAlgorithm = alg
		legacy, err := pkcs7.Encrypt(csr.Raw, []*x509.Certificate{f.e.cert})
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
		if err != nil {
			t.Fatal(err)
		}
		if _, s := f.e.enroll(f.signedEnvelope(t, legacy, pkcs7.OIDDigestAlgorithmSHA256, false, scep.PKCSReq)); s != 400 {
			t.Fatal("accepted legacy/wrong encryption")
		}
	}
	for _, mode := range []string{"alignment", "empty", "iv", "padding"} {
		e, err := inspectEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		e.Content.Ciphertext.FullBytes = nil
		switch mode {
		case "alignment":
			e.Content.Ciphertext.Bytes = e.Content.Ciphertext.Bytes[:17]
		case "empty":
			e.Content.Ciphertext.Bytes = nil
		case "iv":
			e.Content.Algorithm.Parameters = asn1.RawValue{Tag: 4, Bytes: []byte{0}}
		case "padding":
			// Keep only block one and force its final plaintext byte to 255.
			e.Content.Ciphertext.Bytes = e.Content.Ciphertext.Bytes[:16]
			iv := append([]byte(nil), e.Content.Algorithm.Parameters.Bytes...)
			iv[15] ^= csr.Raw[15] ^ 255
			e.Content.Algorithm.Parameters = asn1.RawValue{Tag: 4, Bytes: iv}
		}
		if _, s := f.e.enroll(f.signedEnvelope(t, marshalEnvelope(t, e), pkcs7.OIDDigestAlgorithmSHA256, false, scep.PKCSReq)); s != 400 {
			t.Fatalf("accepted malformed %s: %d", mode, s)
		}
	}
	// The outer CMS remains valid while the inner CSR proof of possession is broken.
	bad := append([]byte(nil), csr.Raw...)
	bad[len(bad)-1] ^= 1
	env, err = pkcs7.Encrypt(bad, []*x509.Certificate{f.e.cert})
	if err != nil {
		t.Fatal(err)
	}
	if _, s := f.e.enroll(f.signedEnvelope(t, env, pkcs7.OIDDigestAlgorithmSHA256, false, scep.PKCSReq)); s != 400 {
		t.Fatal("invalid CSR signature accepted")
	}
	st, _ := f.e.load()
	if !st.Challenges[0].Used.IsZero() {
		t.Fatal("rejected requests consumed challenge")
	}
}

func TestSCEPPartialStorageRecovery(t *testing.T) {
	f := newSCEPFixture(t)
	r := f.request(t, f.csr(t, f.challenge(t), nil))
	dir := filepath.Join(f.e.store.dir, "certs")
	if err := os.Rename(dir, dir+"-offline"); err != nil {
		t.Fatal(err)
	}
	if _, s := f.e.enroll(r.Raw); s != 503 {
		t.Fatalf("expected storage failure: %d", s)
	}
	st, err := f.e.load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Challenges[0].Used.IsZero() || st.Challenges[0].Published {
		t.Fatal("missing durable pending commit")
	}
	serial := st.Challenges[0].Record.Serial
	if err := os.Rename(dir+"-offline", dir); err != nil {
		t.Fatal(err)
	}
	f.e = newSCEPService(f.e.store)
	if err := f.e.startup(""); err != nil {
		t.Fatal(err)
	}
	if err := f.e.selectCA(f.ca, "test-pass"); err != nil {
		t.Fatal(err)
	}
	b, s := f.e.enroll(r.Raw)
	c := f.response(t, b, s, true)
	if serialString(c.SerialNumber) != serial {
		t.Fatal("recovery issued a second certificate")
	}
	recs, _ := f.e.store.Records()
	if len(recs) != 3 {
		t.Fatal("projection duplicated")
	}
}

func TestSCEPHTTPAndAdminSeparation(t *testing.T) {
	f := newSCEPFixture(t)
	h := f.e.Routes()
	for _, p := range []string{"/", "/login", "/setup", "/healthz", "/admin/scep", "/ca"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 404 {
			t.Fatalf("dedicated listener exposed %s", p)
		}
	}
	for _, p := range []string{"/scep", "/scep/cgi-bin/pkiclient.exe", "/cgi-bin/pkiclient.exe"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p+"?operation=GetCACaps", nil))
		if w.Code != 200 || w.Body.String() != "AES\nSHA-256\nPOSTPKIOperation\n" {
			t.Fatal("bad capabilities")
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p+"?operation=GetCACert", nil))
		certs, err := scep.CACerts(w.Body.Bytes())
		if err != nil || len(certs) != 2 {
			t.Fatalf("bad CA chain: %v", err)
		}
	}
	r := f.request(t, f.csr(t, f.challenge(t), nil))
	for _, method := range []string{"GET", "POST"} {
		path := "/cgi-bin/pkiclient.exe?operation=PKIOperation"
		body := bytes.NewReader(r.Raw)
		if method == "GET" {
			path += "&message=" + url.QueryEscape(base64.StdEncoding.EncodeToString(r.Raw))
			body = bytes.NewReader(nil)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, body))
		f.response(t, w.Body.Bytes(), w.Code, true)
	}
	for _, path := range []string{"/scep?operation=GetCACaps&operation=PKIOperation", "/scep?operation=CertPoll", "/scep?operation=PKIOperation&message=bad%"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 {
			t.Fatal("invalid query accepted")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/scep?operation=PKIOperation", strings.NewReader(strings.Repeat("x", scepMaxMessage+1))))
	if w.Code != 400 {
		t.Fatal("oversized body accepted")
	}
	a, err := NewAuth(f.e.store, false, true)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(f.e.store, a)
	srv.scep = f.e
	for _, method := range []string{"GET", "POST"} {
		path := "/admin/scep"
		if method == "POST" {
			path += "/lock"
		}
		if !requiresAdmin(method, path) {
			t.Fatal("missing admin classification")
		}
		r := httptest.NewRequest(method, path, nil)
		r = r.WithContext(context.WithValue(r.Context(), userCtxKey, User{Username: "viewer", Role: RoleViewer}))
		w := httptest.NewRecorder()
		srv.Routes().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("viewer accessed SCEP admin")
		}
	}
	w = httptest.NewRecorder()
	a.Middleware(srv.Routes()).ServeHTTP(w, httptest.NewRequest("GET", "/scep?operation=GetCACaps", nil))
	if w.Code != 200 {
		t.Fatal("protocol requires UI auth")
	}
	rq := httptest.NewRequest("GET", "/admin/scep", nil).WithContext(context.WithValue(context.Background(), userCtxKey, User{Role: RoleAdmin}))
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, rq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Select / unlock in memory") {
		t.Fatalf("admin page failed: %s", w.Body.String())
	}
}

func TestSCEPCompetingFirstEnrollment(t *testing.T) {
	f := newSCEPFixture(t)
	secret := f.challenge(t)
	requests := []*scep.PKIMessage{
		f.request(t, f.csr(t, secret, nil)),
		f.request(t, f.csr(t, secret, []string{"switch.example.net"})),
	}
	var wg sync.WaitGroup
	results := make(chan scep.PKIStatus, 2)
	for _, r := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, s := f.e.enroll(r.Raw)
			if s != 200 {
				t.Errorf("status %d", s)
				return
			}
			m, err := scep.ParsePKIMessage(b)
			if err != nil {
				t.Error(err)
				return
			}
			results <- m.PKIStatus
		}()
	}
	wg.Wait()
	close(results)
	counts := map[scep.PKIStatus]int{}
	for s := range results {
		counts[s]++
	}
	if counts[scep.SUCCESS] != 1 || counts[scep.FAILURE] != 1 {
		t.Fatalf("single-use race: %v", counts)
	}
}

func TestSCEPProfileIssuerBoundsAndRetention(t *testing.T) {
	f := newSCEPFixture(t)
	p, _ := builtinByName("TLS-Server")
	p.Name = "Short"
	p.Builtin = false
	p.ValidDays = 1
	p.MaxDays = 2
	p.AllowedIssuers = []string{f.ca}
	if err := f.e.store.AddTemplate(p); err != nil {
		t.Fatal(err)
	}
	secret, err := f.e.challenge(p.Name, []string{"switch.example.net"}, 365, 168)
	if err != nil {
		t.Fatal(err)
	}
	r := f.request(t, f.csr(t, secret, nil))
	b, s := f.e.enroll(r.Raw)
	c := f.response(t, b, s, true)
	if c.NotAfter.After(time.Now().Add(48*time.Hour)) || c.NotAfter.Before(time.Now().Add(47*time.Hour)) {
		t.Fatal("profile maximum ignored")
	}
	p.Name = "ECOnly"
	p.Algo = algoECP256
	p.AllowedAlgos = []keyAlgo{algoECP256}
	if err := f.e.store.AddTemplate(p); err != nil {
		t.Fatal(err)
	}
	secret, err = f.e.challenge(p.Name, []string{"switch.example.net"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	r = f.request(t, f.csr(t, secret, nil))
	b, s = f.e.enroll(r.Raw)
	f.response(t, b, s, false)
	p.Name = "WrongIssuer"
	p.AllowedIssuers = []string{caRoot}
	if err := f.e.store.AddTemplate(p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.challenge(p.Name, []string{"switch.example.net"}, 0, 0); err == nil {
		t.Fatal("issuer restriction ignored")
	}
	short, err := CreateIntermediate(f.e.store, IntermediateParams{CommonName: "Short CA", Algo: algoRSA2048, ValidDays: 1, ParentID: caRoot, SCEP: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.e.selectCA(short.CAID, ""); err != nil {
		t.Fatal(err)
	}
	secret = f.challenge(t)
	r = f.request(t, f.csr(t, secret, nil))
	b, s = f.e.enroll(r.Raw)
	c = f.response(t, b, s, true)
	if !c.NotAfter.Equal(f.e.cert.NotAfter) {
		t.Fatal("issuer expiry not applied")
	}
	st, _ := f.e.load()
	for i := range st.Challenges {
		st.Challenges[i].Expires = time.Now().Add(-8 * 24 * time.Hour)
		if !st.Challenges[i].Used.IsZero() {
			st.Challenges[i].Used = time.Now().Add(-8 * 24 * time.Hour)
		}
	}
	if err := f.e.save(st); err != nil {
		t.Fatal(err)
	}
	b, s = f.e.enroll(r.Raw)
	f.response(t, b, s, false)
	pruneSCEP(&st)
	if len(st.Challenges) != 0 {
		t.Fatal("retention cleanup failed")
	}
	if err := f.e.selectCA(caRoot, ""); err == nil {
		t.Fatal("root selected for SCEP")
	}
}

func TestSCEPDuplicateChallengeAndSignerBinding(t *testing.T) {
	f := newSCEPFixture(t)
	csr := f.csr(t, f.challenge(t), nil)
	var outer struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if err := strictASN1(csr.Raw, &outer); err != nil {
		t.Fatal(err)
	}
	var info struct {
		Version    int
		Subject    asn1.RawValue
		Key        asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}
	if err := strictASN1(outer.Info.FullBytes, &info); err != nil {
		t.Fatal(err)
	}
	info.Attributes = append(info.Attributes, info.Attributes[len(info.Attributes)-1])
	tbs, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(tbs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	outer.Info = asn1.RawValue{FullBytes: tbs}
	outer.Signature = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	der, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := duplicate.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	r := f.request(t, duplicate)
	if _, s := f.e.enroll(r.Raw); s != 400 {
		t.Fatal("duplicate challenge accepted")
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.key = other // CSR key and self-signed request identity no longer match.
	csr = f.csr(t, f.challenge(t), nil)
	env, err := pkcs7.Encrypt(csr.Raw, []*x509.Certificate{f.e.cert})
	if err != nil {
		t.Fatal(err)
	}
	// Sign with a distinct self-signed identity, unrelated to the CSR key.
	old := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err = x509.CreateCertificate(rand.Reader, old, old, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	if _, s := f.e.enroll(f.signedEnvelope(t, env, pkcs7.OIDDigestAlgorithmSHA256, false, scep.PKCSReq)); s != 400 {
		t.Fatal("signer/CSR key mismatch accepted")
	}
}

func TestSCEPJournalAndIndexFailures(t *testing.T) {
	f := newSCEPFixture(t)
	r := f.request(t, f.csr(t, f.challenge(t), nil))
	// An unreadable journal must not publish a certificate or spend the token.
	if err := os.Rename(f.e.path(), f.e.path()+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.e.path(), 0700); err != nil {
		t.Fatal(err)
	}
	if _, s := f.e.enroll(r.Raw); s != 503 {
		t.Fatal("journal failure accepted")
	}
	recs, _ := f.e.store.Records()
	if len(recs) != 2 {
		t.Fatal("uncommitted issuance published")
	}
	if err := os.Remove(f.e.path()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.e.path()+".saved", f.e.path()); err != nil {
		t.Fatal(err)
	}
	// Simulate index corruption after signing by leaving a committed, unpublished
	// journal entry from a certificate-directory outage, then fail recovery.
	dir := filepath.Join(f.e.store.dir, "certs")
	if err := os.Rename(dir, dir+".saved"); err != nil {
		t.Fatal(err)
	}
	if _, s := f.e.enroll(r.Raw); s != 503 {
		t.Fatal("projection failure accepted")
	}
	if err := os.Rename(dir+".saved", dir); err != nil {
		t.Fatal(err)
	}
	st, _ := f.e.load()
	serial := st.Challenges[0].Record.Serial
	index := f.e.store.indexPath()
	original, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, []byte("invalid JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.e.startup(""); err == nil {
		t.Fatal("corrupt index recovered silently")
	}
	if err := os.WriteFile(index, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.e.startup(""); err != nil {
		t.Fatal(err)
	}
	b, s := f.e.enroll(r.Raw)
	c := f.response(t, b, s, true)
	if serialString(c.SerialNumber) != serial {
		t.Fatal("storage recovery reissued certificate")
	}
}

func TestSCEPAdminChallengeShownOnce(t *testing.T) {
	f := newSCEPFixture(t)
	a, err := NewAuth(f.e.store, false, true)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(f.e.store, a)
	srv.scep = f.e
	body := url.Values{"profile": {"builtin:TLS-Server"}, "sans": {"switch.example.net,192.0.2.10"}, "days": {"365"}, "hours": {"24"}}
	r := httptest.NewRequest("POST", "/admin/scep/challenge", strings.NewReader(body.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, User{Role: RoleAdmin}))
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "Copy this challenge now") {
		t.Fatalf("challenge UI failed: %s", w.Body.String())
	}
	start := strings.Index(w.Body.String(), "<pre>") + 5
	end := strings.Index(w.Body.String(), "</pre>")
	if start < 5 || end < start {
		t.Fatal("missing secret")
	}
	secret := w.Body.String()[start:end]
	if len(secret) != 64 {
		t.Fatal("unexpected challenge entropy")
	}
	st, _ := f.e.load()
	if len(st.Challenges) != 1 || st.Challenges[0].Hash != hashSCEP([]byte(secret)) {
		t.Fatal("challenge not persisted")
	}
	r = httptest.NewRequest("GET", "/admin/scep", nil).WithContext(r.Context())
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("secret redisplayed")
	}
	// Viewer and anonymous requests are denied by the full middleware, including
	// first-run redirects, before they can change the unlocked state.
	if err := a.AddUser("viewer", "test-password", RoleViewer); err != nil {
		t.Fatal(err)
	}
	cookieWriter := httptest.NewRecorder()
	a.issueSession(cookieWriter, "viewer")
	for _, authenticated := range []bool{false, true} {
		r = httptest.NewRequest("POST", "/admin/scep/lock", nil)
		if authenticated {
			r.AddCookie(cookieWriter.Result().Cookies()[0])
		}
		w = httptest.NewRecorder()
		a.Middleware(srv.Routes()).ServeHTTP(w, r)
		want := 401
		if authenticated {
			want = 403
		}
		if w.Code != want {
			t.Fatalf("auth separation: %d", w.Code)
		}
	}
	if f.e.key == nil {
		t.Fatal("unauthorized request locked the service")
	}
}

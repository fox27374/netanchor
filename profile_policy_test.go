package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func testPolicyStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CreateCA(s, CAParams{CommonName: "Root", Algo: algoECP256, ValidDays: 4000}); err != nil {
		t.Fatal(err)
	}
	return s
}
func csrPEM(t *testing.T, subject pkix.Name, dns []string, ext ...pkix.Extension) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, DNSNames: dns, ExtraExtensions: ext}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})
}

func TestPolicyIssuanceArtifactsAndFailures(t *testing.T) {
	s := testPolicyStore(t)
	profile := builtinTemplates()[0]
	rec, err := IssueCert(s, IssueParams{CommonName: "leaf", DNSNames: []string{"leaf.example"}, Algo: algoECP256, ValidDays: 30, IssuerID: caRoot, Template: profile, TemplateName: profile.Name})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.LoadCertPEM(rec.Serial)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseCertPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "leaf.example" {
		t.Fatalf("unexpected leaf policy: %+v", cert)
	}
	bad := profile
	bad.AllowedIssuers = []string{"deadbeef"}
	if _, err = IssueCert(s, IssueParams{CommonName: "x", DNSNames: []string{"x"}, Algo: algoECP256, ValidDays: 30, IssuerID: caRoot, Template: bad}); err == nil {
		t.Fatal("issuer allowlist bypass")
	}
	for _, days := range []int{0, -1, 366} {
		if _, err = IssueCert(s, IssueParams{CommonName: "x", DNSNames: []string{"x"}, Algo: algoECP256, ValidDays: days, IssuerID: caRoot, Template: profile}); err == nil {
			t.Errorf("accepted explicit validity %d", days)
		}
	}
	if _, err = IssueCert(s, IssueParams{CommonName: "x", DNSNames: []string{"x"}, Algo: algoECP256, ValidDays: 10, IssuerID: "not-a-ca", Template: profile}); err == nil {
		t.Fatal("invalid issuer accepted")
	}
	if _, err = IssueCert(s, IssueParams{CommonName: "x", DNSNames: []string{"x"}, URIs: []string{"not a uri"}, Algo: algoECP256, ValidDays: 10, IssuerID: caRoot, Template: builtinTemplates()[1]}); err == nil {
		t.Fatal("URI SAN accepted by client-only profile")
	}
	if _, err = IssueCert(s, IssueParams{URIs: []string{"spiffe://example/service"}, Algo: algoECP256, ValidDays: 10, IssuerID: caRoot, Template: builtinTemplates()[1]}); err == nil {
		t.Fatal("client certificate without subject identity accepted")
	}
}

func TestEveryBuiltinEmitsPurposeEKUAndSANPolicy(t *testing.T) {
	s := testPolicyStore(t)
	want := [][]x509.ExtKeyUsage{{x509.ExtKeyUsageServerAuth}, {x509.ExtKeyUsageClientAuth}, {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, {x509.ExtKeyUsageCodeSigning}, {x509.ExtKeyUsageEmailProtection}}
	for i, profile := range builtinTemplates() {
		p := IssueParams{CommonName: "identity", Algo: algoECP256, ValidDays: 10, IssuerID: caRoot, Template: profile}
		switch profile.Profile {
		case profileServer, profileBoth:
			p.DNSNames = []string{"service.example"}
		case profileClient:
			p.URIs = []string{"spiffe://service/example"}
		case profileEmail:
			p.Emails = []string{"person@example.com"}
		}
		rec, err := IssueCert(s, p)
		if err != nil {
			t.Fatalf("%s: %v", profile.Name, err)
		}
		pemBytes, _ := s.LoadCertPEM(rec.Serial)
		cert, err := parseCertPEM(pemBytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.ExtKeyUsage) != len(want[i]) {
			t.Fatalf("%s EKU: %v", profile.Name, cert.ExtKeyUsage)
		}
		for n, eku := range want[i] {
			if cert.ExtKeyUsage[n] != eku {
				t.Fatalf("%s EKU %v want %v", profile.Name, cert.ExtKeyUsage, want[i])
			}
		}
		if cert.IsCA {
			t.Fatalf("%s leaf has CA flag", profile.Name)
		}
		switch profile.Profile {
		case profileServer, profileBoth:
			if len(cert.DNSNames) != 1 || len(cert.EmailAddresses)+len(cert.URIs) != 0 {
				t.Fatalf("bad server SANs %+v", cert)
			}
		case profileClient:
			if len(cert.URIs) != 1 {
				t.Fatalf("client SANs lost: %+v", cert)
			}
		case profileEmail:
			if len(cert.EmailAddresses) != 1 || len(cert.DNSNames)+len(cert.URIs) != 0 {
				t.Fatalf("bad mail SANs %+v", cert)
			}
		case profileCode:
			if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs) != 0 {
				t.Fatal("code signing SAN was added")
			}
		}
	}
}

func TestCSRPrivilegeAndPurposeRestrictions(t *testing.T) {
	s := testPolicyStore(t)
	server := builtinTemplates()[0]
	caDER, _ := asn1.Marshal(struct{ IsCA bool }{true})
	caExt := pkix.Extension{Id: []int{2, 5, 29, 19}, Value: caDER}
	kuDER, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 6})
	kuExt := pkix.Extension{Id: []int{2, 5, 29, 15}, Value: kuDER}
	critical := pkix.Extension{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}
	serverEKU, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})
	ekuExt := pkix.Extension{Id: []int{2, 5, 29, 37}, Value: serverEKU}
	for _, ext := range [][]pkix.Extension{{caExt}, {kuExt}, {critical}, {ekuExt}} {
		csr := csrPEM(t, pkix.Name{CommonName: "leaf"}, []string{"leaf.example"}, ext...)
		_, err := SignCSR(s, SignCSRParams{CSRPEM: csr, ValidDays: 30, IssuerID: caRoot, Template: func() CertTemplate {
			c := server
			if len(ext) > 0 && ext[0].Id.Equal([]int{2, 5, 29, 37}) {
				c.Profile = profileClient
			}
			return c
		}()})
		if err == nil {
			t.Errorf("accepted disallowed CSR extension %v", ext)
		}
	}
	sanDER, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("leaf.example")}})
	if err != nil {
		t.Fatal(err)
	}
	criticalSAN := pkix.Extension{Id: []int{2, 5, 29, 17}, Critical: true, Value: sanDER}
	if _, err := SignCSR(s, SignCSRParams{CSRPEM: csrPEM(t, pkix.Name{CommonName: "leaf"}, nil, criticalSAN), ValidDays: 30, IssuerID: caRoot, Template: server}); err != nil {
		t.Fatalf("compatible critical SAN rejected: %v", err)
	}
	csr := csrPEM(t, pkix.Name{CommonName: "leaf"}, []string{"leaf.example"})
	signed, err := SignCSR(s, SignCSRParams{CSRPEM: csr, ValidDays: 30, IssuerID: caRoot, Template: server, TemplateName: server.Name})
	if err != nil {
		t.Fatal(err)
	}
	if signed.TemplateName != server.Name || signed.TemplatePolicy.Profile != profileServer {
		t.Fatalf("missing policy snapshot: %+v", signed)
	}
	if err = s.DeleteTemplate(signed.TemplateName); err == nil {
		t.Fatal("builtin deletion should be rejected")
	}
}

func TestSignCSRWithEmailAndCodeProfiles(t *testing.T) {
	s := testPolicyStore(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mailCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "person"}, EmailAddresses: []string{"person@example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		profile CertTemplate
		csr     []byte
		wantEKU x509.ExtKeyUsage
	}{
		{builtinTemplates()[4], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: mailCSR}), x509.ExtKeyUsageEmailProtection},
		{builtinTemplates()[3], csrPEM(t, pkix.Name{CommonName: "program"}, nil), x509.ExtKeyUsageCodeSigning},
	} {
		rec, err := SignCSR(s, SignCSRParams{CSRPEM: tc.csr, ValidDays: 30, IssuerID: caRoot, Template: tc.profile})
		if err != nil {
			t.Fatalf("%s CSR: %v", tc.profile.Name, err)
		}
		certPEM, err := s.LoadCertPEM(rec.Serial)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := parseCertPEM(certPEM)
		if err != nil || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != tc.wantEKU {
			t.Fatalf("%s EKU: %v, %v", tc.profile.Name, cert, err)
		}
		if tc.wantEKU == x509.ExtKeyUsageEmailProtection && (len(cert.EmailAddresses) != 1 || cert.EmailAddresses[0] != "person@example.com") {
			t.Fatalf("email SAN missing: %v", cert.EmailAddresses)
		}
	}
}

func TestTemplateMigrationMaxAndValidation(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`[{"name":"legacy","description":"preserve","algo":"ecp256","valid_days":90,"profile":"server"}]`)
	if err = os.WriteFile(s.templatesPath(), data, 0600); err != nil {
		t.Fatal(err)
	}
	ts, err := s.LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if ts[0].MaxDays != 365 || ts[0].Description != "preserve" || len(ts[0].AllowedAlgos) != 4 {
		t.Fatalf("bad migration %+v", ts[0])
	}
	ts[0].MaxDays = 100
	if err = s.UpdateTemplate("legacy", ts[0]); err != nil {
		t.Fatal(err)
	}
	again, err := s.LoadTemplates()
	if err != nil || again[0].MaxDays != 100 {
		t.Fatalf("custom validity maximum changed on reload: %+v, %v", again, err)
	}
	bad := CertTemplate{Name: "bad", Algo: algoECP256, Profile: profileServer, ValidDays: 1, MaxDays: 1}
	if err = s.AddTemplate(bad); err == nil {
		t.Fatal("empty allowed algorithm set accepted")
	}
	bad.AllowedAlgos = []keyAlgo{algoECP256}
	bad.Profile = "forged"
	if err = s.AddTemplate(bad); err == nil {
		t.Fatal("forged purpose accepted")
	}
	bad.Profile = profileServer
	bad.Algo = algoRSA4096
	if err = s.AddTemplate(bad); err == nil {
		t.Fatal("default algorithm outside allowed set accepted")
	}
}

func TestLegacyTemplateNameCollisionWithBuiltin(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`[{"name":"TLS-Server","description":"previous custom policy","algo":"ecp384","valid_days":60,"profile":"client"}]`)
	if err = os.WriteFile(s.templatesPath(), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	custom, ok := s.GetTemplate("TLS-Server")
	if !ok || custom.Builtin || custom.Description != "previous custom policy" {
		t.Fatalf("legacy custom template shadowed: %+v", custom)
	}
	builtin, ok := s.GetTemplate("builtin:TLS-Server")
	if !ok || !builtin.Builtin || builtin.Profile != profileServer {
		t.Fatalf("built-in template unavailable: %+v", builtin)
	}
	custom.Description = "updated"
	if err = s.UpdateTemplate("TLS-Server", custom); err != nil {
		t.Fatalf("cannot edit legacy colliding template: %v", err)
	}
}

func TestExpiryAndExactRSAAlgorithmPolicy(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CreateCA(s, CAParams{CommonName: "Short Root", Algo: algoECP256, ValidDays: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = IssueCert(s, IssueParams{CommonName: "x", DNSNames: []string{"x"}, Algo: algoECP256, ValidDays: 10, IssuerID: caRoot, Template: builtinTemplates()[0]}); err == nil {
		t.Fatal("leaf outlived CA")
	}
	n2048 := new(big.Int).Lsh(big.NewInt(1), 2047)
	n4096 := new(big.Int).Lsh(big.NewInt(1), 4095)
	if a, _ := publicKeyAlgo(&rsa.PublicKey{N: n2048, E: 65537}); a != algoRSA2048 {
		t.Fatalf("2048-bit RSA classified %q", a)
	}
	if a, _ := publicKeyAlgo(&rsa.PublicKey{N: n4096, E: 65537}); a != algoRSA4096 {
		t.Fatalf("4096-bit RSA classified %q", a)
	}
	if allowedAlgo(CertTemplate{AllowedAlgos: []keyAlgo{algoRSA2048}}, algoRSA4096) {
		t.Fatal("RSA-4096 bypassed RSA-2048-only policy")
	}
}

func TestIssuedTemplateSnapshotSurvivesEditDelete(t *testing.T) {
	s := testPolicyStore(t)
	profile := builtinTemplates()[0]
	profile.Name = "custom"
	profile.Builtin = false
	if err := s.AddTemplate(profile); err != nil {
		t.Fatal(err)
	}
	saved, ok := s.GetTemplate("custom")
	if !ok {
		t.Fatal("template missing")
	}
	rec, err := IssueCert(s, IssueParams{DNSNames: []string{"snap.example"}, Algo: algoECP256, ValidDays: 10, IssuerID: caRoot, Template: saved, TemplateName: saved.Name})
	if err != nil {
		t.Fatal(err)
	}
	changed := saved
	changed.Description = "edited"
	changed.MaxDays = 200
	if err = s.UpdateTemplate("custom", changed); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteTemplate("custom"); err != nil {
		t.Fatal(err)
	}
	stored, ok := s.RecordBySerial(rec.Serial)
	if !ok || stored.TemplateName != "custom" || stored.TemplatePolicy.MaxDays != 365 || stored.TemplatePolicy.Description == "edited" {
		t.Fatalf("policy snapshot changed: %+v", stored)
	}
}

func TestIssueCountryDefaultCanBeOverridden(t *testing.T) {
	s := testPolicyStore(t)
	tmpl := builtinTemplates()[0]
	tmpl.Country = "AT"
	for _, tc := range []struct{ input, want string }{{"", "AT"}, {"DE", "DE"}} {
		rec, err := IssueCert(s, IssueParams{CommonName: "web", DNSNames: []string{"web.example"}, Country: tc.input, Algo: algoECP256, ValidDays: 30, IssuerID: caRoot, Template: tmpl})
		if err != nil {
			t.Fatal(err)
		}
		pemBytes, err := s.LoadCertPEM(rec.Serial)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := parseCertPEM(pemBytes)
		if err != nil || len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != tc.want {
			t.Fatalf("country %q: certificate=%v error=%v", tc.want, cert, err)
		}
	}
}

func TestIssueSignAndTemplateEditHTTP(t *testing.T) {
	s := testPolicyStore(t)
	auth, err := NewAuth(s, false, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(s, auth)
	handler := srv.Routes()
	profiles := httptest.NewRecorder()
	handler.ServeHTTP(profiles, httptest.NewRequest("GET", "/issue", nil))
	if profiles.Code != 200 || !strings.Contains(profiles.Body.String(), `name="template"`) {
		t.Fatalf("issue profile form unavailable: %d", profiles.Code)
	}
	missing := url.Values{"common_name": {"web"}, "dns_sans": {"web.example"}, "issuer": {"root"}, "algo": {"ecp256"}, "valid_days": {"30"}}
	missingReq := httptest.NewRequest("POST", "/issue", strings.NewReader(missing.Encode()))
	missingReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingResp := httptest.NewRecorder()
	handler.ServeHTTP(missingResp, missingReq)
	if !strings.Contains(missingResp.Body.String(), "Select a valid certificate template") {
		t.Fatalf("missing template accepted: %d %s", missingResp.Code, missingResp.Body.String())
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest("GET", "/templates/edit/nope", nil))
	addValues := url.Values{"name": {"custom"}, "description": {"UI profile"}, "algo": {"ecp256"}, "profile": {"server"}, "valid_days": {"30"}, "max_days": {"60"}, "allowed_algorithms": {"ecp256"}, "allowed_issuers": {"root"}}
	addReq := httptest.NewRequest("POST", "/templates/add", strings.NewReader(addValues.Encode()))
	addReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addResp := httptest.NewRecorder()
	handler.ServeHTTP(addResp, addReq)
	if addResp.Code != http.StatusSeeOther {
		t.Fatalf("template add POST: %d %s", addResp.Code, addResp.Body.String())
	}
	custom, ok := s.GetTemplate("custom")
	if !ok || custom.AllowedIssuers[0] != "root" || custom.AllowedAlgos[0] != algoECP256 {
		t.Fatalf("template form values lost: %+v", custom)
	}
	editPostReq := httptest.NewRequest("POST", "/templates/edit/custom", strings.NewReader(addValues.Encode()))
	editPostReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	editPost := httptest.NewRecorder()
	handler.ServeHTTP(editPost, editPostReq)
	if editPost.Code != http.StatusSeeOther {
		t.Fatalf("template edit POST: %d %s", editPost.Code, editPost.Body.String())
	}
	edit := httptest.NewRecorder()
	handler.ServeHTTP(edit, httptest.NewRequest("GET", "/templates/edit/custom", nil))
	if edit.Code != 200 || !strings.Contains(edit.Body.String(), "Allowed issuer CA IDs") || !strings.Contains(edit.Body.String(), `value="root"`) {
		t.Fatalf("template edit render failed: %d %s", edit.Code, edit.Body.String())
	}
	issueBody := url.Values{"template": {"builtin:TLS-Server"}, "common_name": {"web"}, "dns_sans": {"web.example"}, "issuer": {"root"}, "algo": {"ecp256"}, "valid_days": {"30"}, "profile": {"client"}}
	issue := httptest.NewRecorder()
	issueReq := httptest.NewRequest("POST", "/issue", strings.NewReader(issueBody.Encode()))
	issueReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(issue, issueReq)
	if !strings.Contains(issue.Body.String(), "Certificate issued") {
		t.Fatalf("issue form didn't bind selected template: %s", issue.Body.String())
	}
	defaults := url.Values{"template": {"builtin:TLS-Server"}, "common_name": {"default-web"}, "dns_sans": {"default.example"}, "issuer": {"root"}}
	defaultReq := httptest.NewRequest("POST", "/issue", strings.NewReader(defaults.Encode()))
	defaultReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	defaultResp := httptest.NewRecorder()
	handler.ServeHTTP(defaultResp, defaultReq)
	if !strings.Contains(defaultResp.Body.String(), "Certificate issued") {
		t.Fatalf("profile defaults unavailable without JavaScript: %s", defaultResp.Body.String())
	}
	all, err := s.Records()
	if err != nil {
		t.Fatal(err)
	}
	foundDefault := false
	for _, item := range all {
		if item.CommonName == "default-web" {
			foundDefault = true
			if item.NotAfter.Sub(item.NotBefore).Hours() < 89*24 || item.NotAfter.Sub(item.NotBefore).Hours() > 91*24 {
				t.Fatalf("wrong default validity: %s", item.NotAfter.Sub(item.NotBefore))
			}
		}
	}
	if !foundDefault {
		t.Fatal("default-profile certificate not recorded")
	}
	csr := csrPEM(t, pkix.Name{CommonName: "web"}, []string{"web.example"})
	signBody := url.Values{"template": {"builtin:TLS-Server"}, "csr": {string(csr)}, "issuer": {"root"}, "valid_days": {"30"}, "profile": {"client"}}
	signed := httptest.NewRecorder()
	signReq := httptest.NewRequest("POST", "/sign", strings.NewReader(signBody.Encode()))
	signReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(signed, signReq)
	if !strings.Contains(signed.Body.String(), "CSR signed") {
		t.Fatalf("sign form didn't bind selected template: %s", signed.Body.String())
	}
	recs, _ := s.Records()
	var csrRec CertRecord
	for _, item := range recs {
		if item.Kind == "csr" {
			csrRec = item
			break
		}
	}
	certPEM, _ := s.LoadCertPEM(csrRec.Serial)
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("forged profile changed server template EKU: %v", cert.ExtKeyUsage)
	}
	dashboard := httptest.NewRecorder()
	handler.ServeHTTP(dashboard, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(dashboard.Body.String(), `<th>Template</th>`) || !strings.Contains(dashboard.Body.String(), "TLS-Server") {
		t.Fatal("issued-certificates overview omits template")
	}
	details := httptest.NewRecorder()
	handler.ServeHTTP(details, httptest.NewRequest("GET", "/cert/"+csrRec.Serial, nil))
	if !strings.Contains(details.Body.String(), "Issued from template") || !strings.Contains(details.Body.String(), "TLS-Server") {
		t.Fatal("certificate details omit issuance-time policy")
	}
}

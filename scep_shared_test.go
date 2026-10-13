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
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sharedCSR builds a CSR from tmpl, then appends the challengePassword and one
// PKCS#9 unstructuredName attribute per value (the stdlib cannot add those) and re-signs it.
func (f *scepFixture) sharedCSR(t *testing.T, secret string, tmpl x509.CertificateRequest, unstructured ...string) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, f.key)
	if err != nil {
		t.Fatal(err)
	}
	var req struct {
		Raw asn1.RawContent
		TBS struct {
			Raw       asn1.RawContent
			Version   int
			Subject   asn1.RawValue
			PublicKey asn1.RawValue
			Attrs     []asn1.RawValue `asn1:"tag:0"`
		}
		Alg asn1.RawValue
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		t.Fatal(err)
	}
	attr := func(oid asn1.ObjectIdentifier, tag, value string) asn1.RawValue {
		v, err := asn1.MarshalWithParams(value, tag)
		if err != nil {
			t.Fatal(err)
		}
		b, err := asn1.Marshal(struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}{oid, []asn1.RawValue{{FullBytes: v}}})
		if err != nil {
			t.Fatal(err)
		}
		return asn1.RawValue{FullBytes: b}
	}
	attrs := append([]asn1.RawValue{}, req.TBS.Attrs...)
	attrs = append(attrs, attr(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, "printable", secret))
	for _, u := range unstructured {
		attrs = append(attrs, attr(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 2}, "ia5", u))
	}
	tbs, err := asn1.Marshal(struct {
		Version   int
		Subject   asn1.RawValue
		PublicKey asn1.RawValue
		Attrs     []asn1.RawValue `asn1:"tag:0"`
	}{req.TBS.Version, req.TBS.Subject, req.TBS.PublicKey, attrs})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(tbs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, req.Alg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificateRequest(out)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// newSharedFixture returns a SCEP fixture with one shared challenge for 192.0.2.0/24.
func newSharedFixture(t *testing.T, suffixes []string) (*scepFixture, string) {
	t.Helper()
	f := newSCEPFixture(t)
	secret, err := f.e.sharedChallenge("builtin:TLS-Server", []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, suffixes, 0, 30)
	if err != nil {
		t.Fatal(err)
	}
	return f, secret
}

// stubLookup replaces the resolver. Names not in the map fail to resolve.
func stubLookup(t *testing.T, answers map[string][]netip.Addr) {
	t.Helper()
	old := lookupSCEPHost
	lookupSCEPHost = func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := answers[host]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { lookupSCEPHost = old })
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// enrollAt sends csr as a PKIOperation from remote and returns the status.
func (f *scepFixture) enrollAt(t *testing.T, csr *x509.CertificateRequest, remote string) ([]byte, int) {
	t.Helper()
	return f.e.enroll(f.request(t, csr).Raw, remote)
}

func TestSharedChallengeIssuesSourceIPCert(t *testing.T) {
	f, secret := newSharedFixture(t, []string{"example.net"})
	stubLookup(t, map[string][]netip.Addr{"switch.example.net": {addr("192.0.2.10")}})
	csr := f.sharedCSR(t, secret, x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "switch"},
		DNSNames:    []string{"Switch.example.net."},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.99")},
	})
	b, status := f.enrollAt(t, csr, "192.0.2.10:4444")
	c := f.response(t, b, status, true)
	if len(c.IPAddresses) != 1 || c.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("IP SANs %v, want exactly the source", c.IPAddresses)
	}
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "switch.example.net" {
		t.Fatalf("DNS SANs %v", c.DNSNames)
	}
	if c.Subject.CommonName != "switch.example.net" {
		t.Fatalf("CN %q, want the first verified name (CSR CN ignored)", c.Subject.CommonName)
	}
	st, _ := f.e.load()
	if len(st.Shared) != 1 || len(st.Shared[0].Issuances) != 1 || !st.Shared[0].Issuances[0].Published || st.Shared[0].Issuances[0].Identity == "" {
		t.Fatalf("issuance not journaled: %+v", st.Shared)
	}
}

func TestSharedChallengeIPOnlyCN(t *testing.T) {
	f, secret := newSharedFixture(t, []string{"example.net"})
	csr := f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "switch"}})
	b, status := f.enrollAt(t, csr, "192.0.2.10:4444")
	c := f.response(t, b, status, true)
	if c.Subject.CommonName != "192.0.2.10" || len(c.DNSNames) != 0 || len(c.IPAddresses) != 1 {
		t.Fatalf("CN %q DNS %v IP %v", c.Subject.CommonName, c.DNSNames, c.IPAddresses)
	}
}

func TestSharedChallengeRefusals(t *testing.T) {
	cases := []struct {
		name     string
		remote   string
		csr      x509.CertificateRequest
		unstruct []string
		answers  map[string][]netip.Addr
		mutate   func(*scepState)
	}{
		{name: "out of range", remote: "198.51.100.7:1", csr: x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}},
		{name: "resolves elsewhere", remote: "192.0.2.10:1", csr: x509.CertificateRequest{DNSNames: []string{"switch.example.net"}}, answers: map[string][]netip.Addr{"switch.example.net": {addr("192.0.2.99")}}},
		{name: "lookup fails", remote: "192.0.2.10:1", csr: x509.CertificateRequest{DNSNames: []string{"switch.example.net"}}},
		{name: "suffix boundary CN", remote: "192.0.2.10:1", csr: x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil-example.net"}}, answers: map[string][]netip.Addr{"evil-example.net": {addr("192.0.2.10")}}},
		{name: "suffix boundary SAN", remote: "192.0.2.10:1", csr: x509.CertificateRequest{DNSNames: []string{"sw.evil-example.net"}}, answers: map[string][]netip.Addr{"sw.evil-example.net": {addr("192.0.2.10")}}},
		{name: "email SAN", remote: "192.0.2.10:1", csr: x509.CertificateRequest{EmailAddresses: []string{"ops@example.net"}}},
		{name: "more than four names", remote: "192.0.2.10:1", csr: x509.CertificateRequest{DNSNames: []string{"a.example.net", "b.example.net", "c.example.net", "d.example.net", "e.example.net"}}, answers: map[string][]netip.Addr{"a.example.net": {addr("192.0.2.10")}, "b.example.net": {addr("192.0.2.10")}, "c.example.net": {addr("192.0.2.10")}, "d.example.net": {addr("192.0.2.10")}, "e.example.net": {addr("192.0.2.10")}}},
		{name: "expired", remote: "192.0.2.10:1", csr: x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, mutate: func(st *scepState) { st.Shared[0].Expires = time.Now().Add(-time.Minute) }},
		{name: "revoked", remote: "192.0.2.10:1", csr: x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, mutate: func(st *scepState) { st.Shared[0].Revoked = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, secret := newSharedFixture(t, []string{"example.net"})
			stubLookup(t, tc.answers)
			if tc.mutate != nil {
				st, err := f.e.load()
				if err != nil {
					t.Fatal(err)
				}
				tc.mutate(&st)
				if err := f.e.save(st); err != nil {
					t.Fatal(err)
				}
			}
			b, status := f.enrollAt(t, f.sharedCSR(t, secret, tc.csr, tc.unstruct...), tc.remote)
			f.response(t, b, status, false)
			st, _ := f.e.load()
			if len(st.Shared) == 1 && len(st.Shared[0].Issuances) != 0 {
				t.Fatal("refused request was issued")
			}
		})
	}
}

func TestSharedChallengeInventoryFallback(t *testing.T) {
	f, secret := newSharedFixture(t, []string{"example.net"})
	if err := f.e.store.SaveDevice(&Device{Name: "sw1", FQDN: "sw1.example.net", ManagementIP: "192.0.2.10", Port: 443, Platform: "ios-xe"}); err != nil {
		t.Fatal(err)
	}
	// No CSR names: the inventory FQDN for the source address is added. Lookups must not be needed.
	stubLookup(t, nil)
	b, status := f.enrollAt(t, f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "switch"}}), "192.0.2.10:1")
	c := f.response(t, b, status, true)
	if c.Subject.CommonName != "sw1.example.net" || len(c.DNSNames) != 1 || c.DNSNames[0] != "sw1.example.net" {
		t.Fatalf("fallback cert CN %q DNS %v", c.Subject.CommonName, c.DNSNames)
	}
	// A CSR name that the inventory matches verifies without DNS, even when DNS is down.
	secret2, err := f.e.sharedChallenge("builtin:TLS-Server", []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, []string{"example.net"}, 0, 30)
	if err != nil {
		t.Fatal(err)
	}
	b, status = f.enrollAt(t, f.sharedCSR(t, secret2, x509.CertificateRequest{DNSNames: []string{"sw1.example.net"}}), "192.0.2.10:1")
	c = f.response(t, b, status, true)
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "sw1.example.net" {
		t.Fatalf("inventory-matched name DNS %v", c.DNSNames)
	}
}

func TestSharedChallengeNoSuffixesIsIPOnly(t *testing.T) {
	f, secret := newSharedFixture(t, nil)
	stubLookup(t, nil)
	csr := f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "switch.example.net"}, DNSNames: []string{"switch.example.net"}})
	b, status := f.enrollAt(t, csr, "192.0.2.10:1")
	c := f.response(t, b, status, true)
	if len(c.DNSNames) != 0 || c.Subject.CommonName != "192.0.2.10" || len(c.IPAddresses) != 1 {
		t.Fatalf("IP-only cert CN %q DNS %v IP %v", c.Subject.CommonName, c.DNSNames, c.IPAddresses)
	}
}

func TestSharedUnstructuredNameVerified(t *testing.T) {
	f, secret := newSharedFixture(t, []string{"example.net"})
	stubLookup(t, map[string][]netip.Addr{"sw99.example.net": {addr("192.0.2.10")}})
	csr := f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "switch"}}, "hostname=sw99.example.net")
	b, status := f.enrollAt(t, csr, "192.0.2.10:1")
	c := f.response(t, b, status, true)
	if c.Subject.CommonName != "sw99.example.net" {
		t.Fatalf("unstructuredName not used, CN %q", c.Subject.CommonName)
	}
}

func TestSharedRateLimitAndIdempotentRetry(t *testing.T) {
	f, secret := newSharedFixture(t, nil)
	first := f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "a"}})
	b1, status := f.enrollAt(t, first, "192.0.2.10:1")
	c1 := f.response(t, b1, status, true)

	// Same transaction, different CSR content: refused by the rate limit.
	second := f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "b"}})
	b2, status := f.enrollAt(t, second, "192.0.2.10:1")
	f.response(t, b2, status, false)

	// Retry of the first request returns the stored certificate, not counted as a new issuance.
	b3, status := f.enrollAt(t, first, "192.0.2.10:1")
	if c3 := f.response(t, b3, status, true); !bytes.Equal(c1.Raw, c3.Raw) {
		t.Fatal("retry issued a different certificate")
	}
	st, _ := f.e.load()
	if n := len(st.Shared[0].Issuances); n != 1 {
		t.Fatalf("issuances %d, want 1", n)
	}

	// Another source address is a different identity and is not limited.
	b4, status := f.enrollAt(t, second, "192.0.2.11:1")
	c4 := f.response(t, b4, status, true)

	// After the window passes, the same source may be issued again.
	st, _ = f.e.load()
	for i := range st.Shared[0].Issuances {
		st.Shared[0].Issuances[i].Used = time.Now().Add(-sharedRateWindow - time.Minute)
	}
	if err := f.e.save(st); err != nil {
		t.Fatal(err)
	}
	b5, status := f.enrollAt(t, second, "192.0.2.10:1")
	c5 := f.response(t, b5, status, true)
	if c5.SerialNumber.Cmp(c4.SerialNumber) == 0 {
		t.Fatal("source 192.0.2.10 received the certificate issued to 192.0.2.11")
	}
}

func TestSharedRevokedStopsEnrollment(t *testing.T) {
	f, secret := newSharedFixture(t, nil)
	csr := f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "a"}})
	b, status := f.enrollAt(t, csr, "192.0.2.10:1")
	f.response(t, b, status, true)
	if err := f.e.revoke(hashSCEP([]byte(secret))); err != nil {
		t.Fatal(err)
	}
	// Revocation stops enrollment, including retries of an earlier request.
	b, status = f.enrollAt(t, csr, "192.0.2.10:1")
	f.response(t, b, status, false)
}

func TestSharedRecoveryAfterCrash(t *testing.T) {
	f, secret := newSharedFixture(t, nil)
	raw := f.request(t, f.sharedCSR(t, secret, x509.CertificateRequest{Subject: pkix.Name{CommonName: "a"}})).Raw
	dir := filepath.Join(f.e.store.dir, "certs")
	if err := os.Rename(dir, dir+".offline"); err != nil {
		t.Fatal(err)
	}
	if _, status := f.e.enroll(raw, "192.0.2.10:1"); status != 503 {
		t.Fatalf("projection failure status %d", status)
	}
	if err := os.Rename(dir+".offline", dir); err != nil {
		t.Fatal(err)
	}
	st, err := f.e.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Shared) != 1 || len(st.Shared[0].Issuances) != 1 || st.Shared[0].Issuances[0].Published {
		t.Fatal("expected pending shared issuance")
	}
	committed := st.Shared[0].Issuances[0].DER

	// Restart: recovery publishes the committed certificate; the retry returns it.
	f.e = newSCEPService(f.e.store)
	if err := f.e.startup(""); err != nil {
		t.Fatal(err)
	}
	if err := f.e.selectCA(f.ca, "test-pass"); err != nil {
		t.Fatal(err)
	}
	b, status := f.e.enroll(raw, "192.0.2.10:1")
	c := f.response(t, b, status, true)
	if !bytes.Equal(c.Raw, committed) {
		t.Fatal("recovery changed committed certificate")
	}
	st, _ = f.e.load()
	if !st.Shared[0].Issuances[0].Published {
		t.Fatal("issuance not published after recovery")
	}
}

func TestSharedPruneKeepsNewestPerIdentity(t *testing.T) {
	old := time.Now().Add(-scepRetention - time.Hour)
	iss := func(identity string, used time.Time, published bool) scepSharedIssuance {
		return scepSharedIssuance{scepIssuance: scepIssuance{Used: used, Published: published}, Identity: identity}
	}
	st := scepState{Shared: []scepSharedChallenge{{
		Expires: time.Now().Add(-scepRetention - time.Hour),
		Issuances: []scepSharedIssuance{
			iss("a", old.Add(-time.Hour), true),
			iss("a", old, true), // newest for a, kept
			iss("b", old, true), // newest for b, kept
			iss("c", time.Now(), true),
		},
	}, {
		Expires:   time.Now().Add(-scepRetention - time.Hour),
		Issuances: []scepSharedIssuance{iss("d", old, true)},
	}, {
		Expires: time.Now().Add(-scepRetention - time.Hour),
	}}}
	pruneShared(&st)
	if len(st.Shared) != 2 {
		t.Fatalf("challenges kept %d, want 2", len(st.Shared))
	}
	var identities []string
	for _, iss := range st.Shared[0].Issuances {
		identities = append(identities, iss.Identity)
	}
	if strings.Join(identities, ",") != "a,b,c" {
		t.Fatalf("kept issuances %v", identities)
	}
}

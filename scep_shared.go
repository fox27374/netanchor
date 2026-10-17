package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/smallstep/scep"
)

// Shared challenges are reusable secrets for many devices in fixed IP ranges.
// The certificate's only IP SAN is the request's source address, and DNS names
// are accepted only when they belong to a configured suffix and either resolve
// to that address or name an inventory device at that address. See README.

const (
	sharedMaxNames     = 4
	sharedRateWindow   = 10 * time.Minute
	sharedMaxRanges    = 64
	sharedMaxSuffixes  = 16
	sharedLookupBudget = 2 * time.Second
)

// lookupSCEPHost resolves a candidate DNS name for a shared challenge. Tests replace it.
var lookupSCEPHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

type scepSharedChallenge struct {
	Hash      string
	CA        string
	Profile   CertTemplate
	Ranges    []netip.Prefix
	Suffixes  []string // empty means IP-only certificates
	Days      int
	Expires   time.Time
	Created   time.Time
	Revoked   bool
	Issuances []scepSharedIssuance
}

type scepSharedIssuance struct {
	scepIssuance
	Identity string // source address plus the verified DNS names, the rate-limit key
	Source   netip.Addr
}

func (c scepSharedChallenge) Status() string {
	switch {
	case c.Revoked:
		return "revoked"
	case time.Now().After(c.Expires):
		return "expired"
	default:
		return "active"
	}
}

// LastUsed is the time of the most recent issuance, or zero.
func (c scepSharedChallenge) LastUsed() time.Time {
	var last time.Time
	for _, iss := range c.Issuances {
		if iss.Used.After(last) {
			last = iss.Used
		}
	}
	return last
}

// scepDNSName reports whether s is a valid lowercase-or-uppercase DNS name without a trailing dot.
func scepDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

// normalizeSharedSuffixes lowercases suffixes and requires at least two labels,
// so that a suffix can never match a whole top-level domain.
func normalizeSharedSuffixes(in []string) ([]string, error) {
	var out []string
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, ".") || strings.Contains(s, "*") {
			return nil, fmt.Errorf("DNS suffix %q must not start with a dot or contain a wildcard", raw)
		}
		s = strings.TrimSuffix(s, ".")
		if !scepDNSName(s) || !strings.Contains(s, ".") {
			return nil, fmt.Errorf("DNS suffix %q must be a valid name with at least two labels", raw)
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) > sharedMaxSuffixes {
		return nil, fmt.Errorf("at most %d DNS suffixes", sharedMaxSuffixes)
	}
	return out, nil
}

// normalizeSharedRanges masks each prefix and rejects IPv4-mapped IPv6 forms.
func normalizeSharedRanges(in []netip.Prefix) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return nil, errors.New("supply at least one IPv4 or IPv6 CIDR range")
	}
	if len(in) > sharedMaxRanges {
		return nil, fmt.Errorf("at most %d CIDR ranges", sharedMaxRanges)
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid CIDR range %v", p)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// sharedChallenge creates a reusable challenge. The secret is returned once.
func (e *SCEPService) sharedChallenge(profile string, ranges []netip.Prefix, suffixes []string, days, expiryDays int) (string, error) {
	e.store.scepMu.Lock()
	defer e.store.scepMu.Unlock()
	st, err := e.load()
	if err != nil {
		return "", err
	}
	if _, err := e.ca(st.CA); err != nil {
		return "", err
	}
	e.store.mu.Lock()
	t, ok := e.store.GetTemplate(profile)
	e.store.mu.Unlock()
	if !ok || !t.Profile.serverAuth() {
		return "", errors.New("select a TLS server template")
	}
	if days == 0 {
		days = 365
	}
	if days < 1 || days > 36500 {
		return "", errors.New("invalid certificate lifetime")
	}
	if days > t.MaxDays {
		days = t.MaxDays
	}
	if err := policyBasics(t, st.CA, days); err != nil {
		return "", err
	}
	if expiryDays < 1 || expiryDays > 365 {
		return "", errors.New("shared challenge expiry must be 1–365 days")
	}
	ranges, err = normalizeSharedRanges(ranges)
	if err != nil {
		return "", err
	}
	suffixes, err = normalizeSharedSuffixes(suffixes)
	if err != nil {
		return "", err
	}
	if err := e.recover(&st); err != nil {
		return "", err
	}
	pruneSCEP(&st)
	if len(st.Challenges)+len(st.Shared) >= 10000 {
		return "", errors.New("SCEP challenge capacity reached; wait for retention cleanup")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(b)
	now := time.Now()
	st.Shared = append(st.Shared, scepSharedChallenge{Hash: hashSCEP([]byte(secret)), CA: st.CA, Profile: t, Ranges: ranges, Suffixes: suffixes, Days: days, Expires: now.Add(time.Duration(expiryDays) * 24 * time.Hour), Created: now})
	if err := e.save(st); err != nil {
		return "", err
	}
	return secret, nil
}

// pruneShared keeps a challenge while any of its issuances is kept. Issuances
// are kept within retention, while unpublished, or as the newest per identity.
func pruneShared(st *scepState) {
	kept := st.Shared[:0]
	for _, c := range st.Shared {
		newest := map[string]int{}
		for j, iss := range c.Issuances {
			if k, ok := newest[iss.Identity]; !ok || iss.Used.After(c.Issuances[k].Used) {
				newest[iss.Identity] = j
			}
		}
		var issuances []scepSharedIssuance
		for j, iss := range c.Issuances {
			if time.Now().Before(iss.Used.Add(scepRetention)) || !iss.Published || newest[iss.Identity] == j {
				issuances = append(issuances, iss)
			}
		}
		c.Issuances = issuances
		if time.Now().Before(c.Expires.Add(scepRetention)) || len(issuances) > 0 {
			kept = append(kept, c)
		}
	}
	st.Shared = kept
}

// sharedIndex returns the shared challenge for a password hash issued by the selected CA.
func sharedIndex(st *scepState, hash string) int {
	for i := range st.Shared {
		if st.Shared[i].Hash == hash && st.Shared[i].CA == st.CA {
			return i
		}
	}
	return -1
}

// remoteHost returns the IP part of an HTTP peer address, for logs.
func remoteHost(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

// scepSource returns the unmapped peer address of an HTTP request.
func scepSource(remote string) (netip.Addr, error) {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap().WithZone(""), nil
}

// csrUnstructuredNames returns the PKCS#9 unstructuredName values of the CSR.
// Values may be prefixed with "hostname=" (IOS-XE).
func csrUnstructuredNames(csr *x509.CertificateRequest) []string {
	var info struct {
		Version    int
		Subject    asn1.RawValue
		Key        asn1.RawValue
		Attributes []struct {
			OID    asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		} `asn1:"tag:0"`
	}
	if _, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &info); err != nil {
		return nil
	}
	var out []string
	for _, a := range info.Attributes {
		if !a.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 2}) {
			continue
		}
		for _, v := range a.Values {
			var s string
			if _, err := asn1.Unmarshal(v.FullBytes, &s); err == nil {
				out = append(out, s)
			}
		}
	}
	return out
}

// sharedCandidates gathers the DNS names a CSR asks for, in order: DNS SANs,
// the subject CN if it is a dotted name, then dotted unstructuredName values.
func sharedCandidates(csr *x509.CertificateRequest) ([]string, error) {
	norm := func(s string) string {
		return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	}
	var out []string
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, d := range csr.DNSNames {
		n := norm(d)
		if !scepDNSName(n) {
			return nil, fmt.Errorf("invalid DNS SAN %q", d)
		}
		add(n)
	}
	dotted := func(s string) bool { return strings.Contains(s, ".") && scepDNSName(s) }
	if n := norm(csr.Subject.CommonName); dotted(n) {
		add(n)
	}
	for _, v := range csrUnstructuredNames(csr) {
		n := norm(strings.TrimPrefix(norm(v), "hostname="))
		if dotted(n) {
			add(n)
		}
	}
	if len(out) > sharedMaxNames {
		return nil, fmt.Errorf("%d DNS names requested, at most %d allowed", len(out), sharedMaxNames)
	}
	return out, nil
}

// deviceAddr returns the inventory management address with any port removed.
func deviceAddr(d Device) (netip.Addr, bool) {
	host := d.ManagementIP
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func underSuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// sharedNames verifies the DNS names for a request from src. A reason is a
// refusal; the returned names are the certificate's DNS SANs.
func (e *SCEPService) sharedNames(csr *x509.CertificateRequest, suffixes []string, src netip.Addr) (names []string, reason string, err error) {
	if len(suffixes) == 0 {
		return nil, "", nil // IP-only certificate; DNS candidates are ignored
	}
	cands, err := sharedCandidates(csr)
	if err != nil {
		return nil, err.Error(), nil
	}
	devices, err := e.store.ListDevices()
	if err != nil {
		return nil, "", err
	}
	atSource := func(fqdn string) bool {
		for _, d := range devices {
			if a, ok := deviceAddr(d); ok && a == src && strings.EqualFold(strings.TrimSuffix(d.FQDN, "."), fqdn) {
				return true
			}
		}
		return false
	}
	for _, n := range cands {
		if !underSuffix(n, suffixes) {
			return nil, fmt.Sprintf("name %s is not under a challenge DNS suffix", n), nil
		}
		if atSource(n) {
			names = append(names, n)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), sharedLookupBudget)
		addrs, lookupErr := lookupSCEPHost(ctx, n)
		cancel()
		if lookupErr != nil {
			return nil, fmt.Sprintf("name %s did not resolve: %v", n, lookupErr), nil
		}
		found := false
		for _, a := range addrs {
			found = found || a.Unmap() == src
		}
		if !found {
			return nil, fmt.Sprintf("name %s resolves to %v, not source %s", n, addrs, src), nil
		}
		names = append(names, n)
	}
	if len(cands) == 0 {
		for _, d := range devices {
			if a, ok := deviceAddr(d); ok && a == src && d.FQDN != "" {
				fqdn := strings.ToLower(strings.TrimSuffix(d.FQDN, "."))
				if underSuffix(fqdn, suffixes) && !slices.Contains(names, fqdn) {
					names = append(names, fqdn)
				}
			}
		}
	}
	if len(names) > sharedMaxNames {
		return nil, fmt.Sprintf("%d DNS names verified, at most %d allowed", len(names), sharedMaxNames), nil
	}
	return names, "", nil
}

// enrollShared returns the certificate DER for a shared challenge, or a refusal
// reason. Caller holds scepMu; ca is the selected, usable CA.
func (e *SCEPService) enrollShared(st *scepState, c *scepSharedChallenge, msg *scep.PKIMessage, rh, sh, remote string, ca *x509.Certificate, key *rsa.PrivateKey) (der []byte, reason string, err error) {
	now := time.Now()
	tx := string(msg.TransactionID)
	switch {
	case c.Revoked:
		return nil, "shared challenge revoked", nil
	case now.After(c.Expires):
		return nil, "shared challenge expired", nil
	}
	src, err := scepSource(remote)
	if err != nil {
		return nil, fmt.Sprintf("source address %q unusable: %v", remote, err), nil
	}
	inRange := false
	for _, p := range c.Ranges {
		inRange = inRange || p.Contains(src)
	}
	if !inRange {
		return nil, fmt.Sprintf("source %s not in challenge ranges", src), nil
	}
	// A same-transaction retry from the same source returns the stored certificate
	// and is not rate limited. The source must match: a retry never moves a certificate.
	for j := range c.Issuances {
		iss := &c.Issuances[j]
		if iss.Transaction != tx || iss.RequestHash != rh || iss.SignerHash != sh || iss.Source != src || !now.Before(iss.Used.Add(scepRetention)) {
			continue
		}
		if _, ok := e.store.RecordBySerial(iss.Record.Serial); !ok {
			return nil, "certificate of this shared challenge was deleted", nil
		}
		return iss.DER, "", nil
	}
	if len(msg.CSR.EmailAddresses)+len(msg.CSR.URIs) > 0 {
		return nil, "CSR email or URI SANs are not allowed with a shared challenge", nil
	}
	names, reason, err := e.sharedNames(msg.CSR, c.Suffixes, src)
	if err != nil || reason != "" {
		return nil, reason, err
	}
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	identity := src.String() + "|" + strings.Join(sorted, ",")
	for _, iss := range c.Issuances {
		if iss.Identity == identity && now.Before(iss.Used.Add(sharedRateWindow)) {
			return nil, "rate limited: this identity was issued a certificate within the last 10 minutes", nil
		}
	}
	cn := src.String()
	if len(names) > 0 {
		cn = names[0]
	}
	authorized := *msg.CSR
	authorized.Subject.CommonName = cn
	authorized.DNSNames = names
	authorized.IPAddresses = []net.IP{src.AsSlice()}
	authorized.EmailAddresses, authorized.URIs = nil, nil
	rec, der, err := signCSRWithoutPersistence(&authorized, SignCSRParams{IssuerID: st.CA, ValidDays: c.Days, Template: c.Profile, TemplateName: c.Profile.Name}, ca, key, true)
	if err != nil {
		return nil, "signing: " + err.Error(), nil
	}
	rec.Provenance = "scep"
	c.Issuances = append(c.Issuances, scepSharedIssuance{
		scepIssuance: scepIssuance{Used: now, Transaction: tx, RequestHash: rh, SignerHash: sh, DER: der, Record: rec},
		Identity:     identity,
		Source:       src,
	})
	// Commit before touching the certificate projection or returning success.
	if err := e.save(*st); err != nil {
		return nil, "", err
	}
	if err := e.recover(st); err != nil {
		return nil, "", err
	}
	return der, "", nil
}

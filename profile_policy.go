package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strings"
)

func profileKeyUsage(p certProfile, a keyAlgo) x509.KeyUsage {
	ku := x509.KeyUsageDigitalSignature
	if strings.HasPrefix(string(a), "rsa") && (p == profileServer || p == profileBoth) {
		ku |= x509.KeyUsageKeyEncipherment
	}
	if p == profileCode {
		ku |= x509.KeyUsageContentCommitment
	}
	return ku
}
func allowedAlgo(t CertTemplate, a keyAlgo) bool {
	for _, x := range t.AllowedAlgos {
		if x == a {
			return true
		}
	}
	return false
}
func publicKeyAlgo(pub any) (keyAlgo, bool) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() == 4096 {
			return algoRSA4096, true
		}
		if k.N.BitLen() == 2048 {
			return algoRSA2048, true
		}
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return algoECP256, true
		}
		if k.Curve == elliptic.P384() {
			return algoECP384, true
		}
	}
	return "", false
}
func publicKeyAlgoValue(pub any) keyAlgo { a, _ := publicKeyAlgo(pub); return a }
func validPublicKey(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("RSA key must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return errors.New("unsupported or weak ECDSA curve")
		}
	default:
		return errors.New("unsupported public-key algorithm")
	}
	return nil
}
func policyBasics(t CertTemplate, issuer string, days int) error {
	switch t.Profile {
	case profileServer, profileClient, profileBoth, profileCode, profileEmail:
	default:
		return errors.New("invalid certificate purpose")
	}
	if days < 1 || days > t.MaxDays {
		return fmt.Errorf("validity must be between 1 and %d days", t.MaxDays)
	}
	if len(t.AllowedIssuers) > 0 {
		ok := false
		for _, id := range t.AllowedIssuers {
			if id == issuer {
				ok = true
			}
		}
		if !ok {
			return errors.New("selected issuer CA is not allowed by this template")
		}
	}
	return nil
}
func validateIssuePolicy(t CertTemplate, issuer string, days int, a keyAlgo, cn string, dns []string, ips []net.IP, emails, uris []string) error {
	if err := policyBasics(t, issuer, days); err != nil {
		return err
	}
	if !allowedAlgo(t, a) {
		return errors.New("key algorithm is not allowed by this template")
	}
	switch t.Profile {
	case profileServer, profileBoth:
		if len(dns)+len(ips) == 0 || len(emails)+len(uris) > 0 {
			return errors.New("this purpose requires DNS or IP SANs only")
		}
	case profileEmail:
		if len(emails) == 0 || len(dns)+len(ips)+len(uris) > 0 {
			return errors.New("S/MIME requires email SANs only")
		}
	case profileClient:
		if strings.TrimSpace(cn) == "" {
			return errors.New("client identity is required")
		}
	case profileCode:
		if strings.TrimSpace(cn) == "" {
			return errors.New("subject identity is required")
		}
		if len(dns)+len(ips)+len(emails)+len(uris) > 0 {
			return errors.New("code signing does not permit SANs")
		}
	}
	return nil
}
func validateCSRPolicy(c *x509.CertificateRequest, t CertTemplate, issuer string, days int) error {
	if err := policyBasics(t, issuer, days); err != nil {
		return err
	}
	if err := validPublicKey(c.PublicKey); err != nil {
		return err
	}
	seen := map[string]bool{}
	if len(c.Extensions) > 0 {
		for _, e := range c.Extensions {
			key := e.Id.String()
			if seen[key] {
				return errors.New("CSR contains duplicate extensions")
			}
			seen[key] = true
			switch {
			case e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}):
				// x509.ParseCertificateRequest has already decoded SANs into
				// the typed fields checked against the selected purpose below.
				var names asn1.RawValue
				if rest, err := asn1.Unmarshal(e.Value, &names); err != nil || len(rest) != 0 || names.Tag != asn1.TagSequence {
					return errors.New("CSR contains malformed subject alternative names")
				}
				for raw := names.Bytes; len(raw) > 0; {
					var name asn1.RawValue
					rest, err := asn1.Unmarshal(raw, &name)
					if err != nil || name.Class != asn1.ClassContextSpecific || (name.Tag != 1 && name.Tag != 2 && name.Tag != 6 && name.Tag != 7) {
						return errors.New("CSR requests an unsupported SAN type")
					}
					raw = rest
				}
			case e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}):
				var bc struct {
					IsCA       bool
					MaxPathLen int `asn1:"optional,default:-1"`
				}
				if _, err := asn1.Unmarshal(e.Value, &bc); err != nil {
					return errors.New("CSR contains malformed basic constraints")
				}
				if bc.IsCA {
					return errors.New("CSR requests CA privileges")
				}
			case e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}):
				var ku asn1.BitString
				if _, err := asn1.Unmarshal(e.Value, &ku); err != nil {
					return errors.New("CSR contains malformed key usage")
				}
				if ku.At(5) == 1 || ku.At(6) == 1 {
					return errors.New("CSR requests CA key usages")
				}
				if ku.At(0) == 0 {
					return errors.New("CSR key usage conflicts with leaf signing policy")
				}
			case e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}):
				var ekus []asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(e.Value, &ekus); err != nil {
					return errors.New("CSR contains malformed extended key usage")
				}
				for _, oid := range ekus {
					if !ekuAllowed(t.Profile, oid) {
						return errors.New("CSR requests extended key usage conflicting with selected purpose")
					}
				}
			default:
				if e.Critical {
					return errors.New("CSR contains a critical extension that cannot be safely honored")
				}
			}
		}
	}
	switch t.Profile {
	case profileServer, profileBoth:
		if len(c.DNSNames)+len(c.IPAddresses) == 0 || len(c.EmailAddresses)+len(c.URIs) > 0 {
			return errors.New("this purpose requires DNS or IP SANs only")
		}
	case profileEmail:
		if len(c.EmailAddresses) == 0 || len(c.DNSNames)+len(c.IPAddresses)+len(c.URIs) > 0 {
			return errors.New("S/MIME requires email SANs only")
		}
	case profileClient:
		if len(c.Subject.CommonName) == 0 && len(c.Subject.Names) == 0 && len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) == 0 {
			return errors.New("client identity is required")
		}
	case profileCode:
		if len(c.Subject.CommonName) == 0 && len(c.Subject.Names) == 0 {
			return errors.New("subject identity is required")
		}
		if len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) > 0 {
			return errors.New("code signing does not permit SANs")
		}
	}
	return nil
}

func ekuAllowed(p certProfile, oid asn1.ObjectIdentifier) bool {
	allowed := [][]int{}
	switch p {
	case profileServer:
		allowed = [][]int{{1, 3, 6, 1, 5, 5, 7, 3, 1}}
	case profileClient:
		allowed = [][]int{{1, 3, 6, 1, 5, 5, 7, 3, 2}}
	case profileBoth:
		allowed = [][]int{{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 3, 6, 1, 5, 5, 7, 3, 2}}
	case profileCode:
		allowed = [][]int{{1, 3, 6, 1, 5, 5, 7, 3, 3}}
	case profileEmail:
		allowed = [][]int{{1, 3, 6, 1, 5, 5, 7, 3, 4}}
	}
	for _, candidate := range allowed {
		if oid.Equal(candidate) {
			return true
		}
	}
	return false
}

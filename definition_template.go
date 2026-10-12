package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Definition templates. The common name and the SAN entries may contain
// placeholders, filled from the device at push time: {{ fqdn }}, {{ name }} and
// {{ ip }}. Spaces inside the braces are optional. Plain text around them is kept.

// definitionVarLabels lists the placeholders, with the label used in messages.
var definitionVarLabels = map[string]string{"fqdn": "FQDN", "name": "name", "ip": "management IP"}

// definitionSampleVals stands in for a device when a template is checked at save time.
var definitionSampleVals = map[string]string{"fqdn": "host.example.net", "name": "host", "ip": "192.0.2.1"}

// expandDefinitionTemplate replaces each placeholder in s with its value from vals.
// It returns the result and the name of the first placeholder whose value is empty
// ("" when none is). An unknown placeholder or an unmatched brace is an error.
func expandDefinitionTemplate(s string, vals map[string]string) (string, string, error) {
	var b strings.Builder
	emptyVar := ""
	for {
		open := strings.Index(s, "{{")
		shut := strings.Index(s, "}}")
		if open < 0 && shut < 0 {
			b.WriteString(s)
			return b.String(), emptyVar, nil
		}
		if open < 0 || (shut >= 0 && shut < open) {
			return "", "", fmt.Errorf("%q has a \"}}\" without a matching \"{{\"", s)
		}
		end := strings.Index(s[open+2:], "}}")
		if end < 0 {
			return "", "", fmt.Errorf("%q has a \"{{\" without a closing \"}}\"", s)
		}
		name := strings.TrimSpace(s[open+2 : open+2+end])
		if strings.Contains(name, "{{") {
			return "", "", fmt.Errorf("%q has a \"{{\" without a closing \"}}\"", s)
		}
		if _, ok := definitionVarLabels[name]; !ok {
			return "", "", fmt.Errorf("unknown placeholder {{ %s }}: use {{ fqdn }}, {{ name }} or {{ ip }}", name)
		}
		val := vals[name]
		if val == "" && emptyVar == "" {
			emptyVar = name
		}
		b.WriteString(s[:open])
		b.WriteString(val)
		s = s[open+2+end+2:]
	}
}

// checkDefinitionTemplates applies the save-time rules to a definition's templates.
// It is used by the form and by backup restore. Fixed (placeholder-free) DNS names
// and IP addresses must be valid; templated entries are checked at push time.
func checkDefinitionTemplates(cn string, dnsSANs, ipSANs []string) error {
	if cn == "" {
		return errors.New("common name is required")
	}
	if _, _, err := expandDefinitionTemplate(cn, definitionSampleVals); err != nil {
		return fmt.Errorf("common name: %w", err)
	}
	for _, san := range dnsSANs {
		if _, _, err := expandDefinitionTemplate(san, definitionSampleVals); err != nil {
			return fmt.Errorf("DNS SAN: %w", err)
		}
		if !strings.Contains(san, "{{") && !validDNSName(san) {
			return fmt.Errorf("DNS SAN %q is not a valid DNS name or template", san)
		}
	}
	for _, san := range ipSANs {
		if _, _, err := expandDefinitionTemplate(san, definitionSampleVals); err != nil {
			return fmt.Errorf("IP SAN: %w", err)
		}
		if !strings.Contains(san, "{{") && net.ParseIP(san) == nil {
			return fmt.Errorf("IP SAN %q is not an IP address or template", san)
		}
	}
	return nil
}

// definitionSubject fills the templates of def from dev. An empty placeholder drops
// a DNS or IP SAN entry, and duplicates are dropped. An empty common name, or an IP
// entry that is not an IP once filled, is an error: nothing falls back.
func definitionSubject(def CertDefinition, dev Device) (string, []string, []net.IP, error) {
	vals := map[string]string{"fqdn": dev.FQDN, "name": dev.Name, "ip": dev.ManagementIP}
	cn, empty, err := expandDefinitionTemplate(def.CommonName, vals)
	if err != nil {
		return "", nil, nil, fmt.Errorf("common name: %w", err)
	}
	if empty != "" {
		return "", nil, nil, fmt.Errorf("common name template needs the device %s, which is empty", definitionVarLabels[empty])
	}
	if cn == "" {
		return "", nil, nil, errors.New("common name is empty")
	}
	var dns []string
	seenDNS := map[string]bool{}
	for _, t := range def.DNSSANs {
		v, empty, err := expandDefinitionTemplate(t, vals)
		if err != nil {
			return "", nil, nil, fmt.Errorf("DNS SAN: %w", err)
		}
		if empty != "" || seenDNS[v] {
			continue
		}
		seenDNS[v] = true
		dns = append(dns, v)
	}
	var ips []net.IP
	seenIP := map[string]bool{}
	for _, t := range def.IPSANs {
		v, empty, err := expandDefinitionTemplate(t, vals)
		if err != nil {
			return "", nil, nil, fmt.Errorf("IP SAN: %w", err)
		}
		if empty != "" {
			continue
		}
		ip := net.ParseIP(v)
		if ip == nil {
			return "", nil, nil, fmt.Errorf("IP SAN %q is not a valid IP address for this device", v)
		}
		if seenIP[ip.String()] {
			continue
		}
		seenIP[ip.String()] = true
		ips = append(ips, ip)
	}
	return cn, dns, ips, nil
}

// migrateLegacyDefinition converts a record saved before templates existed. A record
// with a common name is left alone. The legacy fields are cleared, so the next save
// writes only the template format.
func migrateLegacyDefinition(d *CertDefinition) {
	if d.CommonName != "" {
		return
	}
	d.CommonName = "{{ fqdn }}"
	if d.CNSource == definitionCNName {
		d.CommonName = "{{ name }}"
	}
	d.DNSSANs = []string{"{{ fqdn }}"}
	d.IPSANs = []string{"{{ ip }}"}
	for _, san := range d.ExtraSANs {
		if net.ParseIP(san) != nil {
			d.IPSANs = append(d.IPSANs, san)
		} else {
			d.DNSSANs = append(d.DNSSANs, san)
		}
	}
	d.ExtraSANs, d.CNSource = nil, ""
}

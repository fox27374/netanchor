package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefinitionTemplateExpansion(t *testing.T) {
	dev := Device{Name: "sw1", FQDN: "sw1.example.net", ManagementIP: "192.0.2.10"}
	for _, tc := range []struct{ name, cn, want string }{
		{"compact", "{{fqdn}}", "sw1.example.net"},
		{"spaced", "{{  name  }}", "sw1"},
		{"mixed", "sw-{{ name }}.example.com", "sw-sw1.example.com"},
		{"ip", "{{ip}}", "192.0.2.10"},
	} {
		got, _, err := expandDefinitionTemplate(tc.cn, map[string]string{"fqdn": dev.FQDN, "name": dev.Name, "ip": dev.ManagementIP})
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}

	noFQDN := Device{Name: "sw1", ManagementIP: "192.0.2.10"}
	def := CertDefinition{CommonName: "{{ name }}", DNSSANs: []string{"{{ fqdn }}", "fixed.example.net", "{{ fqdn }}", "fixed.example.net"}, IPSANs: []string{"{{ ip }}", "192.0.2.10", "{{ fqdn }}"}}
	cn, dns, ips, err := definitionSubject(def, noFQDN)
	if err != nil || cn != "sw1" || strings.Join(dns, ",") != "fixed.example.net" || len(ips) != 1 || ips[0].String() != "192.0.2.10" {
		t.Fatalf("empty FQDN and dedupe: cn=%q dns=%v ips=%v err=%v", cn, dns, ips, err)
	}

	if _, _, _, err := definitionSubject(CertDefinition{CommonName: "{{ fqdn }}"}, noFQDN); err == nil || !strings.Contains(err.Error(), "needs the device FQDN, which is empty") {
		t.Fatalf("empty CN placeholder: %v", err)
	}
	if _, _, _, err := definitionSubject(CertDefinition{CommonName: "{{ name }}", IPSANs: []string{"{{ name }}"}}, dev); err == nil {
		t.Fatal("IP SAN that is not an IP after substitution was accepted")
	}
}

func TestDefinitionTemplateChecks(t *testing.T) {
	for _, bad := range []string{"{{ host }}", "sw }} x", "{{ fqdn", "{{ {{ fqdn }}", "{{}}"} {
		if err := checkDefinitionTemplates(bad, nil, nil); err == nil {
			t.Errorf("common name %q accepted", bad)
		}
	}
	if err := checkDefinitionTemplates("{{ host }}", nil, nil); err == nil || !strings.Contains(err.Error(), "{{ host }}") {
		t.Fatalf("unknown variable error = %v, want it to name {{ host }}", err)
	}
	if err := checkDefinitionTemplates("{{ fqdn }}", []string{"x_y"}, nil); err == nil {
		t.Error("bad fixed DNS SAN accepted")
	}
	if err := checkDefinitionTemplates("{{ fqdn }}", nil, []string{"{{ name }}", "10.0.0.1"}); err != nil {
		t.Errorf("valid templates refused: %v", err)
	}
}

func TestDefinitionLegacyMigration(t *testing.T) {
	legacy := `[{"id":"d1","name":"old","ca_id":"` + caRoot + `","profile":"TLS-Server","country":"NL","state":"Utrecht","organization":"Example",
		"valid_days":90,"cert_id":"netanchor-old","cn_source":"name","extra_sans":["lb.example.net","192.0.2.99"]}]`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "definitions.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateDefinitions(dir); err != nil {
		t.Fatalf("legacy backup refused: %v", err)
	}
	defs, err := (&Store{dir: dir}).ListDefinitions()
	if err != nil || len(defs) != 1 {
		t.Fatalf("list: %v %+v", err, defs)
	}
	d := defs[0]
	if d.CommonName != "{{ name }}" || strings.Join(d.DNSSANs, ",") != "{{ fqdn }},lb.example.net" || strings.Join(d.IPSANs, ",") != "{{ ip }},192.0.2.99" {
		t.Fatalf("migrated = %+v", d)
	}
	if d.ExtraSANs != nil || d.CNSource != "" {
		t.Fatal("legacy fields not cleared")
	}
}

func TestDefinitionFormRendersPlaceholderDefaults(t *testing.T) {
	_, srv := deviceTestStore(t)
	rec := deviceGet(srv, "/definitions/new")
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	for _, want := range []string{`value="{{ fqdn }}"`, `value="{{ ip }}"`, "{{ name }}", "{{ fqdn }}"} {
		if !strings.Contains(body, want) {
			t.Errorf("form does not show %q", want)
		}
	}
}

package main

import (
	"errors"
	"strings"
	"time"
)

// CertTemplate is a server-enforced X.509 leaf profile used for issuance and CSR signing.
type CertTemplate struct {
	Name           string      `json:"name"`
	Description    string      `json:"description"`
	Organization   string      `json:"organization"`
	Country        string      `json:"country"`
	Algo           keyAlgo     `json:"algo"`
	ValidDays      int         `json:"valid_days"`
	MaxDays        int         `json:"max_days"`
	AllowedAlgos   []keyAlgo   `json:"allowed_algorithms"`
	AllowedIssuers []string    `json:"allowed_issuers,omitempty"`
	Profile        certProfile `json:"profile"`
	Builtin        bool        `json:"builtin,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
}

func builtinTemplates() []CertTemplate {
	all := []keyAlgo{algoRSA2048, algoRSA4096, algoECP256, algoECP384}
	return []CertTemplate{
		{Name: "TLS-Server", Description: "TLS server", Profile: profileServer, Algo: algoECP256, ValidDays: 90, MaxDays: 365, AllowedAlgos: all, Builtin: true},
		{Name: "TLS-Client", Description: "TLS client (device/service)", Profile: profileClient, Algo: algoECP256, ValidDays: 365, MaxDays: 730, AllowedAlgos: all, Builtin: true},
		{Name: "Server-Client", Description: "TLS server and client", Profile: profileBoth, Algo: algoECP256, ValidDays: 90, MaxDays: 365, AllowedAlgos: all, Builtin: true},
		{Name: "Code-Signing", Description: "Code signing", Profile: profileCode, Algo: algoECP256, ValidDays: 365, MaxDays: 1095, AllowedAlgos: all, Builtin: true},
		{Name: "S-MIME", Description: "S/MIME email", Profile: profileEmail, Algo: algoECP256, ValidDays: 365, MaxDays: 730, AllowedAlgos: all, Builtin: true},
	}
}

func builtinByName(name string) (CertTemplate, bool) {
	for _, t := range builtinTemplates() {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return CertTemplate{}, false
}

// validTemplateName keeps names safe to embed in a URL path.
func validTemplateName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// normalize validates and fills sensible defaults on a template.
func (t *CertTemplate) normalize() error {
	t.Name = strings.TrimSpace(t.Name)
	if !validTemplateName(t.Name) {
		return errors.New("name must be 1-64 chars: letters, digits, '-' or '_'")
	}
	switch t.Algo {
	case algoRSA2048, algoRSA4096, algoECP256, algoECP384:
	default:
		return errors.New("choose a supported default key algorithm")
	}
	switch t.Profile {
	case profileServer, profileClient, profileBoth, profileCode, profileEmail:
	default:
		return errors.New("choose a supported certificate purpose")
	}
	if t.ValidDays <= 0 || t.MaxDays <= 0 {
		return errors.New("default and maximum validity must be positive")
	}
	if t.ValidDays > t.MaxDays {
		return errors.New("default validity cannot exceed maximum validity")
	}
	if len(t.AllowedAlgos) == 0 {
		return errors.New("select at least one allowed key algorithm")
	}
	seen := map[keyAlgo]bool{}
	for _, a := range t.AllowedAlgos {
		if a != algoRSA2048 && a != algoRSA4096 && a != algoECP256 && a != algoECP384 {
			return errors.New("unsupported allowed key algorithm")
		}
		if seen[a] {
			return errors.New("duplicate allowed key algorithm")
		}
		seen[a] = true
	}
	if !seen[t.Algo] {
		return errors.New("default key algorithm must be allowed by the template")
	}
	for i, id := range t.AllowedIssuers {
		id = strings.TrimSpace(id)
		if id == "" {
			return errors.New("issuer IDs cannot be empty")
		}
		t.AllowedIssuers[i] = id
	}
	return nil
}

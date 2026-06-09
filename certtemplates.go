package main

import (
	"errors"
	"strings"
	"time"
)

// CertTemplate is a reusable issuance preset. When issuing a certificate (or
// signing a CSR) a template pre-fills the form fields so common certificate
// shapes don't have to be retyped each time.
type CertTemplate struct {
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	Organization string      `json:"organization"`
	Country      string      `json:"country"`
	Algo         keyAlgo     `json:"algo"`
	ValidDays    int         `json:"valid_days"`
	Profile      certProfile `json:"profile"`
	CreatedAt    time.Time   `json:"created_at"`
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
		t.Algo = algoECP256
	}
	switch t.Profile {
	case profileServer, profileClient, profileBoth:
	default:
		t.Profile = profileServer
	}
	if t.ValidDays <= 0 {
		t.ValidDays = 365
	}
	return nil
}

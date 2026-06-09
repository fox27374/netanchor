package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
)

// PKCS#7 "certs-only" (degenerate SignedData) encoder, built with encoding/asn1
// so it stays pure standard library. This is the structure OpenSSL produces with
// `openssl crl2pkcs7 -nocrl -certfile ...` and that Windows/Java import as a
// .p7b certificate bundle.

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

type p7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type p7SignedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	ContentInfo      p7ContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// encodePKCS7Certs wraps one or more certificates in a PEM-encoded PKCS#7 bundle.
func encodePKCS7Certs(certs []*x509.Certificate) ([]byte, error) {
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}

	sd := p7SignedData{
		Version:          1,
		DigestAlgorithms: []asn1.RawValue{},
		ContentInfo:      p7ContentInfo{ContentType: oidData},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      raw,
		},
		SignerInfos: []asn1.RawValue{},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}

	// The outer ContentInfo wraps the SignedData in [0] EXPLICIT. We build that
	// wrapper explicitly: a RawValue with FullBytes set would be emitted verbatim
	// (skipping the tag), so instead we set Class/Tag/Bytes to produce the [0].
	outer := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}
	der, err := asn1.Marshal(outer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der}), nil
}

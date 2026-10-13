package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

// encryptForSCEP builds an EnvelopedData with a block cipher pkcs7 cannot produce
// itself (3DES, single DES), the way IOS-XE does, for the CA certificate.
func encryptForSCEP(t *testing.T, plain []byte, ca *x509.Certificate, oid asn1.ObjectIdentifier, keyLen int, newCipher func([]byte) (cipher.Block, error)) []byte {
	t.Helper()
	tmpl, err := pkcs7.Encrypt(plain, []*x509.Certificate{ca}) // borrow the recipient structure
	if err != nil {
		t.Fatal(err)
	}
	e, err := inspectEnvelope(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	key, iv := make([]byte, keyLen), make([]byte, des.BlockSize)
	rand.Read(key)
	rand.Read(iv)
	b, err := newCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	n := des.BlockSize - len(plain)%des.BlockSize
	padded := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(n)}, n)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(ct, padded)
	var r struct {
		Version   int
		Issuer    asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Key       []byte
	}
	if _, err := asn1.Unmarshal(e.Recipients[0].FullBytes, &r); err != nil {
		t.Fatal(err)
	}
	if r.Key, err = rsa.EncryptPKCS1v15(rand.Reader, ca.PublicKey.(*rsa.PublicKey), key); err != nil {
		t.Fatal(err)
	}
	rb, err := asn1.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	e.Recipients[0] = asn1.RawValue{FullBytes: rb}
	e.Content.Algorithm = pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: iv}}
	e.Content.Ciphertext = asn1.RawValue{Class: 2, Tag: 0, Bytes: ct}
	return marshalEnvelope(t, e)
}

func TestSCEPAcceptsTripleDESButNotDES(t *testing.T) {
	f := newSCEPFixture(t)
	csr := f.csr(t, f.challenge(t), nil)
	single := encryptForSCEP(t, csr.Raw, f.e.cert, pkcs7.OIDEncryptionAlgorithmDESCBC, 8, des.NewCipher)
	if _, s := f.e.enroll(f.signedEnvelope(t, single, pkcs7.OIDDigestAlgorithmSHA512, false, scep.PKCSReq), ""); s != 400 {
		t.Fatalf("single DES accepted while switched off, status %d", s)
	}
	triple := encryptForSCEP(t, csr.Raw, f.e.cert, pkcs7.OIDEncryptionAlgorithmDESEDE3CBC, 24, des.NewTripleDESCipher)
	body, s := f.e.enroll(f.signedEnvelope(t, triple, pkcs7.OIDDigestAlgorithmSHA512, false, scep.PKCSReq), "")
	if s != 200 {
		t.Fatalf("3DES refused, status %d", s)
	}
	if m, err := scep.ParsePKIMessage(body); err != nil || m.PKIStatus != scep.SUCCESS {
		t.Fatalf("3DES enrollment not successful: %v %+v", err, m)
	}
	// A 3DES envelope whose RSA-wrapped key is the wrong length is refused.
	short := encryptForSCEP(t, csr.Raw, f.e.cert, pkcs7.OIDEncryptionAlgorithmDESEDE3CBC, 8, des.NewCipher)
	if _, s := f.e.enroll(f.signedEnvelope(t, short, pkcs7.OIDDigestAlgorithmSHA256, false, scep.PKCSReq), ""); s != 400 {
		t.Fatalf("3DES envelope with an 8-byte key accepted, status %d", s)
	}
}

func TestSCEPSingleDESWhenSwitchedOn(t *testing.T) {
	f := newSCEPFixture(t)
	if err := f.e.setAllowDES(true); err != nil {
		t.Fatal(err)
	}
	csr := f.csr(t, f.challenge(t), nil)
	single := encryptForSCEP(t, csr.Raw, f.e.cert, pkcs7.OIDEncryptionAlgorithmDESCBC, 8, des.NewCipher)
	body, s := f.e.enroll(f.signedEnvelope(t, single, pkcs7.OIDDigestAlgorithmSHA512, false, scep.PKCSReq), "")
	if s != 200 {
		t.Fatalf("single DES refused while switched on, status %d", s)
	}
	m, err := scep.ParsePKIMessage(body)
	if err != nil || m.PKIStatus != scep.SUCCESS {
		t.Fatalf("DES enrollment not successful: %v %+v", err, m)
	}
	// The reply is DES too, and the global cipher is back to AES afterwards.
	p, err := pkcs7.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	var ci p7ContentInfo
	if _, err := asn1.Unmarshal(p.Content, &ci); err != nil {
		t.Fatal(err)
	}
	var env scepEnvelope
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &env); err != nil {
		t.Fatal(err)
	}
	if !env.Content.Algorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmDESCBC) {
		t.Fatalf("reply cipher %v, want DES", env.Content.Algorithm.Algorithm)
	}
	if pkcs7.ContentEncryptionAlgorithm != pkcs7.EncryptionAlgorithmAES128CBC {
		t.Fatal("pkcs7 cipher not restored to AES-128-CBC")
	}
	// Switching it off refuses DES again.
	if err := f.e.setAllowDES(false); err != nil {
		t.Fatal(err)
	}
	csr = f.csr(t, f.challenge(t), nil)
	single = encryptForSCEP(t, csr.Raw, f.e.cert, pkcs7.OIDEncryptionAlgorithmDESCBC, 8, des.NewCipher)
	if _, s := f.e.enroll(f.signedEnvelope(t, single, pkcs7.OIDDigestAlgorithmSHA512, false, scep.PKCSReq), ""); s != 400 {
		t.Fatalf("single DES accepted after switching off, status %d", s)
	}
}

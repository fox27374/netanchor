package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

func init() {
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
	if err := pkcs7.SetDefaultDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256); err != nil {
		panic(err)
	}
}

const scepMaxMessage = 1 << 20

var errSCEPRequest = errors.New("invalid enrollment request")

// These are inspection-only ASN.1 views. CMS signing, verification, envelope
// handling and SCEP messages remain the library's responsibility.
type scepEnvelope struct {
	Version    int
	Recipients []asn1.RawValue `asn1:"set"`
	Content    struct {
		Type       asn1.ObjectIdentifier
		Algorithm  pkix.AlgorithmIdentifier
		Ciphertext asn1.RawValue `asn1:"tag:0"`
	}
}

func strictASN1(b []byte, v any) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errSCEPRequest
	}
	return nil
}
func inspectEnvelope(b []byte) (scepEnvelope, error) {
	var ci p7ContentInfo
	var env scepEnvelope
	if err := boundedSCEPASN1(b); err != nil {
		return env, err
	}
	if err := strictASN1(b, &ci); err != nil {
		return env, err
	}
	if !ci.ContentType.Equal(pkcs7.OIDEnvelopedData) {
		return env, errSCEPRequest
	}
	if err := strictASN1(ci.Content.Bytes, &env); err != nil {
		return env, err
	}
	c := env.Content
	if len(env.Recipients) != 1 || !c.Type.Equal(pkcs7.OIDData) || !c.Algorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmAES128CBC) || c.Ciphertext.IsCompound || len(c.Ciphertext.Bytes) == 0 || len(c.Ciphertext.Bytes)%aes.BlockSize != 0 || c.Algorithm.Parameters.Tag != asn1.TagOctetString || len(c.Algorithm.Parameters.Bytes) != aes.BlockSize {
		return env, errSCEPRequest
	}
	var recipient struct {
		Version   int
		Issuer    asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Key       []byte
	}
	if strictASN1(env.Recipients[0].FullBytes, &recipient) != nil || !recipient.Algorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSA) {
		return env, errSCEPRequest
	}
	return env, nil
}

// pkcs7 v0.2.1 slices padding before checking its length. Validate the actual
// plaintext padding before allowing that library path to run. This adapter also
// enforces a 128-bit key (AES's constructor alone accepts 192/256-bit keys).
type scepDecrypter struct {
	key *rsa.PrivateKey
	env scepEnvelope
}

func (d scepDecrypter) Public() crypto.PublicKey { return d.key.Public() }
func (d scepDecrypter) Decrypt(r io.Reader, encrypted []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	k, err := d.key.Decrypt(r, encrypted, opts)
	if err != nil || len(k) != 16 {
		return nil, errSCEPRequest
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, errSCEPRequest
	}
	plain := make([]byte, len(d.env.Content.Ciphertext.Bytes))
	cipher.NewCBCDecrypter(b, d.env.Content.Algorithm.Parameters.Bytes).CryptBlocks(plain, d.env.Content.Ciphertext.Bytes)
	n := int(plain[len(plain)-1])
	if n < 1 || n > aes.BlockSize || n > len(plain) {
		return nil, errSCEPRequest
	}
	for _, v := range plain[len(plain)-n:] {
		if int(v) != n {
			return nil, errSCEPRequest
		}
	}
	return k, nil
}

func uniqueChallenge(c *x509.CertificateRequest) error {
	var info struct {
		Version    int
		Subject    asn1.RawValue
		Key        asn1.RawValue
		Attributes []struct {
			OID    asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		} `asn1:"tag:0"`
	}
	if err := strictASN1(c.RawTBSCertificateRequest, &info); err != nil {
		return err
	}
	count := 0
	for _, a := range info.Attributes {
		if a.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}) {
			count++
			if len(a.Values) != 1 {
				return errSCEPRequest
			}
		}
	}
	if count != 1 {
		return errSCEPRequest
	}
	return nil
}

func parseSCEP(raw []byte, cert *x509.Certificate, key *rsa.PrivateKey) (msg *scep.PKIMessage, signer *x509.Certificate, err error) {
	if err := boundedSCEPASN1(raw); err != nil {
		return nil, nil, err
	}
	// Defense in depth around third-party untrusted ASN.1. No panic escapes and
	// all parse/decrypt failures get the same external error.
	defer func() {
		if recover() != nil {
			msg = nil
			signer = nil
			err = errSCEPRequest
		}
	}()
	p, err := pkcs7.Parse(raw)
	if err != nil {
		return nil, nil, errSCEPRequest
	}
	if len(p.Signers) != 1 || len(p.Certificates) != 1 {
		return nil, nil, errSCEPRequest
	}
	si := p.Signers[0]
	if !si.DigestAlgorithm.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256) || !(si.DigestEncryptionAlgorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSA) || si.DigestEncryptionAlgorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256)) {
		return nil, nil, errSCEPRequest
	}
	seen := map[string]bool{}
	for _, a := range si.AuthenticatedAttributes {
		if seen[a.Type.String()] {
			return nil, nil, errSCEPRequest
		}
		seen[a.Type.String()] = true
		var value asn1.RawValue
		if strictASN1(a.Value.Bytes, &value) != nil {
			return nil, nil, errSCEPRequest
		}
	}
	signer = p.Certificates[0]
	pub, ok := signer.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 || signer.IsCA || signer.CheckSignature(signer.SignatureAlgorithm, signer.RawTBSCertificate, signer.Signature) != nil {
		return nil, nil, errSCEPRequest
	}
	msg, err = scep.ParsePKIMessage(raw)
	if err != nil || msg.MessageType != scep.PKCSReq || len(msg.SenderNonce) != 16 || len(msg.TransactionID) < 1 || len(msg.TransactionID) > 256 {
		return nil, nil, errSCEPRequest
	}
	env, err := inspectEnvelope(p.Content)
	if err != nil {
		return nil, nil, errSCEPRequest
	}
	if err = msg.DecryptPKIEnvelope(cert, scepDecrypter{key, env}); err != nil {
		return nil, nil, errSCEPRequest
	}
	if msg.CSR.CheckSignature() != nil || uniqueChallenge(msg.CSR) != nil || !bytes.Equal(msg.CSR.RawSubjectPublicKeyInfo, signer.RawSubjectPublicKeyInfo) {
		return nil, nil, errSCEPRequest
	}
	return msg, signer, nil
}

func allowedSCEPIdentities(csr *x509.CertificateRequest, c scepChallenge) bool {
	if len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return false
	}
	for _, d := range csr.DNSNames {
		found := false
		for _, a := range c.DNS {
			if d == a {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	for _, ip := range csr.IPAddresses {
		found := false
		for _, a := range c.IPs {
			if ip.Equal(a) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (e *SCEPService) enroll(raw []byte) ([]byte, int) {
	// Reject resource-exhaustion inputs before waiting for the shared state lock.
	if err := boundedSCEPASN1(raw); err != nil {
		return nil, http.StatusBadRequest
	}
	e.store.scepMu.Lock()
	defer e.store.scepMu.Unlock()
	st, err := e.load()
	if err != nil {
		return nil, 503
	}
	ca, err := e.ready(st)
	if err != nil {
		return nil, 503
	}
	msg, signer, err := parseSCEP(raw, e.cert, e.key)
	if err != nil {
		return nil, 400
	}
	fail := func() ([]byte, int) {
		m, err := msg.Fail(e.cert, e.key, scep.BadRequest)
		if err != nil {
			return nil, 503
		}
		return m.Raw, 200
	}
	if err = e.recover(&st); err != nil {
		return nil, 503
	}
	h := hashSCEP([]byte(msg.ChallengePassword))
	rh := hashSCEP(msg.CSR.Raw)
	sh := hashSCEP(signer.Raw)
	for i := range st.Challenges {
		c := &st.Challenges[i]
		if c.Hash != h || c.CA != st.CA {
			continue
		}
		if !c.Used.IsZero() {
			if time.Now().After(c.Used.Add(scepRetention)) || c.Transaction != string(msg.TransactionID) || c.RequestHash != rh || c.SignerHash != sh {
				return fail()
			}
			// A deliberately deleted certificate must not reappear through replay.
			if _, ok := e.store.RecordBySerial(c.Record.Serial); !ok {
				return fail()
			}
		} else {
			if c.Revoked || time.Now().After(c.Expires) || !allowedSCEPIdentities(msg.CSR, *c) {
				return fail()
			}
			if c.Profile.Name == "" || c.Profile.Profile != profileServer {
				return fail()
			}
			authorizedCSR := *msg.CSR
			authorizedCSR.DNSNames, authorizedCSR.IPAddresses = c.DNS, c.IPs
			rec, der, err := signCSRWithoutPersistence(&authorizedCSR, SignCSRParams{IssuerID: st.CA, ValidDays: c.Days, Template: c.Profile, TemplateName: c.Profile.Name}, ca, e.key, true)
			if err != nil {
				return fail()
			}
			rec.Provenance = "scep"
			c.DER = der
			c.Record = rec
			c.Used = time.Now()
			c.Transaction = string(msg.TransactionID)
			c.RequestHash = rh
			c.SignerHash = sh
			// Commit before touching the certificate projection or returning success.
			if err = e.save(st); err != nil {
				return nil, 503
			}
			if err = e.recover(&st); err != nil {
				return nil, 503
			}
		}
		cert, err := x509.ParseCertificate(c.DER)
		if err != nil {
			return nil, 503
		}
		resp, err := msg.Success(e.cert, e.key, cert)
		if err != nil {
			return nil, 503
		}
		return resp.Raw, 200
	}
	return fail()
}

var scepPaths = [...]string{"/scep", "/scep/cgi-bin/pkiclient.exe", "/cgi-bin/pkiclient.exe"}

func scepPath(p string) bool {
	for _, path := range scepPaths {
		if p == path {
			return true
		}
	}
	return false
}

func parseSCEPQuery(r *http.Request) (url.Values, error) {
	if len(r.URL.RawQuery) > 2*scepMaxMessage {
		return nil, errSCEPRequest
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	for _, values := range q {
		if len(values) != 1 {
			return nil, errSCEPRequest
		}
	}
	return q, nil
}
func (e *SCEPService) Routes() http.Handler {
	// Intentionally no UI, login, setup, health or catch-all redirect routes.
	return e.store.operations(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !scepPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		q, err := parseSCEPQuery(r)
		if err != nil {
			http.Error(w, "invalid SCEP request", 400)
			return
		}
		op := q.Get("operation")
		if op != "PKIOperation" && r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		switch op {
		case "GetCACaps":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "AES\nSHA-256\nPOSTPKIOperation\n")
		case "GetCACert":
			e.store.scepMu.Lock()
			defer e.store.scepMu.Unlock()
			st, err := e.load()
			if err != nil {
				w.WriteHeader(503)
				return
			}
			if _, err = e.ca(st.CA); err != nil {
				w.WriteHeader(503)
				return
			}
			chain, err := e.store.IssuerChainPEM(st.CA)
			if err != nil {
				w.WriteHeader(503)
				return
			}
			var certs []*x509.Certificate
			for len(chain) > 0 {
				p, rest := pem.Decode(chain)
				if p == nil {
					w.WriteHeader(503)
					return
				}
				chain = rest
				c, err := x509.ParseCertificate(p.Bytes)
				if err != nil {
					w.WriteHeader(503)
					return
				}
				certs = append(certs, c)
			}
			der, err := scep.DegenerateCertificates(certs)
			if err != nil {
				w.WriteHeader(503)
				return
			}
			w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
			w.Write(der)
		case "PKIOperation":
			var raw []byte
			if r.Method == "GET" {
				raw, err = base64.StdEncoding.DecodeString(q.Get("message"))
			} else {
				raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, scepMaxMessage))
			}
			if err != nil || len(raw) == 0 || len(raw) > scepMaxMessage {
				http.Error(w, "invalid SCEP request", 400)
				return
			}
			body, status := e.enroll(raw)
			if status != 200 {
				http.Error(w, http.StatusText(status), status)
				return
			}
			w.Header().Set("Content-Type", "application/x-pki-message")
			w.Write(body)
		default:
			http.Error(w, "unsupported SCEP operation", 400)
		}
	}))
}

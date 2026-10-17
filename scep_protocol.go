package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
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
	switch {
	case len(env.Recipients) != 1:
		return env, fmt.Errorf("%w: envelope has %d recipients, want 1", errSCEPRequest, len(env.Recipients))
	case !c.Type.Equal(pkcs7.OIDData):
		return env, fmt.Errorf("%w: envelope content type %v", errSCEPRequest, c.Type)
	case scepCipherSizes(c.Algorithm.Algorithm) == [2]int{}:
		return env, fmt.Errorf("%w: envelope cipher %v not allowed (AES-128-CBC, AES-256-CBC, 3DES-CBC or, if switched on, DES-CBC only)", errSCEPRequest, c.Algorithm.Algorithm)
	case c.Ciphertext.IsCompound || len(c.Ciphertext.Bytes) == 0 || len(c.Ciphertext.Bytes)%scepCipherSizes(c.Algorithm.Algorithm)[1] != 0 || c.Algorithm.Parameters.Tag != asn1.TagOctetString || len(c.Algorithm.Parameters.Bytes) != scepCipherSizes(c.Algorithm.Algorithm)[1]:
		return env, fmt.Errorf("%w: envelope ciphertext or IV malformed", errSCEPRequest)
	}
	var recipient struct {
		Version   int
		Issuer    asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Key       []byte
	}
	if err := strictASN1(env.Recipients[0].FullBytes, &recipient); err != nil {
		return env, fmt.Errorf("%w: envelope recipient malformed", errSCEPRequest)
	}
	if !recipient.Algorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSA) {
		return env, fmt.Errorf("%w: envelope key transport %v not allowed (RSA PKCS#1 v1.5 only)", errSCEPRequest, recipient.Algorithm.Algorithm)
	}
	return env, nil
}

// scepCipherSizes returns the key and block size of an allowed envelope cipher, or
// zeros. 3DES and DES exist only because IOS-XE encrypts with them instead of AES;
// parseSCEP refuses DES unless the SCEP page switches it on. See README.
func scepCipherSizes(oid asn1.ObjectIdentifier) [2]int {
	switch {
	case oid.Equal(pkcs7.OIDEncryptionAlgorithmAES128CBC):
		return [2]int{16, aes.BlockSize}
	case oid.Equal(pkcs7.OIDEncryptionAlgorithmAES256CBC):
		return [2]int{32, aes.BlockSize}
	case oid.Equal(pkcs7.OIDEncryptionAlgorithmDESEDE3CBC):
		return [2]int{24, des.BlockSize}
	case oid.Equal(pkcs7.OIDEncryptionAlgorithmDESCBC):
		return [2]int{8, des.BlockSize}
	}
	return [2]int{}
}

// pkcs7 v0.2.1 slices padding before checking its length. Validate the actual
// plaintext padding before allowing that library path to run. This adapter also
// enforces the key length of the envelope's cipher (AES's constructor alone accepts any).
type scepDecrypter struct {
	key *rsa.PrivateKey
	env scepEnvelope
}

func (d scepDecrypter) Public() crypto.PublicKey { return d.key.Public() }
func (d scepDecrypter) Decrypt(r io.Reader, encrypted []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	alg := d.env.Content.Algorithm.Algorithm
	sizes := scepCipherSizes(alg)
	k, err := d.key.Decrypt(r, encrypted, opts)
	if err != nil || len(k) != sizes[0] {
		return nil, errSCEPRequest
	}
	var b cipher.Block
	switch {
	case alg.Equal(pkcs7.OIDEncryptionAlgorithmDESEDE3CBC):
		b, err = des.NewTripleDESCipher(k)
	case alg.Equal(pkcs7.OIDEncryptionAlgorithmDESCBC):
		b, err = des.NewCipher(k)
	default:
		b, err = aes.NewCipher(k)
	}
	if err != nil {
		return nil, errSCEPRequest
	}
	plain := make([]byte, len(d.env.Content.Ciphertext.Bytes))
	cipher.NewCBCDecrypter(b, d.env.Content.Algorithm.Parameters.Bytes).CryptBlocks(plain, d.env.Content.Ciphertext.Bytes)
	n := int(plain[len(plain)-1])
	if n < 1 || n > sizes[1] || n > len(plain) {
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

// parseSCEP reports whether the request envelope used single DES, so the reply
// can use it too; allowDES is the SCEP page switch.
func parseSCEP(raw []byte, cert *x509.Certificate, key *rsa.PrivateKey, allowDES bool) (msg *scep.PKIMessage, signer *x509.Certificate, singleDES bool, err error) {
	// Every rejection wraps errSCEPRequest with the reason, for the log only;
	// the client always gets the same 400.
	bad := func(format string, args ...any) (*scep.PKIMessage, *x509.Certificate, bool, error) {
		return nil, nil, false, fmt.Errorf("%w: "+format, append([]any{errSCEPRequest}, args...)...)
	}
	if err := boundedSCEPASN1(raw); err != nil {
		return bad("message too large or malformed ASN.1")
	}
	// Defense in depth around third-party untrusted ASN.1. No panic escapes and
	// all parse/decrypt failures get the same external error.
	defer func() {
		if recover() != nil {
			msg, signer, singleDES, err = bad("parser panic")
		}
	}()
	p, err := pkcs7.Parse(raw)
	if err != nil {
		return bad("not CMS SignedData: %v", err)
	}
	if len(p.Signers) != 1 || len(p.Certificates) != 1 {
		return bad("need one signer and one certificate, got %d signers and %d certificates", len(p.Signers), len(p.Certificates))
	}
	si := p.Signers[0]
	if !scepDigestOK(si.DigestAlgorithm.Algorithm) || !scepSignatureOK(si.DigestEncryptionAlgorithm.Algorithm) {
		return bad("digest %v with signature %v not allowed (RSA with SHA-256/384/512 only)", si.DigestAlgorithm.Algorithm, si.DigestEncryptionAlgorithm.Algorithm)
	}
	seen := map[string]bool{}
	for _, a := range si.AuthenticatedAttributes {
		if seen[a.Type.String()] {
			return bad("signed attribute %v repeated", a.Type)
		}
		seen[a.Type.String()] = true
		var value asn1.RawValue
		if strictASN1(a.Value.Bytes, &value) != nil {
			return bad("signed attribute %v malformed", a.Type)
		}
	}
	signer = p.Certificates[0]
	pub, ok := signer.PublicKey.(*rsa.PublicKey)
	switch {
	case !ok:
		return bad("signer key is %T; only RSA keys are supported", signer.PublicKey)
	case pub.N.BitLen() < 2048:
		return bad("signer RSA key has %d bits; at least 2048 required", pub.N.BitLen())
	case signer.IsCA:
		return bad("signer certificate is a CA")
	case signer.CheckSignature(signer.SignatureAlgorithm, signer.RawTBSCertificate, signer.Signature) != nil:
		return bad("signer certificate is not validly self-signed (%v)", signer.SignatureAlgorithm)
	}
	msg, err = scep.ParsePKIMessage(raw)
	if err != nil {
		return bad("SCEP message: %v", err)
	}
	if msg.MessageType != scep.PKCSReq || len(msg.SenderNonce) != 16 || len(msg.TransactionID) < 1 || len(msg.TransactionID) > 256 {
		return bad("need a PKCSReq with a 16-byte nonce and a transaction id, got type %v, nonce %d bytes, transaction id %d bytes", msg.MessageType, len(msg.SenderNonce), len(msg.TransactionID))
	}
	env, err := inspectEnvelope(p.Content)
	if err != nil {
		return nil, nil, false, err
	}
	singleDES = env.Content.Algorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmDESCBC)
	if singleDES && !allowDES {
		return bad("envelope cipher is single DES, which is switched off on the SCEP page")
	}
	if err = msg.DecryptPKIEnvelope(cert, scepDecrypter{key, env}); err != nil {
		return bad("decrypt envelope: %v", err)
	}
	switch {
	case msg.CSR.CheckSignature() != nil:
		return bad("CSR signature invalid")
	case uniqueChallenge(msg.CSR) != nil:
		return bad("CSR must carry exactly one challenge password")
	case !bytes.Equal(msg.CSR.RawSubjectPublicKeyInfo, signer.RawSubjectPublicKeyInfo):
		return bad("CSR key differs from the signer certificate key")
	}
	return msg, signer, singleDES, nil
}

// scepDigestOK accepts SHA-256, SHA-384 and SHA-512 request digests (IOS-XE "hash sha512").
func scepDigestOK(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(pkcs7.OIDDigestAlgorithmSHA256) || oid.Equal(pkcs7.OIDDigestAlgorithmSHA384) || oid.Equal(pkcs7.OIDDigestAlgorithmSHA512)
}

// scepSignatureOK accepts RSA request signatures; the key size is checked on the signer certificate.
func scepSignatureOK(oid asn1.ObjectIdentifier) bool {
	for _, ok := range []asn1.ObjectIdentifier{pkcs7.OIDEncryptionAlgorithmRSA, pkcs7.OIDEncryptionAlgorithmRSASHA256, pkcs7.OIDEncryptionAlgorithmRSASHA384, pkcs7.OIDEncryptionAlgorithmRSASHA512} {
		if oid.Equal(ok) {
			return true
		}
	}
	return false
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

// remote is the HTTP peer address (r.RemoteAddr); shared challenges authorize by it.
func (e *SCEPService) enroll(raw []byte, remote string) ([]byte, int) {
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
		log.Printf("scep PKIOperation unavailable: %v", err)
		return nil, 503
	}
	msg, signer, singleDES, err := parseSCEP(raw, e.cert, e.key, st.AllowDES)
	if err != nil {
		log.Printf("scep PKIOperation rejected: %v", err)
		return nil, 400
	}
	fail := func(reason string) ([]byte, int) {
		log.Printf("scep PKIOperation failed (CertRep FAILURE sent): %s", reason)
		m, err := msg.Fail(e.cert, e.key, scep.BadRequest)
		if err != nil {
			return nil, 503
		}
		return m.Raw, 200
	}
	if err = e.recover(&st); err != nil {
		return nil, 503
	}
	// respond encodes the issued certificate in the reply's envelope cipher.
	respond := func(der []byte, origin string) ([]byte, int) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, 503
		}
		if singleDES {
			// A client that only sends DES cannot be assumed to read AES. pkcs7's cipher is a
			// global; only this path encrypts in production and it holds scepMu.
			pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmDESCBC
		}
		resp, err := msg.Success(e.cert, e.key, cert)
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
		if err != nil {
			return nil, 503
		}
		log.Printf("scep PKIOperation issued %q serial %s%s (single DES reply: %v)", cert.Subject.CommonName, cert.SerialNumber.Text(16), origin, singleDES)
		return resp.Raw, 200
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
				return fail("challenge already used by a different or expired request")
			}
			// A deliberately deleted certificate must not reappear through replay.
			if _, ok := e.store.RecordBySerial(c.Record.Serial); !ok {
				return fail("certificate of this challenge was deleted")
			}
		} else {
			switch {
			case c.Revoked:
				return fail("challenge revoked")
			case time.Now().After(c.Expires):
				return fail("challenge expired")
			case !allowedSCEPIdentities(msg.CSR, *c):
				return fail(fmt.Sprintf("CSR SANs (DNS %v, IP %v, email/URI %d) not all authorized by the challenge (DNS %v, IP %v)", msg.CSR.DNSNames, msg.CSR.IPAddresses, len(msg.CSR.EmailAddresses)+len(msg.CSR.URIs), c.DNS, c.IPs))
			case c.Profile.Name == "" || !c.Profile.Profile.serverAuth():
				return fail("challenge template does not have the TLS server purpose")
			}
			authorizedCSR := *msg.CSR
			authorizedCSR.DNSNames, authorizedCSR.IPAddresses = c.DNS, c.IPs
			rec, der, err := signCSRWithoutPersistence(&authorizedCSR, SignCSRParams{IssuerID: st.CA, ValidDays: c.Days, Template: c.Profile, TemplateName: c.Profile.Name}, ca, e.key, true)
			if err != nil {
				return fail("signing: " + err.Error())
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
		return respond(c.DER, "")
	}
	if i := sharedIndex(&st, h); i >= 0 {
		der, reason, err := e.enrollShared(&st, &st.Shared[i], msg, rh, sh, remote, ca)
		switch {
		case err != nil:
			return nil, 503
		case reason != "":
			return fail(reason)
		}
		return respond(der, " shared from "+remoteHost(remote))
	}
	return fail("challenge password unknown or for another CA (create one on the SCEP page)")
}

// IOS-XE appends /pkiclient.exe to an enrollment URL that has a path, e.g. /scep/pkiclient.exe.
var scepPaths = [...]string{"/scep", "/scep/pkiclient.exe", "/scep/cgi-bin/pkiclient.exe", "/cgi-bin/pkiclient.exe"}

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

// scepStatusWriter remembers the response status for the SCEP request log.
type scepStatusWriter struct {
	http.ResponseWriter
	code int
}

func (w *scepStatusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *scepStatusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// logSCEP logs one line per SCEP request, so a switch's attempts show on the Logs page.
func logSCEP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &scepStatusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		from, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			from = r.RemoteAddr
		}
		if sw.code == 0 {
			sw.code = http.StatusOK
		}
		log.Printf("scep %s %s op=%s from=%s status=%d", r.Method, r.URL.Path, r.URL.Query().Get("operation"), from, sw.code)
	})
}

func (e *SCEPService) Routes() http.Handler {
	// Intentionally no UI, login, setup, health or catch-all redirect routes.
	return logSCEP(e.store.operations(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			io.WriteString(w, "AES\nDES3\nSHA-256\nSHA-512\nPOSTPKIOperation\n")
		case "GetCACert":
			e.store.scepMu.Lock()
			defer e.store.scepMu.Unlock()
			st, err := e.load()
			if err != nil {
				log.Printf("scep GetCACert: load state: %v", err)
				w.WriteHeader(503)
				return
			}
			if _, err = e.ca(st.CA); err != nil {
				log.Printf("scep GetCACert: no usable SCEP CA selected: %v", err)
				w.WriteHeader(503)
				return
			}
			chain, err := e.store.IssuerChainPEM(st.CA)
			if err != nil {
				log.Printf("scep GetCACert: chain: %v", err)
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
				// Clients such as IOS-XE send base64 unescaped, so '+' arrives as a space.
				raw, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(q.Get("message"), " ", "+"))
			} else {
				raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, scepMaxMessage))
			}
			if err != nil || len(raw) == 0 || len(raw) > scepMaxMessage {
				log.Printf("scep PKIOperation rejected: message not readable (%d bytes, %v)", len(raw), err)
				http.Error(w, "invalid SCEP request", 400)
				return
			}
			body, status := e.enroll(raw, r.RemoteAddr)
			if status != 200 {
				http.Error(w, http.StatusText(status), status)
				return
			}
			w.Header().Set("Content-Type", "application/x-pki-message")
			w.Write(body)
		default:
			http.Error(w, "unsupported SCEP operation", 400)
		}
	})))
}

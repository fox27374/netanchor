package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const toolsMaxUpload = 8 << 20

type toolItem struct {
	Kind, Label string
	Cert        *x509.Certificate
	CSR         *x509.CertificateRequest
	Key         crypto.Signer
	KeyDER      []byte
	Match       int
}
type toolEntry struct {
	Owner    string
	Session  string
	Expires  time.Time
	Items    []toolItem
	Warnings []string
}

var toolsCache = struct {
	sync.Mutex
	entries map[string]toolEntry
}{entries: make(map[string]toolEntry)}

func (s *Server) toolOwner(r *http.Request) string {
	if !s.auth.enabled {
		return "admin:disabled"
	}
	u, ok := userFromContext(r.Context())
	if !ok {
		return ""
	}
	return u.Username
}
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
}
func validToolsOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host) && (u.Scheme == "http" || u.Scheme == "https")
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin" || r.Header.Get("Sec-Fetch-Site") == "same-site"
}

func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	d := s.base(r, "Tools", "tools")
	s.render(w, "tools", d)
}

// handleToolsPasswordCheck checks uploaded content without retaining or logging it.
func (s *Server) handleToolsPasswordCheck(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !validToolsOrigin(r) {
		http.Error(w, "cross-origin request denied", http.StatusForbidden)
		return
	}
	const maxRequest = toolsMaxUpload + (1 << 20)
	r.Body = http.MaxBytesReader(w, r.Body, maxRequest)
	if err := r.ParseMultipartForm(maxRequest); err != nil || r.MultipartForm == nil {
		http.Error(w, "upload is too large or invalid", http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll()
	files := r.MultipartForm.File["file"]
	if len(files) != 1 || len(r.MultipartForm.File) != 1 {
		http.Error(w, "upload exactly one file", http.StatusBadRequest)
		return
	}
	file, err := files[0].Open()
	if err != nil {
		http.Error(w, "invalid uploaded file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, toolsMaxUpload+1))
	if err != nil || len(data) > toolsMaxUpload {
		http.Error(w, "upload is too large", http.StatusBadRequest)
		return
	}
	state := pkcs12PasswordState(data)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		State string `json:"state"`
	}{state})
}

func pkcs12PasswordState(data []byte) string {
	if _, _, _, err := pkcs12.DecodeChain(data, ""); err == nil {
		return "not-required"
	}
	if certs, err := pkcs12.DecodeTrustStore(data, ""); err == nil && len(certs) > 0 {
		return "not-required"
	}
	// Require a complete PFX containing a valid authenticated-safe payload and
	// well-formed MAC data before reporting a password requirement. A partial
	// PFX-looking prefix is unknown, not evidence of protection.
	var pfx struct {
		Version  int
		AuthSafe asn1.RawValue
		MacData  asn1.RawValue `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(data, &pfx); err != nil || len(rest) != 0 || pfx.Version != 3 || pfx.AuthSafe.Tag != asn1.TagSequence || pfx.MacData.Tag != asn1.TagSequence {
		return "unknown"
	}
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	if rest, err := asn1.Unmarshal(pfx.AuthSafe.FullBytes, &contentInfo); err != nil || len(rest) != 0 || !contentInfo.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}) {
		return "unknown"
	}
	var octets asn1.RawValue
	if rest, err := asn1.Unmarshal(contentInfo.Content.Bytes, &octets); err != nil || len(rest) != 0 || octets.Tag != asn1.TagOctetString {
		return "unknown"
	}
	var safe asn1.RawValue
	if rest, err := asn1.Unmarshal(octets.Bytes, &safe); err != nil || len(rest) != 0 || safe.Tag != asn1.TagSequence {
		return "unknown"
	}
	var mac struct {
		Digest struct {
			Algorithm struct {
				OID    asn1.ObjectIdentifier
				Params asn1.RawValue `asn1:"optional"`
			}
			Value []byte
		}
		Salt       []byte
		Iterations int `asn1:"optional,default:1"`
	}
	if rest, err := asn1.Unmarshal(pfx.MacData.FullBytes, &mac); err != nil || len(rest) != 0 || len(mac.Digest.Algorithm.OID) == 0 || len(mac.Digest.Value) == 0 || len(mac.Salt) == 0 || mac.Iterations < 1 {
		return "unknown"
	}
	return "required"
}
func (s *Server) handleToolsDecode(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !validToolsOrigin(r) {
		http.Error(w, "cross-origin request denied", http.StatusForbidden)
		return
	}
	const maxRequest = toolsMaxUpload + (1 << 20)
	r.Body = http.MaxBytesReader(w, r.Body, maxRequest)
	// maxMemory is at least the maximum entire request body. ParseMultipartForm
	// therefore retains every file part in memory rather than spooling uploads
	// to its temporary-file fallback.
	if err := r.ParseMultipartForm(maxRequest); err != nil {
		http.Error(w, "upload is too large or invalid", http.StatusBadRequest)
		return
	}
	if r.MultipartForm == nil {
		http.Error(w, "multipart form required", http.StatusBadRequest)
		return
	}
	pasted := r.FormValue("pem")
	if len(pasted) > toolsMaxUpload {
		http.Error(w, "pasted input is too large", http.StatusBadRequest)
		return
	}
	data := []byte(strings.TrimSpace(pasted))
	fileCount := 0
	for _, files := range r.MultipartForm.File {
		fileCount += len(files)
	}
	if fileCount > 1 {
		http.Error(w, "upload exactly one file", http.StatusBadRequest)
		return
	}
	if fileCount == 1 {
		if len(data) != 0 {
			http.Error(w, "paste PEM or upload one file, not both", 400)
			return
		}
		var file multipart.File
		var err error
		for _, files := range r.MultipartForm.File {
			for _, header := range files {
				file, err = header.Open()
				break
			}
			if file != nil {
				break
			}
		}
		if err != nil {
			http.Error(w, "invalid uploaded file", http.StatusBadRequest)
			return
		}
		defer file.Close()
		data, err = io.ReadAll(io.LimitReader(file, toolsMaxUpload+1))
		if err != nil || len(data) > toolsMaxUpload {
			http.Error(w, "upload is too large", 400)
			return
		}
	}
	if len(data) == 0 {
		s.renderToolError(w, r, "Paste PEM or upload one file.")
		return
	}
	items, warnings := decodeToolInput(data, r.FormValue("password"))
	if len(items) == 0 {
		msg := "No supported certificates, CSRs, or private keys were found. Check the input format and password."
		if len(data) > 0 && pkcs12PasswordState(data) == "required" && strings.TrimSpace(r.FormValue("password")) == "" {
			msg = "This PKCS#12 file is password-protected. Enter its password and try again."
		} else if len(warnings) > 0 {
			msg += " " + strings.Join(warnings, " ")
		}
		s.renderToolError(w, r, msg)
		return
	}
	for i := range items {
		items[i].Match = -1
		if items[i].Key != nil {
			for j := range items {
				if items[j].Cert != nil && publicKeysEqual(items[i].Key.Public(), items[j].Cert.PublicKey) {
					items[i].Match = j
					break
				}
			}
		}
	}
	tok := make([]byte, 24)
	if _, err := rand.Read(tok); err != nil {
		http.Error(w, "could not create result", 500)
		return
	}
	id := hex.EncodeToString(tok)
	owner := s.toolOwner(r)
	now := time.Now()
	toolsCache.Lock()
	for k, e := range toolsCache.entries {
		if !now.Before(e.Expires) {
			delete(toolsCache.entries, k)
		}
	}
	if len(toolsCache.entries) >= 64 {
		for k := range toolsCache.entries {
			delete(toolsCache.entries, k)
			break
		}
	}
	session := ""
	if s.auth.enabled {
		if c, err := r.Cookie(sessionCookie); err == nil {
			session = c.Value
		}
	}
	toolsCache.entries[id] = toolEntry{Owner: owner, Session: session, Expires: now.Add(10 * time.Minute), Items: items, Warnings: warnings}
	toolsCache.Unlock()
	http.Redirect(w, r, "/tools/"+id, http.StatusSeeOther)
}
func (s *Server) renderToolError(w http.ResponseWriter, r *http.Request, msg string) {
	d := s.base(r, "Tools", "tools")
	d.Error = msg
	s.render(w, "tools", d)
}
func toolEntryFor(r *http.Request) (toolEntry, bool) {
	toolsCache.Lock()
	defer toolsCache.Unlock()
	e, ok := toolsCache.entries[r.PathValue("token")]
	session := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		session = c.Value
	}
	if !ok || !time.Now().Before(e.Expires) || e.Owner != ownerFromRequest(r) || (e.Session != "" && e.Session != session) {
		if ok && !time.Now().Before(e.Expires) {
			delete(toolsCache.entries, r.PathValue("token"))
		}
		return toolEntry{}, false
	}
	return e, true
}
func ownerFromRequest(r *http.Request) string {
	if u, ok := userFromContext(r.Context()); ok {
		return u.Username
	}
	return "admin:disabled"
}

type toolView struct {
	Items    []toolItemView
	Warnings []string
	Token    string
	IsAdmin  bool
}
type toolItemView struct {
	Kind, Label                     string
	Cert                            *CertInfo
	CSRSubject                      string
	CSRCommonName                   string
	CSRDNS, CSRIP, CSREmail, CSRURI []string
	CSRKey, CSRSignature            string
	Validity                        string
	KeyType                         string
	Match                           int
	MatchLabel                      string
}

func (s *Server) handleToolsResult(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	e, ok := toolEntryFor(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	v := toolView{Warnings: e.Warnings, Token: r.PathValue("token"), IsAdmin: s.isAdmin(r)}
	for _, it := range e.Items {
		x := toolItemView{Kind: it.Kind, Label: it.Label, Match: it.Match}
		if it.Match >= 0 {
			x.MatchLabel = fmt.Sprintf("%d", it.Match+1)
		}
		if it.Cert != nil {
			z := describeCert(it.Cert)
			x.Cert = &z
			switch {
			case time.Now().Before(it.Cert.NotBefore):
				x.Validity = "Not yet valid"
			case time.Now().After(it.Cert.NotAfter):
				x.Validity = "Expired"
			default:
				x.Validity = "Currently valid"
			}
		}
		if it.CSR != nil {
			x.CSRSubject = it.CSR.Subject.String()
			x.CSRCommonName = it.CSR.Subject.CommonName
			x.CSRDNS = it.CSR.DNSNames
			x.CSRKey = describePublicKey(it.CSR.PublicKey)
			x.CSRSignature = it.CSR.SignatureAlgorithm.String()
			for _, ip := range it.CSR.IPAddresses {
				x.CSRIP = append(x.CSRIP, ip.String())
			}
			for _, mail := range it.CSR.EmailAddresses {
				x.CSREmail = append(x.CSREmail, mail)
			}
			for _, u := range it.CSR.URIs {
				x.CSRURI = append(x.CSRURI, u.String())
			}
		}
		if it.Key != nil {
			x.KeyType = describePublicKey(it.Key.Public())
		}
		v.Items = append(v.Items, x)
	}
	d := s.base(r, "Tools", "tools")
	d.Data = v
	s.render(w, "tools", d)
}
func (s *Server) handleToolsDownload(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !validToolsOrigin(r) {
		http.Error(w, "cross-origin request denied", http.StatusForbidden)
		return
	}
	e, ok := toolEntryFor(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	what := r.FormValue("what")
	n := -1
	if what != "bundle" && what != "p7b" {
		n, _ = strconv.Atoi(r.FormValue("item"))
		if n < 0 || n >= len(e.Items) {
			http.Error(w, "invalid item", 400)
			return
		}
	}
	var it toolItem
	if n >= 0 {
		it = e.Items[n]
	}
	var b []byte
	typ, name := "application/octet-stream", "download"
	switch what {
	case "pem", "der":
		if it.Cert != nil {
			if what == "pem" {
				b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: it.Cert.Raw})
				typ = "application/x-pem-file"
				name = "certificate.pem"
			} else {
				b = it.Cert.Raw
				typ = "application/pkix-cert"
				name = "certificate.der"
			}
		} else if it.CSR != nil {
			if what == "pem" {
				b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: it.CSR.Raw})
				typ = "application/x-pem-file"
				name = "request.pem"
			} else {
				b = it.CSR.Raw
				name = "request.der"
			}
		} else if it.Key != nil && s.isAdmin(r) {
			b = it.KeyDER
			if what == "pem" {
				b = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
				typ = "application/x-pem-file"
				name = "key.pem"
			} else {
				name = "key.der"
			}
		} else {
			http.Error(w, "not found", 404)
			return
		}
	case "bundle":
		for _, v := range e.Items {
			if v.Cert != nil {
				b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.Cert.Raw})...)
			}
		}
		typ = "application/x-pem-file"
		name = "certificates.pem"
	case "p7b":
		var cs []*x509.Certificate
		for _, v := range e.Items {
			if v.Cert != nil {
				cs = append(cs, v.Cert)
			}
		}
		p, err := encodePKCS7Certs(cs)
		if err != nil {
			http.Error(w, "export failed", 500)
			return
		}
		b = p
		typ = "application/x-pkcs7-certificates"
		name = "certificates.p7b"
	case "p12":
		if !s.isAdmin(r) || it.Key == nil || it.Match < 0 || strings.TrimSpace(r.FormValue("password")) == "" {
			http.Error(w, "PKCS#12 requires an admin, matched key and nonempty export password", 400)
			return
		}
		chain := []*x509.Certificate{e.Items[it.Match].Cert}
		// Include only certificates linked by issuer/subject names, walking in
		// supplied order; this is packaging, not trust or signature verification.
		for len(chain) < len(e.Items)+1 {
			found := false
			cur := chain[len(chain)-1]
			for _, v := range e.Items {
				if v.Cert != nil && v.Cert != cur && bytes.Equal(cur.RawIssuer, v.Cert.RawSubject) {
					chain = append(chain, v.Cert)
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
		p, err := pkcs12.Modern.Encode(it.Key, chain[0], chain[1:], r.FormValue("password"))
		if err != nil {
			http.Error(w, "export failed", 500)
			return
		}
		b = p
		typ = "application/x-pkcs12"
		name = "certificate.p12"
	default:
		http.Error(w, "unknown export", 400)
		return
	}
	serveBytes(w, typ, name, b)
}

func decodeToolInput(data []byte, password string) ([]toolItem, []string) {
	var out []toolItem
	var warn []string
	p12Candidate := len(data) > 0 && data[0] == 0x30
	if len(data) > 0 && data[0] == 0x30 {
		if certs, err := decodePKCS7Certs(data); err == nil {
			for _, c := range certs {
				out = append(out, toolItem{Kind: "Certificate", Label: c.Subject.CommonName, Cert: c})
			}
			return out, warn
		}
		if key, cert, certs, err := pkcs12.DecodeChain(data, password); err == nil {
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, []string{"PKCS#12 private key is not a usable signer."}
			}
			der, _ := x509.MarshalPKCS8PrivateKey(signer)
			out = append(out, toolItem{Kind: "Private key", Key: signer, KeyDER: der})
			if cert != nil {
				out = append(out, toolItem{Kind: "Certificate", Label: cert.Subject.CommonName, Cert: cert})
			}
			for _, c := range certs {
				out = append(out, toolItem{Kind: "Certificate", Label: c.Subject.CommonName, Cert: c})
			}
			return out, warn
		}
		if certs, err := pkcs12.DecodeTrustStore(data, password); err == nil && len(certs) > 0 {
			for _, c := range certs {
				out = append(out, toolItem{Kind: "Certificate", Label: c.Subject.CommonName, Cert: c})
			}
			return out, warn
		}
		if cert, err := x509.ParseCertificate(data); err == nil {
			return []toolItem{{Kind: "Certificate", Label: cert.Subject.CommonName, Cert: cert}}, nil
		}
		if csr, err := x509.ParseCertificateRequest(data); err == nil {
			if err = csr.CheckSignature(); err == nil {
				return []toolItem{{Kind: "CSR", Label: csr.Subject.CommonName, CSR: csr}}, nil
			}
		}
		if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
			if signer, ok := key.(crypto.Signer); ok {
				der, _ := x509.MarshalPKCS8PrivateKey(signer)
				return []toolItem{{Kind: "Private key", Key: signer, KeyDER: der}}, nil
			}
		}
		if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
			der, _ := x509.MarshalPKCS8PrivateKey(key)
			return []toolItem{{Kind: "Private key", Key: key, KeyDER: der}}, nil
		}
		if key, err := x509.ParseECPrivateKey(data); err == nil {
			der, _ := x509.MarshalPKCS8PrivateKey(key)
			return []toolItem{{Kind: "Private key", Key: key, KeyDER: der}}, nil
		}
	}
	rest := data
	for block, rem := pem.Decode(rest); block != nil; block, rem = pem.Decode(rem) {
		rest = rem
		switch block.Type {
		case "PKCS7":
			certs, err := decodePKCS7Certs(block.Bytes)
			if err != nil {
				warn = append(warn, "Invalid PKCS#7 block: "+err.Error())
			} else {
				for _, c := range certs {
					out = append(out, toolItem{Kind: "Certificate", Label: c.Subject.CommonName, Cert: c})
				}
			}
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				warn = append(warn, "Invalid certificate block: "+err.Error())
			} else {
				out = append(out, toolItem{Kind: "Certificate", Label: c.Subject.CommonName, Cert: c})
			}
		case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
			c, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				warn = append(warn, "Invalid CSR block: "+err.Error())
			} else if err = c.CheckSignature(); err != nil {
				warn = append(warn, "CSR signature is invalid")
			} else {
				out = append(out, toolItem{Kind: "CSR", Label: c.Subject.CommonName, CSR: c})
			}
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", encKeyType:
			key, err := decodePEMKey(block, password)
			if err != nil {
				warn = append(warn, "Private key block could not be decoded; verify its format and supplied password")
			} else {
				der, _ := x509.MarshalPKCS8PrivateKey(key)
				out = append(out, toolItem{Kind: "Private key", Key: key, KeyDER: der})
			}
		default:
			warn = append(warn, fmt.Sprintf("Unsupported PEM block: %s", block.Type))
		}
	}
	if len(out) == 0 && len(warn) == 0 && p12Candidate {
		warn = append(warn, "DER input could not be decoded; if this is PKCS#12, check the supplied password and file format.")
	}
	if len(out) == 0 && len(warn) == 0 {
		warn = append(warn, "Input is not recognized PEM, DER, PKCS#7, or PKCS#12.")
	}
	return out, warn
}
func decodePEMKey(block *pem.Block, password string) (crypto.Signer, error) {
	if block.Type == encKeyType {
		return unmarshalKey(pem.EncodeToMemory(block), password)
	}
	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if password == "" {
			return nil, fmt.Errorf("password required")
		}
		var err error
		der, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("wrong password or invalid encrypted key")
		}
	}
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(der)
	default:
		key, err = x509.ParsePKCS8PrivateKey(der)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("not a signer")
	}
	return signer, nil
}
func publicKeysEqual(a, b any) bool {
	x, e1 := x509.MarshalPKIXPublicKey(a)
	y, e2 := x509.MarshalPKIXPublicKey(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}
func decodePKCS7Certs(der []byte) ([]*x509.Certificate, error) {
	var outer p7ContentInfo
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || !outer.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("not signedData")
	}
	var seq p7SignedData
	if _, err = asn1.Unmarshal(outer.Content.Bytes, &seq); err != nil {
		return nil, err
	}
	raw := seq.Certificates.Bytes
	var out []*x509.Certificate
	for len(raw) > 0 {
		var rv asn1.RawValue
		rest, err := asn1.Unmarshal(raw, &rv)
		if err != nil {
			return nil, err
		}
		raw = rest
		c, err := x509.ParseCertificate(rv.FullBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certs")
	}
	return out, nil
}

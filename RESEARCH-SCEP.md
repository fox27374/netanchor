# Issue #2: Cisco IOS-XE SCEP research

Research date: 2026-10-05. Documentation/source review only; no switch verification or implementation.

## Fixed decisions

Automatic enrollment; single-use expiring challenges bound to a dedicated RSA intermediate, profile, and allowed DNS/IP SANs; optional SCEP-only HTTP listener; renewal deferred; UI-triggered in-memory CA unlock with an optional startup secret file; challenge lifetime 24 hours by default and at most seven days; certificate lifetime 365 days bounded by profile and CA.

## Findings and confidence

### Cisco algorithms

- **Documented:** IOS-XE 16 PKI documentation supports RSA enrollment and configurable SHA-256 in PKI. Its description of `hash` includes self-signed certificate signing and CA-issued certificate signing. This is not sufficient evidence that every 16.x SCEP client uses SHA-256 for the outer CMS signature. [C1, C2]
- **Unverified:** AES-128-CBC SCEP support/negotiation and the earliest interoperable IOS-XE release. No Cisco source retrieved in this review establishes an all-16.x guarantee. TLS/IPsec AES support does not establish SCEP AES support.
- **Protocol baseline:** RFC 8894 requires AES-128-CBC and SHA-256; the `AES` capability specifically means AES-128-CBC, not AES-GCM. It forbids single DES and MD5. This requirement is not proof that older Cisco implementations meet it. [R1 §§2.9, 3.5.2]

### CSR identities

- Cisco documents `subject-name`, `ip-address {address | interface | none}`, RSA key selection, and `password` for SCEP authorization. [C1]
- Cisco's 16.12.1 YANG model contains trustpoint `fqdn`, `ip-address`, `subject-name`, and `subject-alt-name` leaves. [C3]
- **Important documentation discrepancy:** the current IOS-XE 17 enrollment guide says SAN in CSR is supported from **17.9.x**, despite that older model exposing `subject-alt-name`. Command/model presence alone is not proof that the SAN extension is emitted in an older CSR. Multiple SAN syntax, DNS/IP encoding, and exact behavior on 16.x remain unverified. [C3, C4]
- Recommendation: reject requested names outside the challenge allowlist. Decide whether an empty/partial CSR SAN list may be replaced by the exact administrator-authorized DNS/IP identities; do not infer them from arbitrary CN/subject fields. This would avoid depending on older CSR SAN generation, but certificate acceptance still needs testing.

### One certificate for HTTPS and gNMI

- HTTPS selects its trustpoint with `ip http secure-trustpoint NAME`. [C5]
- Cisco documents `gnmi-yang secure-trustpoint NAME` for 16.8.1 through 17.2.x, and `gnxi secure-trustpoint NAME` for 17.3.1 onward. Both select the trustpoint/certificate set used by the service. [C6, C7]
- **Supported design inference:** both services can be configured to select the same identity trustpoint. The cited documents describe each selector independently, not a tested simultaneous SCEP-to-both-services recipe.
- gNMI platform introductions differ: C9300/C9400/C9500 at 16.8.1a; C9500 high-performance at 16.10.1; C9600 at 16.11.1; C9200/9200L and C9300L at 16.12.1. “IOS-XE 16+” is too broad for a universal gNMI promise. [C7 feature table]
- Recommend a single general-purpose RSA keypair and serverAuth certificate, with digitalSignature/keyEncipherment and the actual DNS/IP connection identities. Avoid separate Cisco signature/encryption usage keys, which can produce two enrollment requests. Optional gNMI client authentication is distinct from the switch's server certificate. [C1, C6, C7]
- Unverified: automatic certificate reload by both services, intermediate-chain presentation, simultaneous reuse on specific switch images.

### smallstep/scep

Reviewed commit `261f960a40d1e733627203ed817413b38e4133ad` (2026-03-31), pseudo-version `v0.0.0-20260331191114-261f960a40d1`; its go.mod requires smallstep/pkcs7 v0.2.1. No stable v1/tagged release is shown by the package documentation. [L1, L2]

- A useful protocol library, not a complete HTTP enrollment service. API: `ParsePKIMessage`, `DecryptPKIEnvelope`, `CSRReqMessage.CSR`, `CSRReqMessage.ChallengePassword`, `Success`, `Fail`, `DegenerateCertificates`. [L1, L2]
- `ParsePKIMessage` verifies outer CMS signatures. `DecryptPKIEnvelope` requires an RSA `crypto.Decrypter`, decrypts CMS, parses the PKCS#10 request, and extracts challengePassword. It does **not** call `CSR.CheckSignature`; authorization, CSR signature checking, key policy, and SAN policy are application responsibilities. [L2]
- `x509util.ParseChallengePassword` parses DER attributes for OID `1.2.840.113549.1.9.7`, returns an empty string when absent, and does not enforce the application's one-time/expiry/binding rules. Duplicate challenge attributes are not rejected by this helper. [L3]
- `Success(authCert, authKey, issuedCert)` packages the issued leaf, encrypts it to certificates from the incoming message, then signs the response. A separately decrypted request permits an RA response identity distinct from the issuing CA. Recipient selection needs review: the helper uses the incoming certificate collection, not just an explicitly selected verified signer. [L2]
- `CertPoll`, `GetCert`, and `GetCRL` return not-implemented; parsing RenewalReq does not mean the application should authorize renewal. Never return PENDING for this immediate-issuance scope. [L2]
- pkcs7 supports AES-128/256-CBC and GCM encryption/decryption; DES and 3DES decryption are also present, but its encryption API has no 3DES option. RSA PKCS#1 v1.5 and OAEP key transport exist. [L4, L5]
- **Defaults must be overridden:** response encryption defaults to single DES; message signing defaults to SHA-1. Set AES-128-CBC via `ContentEncryptionAlgorithm` and SHA-256 via `SetDefaultDigestAlgorithm`. Configure process-wide defaults once, not per request. Those settings do not restrict accepted inbound algorithms. [L4, L6]
- **Hardening concern from source inspection:** v0.2.1 CBC decryption calls `CryptBlocks` before validating ciphertext block alignment; padding code slices using the final byte before checking its bounds. Malformed messages can reach panic-prone paths. Require malformed-input tests and a hardened dependency/patch before public exposure; this review did not execute an exploit. [L5]
- Root license is MIT, as is pkcs7. The copied x509util code also carries Go's BSD-style attribution notice; retain applicable notices. [L3, L7, L8]

## Architectural blockers and recommendations

1. **CA key usage:** local `ca.go:215` gives intermediates certSign, crlSign, digitalSignature, but no keyEncipherment. RFC 8894 §2.1.2 requires keyEncipherment if the CA key decrypts SCEP. Being RSA alone is insufficient. Create a purpose-built SCEP intermediate with the required usages, or use a distinct RSA RA encryption/signing certificate. Existing certificates cannot gain a usage bit without reissuance. A dedicated RA is an alternative, not inherently mandatory. [R1 §§2.1.2, 7.2]
2. **Unlock state:** the resident private key must support both signing and RSA decryption for direct-CA operation. `loadCA` currently returns `crypto.Signer`; concrete RSA keys satisfy both interfaces, but the runtime requirement must be explicit. With an RA, both RA and issuer key availability must be designed. GetCACert/GetCACaps can remain available while locked; issuance should fail transiently without consuming a challenge.
3. **Issuance integration:** current `SignCSR` reloads the key from storage, copies CSR SANs, and only checks issuer expiry inside its template branch (`ca.go:422–483`). It cannot simply be reused unchanged for unlocked-key issuance, challenge-specific identity rules, and unconditional lifetime bounds.
4. **Validity recommendation:** effective expiry = minimum of 365-day default/request, profile maximum, and CA/chain expiry. Reject already-expired issuers and nonpositive remaining validity. Challenge expiry controls authorization time, not certificate expiry.
5. **Single-use with retries:** atomically bind consumption to durable issuance, and permit replay of the same authenticated transaction/CSR to retrieve the same issuance result after a lost response. Never issue a second certificate from that token. Define a bounded retry retention period.
6. **Transport/bootstrap:** optional HTTP is consistent with SCEP CMS protection, but GetCACert/GetCACaps are unauthenticated bootstrap operations. Pin/verify the CA out of band; HTTP protection is only as strong as that bootstrap. Use a CA-specific route so GetCACert can identify the issuer before the encrypted challenge is visible. [R1 §§2.2, 7.5, 7.10]
7. **Capability policy:** provisionally target RSA >=2048, AES-128-CBC, SHA-256, POSTPKIOperation; support legacy GET transport if needed. Do not advertise Renewal, DES3, GetNextCACert, or SCEPStandard without implementing/verifying the corresponding behavior. Initial AES/SHA-256 Cisco interoperability remains a release-qualification gate.

## Remaining user decisions

- Exact switch models and minimum images to qualify; recommendation: name specific 16.x legacy targets and a 17.9+ baseline, without assuming the latter proves AES interoperability.
- Purpose-built encryption-capable intermediate versus dedicated RA; recommendation for the stated initial scope: purpose-built leaf-only RSA intermediate, with RA as the alternative if CA key separation is required.
- SAN policy: CSR must supply approved SANs versus issuing the exact pre-authorized names even when absent; recommendation: allow the latter explicitly and reject any unapproved requested identities.
- Retry retention window and locked-service behavior; recommendation: transient failure while locked and a bounded durable same-request retry cache.

## Primary sources

- [C1] Cisco IOS-XE 16 certificate enrollment: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_pki/configuration/xe-16/sec-pki-xe-16-book/sec-cert-enroll-pki.html
- [C2] Cisco IOS-XE 16 certificate server/hash configuration: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_pki/configuration/xe-16/sec-pki-xe-16-book/sec-cfg-mng-cert-serv.html
- [C3] Cisco-authored 16.12.1 crypto YANG model: https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/16121/Cisco-IOS-XE-crypto.yang
- [C4] Cisco IOS-XE 17 enrollment/SAN caveat: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_pki/configuration/xe-17/sec-pki-xe-17-book/sec-cert-enroll-pki.html
- [C5] Cisco HTTPS trustpoint selector (legacy-titled chapter; not a recommendation of its old cipher examples): https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-16/https-xe-16-book/HTTPS--HTTP_Server_and_Client_with_SSL_3-0.html
- [C6] Cisco 16.12 gNMI: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1612/b_1612_programmability_cg/grpc_network_management_interface.html
- [C7] Cisco 17.12 gNMI and release/platform table: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1712/b_1712_programmability_cg/m_1712_prog_gnmi.html
- [R1] RFC 8894: https://www.rfc-editor.org/rfc/rfc8894.html
- [L1] Package API/version: https://pkg.go.dev/github.com/smallstep/scep@v0.0.0-20260331191114-261f960a40d1
- [L2] SCEP implementation: https://github.com/smallstep/scep/blob/261f960a40d1/scep.go and https://github.com/smallstep/scep/blob/261f960a40d1/go.mod
- [L3] CSR challenge helper: https://github.com/smallstep/scep/blob/261f960a40d1/x509util/x509util.go
- [L4] PKCS#7 encryption: https://github.com/smallstep/pkcs7/blob/v0.2.1/encrypt.go
- [L5] PKCS#7 decryption: https://github.com/smallstep/pkcs7/blob/v0.2.1/decrypt.go
- [L6] PKCS#7 signing: https://github.com/smallstep/pkcs7/blob/v0.2.1/sign.go
- [L7] SCEP license: https://github.com/smallstep/scep/blob/261f960a40d1/LICENSE
- [L8] PKCS#7 license: https://github.com/smallstep/pkcs7/blob/v0.2.1/LICENSE

# gNOI certificate push to switches

Approval: grilled with the user and summarised; user said "save the spec". Phase 0
(spike) done 2026-10-09 on lab switch 172.24.80.240 (Cat9K IOS-XE 17.18.2); results
under "Phase 0 results". Phase 1 not started.

## Goal
Admin pushes a NetAnchor-issued certificate (and CA bundle) to a switch over gNOI
Certificate Management, so the switch CLI does not need touching. First targets:
Cisco IOS-XE and NX-OS. SCEP already exists and is out of scope.

## Acceptance criteria
- Admin-only "Push to device (gNOI)" page modelled on `scep_admin.go`. Always on,
  no enable flag (same as SCEP). Outbound gRPC only: no new listener or port.
- Flow (CSR, per Phase 0): `CanGenerateCSR`, then `Install` stream (new cert_id) with
  `GenerateCSR`; NetAnchor signs the returned CSR (chosen CA and profile, under
  sign-CSR rules) and sends `LoadCertificate` (cert + CA chain, no key). `Rotate` for
  an existing cert_id (untested). Private keys never exist in NetAnchor.
- Optional `LoadCertificateAuthorityBundle` checkbox (default on); result reported
  separately from the certificate install.
- Form: host:port; auth (user/password, mTLS, or both; credentials used once, never
  stored); server verification (trust selected NetAnchor CA, or confirm fingerprint
  on first use; explicit "unverified" checkbox warns that credentials are exposed);
  CA + profile; CN + SANs; Country, State, Organization (required by IOS-XE for the
  CSR); cert_id (default sanitised CN); key size fixed to RSA 2048 (device offers RSA
  only), checked against profile policy.
- Step-by-step result display: connect, auth, capabilities, generate, sign, install,
  verify.
- Warning on the page: installing a cert can rebind the switch's own gNMI/gNOI server
  to it, and revoking it can take that server down. No revoke feature in this phase.
- Verify the install on a fresh connection (open calls are reset after a load).
- `NETANCHOR_GNOI_ALLOW`: CIDR allowlist of permitted targets; empty = refuse all.
  Guards against SSRF since the feature cannot be disabled.
- Timeouts: 10 s connect, 60 s overall, cancel button. On failure leave the device
  as-is; no cleanup attempts. Prefer Rotate when the device already has a cert.
- Each push recorded (target, serial, user, time, outcome); shown on the certificate
  details page as "Pushed to <host>". Never record credentials or keys.

## Non-goals
Device inventory, expiry tracking, automatic renewal, a separate gNOI agent process,
vendors other than Cisco in the first phase.

## Key files
New: gnoi_*.go, templates/gnoi.html (+ tests). Touch: server.go (routes), store.go
(push records), templates/details.html, templates/layout.html (nav), go.mod/go.sum,
README.md. Reuse: ca.go signing, certtemplates.go / profile_policy.go.

## Decisions not discoverable from code
- Dependencies accepted: `google.golang.org/grpc`, `github.com/openconfig/gnoi/cert`
  (larger binary is fine); repo does not vendor.
- Dev host ataltpr06 cannot reach the switch. Lab verification needs the whole stack
  deployed on a host that can; user is arranging access.
- NX-OS is untested; Phase 0 covered IOS-XE only.

## Phase 0 results (IOS-XE 17.18.2, gRPC 57400, TLS + username/password metadata)
- gNOI cert service works: `GetCertificates`, `CanGenerateCSR` (RSA 2048). `system.Time`
  is Unimplemented (not needed).
- Importing a client key (`key_pair` via `Install` or `Rotate`, PKCS#1 RSA PEM, self-
  signed cert) fails with `Aborted: Timeout waiting for event`; nothing is installed.
  **The CSR flow is therefore primary**; the "preferred" key-generated-in-memory flow in
  the acceptance criteria does not apply to IOS-XE. No private key ever leaves NetAnchor
  or the device, so the "key never persisted" criterion is moot for this flow.
- CSR flow that works: `Install` stream, `GenerateCSR` (cert_id, `CSRParams` type
  X509, KT_RSA, min key size 2048, CN) returns a PEM CSR; sign it; send
  `LoadCertificate` (cert + `ca_certificates`, no key, no certificate_id). `Install`
  has no finalize message. The device rejects the CSR request with `InvalidArgument`
  unless Country, State and Organization are set, so the form must collect them.
- `Rotate` on an unknown cert_id returns `NotFound`; use `Install` for new ids, `Rotate`
  only for existing ones (untested).
- Only RSA is offered (proto `KeyType` has just `KT_RSA`); the ECDSA default and key
  algorithm dropdown in the form do not apply to this flow.
- **Side effect:** installing a cert makes the switch bind its own gNMI/gNOI server to
  it (`gnxi secure-trustpoint <cert_id>`). Revoking that cert removed the trustpoint
  and port 57400 stopped listening until fixed on the CLI. The page must warn about
  this, must not offer revoke in this phase, and lab tests need a cert_id the user is
  prepared to rebind.
- Open connections are reset right after a load (`Unavailable: Cancelling all calls`),
  so verify the install on a fresh connection.
- Untested: `Rotate` on an existing id, `LoadCertificateAuthorityBundle`, NX-OS.

## Phases (each its own patch release)
0. Throwaway spike on the lab switch: Capabilities, CanGenerateCSR, GetCertificates,
   trial Install with a client-generated key. Not merged as a feature. DONE.
1. Feature, unit-tested against a fake in-process gNOI server (Install, Rotate,
   rollback, errors, allowlist, key never persisted).
2. Verification on the lab switch.

## Verification
`make verify` (build, vet, test); `go test -race ./...` for gNOI code. Containers
only via `podhost` on ataltpr06. Log noisy output under /tmp, report command, exit
status and log path.

## Authorization
Per the standing instruction for this repo: after each change, commit to main, bump
the patch version, tag, push, `make deploy-dev`. Phase 0 and any push to a real
switch need the user's go-ahead and lab host details first. Leave `.claude/`
untracked.

## Existing local changes to preserve
Only untracked `.claude/`.

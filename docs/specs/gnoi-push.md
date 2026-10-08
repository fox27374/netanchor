# gNOI certificate push to switches

Approval: grilled with the user and summarised; user said "save the spec". Phase 0
(spike) is blocked until the user provides a host that can reach the lab switch.

## Goal
Admin pushes a NetAnchor-issued certificate (and CA bundle) to a switch over gNOI
Certificate Management, so the switch CLI does not need touching. First targets:
Cisco IOS-XE and NX-OS. SCEP already exists and is out of scope.

## Acceptance criteria
- Admin-only "Push to device (gNOI)" page modelled on `scep_admin.go`. Always on,
  no enable flag (same as SCEP). Outbound gRPC only: no new listener or port.
- Preferred flow: NetAnchor generates the key in memory, signs it (chosen CA and
  profile), pushes certificate + key via `Install` (new cert_id) or `Rotate`
  (existing cert_id, device rolls back on failure). Fallback flow: device generates
  the CSR (`CanGenerateCSR`/`GenerateCSR`), NetAnchor signs under sign-CSR rules.
  Phase 0 decides which is primary.
- Optional `LoadCertificateAuthorityBundle` checkbox (default on); result reported
  separately from the certificate install.
- Form: host:port; auth (user/password, mTLS, or both; credentials used once, never
  stored); server verification (trust selected NetAnchor CA, or confirm fingerprint
  on first use; explicit "insecure" only for pushes carrying no key); CA + profile;
  CN + SANs; cert_id (default sanitised CN); key algorithm dropdown (ECDSA P-256
  default, RSA 2048/3072, constrained by profile policy).
- Step-by-step result display: connect, auth, capabilities, generate, sign, install,
  verify.
- Generated private key is never written to disk, store, or logs. Pushing a key
  requires a verified server connection.
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
- Unverified: whether IOS-XE/NX-OS accept an imported `key_pair`. If rejected, the
  CSR flow becomes primary and a small one-time CLI step (e.g. trustpoint) remains.

## Phases (each its own patch release)
0. Throwaway spike on the lab switch: Capabilities, CanGenerateCSR, GetCertificates,
   trial Install with a client-generated key. Not merged as a feature.
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

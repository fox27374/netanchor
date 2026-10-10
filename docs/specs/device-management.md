# Device management (gNOI certificate lifecycle for Cisco devices)

Approval: grilled with the user on 2026-10-10 and confirmed ("yes, go ahead").
Supersedes the single-form push page from `gnoi-push.md`. The device facts in
`gnoi-push.md` (Phase 0 and Phase 2 results) remain authoritative.

## Goal
NetAnchor grows into a certificate management tool for network devices, Cisco first.
Admins keep an inventory of devices, define how device certificates look, and push
certificates to one or many devices over gNOI without touching the device CLI.

## Constraints from the lab (IOS-XE 17.18.2, see `gnoi-push.md`)
- The device generates the key. Key import is impossible over gRPC: gNOI `cert`
  `Install` with a `key_pair` times out for PKCS#1/PKCS#8, PEM/DER, with and without
  chain (`Aborted: Timeout waiting for event` after 10 s), and gNSI Certz is
  `Unimplemented`. So every push is: `GenerateCSR` on the device, NetAnchor signs,
  `LoadCertificate` (cert + CA chain, no key). Private keys never exist in NetAnchor.
- `GenerateCSR` needs Country, State and Organization. Key is RSA 2048 (device).
- Installing a cert can rebind the device's own gNMI/gNOI server to it
  (`gnxi secure-trustpoint`). Revoke is not offered.
- Open calls are reset after a load; verify on a fresh connection, retry up to 30 s.
- Device clocks drift; pushed certs are backdated 24 h (`gnoiBackdate`).
- `Rotate` on an unknown cert_id returns `NotFound`. `Rotate` is otherwise untested.

## Menu
- Certificate Management: CA, Issue Certificate, Sign CSR, Templates, Issued
  certificates (own page; also stays on the Dashboard), Device certificate definitions.
- Device Management: Devices, Push (gNOI), SCEP.
- Admin (unchanged): Users, Backup & Restore. Secondary (unchanged): Dashboard, Tools.
- Same grouping on desktop and in the mobile burger menu.

## Devices
- Fields: name (unique), FQDN, management IP, gNOI port (default 57400), platform
  (IOS-XE, NX-OS), site, tags, notes, model, serial, credentials, server verification.
- Credentials (username/password) stored encrypted with a key read from
  `NETANCHOR_DEVICE_KEY_FILE` (outside the data dir, like `NETANCHOR_SCEP_SECRET_FILE`).
  Without the file NetAnchor stores no credentials; push asks for them instead.
  Passwords are never rendered back, logged, or included in plaintext anywhere.
- Server verification: probe the device's gRPC certificate on create, admin confirms
  the SHA-256 fingerprint, it is pinned. Alternatives: trust a NetAnchor CA, or
  explicit unverified. After a successful push the pin is updated to the certificate
  NetAnchor just installed.
- "Test connection": connects with stored credentials and verification, calls
  `GetCertificates`, fills model and serial from the Cisco SUDI certificate
  (subject serialNumber `PID:<model> SN:<serial>`).
- "Refresh certificates": live `GetCertificates` list (cert_id, subject, issuer,
  expiry) plus which certificate the gRPC port serves. Stored as a snapshot with a
  timestamp. No background polling.
- Roles: admins create/edit/delete devices, manage credentials, run tests and pushes.
  Normal users can view devices and their snapshots.
- `NETANCHOR_GNOI_ALLOW` is removed. Accepted risk (user decision): any admin can make
  NetAnchor open gRPC connections, with stored credentials, to any host.

## Device certificate definitions
- Fields: name, issuing CA, profile (existing templates), Country, State,
  Organization (required), City, OU (optional), validity days (capped by profile),
  cert_id (default `netanchor-<name>`), SAN rule (DNS = device FQDN, IP = management
  IP, plus fixed extra SANs).
- CN = device FQDN, or device name when FQDN is empty. Key fixed RSA 2048, checked
  against profile policy.

## Push
- Pick one definition and one or more devices; CA passphrase asked once, never stored.
- Devices processed one at a time; a failure does not stop the rest. Per-device steps
  (connect, auth, capabilities, generate, sign, install, verify) and outcome in a
  results panel next to the push button.
- Device that already has the definition's cert_id: skipped, "already installed;
  renewal comes with Rotate".
- Timeouts per device: 10 s connect, 60 s overall. No cleanup on failure.
- Each issued certificate is recorded with its push (device, user, time, outcome) and
  shown on the certificate details page and the device page.
- Rebind notice is neutral, not a red alert; real errors use the error style.
- The old single-form `/admin/gnoi` page is removed. Existing push records on
  certificates stay visible.

## Backup and restore
Devices, definitions, snapshots and encrypted credentials are part of the backup.
Restoring without the matching device key file keeps devices and drops credentials,
with a visible warning.

## Non-goals (for now)
Key import (SSH/CLI path), `Rotate`/renewal (Phase C), NX-OS lab support, scheduled
refresh, expiry alerts, gNMI discovery, `LoadCertificateAuthorityBundle`, mTLS to
devices, revoke on devices.

## Phases (each its own patch release, each lab-tested before the next)
- A: menu split; Devices with encrypted credentials, pinning, Test connection, live
  certificate list; backup/restore; allowlist removed.
- B: definitions; multi-device push with re-pin and per-device results; old page
  removed.
- C: `Rotate` spike on the lab switch (needs the user's go-ahead), then renewal.

## Lab
Lab switch 172.24.80.240:57400 (Cat9K, IOS-XE 17.18.2). Lab deploy host 172.24.89.69
(rootless podman, other projects' containers must not be touched). Credentials come
from the user and are never written to the repo or issues.

## Verification
`gofmt -l .`, `go build ./...`, `go vet ./...`, `go test ./...`, `go test -race ./...`
for gNOI code, `make verify`. Unit tests use an in-process fake gNOI server.

# NetAnchor

A simple, web-based certificate authority written in Go — single static binary.
It uses pure-Go libraries for PKCS#12 (`software.sslmate.com/src/go-pkcs12`)
and SCEP/CMS (`github.com/smallstep/scep` and `github.com/smallstep/pkcs7`),
with no cgo. The rest uses the standard library:

- `net/http` (Go 1.22+ method/pattern routing) for the web GUI
- `crypto/x509`, `crypto/ecdsa`, `crypto/rsa` for the PKI work
- `encoding/asn1` for the (hand-rolled, stdlib) PKCS#7 export
- `crypto/tls` for HTTPS, `crypto/hmac` for sessions
- `crypto/pbkdf2` + `crypto/aes` (Go 1.24) for passphrase & password protection
- `html/template` + `embed` for the UI (templates are baked into the binary)

## Features

- **Root CA** — create a self-signed root (ECDSA P-256/P-384 or RSA 2048/4096,
  configurable subject & validity)
- **Intermediate CAs (any depth)** — create a hierarchy of intermediate CAs signed
  by the root or other intermediates (each can optionally allow sub-CAs). Choose
  any CA as the issuer. Entirely optional; issue directly from the root if you prefer.
- **Delete** — admins can delete an intermediate CA (together with its sub-CAs and
  every certificate they issued) or a single issued certificate. Nothing is erased:
  files move to `<data>/trash/<timestamp>/` with an `index.json` of the removed
  records, so a manual restore is possible. There is no revocation/CRL.
- **Issue certificates** — generates a key pair and signs a leaf cert, with
  Subject Alternative Names (DNS + IP, auto-detected) and server/client/both profiles
- **Sign CSRs** — paste PEM or upload a file; the request signature is verified
  before signing, and the requester keeps their own private key
- **SCEP enrollment** — immediate switch HTTPS/gNMI serverAuth certificates,
  with dedicated RSA intermediate, administrator-authorized SANs, expiring
  single-use challenges, and durable same-request retries. See limitations below.
- **Passphrase protection** — optionally encrypt a CA's private key at rest
  (PBKDF2-SHA256 + AES-256-GCM). The passphrase is then required to issue or sign
  with that CA.
- **Authentication & roles** — login-gated UI with two roles:
  - **admin** — full control: manage CAs, issue, sign, download private keys, manage users
  - **viewer** — read-only: view and download public certificates and chains (no private keys, no issuing)

  On first run you create the initial admin account. Passwords are hashed with
  PBKDF2-SHA256; sessions are stateless HMAC-signed cookies (survive restarts).
- **Encrypted full-instance backup/restore** — manual administrator downloads
  under **Management → Backup & Restore**, protected by a separate password.
  Restore validates and stages a full replacement, invalidates sessions and unused
  SCEP challenges, then shuts down for restart. Fresh installations can restore
  immediately after creating a temporary admin. See [BACKUP.md](BACKUP.md) for
  format/size limits, recovery, identity options and operational consequences.
- **HTTPS by default** — the GUI is served over TLS. The server certificate is
  issued by your own root CA when one is available (import the root and the GUI
  is trusted), otherwise it's self-signed.
- **Certificate profiles** — choose a built-in TLS server, TLS client, dual-use,
  code-signing, or S/MIME template when issuing or signing a CSR. The server
  enforces the selected purpose, identity/SAN rules, allowed keys and issuers,
  and validity maximum. Admins can duplicate built-ins or create custom
  profiles; existing templates are migrated. Issued certificates retain a
  snapshot of the policy used, visible on the dashboard and details page.
- **Certificate details page** — full inspection with Common Name and SANs shown
  up front, plus issuer, validity, key usages, algorithms, and SHA-256/SHA-1
  fingerprints. The cert (and, for admins, the private key) are shown inline as
  **copy-paste PEM**.
- **Multiple export formats** — download a certificate as **PEM**, **DER**, or
  **PKCS#7** (`.p7b`), the chain as **PEM** or **PKCS#7** (optionally without
  the root), the private key as **PEM** or **DER**, and export the cert + key + chain as a
  password-protected **PKCS#12** (`.p12` / `.pfx`) for browsers, Windows, macOS
  Keychain, or Java keystores.
- **Dashboard** with one-click downloads: cert, key (admin only), and full
  chain (leaf + intermediate + root)
- **Tools inspector & converter** — paste PEM or upload PEM, DER, PKCS#7, or
  PKCS#12 to inspect certificates, CSRs, and private-key metadata. Convert
  certificates and CSRs to PEM/DER, certificate bundles to PEM/PKCS#7, and
  (for admins) private keys to PEM/DER or matching cert + key + chain to
  password-protected PKCS#12. Inputs are not stored on disk; results expire
  from memory after ten minutes.

Everything is stored under the data directory as PEM/JSON. Downloaded **leaf**
private keys are always standard, unencrypted PKCS#8 so other tools (nginx,
openssl, …) can use them directly; only **CA** keys are encrypted at rest when
you set a passphrase.

## Run locally

```sh
go run .
# or build a standalone binary:
go build -o netanchor .
./netanchor
```

Then open <https://127.0.0.1:8443> (note **https**; you'll get a self-signed-cert
warning until you trust/import the CA). On first load you'll be asked to create
the admin account.

### Configuration

| Flag    | Env var                 | Default            | Description                                   |
|---------|-------------------------|--------------------|-----------------------------------------------|
| `-addr` | `NETANCHOR_ADDR`          | `127.0.0.1:8443`   | Address to listen on                          |
| `-data` | `NETANCHOR_DATA`          | `./netanchor-data`   | Directory for all data                        |
| `-health` | —                     | —                  | Probe a running server's `/healthz` and exit  |
|         | `NETANCHOR_TLS`           | `on`               | Set to `off` to serve plain HTTP (e.g. behind a TLS-terminating proxy) |
|         | `NETANCHOR_TLS_HOSTS`     | `localhost,127.0.0.1` | SANs for the auto-generated server certificate |
|         | `NETANCHOR_CA_PASSPHRASE` | —                  | Unlocks an encrypted root so the server cert can be issued by it at startup |
|         | `NETANCHOR_DISABLE_AUTH`  | —                  | Set to `1` to disable login (trusted local use only) |
|         | `NETANCHOR_SCEP_ADDR`     | —                  | Optional additional SCEP-only HTTP listener, e.g. `0.0.0.0:8080` |
|         | `NETANCHOR_SCEP_SECRET_FILE` | —               | Mounted file containing the selected SCEP CA passphrase; unlock at startup (trailing CR/LF removed) |

## SCEP for switch HTTPS and gNMI

### Setup and bootstrap

1. On **CA**, create an intermediate with **Dedicated SCEP intermediate** checked,
   RSA 2048 or 4096, and **Allow sub-CAs** unchecked. This adds certSign,
   crlSign, digitalSignature and keyEncipherment. Existing ordinary intermediates
   cannot gain the missing usage without reissuance.
2. On the admin-only **SCEP** page, select and unlock that intermediate. Only one
   is active. The key stays in process memory until locked or restarted. Locked,
   expired, or deleted issuers cannot enroll; a deleted selected CA is not replaced
   automatically. GetCACert/GetCACaps remain available while locked.
3. Verify the selected intermediate's **SHA-256 fingerprint out of band**, from
   the authenticated SCEP/CA details page or a trusted downloaded certificate:
   `openssl x509 -in scep-ca.pem -noout -fingerprint -sha256`. Also verify the
   root trust anchor. Compare these against the certificates received by the
   switch before accepting its bootstrap authentication prompt. GetCACert and
   GetCACaps are unauthenticated; HTTP CMS protection depends on this bootstrap.
4. Create a challenge bound to that CA, a TLS server profile, and the exact DNS/IP
   SANs used to connect to the switch. Copy the random secret from the one-time
   response. Only its SHA-256 hash is persisted; losing it requires a new challenge.
   Unused challenges can be revoked in the UI.
5. Enroll using `/scep`, `/scep/cgi-bin/pkiclient.exe`, or
   `/cgi-bin/pkiclient.exe`. The normal GUI listener also serves these public
   protocol paths. The optional `NETANCHOR_SCEP_ADDR` listener is plain HTTP and
   serves **only SCEP**, never the UI, setup, login, admin routes, or health probe.

The challenge defaults to 24 hours and has a seven-day maximum. Certificate
validity defaults to 365 days, capped by the profile maximum and the entire
issuer chain's expiry. The profile is snapshotted at challenge creation; later
profile edits do not alter outstanding authorization (revoke and recreate it).
Issued SANs are **exactly the administrator-authorized DNS/IP identities**, even
when absent or partial in the CSR. Extra SANs, email/URI SANs, CA privileges,
conflicting EKUs, invalid signatures and keys outside the profile are rejected.
The CSR subject/CN is retained, but is not used to authorize SANs. Issuances stay
`kind=csr` with `provenance=scep` and a dashboard badge; device keys never leave
the device.

### Runtime and deployment

For an additional switch-facing port, set `NETANCHOR_SCEP_ADDR=0.0.0.0:8080`
and publish `8080:8080` alongside the GUI's `8443:8443`. `compose.yaml` includes
commented listener/port/secret-mount examples. SCEP is included starting with
version 1.5.0.
For the designated remote container host, the parent deployment can use
`podhost <build/run command>` to run on `ataltpr06.lnxnet.org`.

### Developer workflow

Install Go and GNU Make for local checks. `make verify` runs build, vet, and all
Go tests. For development deployment, install `podhost` at `~/.local/bin/podhost`
and put that directory on `PATH`; it copies this checkout to `ataltpr06` and runs
the requested command there. The remote host needs Podman plus a working Compose
provider and the existing `netanchor-data` volume. `make deploy-dev` builds and
recreates only the development app using `compose.dev.yaml` (override published
ports with `NETANCHOR_HTTPS_PORT` and `NETANCHOR_SCEP_PORT`). It never creates or
removes data volumes. It inspects legacy container mounts before replacement and
refuses a mismatched mount. Restarting interrupts active requests, including
locked SCEP enrollments; avoid deploying during enrollment activity.

After committing feature work, a clean, up-to-date `main` can be released with
`make release VERSION=1.6.0`. This verifies first, updates the four intentional
version references, commits them, creates an annotated tag, and atomically pushes
branch and tag. This is distinct from `make deploy-dev`: development builds the
current source on the remote host, while release pushes source metadata and the
tag-driven publication workflow creates the published image. No credentials are
embedded; configure Git transport credentials externally. If release fails,
inspect `git status`, the current commit/tag, and the remote before any retry; the
local commit/tag steps are not transactionally rolled back. Never manually rerun
blindly after a push error.

Without `NETANCHOR_SCEP_SECRET_FILE`, each restart requires an explicit UI unlock,
even for an unencrypted CA key. To auto-unlock, mount a file read-only, readable
by container uid 65532, and set the variable to its **container path**, e.g.
`/run/secrets/scep-passphrase`. An empty file unlocks an unencrypted key. Selection
persists in `/data/scep.json`; the passphrase does not. Missing/wrong secrets or
recovery errors leave enrollment locked and log a startup error; the UI remains
available to repair/unlock it. Locking in the UI is an in-memory action; remove
the startup secret configuration if it must remain locked after restart.

Run exactly **one process per data directory**, on a local filesystem supporting
atomic rename and fsync. SCEP serializes enrollment/deletion within that process.
Its fsynced, atomically replaced journal commits the certificate and token
consumption together before publishing PEM/index files or returning success.
If publication fails, the request receives HTTP 503; repair storage and retry.
Startup or a later valid request completes the same committed issuance, without
minting another certificate. Use the encrypted full-instance backup under
Management, or copy the complete data directory while stopped; do not restore
the SCEP journal independently.
CA/certificate deletion first completes pending journal projections, including
PEMs whose index update failed; if reconciliation fails, deletion aborts before
moving files. A missing or unreadable CA is never interpreted as proof of deletion:
its committed pending issuances remain recoverable after storage is restored.

Authenticated retries with the **same challenge, transaction ID, exact CSR DER,
and signer certificate** return the same certificate for seven days after
issuance (the response envelope/nonce can differ). A different request cannot
reuse a spent challenge. Deleted certificates are not resurrected by retries.
Expired/used challenge entries are pruned when creating another challenge,
seven days after expiry/use; unused revoked entries follow their original
expiry. At most 10,000 entries are retained; unfinished committed publications
are retained until recovered. Issued PEMs/index records follow normal certificate
retention and are not removed by challenge cleanup.

### Cisco configuration sketch — **unverified on hardware**

Adapt hostnames, SANs, ports and commands to the exact switch image. This is a
starting point, **not verified IOS-XE 16.x interoperability**. A general-purpose
RSA keypair avoids separate signing/encryption-key enrollments:

```text
crypto key generate rsa general-keys label SWITCH-TLS modulus 2048
crypto pki trustpoint NETANCHOR
 enrollment url http://pki.example.net:8080/scep
 subject-name CN=switch.example.net
 fqdn switch.example.net
 ip-address 192.0.2.10
 rsakeypair SWITCH-TLS
 hash sha256
 password <ONE-TIME-CHALLENGE>
exit
crypto pki authenticate NETANCHOR
! Verify downloaded CA fingerprints out of band before accepting.
crypto pki enroll NETANCHOR
ip http secure-trustpoint NETANCHOR
ip http secure-server
! IOS-XE 16.8.1 through 17.2.x (platform-dependent):
gnmi-yang secure-trustpoint NETANCHOR
! On 17.3.1+ use the image's gnxi secure-trustpoint NETANCHOR selector instead.
```

Remove the challenge password from switch configuration after enrollment. Configure
gNMI service enablement, authorization and optional client authentication according
to the platform guide; the trustpoint only selects the server identity. Verify
both HTTPS and gNMI actually present the new leaf and intermediate chain, with
serverAuth and the intended DNS/IP SANs; verify service reload behavior on your image.

Only **AES-128-CBC content encryption, RSA PKCS#1 v1.5 key transport, and SHA-256
RSA CMS signatures** are accepted. DES, 3DES, SHA-1/MD5 CMS signatures and other
content algorithms are rejected; there is no downgrade. Setting Cisco `hash sha256`
does not prove that its SCEP CMS layer supports this policy. Clients must send one
self-signed RSA signer certificate matching the CSR key and one envelope recipient.
Requests are limited to 1 MiB (decoded), with one challengePassword attribute.
CMS framing must use definite, minimal ASN.1 lengths and low-numbered tags;
indefinite BER is rejected. Before library parsing, an allocation-free iterative
preflight enforces 32 levels, 8,192 elements, and 8 MiB cumulative encoded lengths
(bounding recursive conversion/copying work). It runs before the enrollment state
lock, with an independent check for the embedded CMS envelope.
The smallstep CBC dependency is protected by envelope/key-length/padding checks
before its panic-prone unpadding path and a defensive parse/decrypt panic boundary.

Supported operations: GetCACaps, GetCACert, PKIOperation via GET or POST, and
immediate PKCSReq success/failure. No approval queue, PENDING, polling, renewal,
GetNextCACert, CRL/OCSP, certificate revocation, or automated device service reload.
Re-enrollment requires a new challenge. Older Cisco SAN emission, AES support,
chain handling and HTTPS/gNMI reuse remain unverified; see [RESEARCH-SCEP.md](RESEARCH-SCEP.md)
for source references and release-specific uncertainties.

## Run in a container (Podman)

The image is a static binary on Alpine, runs as a **non-root** user (uid 65532),
and stores everything under `/data`.

```sh
# Build
podman build -t netanchor:latest -f Containerfile .

# Create a named volume and run
podman volume create netanchor-data
podman run -d --name netanchor -p 8443:8443 -v netanchor-data:/data netanchor:latest
```

Open <https://127.0.0.1:8443> and create the admin account.

### Published image (GHCR) & multi-arch

A multi-architecture image is published to the GitHub Container Registry. It
supports **`linux/amd64`** (x86-64 servers/PCs), **`linux/arm64`** (64-bit
Raspberry Pi 3/4/5 and ARM servers), and **`linux/arm/v7`** (32-bit Pi / older
ARM). Podman or Docker automatically pull the variant matching your machine:

```sh
podman pull ghcr.io/fox27374/netanchor:1.5.0
podman run -d --name netanchor -p 8443:8443 -v netanchor-data:/data \
  ghcr.io/fox27374/netanchor:1.5.0
```

On a Raspberry Pi this is the only command you need — no building required.

**Publishing** is handled by [`.github/workflows/publish.yml`](.github/workflows/publish.yml).
Push a version tag and it builds all three arches and pushes the manifest:

```sh
git tag v1.5.0
git push origin v1.5.0
```

The workflow authenticates with the built-in `GITHUB_TOKEN` (no secrets to
configure) and publishes `:1.5.0`, `:1.5`, `:1`, and `:latest`. After the first
publish, make the package public under the repo's *Packages* settings if you
want unauthenticated pulls. The Go binary is cross-compiled natively per arch
(fast); only the tiny user-creation step in the runtime stage runs under QEMU.

**Building the manifest locally** (without GitHub Actions) is also possible with
Podman:

```sh
podman manifest create netanchor:1.5.0
podman build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  --manifest netanchor:1.5.0 --build-arg VERSION=1.5.0 -f Containerfile .
podman manifest push --all netanchor:1.5.0 \
  docker://ghcr.io/fox27374/netanchor:1.5.0
```

### Why a volume (and not a database)?

For this workload a **named volume is the right choice**:

- The data is naturally file-shaped (PEM files + small JSON indexes) and
  low-write — no need for a query engine.
- It keeps the zero-dependency design; a DB would mean another container or a
  cgo-linked embedded engine.
- Encrypted live backup/restore in Management; offline volume exports must be
  taken while stopped and contain unencrypted private material.
- Directly inspectable: `openssl x509 -in cert.pem -text`.

A database only pays off once you need concurrent multi-instance writers,
querying across thousands of certs, or transactional revocation lists. The next
step then would be **SQLite stored on the same volume** (still embedded), not a
separate DB service.

### Notes for Podman

- **Volume ownership** is handled automatically: the image creates `/data` owned
  by uid 65532, and Podman's volume "copy-up" gives a fresh named volume that
  same ownership on first use. The volume holds the CA(s), issued certs, the TLS
  server cert, the session-signing key, and `users.json`.
- **Graceful shutdown**: the server traps `SIGTERM` (what `podman stop` sends)
  and shuts down cleanly.
- **Health check**: the binary self-probes via `netanchor -health` (no extra tools
  in the image; it tolerates the self-signed TLS cert and returns exit 0/1). The
  `HEALTHCHECK` line is only embedded when building in Docker format
  (`podman build --format docker ...`); OCI format ignores it. Either build with
  `--format docker`, or supply it at run time:

  ```sh
  podman run -d --name netanchor -p 8443:8443 -v netanchor-data:/data \
    --health-cmd '/usr/local/bin/netanchor -health' --health-interval 30s \
    netanchor:latest
  ```

  A `GET /healthz` endpoint returns `200 ok` and bypasses authentication.

## Run on Kubernetes

Manifests live in [`k8s/`](k8s/) as a kustomize base: namespace, 1Gi PVC, a
single-replica Deployment (`Recreate`, since the file store is single-writer),
Service, and a Gateway API `Gateway` + `HTTPRoute` (plus an HTTP→HTTPS
redirect). The Gateway terminates TLS, so the pod runs with
`NETANCHOR_TLS=off`.

Before applying, edit:

- `gateway.yaml`: `gatewayClassName` (currently `change-me`) and the hostname,
  and create the TLS Secret `netanchor-tls` (`kubernetes.io/tls`, e.g. via
  cert-manager). If you already have a shared Gateway, delete `gateway.yaml`
  and point the `parentRefs` in `httproute.yaml` at it.
- `httproute.yaml`: the hostname (matches the Gateway's).
- `pvc.yaml`: optionally a `storageClassName`.

```sh
kubectl apply -k k8s/
kubectl -n netanchor get gateway,httproute,pods
```

The image tag is pinned in `k8s/kustomization.yaml`. With TLS off the app does
not mark its session cookies `Secure`; clients still connect over HTTPS through
the Gateway.

## Quick test with OpenSSL

Generate a CSR to sign from the "Sign CSR" page:

```sh
openssl req -newkey rsa:2048 -nodes -keyout test.key -out test.csr -subj "/CN=test.local"
```

Verify an issued cert chains to your CA (use the downloaded full chain for
intermediate-signed certs):

```sh
openssl verify -CAfile root-cert.pem some-cert.pem
# intermediate-signed:
openssl verify -CAfile root-cert.pem -untrusted intermediate-cert.pem some-cert.pem
```

## Security notes

This is a lightweight tool for development, labs, and internal PKI. It binds to
localhost by default (and to `0.0.0.0` inside the container, reached via the
published port). With the defaults it now serves over **HTTPS** and requires
**login**, so it's reasonable to put on a trusted LAN — but the server cert is
self-signed unless issued by your own (imported) root, and there's no rate
limiting or CSRF protection, so don't expose it to the public internet without a
hardened reverse proxy in front. CA keys are encrypted at rest only when you set
a passphrase; there is no recovery if you forget it.

## Layout

| File           | Responsibility                                              |
|----------------|-------------------------------------------------------------|
| `main.go`      | Entry point, flags/env, TLS startup, health probe, graceful shutdown |
| `ca.go`        | Crypto: key gen, root/intermediate CA, issuing, CSR signing |
| `keycrypt.go`  | Passphrase encryption of CA keys (PBKDF2 + AES-GCM)         |
| `auth.go`      | Users, password hashing, HMAC sessions, RBAC middleware     |
| `tlscert.go`   | Auto-generated TLS server certificate (root-issued or self-signed) |
| `pkcs7.go`     | Pure-stdlib PKCS#7 (`.p7b`) certificate-bundle encoder      |
| `certtemplates.go` | Certificate template (issuance preset) model + validation |
| `certinfo.go`  | Parsing a cert into a details view                          |
| `store.go`     | File-backed persistence + metadata index                    |
| `backup*.go`, `restore.go` | Encrypted archives, validation, operation barrier, durable replacement/recovery |
| `server.go`    | HTTP routes, handlers, template rendering                    |
| `scep_protocol.go` | SCEP/CMS policy checks, enrollment and protocol HTTP routes |
| `scep_store.go` | CA unlock state, challenge journal and issuance recovery |
| `scep_admin.go` | Admin-only SCEP selection, lock and challenge UI |
| `templates/`   | Embedded HTML UI                                             |
| `Containerfile`| Multi-stage build → static binary on Alpine, non-root       |
| `k8s/`         | Kustomize base: Deployment, PVC, Service, Gateway API Gateway + HTTPRoute |

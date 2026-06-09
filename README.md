# NetAnchor

A simple, web-based certificate authority written in Go — single static binary.
It is standard-library-only except for **one** small dependency
(`software.sslmate.com/src/go-pkcs12`, pure Go, no cgo) because the stdlib has no
PKCS#12 encoder. Everything else uses the standard library:

- `net/http` (Go 1.22+ method/pattern routing) for the web GUI
- `crypto/x509`, `crypto/ecdsa`, `crypto/rsa` for the PKI work
- `encoding/asn1` for the (hand-rolled, stdlib) PKCS#7 export
- `crypto/tls` for HTTPS, `crypto/hmac` for sessions
- `crypto/pbkdf2` + `crypto/aes` (Go 1.24) for passphrase & password protection
- `html/template` + `embed` for the UI (templates are baked into the binary)

## Features

- **Root CA** — create a self-signed root (ECDSA P-256/P-384 or RSA 2048/4096,
  configurable subject & validity)
- **Optional intermediate CA** — create one intermediate signed by the root, then
  choose root or intermediate as the issuer. Entirely optional; issue directly
  from the root if you prefer.
- **Issue certificates** — generates a key pair and signs a leaf cert, with
  Subject Alternative Names (DNS + IP, auto-detected) and server/client/both profiles
- **Sign CSRs** — paste PEM or upload a file; the request signature is verified
  before signing, and the requester keeps their own private key
- **Passphrase protection** — optionally encrypt a CA's private key at rest
  (PBKDF2-SHA256 + AES-256-GCM). The passphrase is then required to issue or sign
  with that CA.
- **Authentication & roles** — login-gated UI with two roles:
  - **admin** — full control: manage CAs, issue, sign, download private keys, manage users
  - **viewer** — read-only: view and download public certificates and chains (no private keys, no issuing)

  On first run you create the initial admin account. Passwords are hashed with
  PBKDF2-SHA256; sessions are stateless HMAC-signed cookies (survive restarts).
- **HTTPS by default** — the GUI is served over TLS. The server certificate is
  issued by your own root CA when one is available (import the root and the GUI
  is trusted), otherwise it's self-signed.
- **Certificate templates** — reusable issuance presets (key algorithm, validity,
  profile/EKU, organization, country). Manage them under the **Templates** menu
  (admin) and pick one on the Issue / Sign pages to pre-fill the form.
- **Certificate details page** — full inspection with Common Name and SANs shown
  up front, plus issuer, validity, key usages, algorithms, and SHA-256/SHA-1
  fingerprints. The cert (and, for admins, the private key) are shown inline as
  **copy-paste PEM**.
- **Multiple export formats** — download a certificate as **PEM**, **DER**, or
  **PKCS#7** (`.p7b`, full chain), and export the cert + key + chain as a
  password-protected **PKCS#12** (`.p12` / `.pfx`) for browsers, Windows, macOS
  Keychain, or Java keystores.
- **Dashboard** with one-click downloads: cert, key (admin only), and full
  chain (leaf + intermediate + root)

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
podman pull ghcr.io/OWNER/netanchor:1.1.0
podman run -d --name netanchor -p 8443:8443 -v netanchor-data:/data \
  ghcr.io/OWNER/netanchor:1.1.0
```

Replace `OWNER` with your GitHub user/org. On a Raspberry Pi this is the only
command you need — no building required.

**Publishing** is handled by [`.github/workflows/publish.yml`](.github/workflows/publish.yml).
Push a version tag and it builds all three arches and pushes the manifest:

```sh
git tag v1.1.0
git push origin v1.1.0
```

The workflow authenticates with the built-in `GITHUB_TOKEN` (no secrets to
configure) and publishes `:1.1.0`, `:1.1`, `:1`, and `:latest`. After the first
publish, make the package public under the repo's *Packages* settings if you
want unauthenticated pulls. The Go binary is cross-compiled natively per arch
(fast); only the tiny user-creation step in the runtime stage runs under QEMU.

**Building the manifest locally** (without GitHub Actions) is also possible with
Podman:

```sh
podman manifest create netanchor:1.1.0
podman build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  --manifest netanchor:1.1.0 --build-arg VERSION=1.1.0 -f Containerfile .
podman manifest push --all netanchor:1.1.0 \
  docker://ghcr.io/OWNER/netanchor:1.1.0
```

### Why a volume (and not a database)?

For this workload a **named volume is the right choice**:

- The data is naturally file-shaped (PEM files + small JSON indexes) and
  low-write — no need for a query engine.
- It keeps the zero-dependency design; a DB would mean another container or a
  cgo-linked embedded engine.
- Easy backup/restore: `podman volume export netanchor-data > backup.tar`.
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
| `server.go`    | HTTP routes, handlers, template rendering                    |
| `templates/`   | Embedded HTML UI                                             |
| `Containerfile`| Multi-stage build → static binary on Alpine, non-root       |

# Encrypted instance backup and restore

Use **Management → Backup & Restore** as an administrator. This is a manual,
password-encrypted full-instance backup, available even before a CA exists.
Choose a long, unique passphrase (12–1024 UTF-8 bytes); keep it separately from
the `.nab` download. The password is used only for this request and is not saved.
**There is no password recovery.** Protect the backup like all of its private keys.

## Included and excluded

Included: root and intermediate CA certificates and private keys (existing CA
encryption is preserved), issued certificates and keys, metadata index, custom
certificate profiles, users/password hashes, HTTPS certificate and key, session
key, authoritative SCEP journal including challenge/issuance history, all
trash records and their certificate/key files, and devices with their last
certificate snapshot and encrypted credentials (`devices.json`).

Device credentials are encrypted with the key in `NETANCHOR_DEVICE_KEY_FILE`, which
is **not** in the backup. Keep that key file with the backup: it is needed to
decrypt the credentials after restore. Without it (or with a different key), the
restore keeps the devices, drops their credentials, and the restore page lists the
affected devices. Re-enter those credentials before pushing or testing.

Excluded: temporary files, restore recovery/staging material, in-memory tools
results and notifications, environment variables, compose/Kubernetes/proxy
configuration, external mounted secrets, and other files outside the application's
logical data paths. Deployment configuration and SCEP startup passphrase files
must be managed separately. Unknown files **inside** logical directories cause
backup to fail rather than silently omit potentially important data.

All complete HTTP operations on both the GUI and optional SCEP-only listener
participate in one process-wide barrier. Backup waits for in-flight operations,
briefly stops new operations, reconciles committed but unpublished SCEP issuance,
and copies the snapshot. Ordinary operations resume before password derivation,
encryption and download. This includes GET handlers that can migrate profiles.
Maintenance acquisition is cancelable and waits at most five seconds. While it
waits, new GUI and SCEP requests continue normally; a busy instance returns HTTP
503 instead of queuing an exclusive lock behind slow requests. Retry when traffic
has settled. Canceling a waiting request abandons acquisition without leaving a
queued writer. Once activation starts, its durable transaction runs to completion
or rollback even if the client disconnects.

All barrier-covered requests, including unauthenticated login, have an absolute
30-second body-read deadline (two minutes for restore uploads). Response writes
are bounded by the read allowance plus two minutes, measured from handler entry.
Slow or unfinished bodies and clients that stop reading responses cannot retain
an operation lease indefinitely. Maintenance releases its read lease before
waiting and never retains it during encryption/download or its final response.

Only one backup/restore request runs at a time. One process per data directory is
required; external writers and live volume copies are not supported.

## Restore procedure

1. Stop the source when moving to another instance; do not keep two independently
   issuing copies of the same CA. Keep a separate current backup before replacing
   a populated destination.
2. On a fresh destination, create a **temporary administrator** in setup. Setup
   sends you to Management; use Backup & Restore **before creating a CA**.
3. Upload the `.nab` archive and enter its password again. Type **REPLACE**.
4. Normally preserve the archived HTTPS identity. For a new destination, check
   **Regenerate HTTPS identity** to generate a new key/certificate using the
   destination's `NETANCHOR_TLS_HOSTS`. It is issued by the restored root if the
   root is unencrypted or `NETANCHOR_CA_PASSPHRASE` can unlock it; otherwise it is
   self-signed. Generation happens in staging before activation. Normal startup
   expiry renewal still applies even when preserving an identity.
5. Successful restore displays a restart page and **shuts down the process**.
   `compose.yaml` uses `restart: unless-stopped`, which starts it again; Kubernetes
   also restarts exited containers. A standalone binary must be started manually.
   New requests on both listeners receive 503 until shutdown; old in-memory
   authentication, TLS and SCEP state cannot continue serving.
6. After restart, verify any changed HTTPS identity and sign in using an account
   from the backup. Restored users replace the temporary/current users. If an
   auth-disabled source had no users and destination authentication is enabled,
   first-run setup creates a new administrator.

All browser sessions are invalidated with a newly generated session-signing key.
**Every unused SCEP challenge is revoked**, including challenges that were still
unused in an older snapshot but have since been consumed or revoked elsewhere.
Used history and certificates are retained, and committed unpublished issuance is
reconciled in staging. Used same-request retries keep their existing retention
rules; deliberately deleted certificates stay deleted. Create fresh challenges
after restore. SCEP starts locked unless the destination has a matching
`NETANCHOR_SCEP_SECRET_FILE`. Existing CA passphrases still apply and are never
replaced by the backup password.

Restoring an older snapshot removes later records, users, policy edits and trash.
It **does not revoke certificates already distributed**. Those certificates may
remain valid even though the restored instance no longer knows about them.
Restoring trash replaces the destination's trash too; this is never a merge.

## Format, validation and limits

The first format is `NETANCHOR-BACKUP-1`: a fixed PBKDF2-SHA256 cost of 600,000
iterations, random 16-byte salt, random 12-byte nonce, AES-256-GCM authentication
and encryption, with the complete header authenticated. There are no adjustable
untrusted KDF parameters and no compressed data. The encrypted plaintext is a
versioned JSON manifest containing application version, creation time and a list
of regular files with their relative paths and bytes. It cannot represent links,
devices or filesystem ownership. Restore rejects unknown fields, duplicate JSON
fields/file paths, traversal, unexpected paths, and unsupported format versions.

Limits are fixed in this release: 64 MiB plaintext manifest (encrypted file adds
63 bytes), 48 MiB total logical file contents, 16 MiB per logical file, 10,000 file
entries, 1 MiB per certificate/HTTPS chain, 64 KiB per private key, and a maximum
64 intermediate ancestors. Collection/schema limits also bound users, profiles,
index records and SCEP challenges at 10,000 each. This targets small internal PKIs;
larger instances need an offline stopped-volume backup. JSON/base64, encryption
and validation use bounded in-memory buffers; allow approximately **512 MiB free
memory** at the limit. Uploads may spill encrypted bytes to the system temporary
directory; decrypted files are staged only inside the private data directory.

Allow free data-volume space for the restored contents plus filesystem overhead
(at least **64 MiB beyond the current data** at these limits), and up to 65 MiB
temporary upload space. Existing data is retained by rename for rollback, not
copied. Storage errors during staging leave the live instance untouched.
Use a local filesystem supporting atomic rename and file/directory fsync.

Validation checks users/roles/password-hash bounds, profiles, index/file coverage,
certificate serials/validity/CA flags/issuer signatures and chains, unencrypted
private-key matches, HTTPS identity, trash records and available issuers, and
SCEP journal/projection consistency. Encrypted CA keys are checked for a supported
envelope and preserved byte-for-byte: proving their public/private match or
authenticating their inner ciphertext requires their separate CA passphrase and
is deferred to normal unlock. A historical trash certificate whose issuer is no
longer stored cannot have that missing issuer's signature verified.

Format 1 is supported only by builds containing this feature. The manifest's
application version is informational; compatibility is determined by format 1
and the strictly validated logical schemas. Older builds (including 1.5.0) cannot
import `.nab` files. Future formats or unknown schema fields are rejected, never
automatically migrated or merged. Retain the matching application release with
long-term backups. This format does not import arbitrary tar/volume exports.

## Activation and recovery

The data mount itself is never renamed. After decryption and validation, staging
applies token/session invalidation and optional HTTPS regeneration, then fsyncs
files and directories. A private `.restore/journal.json` records original
component presence before any live component is moved. Each logical top-level
component is renamed into `.restore/old`, then replaced from `.restore/new`, with
directory fsyncs. A durable commit marker is written only after all swaps finish.

An activation error rolls back. An unresolved storage/fsync error blocks serving
and shuts down so startup can recover. Before `OpenStore`, authentication, TLS or
SCEP initialization, startup rolls an uncommitted transaction back or finishes
cleanup of a committed one. Recovery is repeatable after interrupted recovery.
If recovery itself fails, startup refuses to serve: repair storage and restart.
Do not manually delete `.restore` to bypass a recovery error.

Staged/rollback directories use mode 0700 and files 0600, owned by the running
process. Abandoned decrypted staging is removed on the next startup. Cleanup is
unlink/removal, not guaranteed physical erasure on SSDs, copy-on-write filesystems
or snapshots; use encrypted storage if that is needed.

Backup and restore require administrator authorization in middleware and handlers,
an unpredictable session-bound CSRF token, and an Origin matching the browser's
Host. Auth-disabled trusted-local mode uses a process-secret-derived token too.
Reverse proxies must preserve the public Host; HTTPS termination is supported
without trusting arbitrary forwarded headers. Downloads/forms are `no-store`.
These protections apply to backup/restore; they do not add CSRF protection to
unrelated existing forms.

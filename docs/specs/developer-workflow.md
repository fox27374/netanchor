# Repeatable verification, development deployment and release

Approval: user requested "add the workflow" after proposal of make verify,
make deploy-dev, make release VERSION=..., and a dedicated development Compose file.

## Acceptance criteria
- `make verify`: go build ./..., go vet ./..., go test ./... with useful exit codes.
- `make deploy-dev`: use podhost to copy/build current source ONLY on ataltpr06;
  declarative development Compose settings; recreate app preserving named data
  volume; bounded readiness/health check with nonzero exit on failure and useful
  diagnostics. No local containers, implicit commits or release publication.
- Current dev deployment defaults: container netanchor, external named volume
  netanchor-data at /data; host8443->8443 HTTPS, host8085->8080 SCEP;
  NETANCHOR_ADDR=0.0.0.0:8443, NETANCHOR_DATA=/data,
  NETANCHOR_SCEP_ADDR=0.0.0.0:8080; TLS hosts ataltpr06.lnxnet.org,ataltpr06,
  10.140.60.248,localhost,127.0.0.1. Preserve security/health/restart settings in
  existing compose.yaml. Keep published-image production compose separate.
- Account for existing dev container created with podman run rather than compose.
  Inspect ownership/mounts before replacing that known container; refuse if mounted
  data differs. Do not delete volumes or blindly remove other containers. Verify
  remote compose provider availability and give actionable errors if missing.
- Prefer repository deployment scripts+config, not copies of long commands in
  prompts. podhost currently exists at ~/.local/bin/podhost; read its contract,
  document prerequisite and PATH resolution without embedding credentials.
- `make release VERSION=1.6.0`: stable plain X.Y.Z SemVer only (no prerelease or
  build metadata), clean tracked/untracked
  working tree required, inspect branch/tracking remote, require release branch
  main and up-to-date remote before changes. Reject existing local OR remote tag.
  Run verification before commit. Update intentional version refs in README.md,
  compose.yaml, k8s/deployment.yaml and k8s/kustomization.yaml consistent with
  current convention. No blind replacements in history/research/spec docs.
  Stage only those paths; create concise release version commit, annotated vVERSION
  tag; atomic push current main and that tag. Never force, amend, delete tags,
  silently stash/reset, modify Git configuration or add arbitrary files.
  Failures preserve inspectable local work with recovery instructions; do not
  promise transactional rollback of local commit/tag steps or rerun blindly.
- Explicit user invocation of make release authorizes its documented git actions;
  creating these scripts does NOT authorize an actual release during this task.
- Keep commands simple and maintainable, no gratuitous dependencies. Document
  dependencies, remote host/port overrides, secrets supplied externally, workflow
  order (commit feature before release), difference between dev image and published
  release, restart effects on locked SCEP, and what to do on failure.

## Existing work to preserve
Base main ca92134; uncommitted backup/restore and theme feature work present.
Modified README.md, auth.go, compose.yaml, main.go, scep_protocol.go, server.go,
store.go, templates/layout.html, templates/setup.html, templates/users.html.
Untracked BACKUP.md, backup*.go, restore.go, templates/backup.html and docs/specs/.
Inspect git status/diff before coding; integrate README/compose edits without
overwriting unrelated work. Do not commit any of it.

## Verification and authority
Coder focused script checks; checker independently owns final verify + one combined
spec/correctness/standards review. Test release in disposable local Git repos and
bare remotes with fake build tools (success, invalid/existing tag, dirty/diverged
tree, push failure). Never test releases against origin. Test deploy command
assembly and failure/health paths via mocks; non-mutating remote prerequisite and
compose validation allowed via podhost, but NO actual deployment/container changes.
No commits/push/tags/PRs/deploy in netanchor authorized. Tests in disposable repos
may create local commits/tags to validate the workflow. Logs under /tmp/opencode.
No need to rerun race suite for build/script-only changes.
Maximum two repair rounds between coder/checker. Dispatcher returns concise
commands/status/limitations, not full logs or diffs. No parent duplicate tests.

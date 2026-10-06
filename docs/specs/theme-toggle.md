# Light/dark theme toggle

Approval: user requested implementation as a live test of the cheaper-agent workflow.

## Acceptance criteria
- Preserve current dark appearance as default; add a readable light appearance.
- Small accessible sun/moon toggle next to the logged-in user. It changes theme
  immediately, has a descriptive changing accessible label, visible keyboard focus,
  and a mobile-friendly touch target. Honor existing auth-disabled UI behavior.
- Remember choice in browser localStorage across navigation/reload; apply before
  paint to avoid a theme flash. Storage failures must not break rendering/toggling.
- Shared layout styling must cover panels, forms, tables, status badges, code/PEM,
  notifications, sidebar and inline color usages sufficiently for readable contrast.
- No server/account preference required. No automatic OS-theme selection: default dark.
- No external JS/CSS/icon dependency; keep existing template/CSS conventions.

## Relevant files
templates/layout.html and other templates only where hard-coded colors need attention.
Read applicable repository/global instructions and existing template rendering tests.

## Existing local changes to preserve
Uncommitted backup/restore work: README.md, auth.go, compose.yaml, main.go,
scep_protocol.go, server.go, store.go, templates/layout.html, templates/setup.html,
templates/users.html; untracked BACKUP.md, backup.go, backup_http.go,
backup_regression_test.go, backup_test.go, backup_validate.go, restore.go,
templates/backup.html. Do not rewrite, remove, or commit these changes.

## Verification
Coder: focused rendering checks; meaningful tests only where useful.
Checker: one combined spec/correctness/standards review, go build ./..., go vet ./...,
go test ./... (existing tests). Theme-only change does not justify race rerun.
Prefer browser checks at desktop/mobile in both themes, keyboard toggle and reload
persistence. Use isolated temporary data, never modify deployed accounts to test.
Report any unavailable browser tooling rather than claim visual verification.
Log noisy outputs outside repo under /tmp/opencode; return command/status/log path.

## Authorization
Implement and verify locally. No commit, push, tag, PR or deployment is authorized
by this spec. Containers, if needed, run only through podhost on ataltpr06.

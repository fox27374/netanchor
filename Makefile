.PHONY: verify deploy-dev release

# Use PATH when available, otherwise the installed per-user helper. Override with
# make deploy-dev PODHOST=/path/to/podhost when using another installation.
PODHOST ?= $(shell command -v podhost 2>/dev/null || printf '%s' "$(HOME)/.local/bin/podhost")

verify:
	go build ./...
	go vet ./...
	go test ./...

deploy-dev:
	@"$(PODHOST)" bash scripts/deploy-dev-remote.sh

release:
	@test -n "$(VERSION)" || { echo 'usage: make release VERSION=1.6.0' >&2; exit 2; }
	@bash scripts/release.sh '$(VERSION)'

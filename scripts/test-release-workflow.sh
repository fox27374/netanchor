#!/bin/sh
set -eu
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/netanchor-release-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
real_git=$(command -v git)
mkdir -p "$tmp/bin" "$tmp/repo"
cat >"$tmp/bin/git" <<'EOF'
#!/bin/sh
if [ "${TEST_GIT_FAIL_LS_REMOTE:-}" = 1 ] && [ "$1" = ls-remote ]; then exit 128; fi
if [ "${TEST_GIT_FAIL_PUSH:-}" = 1 ] && [ "$1" = push ]; then exit 1; fi
exec "$REAL_GIT" "$@"
EOF
cat >"$tmp/bin/make" <<'EOF'
#!/bin/sh
[ "${TEST_VERIFY_FAIL:-}" != 1 ] || exit 1
exit 0
EOF
chmod +x "$tmp/bin/git" "$tmp/bin/make"
export REAL_GIT="$real_git" PATH="$tmp/bin:$PATH"
git init --bare "$tmp/remote.git" >/dev/null
cd "$tmp/repo"
git init -b main >/dev/null
git config user.name Test; git config user.email test@example.invalid
git remote add origin "$tmp/remote.git"
git config branch.main.remote origin; git config branch.main.merge refs/heads/main
cp "$source_dir/scripts/release.sh" .
mkdir -p k8s
printf 'image: ghcr.io/fox27374/netanchor:1.0.0\n' > compose.yaml
printf 'image: ghcr.io/fox27374/netanchor:1.0.0\n' > k8s/deployment.yaml
printf 'newTag: 1.0.0\n' > k8s/kustomization.yaml
printf 'podman pull ghcr.io/fox27374/netanchor:1.0.0\ngit tag v1.0.0\ngit push origin v1.0.0\npublishes `:1.0.0`, `:1.0`, `:1`, and `:latest`\nHistorical since version 1.5.0.\n' > README.md
git add .; git commit -m initial >/dev/null; git push -u origin main >/dev/null
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_fail() { code=$1; shift; if output=$("$@" 2>&1); then fail "unexpected success: $*"; else status=$?; fi; [ "$status" -eq "$code" ] || fail "expected $code, got $status: $output"; }

for bad in '1.2.3-rc.1' '1.2.3+meta' '1.2.3-..'; do expect_fail 2 bash ./release.sh "$bad"; done
expect_fail 1 env TEST_GIT_FAIL_LS_REMOTE=1 bash ./release.sh 1.1.0
expect_fail 1 env TEST_VERIFY_FAIL=1 bash ./release.sh 1.1.0
bash ./release.sh 1.1.0 >/dev/null
grep -q 'image: ghcr.io/fox27374/netanchor:1.1.0' compose.yaml
grep -q 'git tag v1.1.0' README.md
grep -q 'publishes `:1.1.0`, `:1.1`, `:1`, and `:latest`' README.md
grep -q 'Historical since version 1.5.0.' README.md
grep -q 'version 1.5.0' "$source_dir/README.md" 2>/dev/null && : || :
bash ./release.sh 1.2.0 >/dev/null
grep -q 'image: ghcr.io/fox27374/netanchor:1.2.0' compose.yaml
git checkout -b ahead >/dev/null; git commit --allow-empty -m ahead >/dev/null
expect_fail 1 bash ./release.sh 1.3.0
git checkout main >/dev/null
git tag v1.3.0
expect_fail 1 bash ./release.sh 1.3.0
git tag -d v1.3.0 >/dev/null
git tag v1.3.0; git push origin v1.3.0 >/dev/null
git tag -d v1.3.0 >/dev/null
expect_fail 1 bash ./release.sh 1.3.0
printf dirty >junk; expect_fail 1 bash ./release.sh 1.3.0; rm junk
expect_fail 1 env TEST_GIT_FAIL_PUSH=1 bash ./release.sh 1.4.0
git clone -b main "$tmp/remote.git" "$tmp/diverger" >/dev/null 2>&1
git -C "$tmp/diverger" config user.name Test
git -C "$tmp/diverger" config user.email test@example.invalid
git -C "$tmp/diverger" commit --allow-empty -m remote-ahead >/dev/null
git -C "$tmp/diverger" push origin main >/dev/null
expect_fail 1 bash ./release.sh 1.5.0
echo 'release workflow checks passed'

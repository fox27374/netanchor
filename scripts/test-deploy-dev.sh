#!/bin/sh
set -eu
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/netanchor-deploy-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/bin"
cat >"$tmp/bin/podman" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$CALL_LOG"
if [ "$1" = compose ]; then
  case " $* " in *" config "*) [ "${CONFIG_FAIL:-}" != 1 ] || exit 1;; *" build "*) [ "${BUILD_FAIL:-}" != 1 ] || exit 1;; esac
  exit 0
fi
if [ "$1" = container ] && [ "$2" = exists ]; then [ "${CONTAINER_EXISTS:-1}" = 1 ]; exit $?; fi
if [ "$1" = volume ] && [ "$2" = inspect ]; then
  [ "${VOLUME_FAIL:-}" != 1 ] || exit 1
  case "$*" in *--format*) printf '%s\n' "${VOLUME_NAME:-netanchor-data}";; esac
  exit 0
fi
if [ "$1" = inspect ]; then
  case "$*" in *Mounts*) printf '%s\n' "${MOUNT_DETAILS:-volume netanchor-data /mock/data}";; *) printf '%s\n' "${HEALTH_STATE:-healthy}";; esac
  exit 0
fi
if [ "$1" = stop ] || [ "$1" = rm ]; then echo "$1" >>"$CALL_LOG"; exit 0; fi
if [ "$1" = logs ]; then echo mocked-logs; exit 0; fi
exit 0
EOF
printf '#!/bin/sh\nexit 0\n' >"$tmp/bin/sleep"
chmod +x "$tmp/bin/podman" "$tmp/bin/sleep"
export PATH="$tmp/bin:$PATH" CALL_LOG="$tmp/calls"
script=$source_dir/scripts/deploy-dev-remote.sh
fail() { echo "FAIL: $*" >&2; exit 1; }
run_fail() { if "$@" >"$tmp/out" 2>&1; then fail "unexpected success: $*"; fi; }

export BUILD_FAIL=1; run_fail sh "$script"; unset BUILD_FAIL
if grep -q '^stop$\|^rm$' "$CALL_LOG"; then fail 'build failure stopped or removed the existing app'; fi
: >"$CALL_LOG"
export MOUNT_DETAILS='bind /other /data'; run_fail sh "$script"; unset MOUNT_DETAILS
if grep -q '^stop$\|^rm$' "$CALL_LOG"; then fail 'mount mismatch stopped or removed the app'; fi
: >"$CALL_LOG"
export HEALTH_STATE=healthy; sh "$script" >"$tmp/out" 2>&1 || fail 'valid legacy container was not adopted'
grep -q '^stop$' "$CALL_LOG" || fail 'adoption did not stop known container'
grep -q '^rm$' "$CALL_LOG" || fail 'adoption did not remove known container'
: >"$CALL_LOG"
export HEALTH_STATE=starting; run_fail sh "$script"
grep -q 'mocked-logs' "$tmp/out" || fail 'health failure did not show diagnostics'
echo 'deployment preflight/build/adoption/health checks passed'

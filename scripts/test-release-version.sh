#!/bin/sh
set -eu

script=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/release.sh
expect_invalid() {
  output=$(bash "$script" "$1" 2>&1) && { echo "unexpectedly accepted invalid SemVer: $1" >&2; exit 1; }
  status=$?
  [ "$status" -eq 2 ] || { echo "invalid SemVer $1 returned $status, expected 2: $output" >&2; exit 1; }
}
expect_valid_syntax() {
  output=$(bash "$script" "$1" 2>&1) && { echo "unexpectedly completed release in test checkout: $1" >&2; exit 1; }
  status=$?
  [ "$status" -eq 1 ] || { echo "valid SemVer $1 failed validation (exit $status): $output" >&2; exit 1; }
  case "$output" in *"completely clean working tree"*) ;; *) echo "valid SemVer $1 failed before dirty-tree check: $output" >&2; exit 1;; esac
}

expect_invalid '1.2.3-..'
expect_invalid '1.2.3-alpha..1'
expect_invalid '1.2.3-01'
expect_invalid '1.2.3+build..7'
expect_invalid '1.2.3-alpha.1'
expect_invalid '1.2.3+build.5'
expect_valid_syntax '1.2.3'
echo 'release SemVer checks passed'

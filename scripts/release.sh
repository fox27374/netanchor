#!/bin/sh
set -eu

version=${1:-}
numeric='(0|[1-9][0-9]*)'
semver="^${numeric}\.${numeric}\.${numeric}$"
if ! printf '%s\n' "$version" | grep -Eq "$semver"; then
  echo "Invalid plain SemVer version: '$version' (expected e.g. 1.6.0)" >&2
  exit 2
fi
tag=v$version
fail() { echo "$*; no cleanup/reset was attempted. Inspect git status and recover manually." >&2; exit 1; }

[ -z "$(git status --porcelain)" ] || fail 'Release requires a completely clean working tree'
branch=$(git branch --show-current)
[ "$branch" = main ] || fail "Release requires branch main (currently '$branch')"
remote=$(git config --get branch.main.remote || true)
merge=$(git config --get branch.main.merge || true)
[ -n "$remote" ] && [ "$merge" = refs/heads/main ] || fail 'main must track a remote main branch'
git remote get-url "$remote" >/dev/null 2>&1 || fail "Tracking remote '$remote' is unavailable"
git fetch "$remote" || fail 'Could not fetch tracking remote; verify connectivity and retry after inspection'
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$remote/main")" ] || fail "Local main is not up to date with $remote/main"
if git show-ref --verify --quiet "refs/tags/$tag"; then fail "Local tag $tag already exists"; fi
tag_result=$(git ls-remote --exit-code --tags "$remote" "refs/tags/$tag" 2>&1) || {
  status=$?
  [ "$status" -eq 2 ] || fail "Could not check remote tag $tag (git ls-remote exit $status): $tag_result"
}
[ -z "$tag_result" ] || fail "Remote tag $tag already exists"

make verify || fail 'Verification failed; no release changes were made'
current=$(sed -n 's/^[[:space:]]*image: ghcr\.io\/fox27374\/netanchor:\([0-9][0-9.]*\)$/\1/p' compose.yaml)
[ -n "$current" ] || fail 'Could not derive current release version from compose.yaml'
for path in compose.yaml k8s/deployment.yaml k8s/kustomization.yaml; do
  VERSION="$version" CURRENT="$current" perl -0pi -e 's{(?<![0-9.])\Q$ENV{CURRENT}\E(?![0-9.])}{$ENV{VERSION}}g' "$path"
done
old_major=${current%%.*}
old_minor=${current#*.}; old_minor=${old_minor%%.*}
new_major=${version%%.*}
new_minor=${version#*.}; new_minor=${new_minor%%.*}
VERSION="$version" CURRENT="$current" perl -0pi -e '
  s{(ghcr\.io/fox27374/netanchor:)\Q$ENV{CURRENT}\E}{$1$ENV{VERSION}}g;
  s{(git tag v)\Q$ENV{CURRENT}\E}{$1$ENV{VERSION}}g;
  s{(git push origin v)\Q$ENV{CURRENT}\E}{$1$ENV{VERSION}}g;
  s{(netanchor:)\Q$ENV{CURRENT}\E}{$1$ENV{VERSION}}g;
  s{(VERSION=)\Q$ENV{CURRENT}\E}{$1$ENV{VERSION}}g;
' README.md
CURRENT="$current" VERSION="$version" NEW_MAJOR="$new_major" NEW_MINOR="$new_minor" perl -0pi -e 's{`:\Q$ENV{CURRENT}\E`, `:[^`]+`, `:[^`]+`, and `:latest`}{`:$ENV{VERSION}`, `:$ENV{NEW_MAJOR}.$ENV{NEW_MINOR}`, `:$ENV{NEW_MAJOR}`, and `:latest`}' README.md
git add -- README.md compose.yaml k8s/deployment.yaml k8s/kustomization.yaml
git commit -m "Release $version" || fail 'Release commit failed; inspect staged/working changes'
git tag -a "$tag" -m "NetAnchor $version" || fail 'Tag creation failed; inspect commit and tag state'
git push --atomic "$remote" HEAD:main "refs/tags/$tag" || fail 'Atomic push failed; inspect local commit/tag and remote state before retrying'
echo "Released $version to $remote"

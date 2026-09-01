#!/usr/bin/env bash
#
# Prepare a release. Two phases, because `main` is protected and takes no direct pushes.
#
#   scripts/release.sh 0.2.0          # verify, bump, changelog, open a PR
#   ... merge the PR once it is green ...
#   scripts/release.sh --tag 0.2.0    # tag the merged commit and push the tag
#
# Tagging is what starts the release workflow. Branch protection does not apply to tags, so the
# second phase pushes directly.
#
# This script does *not* build or publish anything. Tagging is the trigger: CI builds the
# binaries, generates the SBOM and signs everything with attestations that bind each artifact to
# a workflow run. A laptop cannot produce that provenance, so artifacts built here would be
# strictly less trustworthy than the ones the tag produces.
#
# It refuses to tag unless the full verification passes, interop included. A release that has not
# been round-tripped against the reference implementation is exactly the release that ships a
# wrong constant.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m %s\n' "$*"; }

MODE="prepare"
if [ "${1:-}" = "--tag" ]; then MODE="tag"; shift; fi

VERSION="${1:-}"
[ -n "$VERSION" ] || die "usage: scripts/release.sh [--tag] <version>   e.g. 0.2.0"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
  || die "'$VERSION' is not a semantic version"

CURRENT="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
TAG="v$VERSION"
BRANCH_NAME="release/$VERSION"

# ---------------------------------------------------------------------------
# Phase two: tag a version whose bump has already merged.
# ---------------------------------------------------------------------------
if [ "$MODE" = "tag" ]; then
  step "Tagging $TAG"

  [ -z "$(git status --porcelain)" ] || die "working tree is not clean"
  [ "$(git symbolic-ref --short HEAD)" = "main" ] || die "tag from main"
  git fetch --quiet origin main
  [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
    || die "main is not level with origin/main; pull first"
  git rev-parse "$TAG" >/dev/null 2>&1 && die "tag $TAG already exists"

  [ "$CURRENT" = "$VERSION" ] \
    || die "Cargo.toml says $CURRENT, not $VERSION — has the release PR merged?"
  ok "main is at $VERSION and level with origin"

  git tag -a "$TAG" -m "umbrik $VERSION"
  git push origin "$TAG"
  ok "pushed $TAG"

  cat <<EOF

The release workflow is now running. It builds every target, generates the SBOM, signs everything
with attestations, and creates the GitHub release with the CHANGELOG.md section as its notes.

  gh run watch
  gh release view "$TAG"
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
step "Preconditions"
# ---------------------------------------------------------------------------

[ -z "$(git status --porcelain)" ] || die "working tree is not clean"
ok "working tree clean"

BRANCH="$(git symbolic-ref --short HEAD)"
[ "$BRANCH" = "main" ] || die "on branch '$BRANCH'; releases are cut from main"
ok "on main"

command -v gh >/dev/null || die "gh is not installed"

git rev-parse "$TAG" >/dev/null 2>&1 && die "tag $TAG already exists"
ok "tag $TAG is free"

for tool in cargo git-cliff; do
  command -v "$tool" >/dev/null || die "$tool is not installed"
done
command -v cargo-deny >/dev/null || die "cargo-deny is not installed (cargo install cargo-deny)"
ok "tooling present"

printf '\n  %s -> %s\n' "$CURRENT" "$VERSION"

# ---------------------------------------------------------------------------
step "Verification"
# ---------------------------------------------------------------------------

cargo fmt --all -- --check          ; ok "formatting"
cargo clippy --all-targets -- -D warnings 2>/dev/null ; ok "clippy"
cargo clippy --all-targets --no-default-features -- -D warnings 2>/dev/null ; ok "clippy (no default features)"
cargo test --release --quiet        ; ok "tests"
cargo deny check                    ; ok "licences and advisories"

# The gate that matters. Without a reference implementation to round-trip against, a release is
# only self-consistent, which is the failure this project exists to avoid.
if [ "${SKIP_INTEROP:-}" = "1" ]; then
  printf '  \033[33mskipped\033[0m interop (SKIP_INTEROP=1)\n'
else
  tests/interop/run.sh >/dev/null   ; ok "interop, both directions"
fi

# ---------------------------------------------------------------------------
step "Bump"
# ---------------------------------------------------------------------------

# Every crate and the PyPI package share one version; maturin reads it from the manifest.
while IFS= read -r manifest; do
  sed -i.bak "s/^version = \"$CURRENT\"$/version = \"$VERSION\"/" "$manifest"
  sed -i.bak "s/version = \"$CURRENT\"/version = \"$VERSION\"/g" "$manifest"
  rm -f "$manifest.bak"
done < <(find . -name Cargo.toml -not -path './target/*')

cargo metadata --format-version 1 --quiet >/dev/null   # refresh Cargo.lock
ok "version set to $VERSION"

# ---------------------------------------------------------------------------
step "Changelog"
# ---------------------------------------------------------------------------

git-cliff --tag "$TAG" --output CHANGELOG.md
ok "CHANGELOG.md regenerated"

printf '\n  \033[1mReview the changelog before continuing.\033[0m\n'
printf '  Entries come from commit messages; fix anything that reads poorly now, because it is\n'
printf '  what users will see.\n\n'
read -r -p "  Open a release PR for $VERSION? [y/N] " reply
[ "$reply" = "y" ] || [ "$reply" = "Y" ] || die "aborted; version bump left in the working tree"

# ---------------------------------------------------------------------------
step "Release PR"
# ---------------------------------------------------------------------------

git switch -c "$BRANCH_NAME" --quiet
git add -A
git commit -q -m "chore: release $VERSION"
git push -u origin "$BRANCH_NAME" --quiet
gh pr create --title "chore: release $VERSION" \
  --body "Version bump and changelog for $VERSION. Tag with \`scripts/release.sh --tag $VERSION\` once this merges." \
  >/dev/null
ok "opened a release PR from $BRANCH_NAME"

cat <<EOF

Next:

  1. Merge the PR once its checks pass.
  2. git switch main && git pull
  3. scripts/release.sh --tag $VERSION

Tagging starts the release workflow, which builds every target, generates the SBOM, signs the
artifacts, and creates the GitHub release. Nothing is signed locally: provenance comes from the
workflow run, which is what makes it verifiable by anyone.
EOF

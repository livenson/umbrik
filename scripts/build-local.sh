#!/usr/bin/env bash
#
# Build the CLI, the Rust library and a Python wheel for *this* machine, into dist/.
#
# For trying things out. These artifacts are unsigned and carry no provenance: an attestation
# binds an artifact to a workflow run, which a laptop cannot produce. Release artifacts come from
# CI and are attached to the GitHub release.
#
# Only the host platform is built. Cross-compiling the seven release targets needs the runners.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DIST="$REPO_ROOT/dist"
rm -rf "$DIST"; mkdir -p "$DIST"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "CLI and library"
cargo build --release
TARGET="$(rustc -vV | sed -n 's/^host: //p')"
cp target/release/umbrik "$DIST/umbrik-$TARGET"
cargo package -p umbrik-core --allow-dirty --no-verify >/dev/null 2>&1 || true
find target/package -maxdepth 1 -name 'umbrik-core-*.crate' -exec cp {} "$DIST/" \; 2>/dev/null || true

step "Python wheel"
if command -v maturin >/dev/null 2>&1; then
  # PyO3 needs an interpreter at or above the abi3 floor to build against.
  if [ -z "${PYO3_PYTHON:-}" ]; then
    for candidate in python3.14 python3.13 python3.12 python3.11 python3.10; do
      if command -v "$candidate" >/dev/null 2>&1; then
        export PYO3_PYTHON="$(command -v "$candidate")"
        break
      fi
    done
  fi
  if [ -n "${PYO3_PYTHON:-}" ]; then
    echo "  building against $PYO3_PYTHON"
    (cd bindings/python && maturin build --release --out "$DIST")
  else
    echo "  skipped: no Python 3.10+ interpreter found"
  fi
else
  echo "  skipped: maturin is not installed (pip install maturin)"
fi

step "Checksums"
(cd "$DIST" && sha256sum ./* > SHA256SUMS 2>/dev/null || shasum -a 256 ./* > SHA256SUMS)

step "Built"
ls -1 "$DIST"
cat <<EOF

These are local, unsigned builds for one platform. Release artifacts are built by CI, signed with
attestations, and attached to the GitHub release:

  scripts/release.sh <version> && git push origin main --follow-tags
EOF

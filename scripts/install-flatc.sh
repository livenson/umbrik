#!/usr/bin/env bash
#
# Install the flatc matching the pinned `flatbuffers` crate.
#
# The two versions must agree. flatc generates the code; the crate provides the runtime it calls
# into, and their contract changes between releases. A mismatch does not fail politely — it
# produces code that will not compile, with errors pointing into a generated file nobody wrote.
# Distribution packages are routinely a year or more behind, so installing "flatbuffers-compiler"
# is not enough.
#
# The version is read from Cargo.toml so there is one source of truth.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSION="$(sed -n 's/^flatbuffers = "=\(.*\)"$/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)"
[ -n "$VERSION" ] || { echo "could not read the flatbuffers version from Cargo.toml" >&2; exit 1; }

if command -v flatc >/dev/null 2>&1; then
  have="$(flatc --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [ "$have" = "$VERSION" ]; then
    echo "flatc $VERSION already installed"
    exit 0
  fi
  echo "flatc $have is installed but $VERSION is required"
fi

BIN_DIR="${FLATC_BIN_DIR:-/usr/local/bin}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Install without assuming a writable prefix or that sudo exists — Windows git-bash has no
# sudo, and a custom FLATC_BIN_DIR may not exist yet.
install_flatc() {
  src="$1"
  mkdir -p "$BIN_DIR" 2>/dev/null || sudo mkdir -p "$BIN_DIR"
  dest="$BIN_DIR/$(basename "$src")"
  if install -m 0755 "$src" "$dest" 2>/dev/null; then
    :
  elif command -v sudo >/dev/null 2>&1 && sudo install -m 0755 "$src" "$dest" 2>/dev/null; then
    :
  else
    cp "$src" "$dest"
    chmod 0755 "$dest" 2>/dev/null || true
  fi
  echo "installed $dest"
  "$dest" --version
}

# The archive holds flatc.exe on Windows.
extracted_flatc() {
  if [ -f "$TMP/flatc.exe" ]; then echo "$TMP/flatc.exe"; else echo "$TMP/flatc"; fi
}

base="https://github.com/google/flatbuffers/releases/download/v${VERSION}"
asset=""
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)          asset="Linux.flatc.binary.g++-13.zip" ;;
  Darwin-arm64)          asset="Mac.flatc.binary.zip" ;;
  Darwin-x86_64)         asset="MacIntel.flatc.binary.zip" ;;
  MINGW*|MSYS*|CYGWIN*)  asset="Windows.flatc.binary.zip" ;;
esac

if [ -n "$asset" ]; then
  echo "downloading $asset"
  curl -fsSL "$base/$asset" -o "$TMP/flatc.zip"
  unzip -q "$TMP/flatc.zip" -d "$TMP"
  install_flatc "$(extracted_flatc)"
else
  # No official binary for this platform — Linux arm64 in particular. Building takes a few
  # minutes but is the only way to get the exact version.
  echo "no prebuilt flatc for $(uname -s)-$(uname -m); building v${VERSION} from source"
  command -v cmake >/dev/null || { echo "cmake is required to build flatc" >&2; exit 1; }
  git clone --depth 1 --branch "v${VERSION}" \
    https://github.com/google/flatbuffers.git "$TMP/flatbuffers"
  cmake -S "$TMP/flatbuffers" -B "$TMP/build" \
    -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=OFF
  cmake --build "$TMP/build" --target flatc -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
  install_flatc "$TMP/build/flatc"
fi

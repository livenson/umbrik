#!/usr/bin/env bash
#
# Round-trip umbrik against the CDOC2 reference CLI, both directions, every implemented scheme.
#
# This is the gate that catches a wrong cryptographic constant. A container umbrik can read back
# proves nothing on its own; a container the reference implementation can read proves the wire
# format is right.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${UMBRIK_INTEROP_IMAGE:-umbrik-interop:cdoc2-ref}"
# The reference build needs x86_64 for its flatc binary; see README.md.
PLATFORM="${UMBRIK_INTEROP_PLATFORM:-linux/amd64}"

SECRET_B64="SGVsbG8gdW1icmlrIGludGVyb3AgdGVzdCBrZXkhISE="
SECRET_LABEL="interop-secret"
# cdoc2-cli enforces an encrypt-side password policy (8-64 characters, at least one upper and
# one lower case letter). That is a CLI usability rule, not a CDOC2 requirement — umbrik does
# not impose it, and cdoc2-cli happily *decrypts* containers whose password would fail it. The
# fixture satisfies the policy so that both tools can act as the encrypting side.
PASSWORD="Interop-pässword-with-nön-ascii"
PASSWORD_LABEL="interop-password"

pass=0
fail=0

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "Building reference CLI image ($IMAGE) — this takes a few minutes"
  docker build --platform "$PLATFORM" -t "$IMAGE" "$REPO_ROOT/tests/interop"
fi

log "Building umbrik"
cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
UMBRIK="$REPO_ROOT/target/release/umbrik"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# cdoc2-cli runs as root in the container and writes files back into $WORK.
cdoc2() {
  docker run --rm --platform "$PLATFORM" -v "$WORK:/work" -w /work "$IMAGE" "$@"
}

# The reference implementation's test keys, so both tools can act as either side.
KEYS="$REPO_ROOT/tests/vectors/keys"
mkdir -p "$WORK/keys"
cp "$KEYS"/cdoc2client-certificate.pem "$KEYS"/cdoc2client_priv.key \
   "$KEYS"/rsa_priv.pem "$WORK/keys/"
# cdoc2-cli encrypts to a public key; derive the RSA one to build an SC02 container umbrik
# should refuse.
openssl rsa -in "$KEYS/rsa_priv.pem" -pubout -out "$WORK/keys/rsa_pub.pem" 2>/dev/null

mkdir -p "$WORK/src"
printf 'Tere, maailm!\nSecond line.\n' > "$WORK/src/hello.txt"
printf '# notes\n\nÕäöü ja ☠\n'        > "$WORK/src/notes.md"
head -c 200000 /dev/urandom            > "$WORK/src/random.bin"

# Compare extracted output against the originals.
compare() {
  local dir="$1" label="$2" f base
  for f in "$WORK"/src/*; do
    base="$(basename "$f")"
    if [ ! -f "$dir/$base" ]; then
      bad "$label: $base missing from output"
      return
    fi
    if ! cmp -s "$f" "$dir/$base"; then
      bad "$label: $base differs after round trip"
      return
    fi
  done
  ok "$label"
}

# ---------------------------------------------------------------------------
# umbrik encrypts -> cdoc2-cli decrypts
# ---------------------------------------------------------------------------

log "umbrik -> cdoc2-cli"

"$UMBRIK" encrypt -f "$WORK/u_sc05.cdoc2" \
  --secret "$SECRET_LABEL:base64,$SECRET_B64" \
  "$WORK"/src/* >/dev/null
mkdir -p "$WORK/out_u_sc05"
if cdoc2 decrypt -f /work/u_sc05.cdoc2 \
      --secret "$SECRET_LABEL:base64,$SECRET_B64" \
      -o /work/out_u_sc05 >/dev/null 2>&1; then
  compare "$WORK/out_u_sc05" "SC05: umbrik container read by cdoc2-cli"
else
  bad "SC05: cdoc2-cli could not decrypt umbrik's container"
fi

"$UMBRIK" encrypt -f "$WORK/u_sc06.cdoc2" \
  --password "$PASSWORD_LABEL:$PASSWORD" \
  "$WORK"/src/* >/dev/null
mkdir -p "$WORK/out_u_sc06"
if cdoc2 decrypt -f /work/u_sc06.cdoc2 \
      --password "$PASSWORD_LABEL:$PASSWORD" \
      -o /work/out_u_sc06 >/dev/null 2>&1; then
  compare "$WORK/out_u_sc06" "SC06: umbrik container read by cdoc2-cli"
else
  bad "SC06: cdoc2-cli could not decrypt umbrik's container"
fi

# ---------------------------------------------------------------------------
# cdoc2-cli encrypts -> umbrik decrypts
# ---------------------------------------------------------------------------

log "cdoc2-cli -> umbrik"

if cdoc2 create -f /work/j_sc05.cdoc2 \
      --secret "$SECRET_LABEL:base64,$SECRET_B64" \
      /work/src/hello.txt /work/src/notes.md /work/src/random.bin >/dev/null 2>&1; then
  mkdir -p "$WORK/out_j_sc05"
  if "$UMBRIK" decrypt -f "$WORK/j_sc05.cdoc2" \
        --secret "$SECRET_LABEL:base64,$SECRET_B64" \
        -o "$WORK/out_j_sc05" >/dev/null; then
    compare "$WORK/out_j_sc05" "SC05: cdoc2-cli container read by umbrik"
  else
    bad "SC05: umbrik could not decrypt cdoc2-cli's container"
  fi
else
  bad "SC05: cdoc2-cli failed to create a container"
fi

if cdoc2 create -f /work/j_sc06.cdoc2 \
      --password "$PASSWORD_LABEL:$PASSWORD" \
      /work/src/hello.txt /work/src/notes.md /work/src/random.bin >/dev/null 2>&1; then
  mkdir -p "$WORK/out_j_sc06"
  if "$UMBRIK" decrypt -f "$WORK/j_sc06.cdoc2" \
        --password "$PASSWORD_LABEL:$PASSWORD" \
        -o "$WORK/out_j_sc06" >/dev/null; then
    compare "$WORK/out_j_sc06" "SC06: cdoc2-cli container read by umbrik"
  else
    bad "SC06: umbrik could not decrypt cdoc2-cli's container"
  fi
else
  bad "SC06: cdoc2-cli failed to create a container"
fi

# ---------------------------------------------------------------------------
# SC01 / SC02 — asymmetric recipients
#
# ec_simple.cdoc2 cannot be decrypted with the committed P-384 key (the upstream vector and keys
# have drifted; see tests/vectors/PROVENANCE.md), so secp384r1 coverage comes from here: a
# freshly generated container, encrypted by each side in turn.
# ---------------------------------------------------------------------------

log "SC01/SC02: asymmetric recipients"

"$UMBRIK" encrypt -f "$WORK/u_sc01.cdoc2" \
  -c "$WORK/keys/cdoc2client-certificate.pem" \
  "$WORK"/src/* >/dev/null
mkdir -p "$WORK/out_u_sc01"
if cdoc2 decrypt -f /work/u_sc01.cdoc2 \
      -k /work/keys/cdoc2client_priv.key \
      -o /work/out_u_sc01 >/dev/null 2>&1; then
  compare "$WORK/out_u_sc01" "SC01 (secp384r1): umbrik container read by cdoc2-cli"
else
  bad "SC01 (secp384r1): cdoc2-cli could not decrypt umbrik's container"
fi

if cdoc2 create -f /work/j_sc01.cdoc2 \
      -c /work/keys/cdoc2client-certificate.pem \
      /work/src/hello.txt /work/src/notes.md /work/src/random.bin >/dev/null 2>&1; then
  mkdir -p "$WORK/out_j_sc01"
  if "$UMBRIK" decrypt -f "$WORK/j_sc01.cdoc2" \
        -k "$WORK/keys/cdoc2client_priv.key" \
        -o "$WORK/out_j_sc01" >/dev/null; then
    compare "$WORK/out_j_sc01" "SC01 (secp384r1): cdoc2-cli container read by umbrik"
  else
    bad "SC01 (secp384r1): umbrik could not decrypt cdoc2-cli's container"
  fi
else
  bad "SC01 (secp384r1): cdoc2-cli failed to create a container"
fi

# SC02 is not supported: pre-2018 RSA cards are out of scope. A container using it must be
# refused with an unsupported-scheme error rather than a parse failure — a user has to be able to
# tell "umbrik cannot do this" from "this file is corrupt".
if cdoc2 create -f /work/j_sc02.cdoc2 \
      -p /work/keys/rsa_pub.pem \
      /work/src/hello.txt >/dev/null 2>&1; then
  if "$UMBRIK" recipients -f "$WORK/j_sc02.cdoc2" | grep -q SC02; then
    # Decrypt with a valid EC key so the failure comes from the container's scheme rather than
    # from the key being unloadable. The output is captured before matching because `pipefail`
    # would otherwise fail the pipeline on umbrik's non-zero exit, which is the expected result.
    sc02_output="$("$UMBRIK" decrypt -f "$WORK/j_sc02.cdoc2" \
        -k "$WORK/keys/cdoc2client_priv.key" -o "$WORK/out_j_sc02" 2>&1 || true)"
    if printf '%s' "$sc02_output" | grep -qi "SC02 RSA is not supported"; then
      ok "SC02: cdoc2-cli container parses and is refused as unsupported"
    else
      bad "SC02: umbrik did not refuse the container with an unsupported-scheme error"
    fi
  else
    bad "SC02: umbrik did not report the container as SC02"
  fi
else
  bad "SC02: cdoc2-cli failed to create a container"
fi

# ---------------------------------------------------------------------------

log "Result"
printf '  %d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

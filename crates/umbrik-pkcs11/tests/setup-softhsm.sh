#!/usr/bin/env bash
#
# Build a SoftHSM2 token holding a secp384r1 key and a matching certificate, so the PKCS#11
# provider can be exercised without a smart card.
#
# SoftHSM is a software token: it validates the PKCS#11 mechanics (sessions, login, object
# discovery, CKM_ECDH1_DERIVE) but says nothing about how a real card behaves. See the
# CARD-SPECIFIC notes in src/lib.rs for what still needs hardware.
#
# Prints the environment the tests need. Usage:
#
#   eval "$(tests/setup-softhsm.sh)"
#   cargo test -p umbrik-pkcs11

set -euo pipefail

WORK="${UMBRIK_SOFTHSM_DIR:-$(mktemp -d)}"
PIN="${UMBRIK_PKCS11_PIN:-648219}"
SO_PIN="${UMBRIK_PKCS11_SO_PIN:-1234}"
LABEL="umbrik-test"
KEY_ID="01"

# Locate the module: Homebrew on macOS, distribution paths on Linux.
for candidate in \
  "${SOFTHSM2_MODULE:-}" \
  /opt/homebrew/lib/softhsm/libsofthsm2.so \
  /usr/local/lib/softhsm/libsofthsm2.so \
  /usr/lib/softhsm/libsofthsm2.so \
  /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so ; do
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then MODULE="$candidate"; break; fi
done
if [ -z "${MODULE:-}" ]; then
  echo "could not find libsofthsm2.so; set SOFTHSM2_MODULE" >&2
  exit 1
fi

mkdir -p "$WORK/tokens"
cat > "$WORK/softhsm2.conf" <<EOF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
EOF
export SOFTHSM2_CONF="$WORK/softhsm2.conf"

softhsm2-util --init-token --free --label "$LABEL" --pin "$PIN" --so-pin "$SO_PIN" >/dev/null

# A self-signed certificate: the provider enumerates identities from certificates, because a
# token exposes those without a login. That is what lets recipient matching happen before a PIN
# is ever requested.
openssl ecparam -name secp384r1 -genkey -noout -out "$WORK/key.pem" 2>/dev/null
openssl req -new -x509 -key "$WORK/key.pem" -out "$WORK/cert.pem" -days 3650 \
  -subj "/C=EE/CN=UMBRIK TEST,SOFTHSM,00000000000/serialNumber=PNOEE-00000000000" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.pem" -out "$WORK/key.p8" 2>/dev/null
openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.der" 2>/dev/null

# The private key and its certificate must share a CKA_ID: that is how the provider pairs them.
#
# --usage-derive sets CKA_DERIVE, without which the token refuses CKM_ECDH1_DERIVE with
# CKR_KEY_FUNCTION_NOT_PERMITTED. Estonian ID-card authentication keys have this set — it is
# what makes ECDH on the card possible at all — so the fixture must match.
pkcs11-tool --module "$MODULE" --token-label "$LABEL" --pin "$PIN" \
  --write-object "$WORK/key.p8"  --type privkey --id "$KEY_ID" --label "$LABEL" \
  --usage-derive >/dev/null 2>&1
pkcs11-tool --module "$MODULE" --token-label "$LABEL" --pin "$PIN" \
  --write-object "$WORK/cert.der" --type cert    --id "$KEY_ID" --label "$LABEL" >/dev/null 2>&1

echo "export SOFTHSM2_CONF='$WORK/softhsm2.conf'"
echo "export UMBRIK_PKCS11_MODULE='$MODULE'"
echo "export UMBRIK_PKCS11_PIN='$PIN'"
echo "export UMBRIK_PKCS11_CERT='$WORK/cert.pem'"

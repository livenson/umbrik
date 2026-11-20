#!/usr/bin/env bash
#
# Check, against the live servers, that each eID directory's certificate still verifies the way
# umbrik-ldap verifies it: the chain the server sends, plus the intermediate bundled in
# crates/umbrik-ldap/certs/, up to a root in the system trust store, for the directory's name.
#
# The offline tests in umbrik-ldap pin a snapshot of SK's certificate, so they cannot notice SK
# reissuing under a different intermediate. That would break every SK lookup while every test
# stayed green; this check is what notices. It also reports when SK starts sending its full chain,
# which is when the bundled intermediate can be removed.
#
# Needs only openssl and the system CA bundle. Exit status: 0 = all verify, 1 = at least one fails.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLED="$REPO_ROOT/crates/umbrik-ldap/certs/digicert-global-g2-tls-rsa-sha256-2020-ca1.der"
DIRECTORIES=(esteid.ldap.sk.ee ldap.eidpki.ee)

# GitHub annotations when running in Actions, plain text otherwise.
note() { if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::$1::$2"; else echo "$1: $2"; fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

openssl x509 -inform DER -in "$BUNDLED" -out "$TMP/bundled.pem"
if ! openssl x509 -in "$TMP/bundled.pem" -noout -checkend $((90 * 24 * 3600)) >/dev/null; then
  note warning "the bundled intermediate expires within 90 days: $(openssl x509 -in "$TMP/bundled.pem" -noout -enddate)"
fi

failed=0
for host in "${DIRECTORIES[@]}"; do
  echo "== $host"
  if ! echo | openssl s_client -connect "$host:636" -servername "$host" -showcerts \
      >"$TMP/handshake.txt" 2>"$TMP/handshake.err"; then
    note error "$host: TLS handshake failed: $(tail -1 "$TMP/handshake.err")"
    failed=1
    continue
  fi
  grep -E '^ *Protocol *:|Cipher is' "$TMP/handshake.txt" | sed 's/^ */   /' | sort -u

  # Split what the server sent: the first certificate is its own, the rest are intermediates.
  awk -v dir="$TMP" '
    /-----BEGIN CERTIFICATE-----/ { n++; out = sprintf("%s/served-%d.pem", dir, n) }
    out { print > out }
    /-----END CERTIFICATE-----/   { out = "" }
  ' "$TMP/handshake.txt"
  served=$(find "$TMP" -name 'served-*.pem' | wc -l | tr -d ' ')
  echo "   server sent $served certificate(s)"
  cat "$TMP"/served-*.pem "$TMP/bundled.pem" >"$TMP/untrusted.pem"

  if openssl verify -verify_hostname "$host" -untrusted "$TMP/untrusted.pem" "$TMP/served-1.pem" \
      >"$TMP/verify.txt" 2>&1; then
    echo "   verifies with the system roots and the bundled intermediate"
  else
    note error "$host: certificate does not verify: $(tail -1 "$TMP/verify.txt"). Issuer: $(openssl x509 -in "$TMP/served-1.pem" -noout -issuer). If the issuer changed, replace the intermediate in crates/umbrik-ldap/certs/ (see its README)."
    failed=1
  fi

  # Report when a server's own chain is enough, so the workaround can be retired.
  if [ "$served" -gt 1 ] && openssl verify -verify_hostname "$host" \
      -untrusted <(cat "$TMP"/served-*.pem) "$TMP/served-1.pem" >/dev/null 2>&1; then
    if [ "$host" = esteid.ldap.sk.ee ]; then
      note notice "$host now sends a complete chain; the bundled intermediate can be removed (see crates/umbrik-ldap/certs/README.md)"
    fi
  fi
  rm -f "$TMP"/served-*.pem
done

exit "$failed"

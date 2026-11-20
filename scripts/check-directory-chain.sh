#!/usr/bin/env bash
#
# Check, against the live servers, that each eID directory's certificate still verifies the way
# umbrik-ldap verifies it: the chain the server sends, up to a root in the system trust store, for
# the directory's name. rustls does not fetch an intermediate a server leaves out, so a server
# that stops sending its full chain breaks every lookup against it.
#
# The offline tests in umbrik-ldap pin a snapshot of SK's chain, so they cannot notice SK
# reissuing its certificate or leaving its intermediate out again (as it did until 2026-11). That
# would break every SK lookup while every test stayed green; this check is what notices.
#
# Needs only openssl and the system CA bundle. Exit status: 0 = all verify, 1 = at least one fails.

set -euo pipefail

DIRECTORIES=(esteid.ldap.sk.ee ldap.eidpki.ee)

# GitHub annotations when running in Actions, plain text otherwise.
note() { if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::$1::$2"; else echo "$1: $2"; fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

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

  if openssl verify -verify_hostname "$host" -untrusted <(cat "$TMP"/served-*.pem) \
      "$TMP/served-1.pem" >"$TMP/verify.txt" 2>&1; then
    echo "   verifies with the system roots and the served chain"
  else
    hint=""
    [ "$served" -eq 1 ] && hint=" The server sent only its own certificate: it is omitting its intermediate again, and rustls will not fetch it."
    note error "$host: certificate does not verify: $(tail -1 "$TMP/verify.txt"). Issuer: $(openssl x509 -in "$TMP/served-1.pem" -noout -issuer).$hint"
    failed=1
  fi
  rm -f "$TMP"/served-*.pem
done

exit "$failed"

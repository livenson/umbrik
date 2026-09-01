# Test vector provenance

Containers produced by the CDOC2 **reference implementation's** CLI, not by umbrik. That is the
point: they make the test suite an interoperability check rather than a self-consistency check.
A constant that is wrong in the same way in both umbrik's encrypt and decrypt paths passes a
round-trip test and fails these.

| Field | Value |
|---|---|
| Upstream repo | `https://github.com/open-eid/cdoc2-java-ref-impl` |
| Upstream path | `test/testvectors/` |
| Commit | `daff207f719b4c1cfc4a1138733a4f8c531524c6` |
| CDOC2 spec version | 1.7 |
| Upstream license | MIT |
| Copied on | 2026-09-01 |

## Files and what each one covers

| File | Scheme | Covers |
|---|---|---|
| `symmetric.cdoc2` | SC05 | `SymmetricKeyCapsule`; the M1 HMAC gate and the FMK/CEK golden values |
| `symmetric_longfilename.cdoc2` | SC05 | pax long filenames (>100 bytes) and a non-ASCII entry name |
| `password.cdoc2` | SC06 | `PBKDF2Capsule`; 600 000 iterations, two distinct salts |
| `ec_simple.cdoc2` | SC01 | `ECCPublicKeyCapsule` on secp384r1; 97-byte TLS points |
| `ec_256_simple.cdoc2` | SC01 | secp256r1 variant |
| `rsa_simple.cdoc2` | SC02 | `RSAPublicKeyCapsule`; 256-byte wrapped KEK |
| `ec_server_ria_dev_pkcs12.cdoc2` | SC03/SC04 | `KeyServerCapsule` — must *parse* but report unsupported |

## Secrets

Published upstream in `test/generate_documents.sh`; these protect sample data only.

- Symmetric vectors: `HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=` (base64, 32 bytes)
- `password.cdoc2`: `Kui-Arno-isaga-koolimajja-jõudis-olid-tunnid-juba-alanud`

Read the key label from the container, never from the script above — the two have already
drifted (`symmetric.cdoc2` carries `create_symmetric_label`, not the script's `test_label`).
The label is an input to KEK derivation for SC05/SC06, so using the wrong one silently yields a
wrong KEK.

## Updating

Re-copy from the pinned commit and bump the table. Do not regenerate these locally with umbrik —
a vector produced by the implementation under test proves nothing.

## Known gap: `password.cdoc2` cannot be opened

The password in upstream's `test/generate_documents.sh` does not open the checked-in
`password.cdoc2`; the vector and the script have drifted apart. Confirmed independently in
Python, so it is not an umbrik bug. Unicode normalisation was ruled out — both are NFC.

The vector is therefore used only for header-structure assertions and never decrypted. SC06
decryption is proven by the interop job instead.

## Known gap: `ec_simple.cdoc2` key has drifted

`ec_simple.cdoc2` is addressed to a P-384 key that is not the committed
`keys/cdoc2client_priv.key`, so it cannot be decrypted here. It is used for structure assertions
plus a canary test asserting the mismatch; if upstream republishes matching keys, that canary
fails and should become a real decryption test.

Coverage is unaffected: SC01 on secp256r1 and SC02 are verified end to end against the committed
keys, and SC01 on secp384r1 is covered by the interop job.

Treat any vector/key pairing here as unverified until a test exercises it — three have drifted
so far.

## Private keys

`keys/` holds the reference implementation's test keys, copied from `cdoc2-cli/keys/` at the same
commit. They protect sample data only and are published upstream. Never use them for anything
real.

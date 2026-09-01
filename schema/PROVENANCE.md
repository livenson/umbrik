# Schema provenance

The FlatBuffers schemas in this directory are vendored verbatim — not a git submodule — so that
schema changes are a deliberate, reviewable bump rather than a moving target. CDOC2 is at 1.7
with a 2.0 draft in flight.

| Field | Value |
|---|---|
| Upstream repo | `https://github.com/open-eid/cdoc2-java-ref-impl` |
| Upstream path | `cdoc2-schema/src/main/fbs/` |
| Commit | `daff207f719b4c1cfc4a1138733a4f8c531524c6` |
| Commit date | 2026-08-15 |
| `cdoc2-schema` Maven version | 2.1.0 |
| CDOC2 spec version | 1.7 |
| Upstream license | MIT (Copyright (c) 2024 Open Electronic Identity) |
| Vendored on | 2026-09-01 |

## Files

- `header.fbs` — `Header`, `RecipientRecord`, the `Capsule` union, `FMKEncryptionMethod`,
  `PayloadEncryptionMethod`. Root type is `Header`.
- `recipients.fbs` — the six capsule tables plus `EllipticCurve` and `KDFAlgorithmIdentifier`.

`header.fbs` has `include "recipients.fbs";`, so both must stay in the same directory and be
passed to `flatc` together.

## Updating

1. Bump the commit hash and dates in the table above.
2. Re-copy both files unmodified.
3. Re-run the interop CI job. A schema bump is a wire-format change until proven otherwise.

Do not hand-edit these files. Local divergence from upstream is the exact failure mode this
directory exists to prevent.

## Note on capsules we do not implement

`KeySharesCapsule` (SC07, spec 2.0 draft) and `KeyServerCapsule` (SC03/SC04) are present in the
upstream schema and are therefore present here. Vendoring them is not a commitment to implement
them — the parser must recognise these union variants and reject them with a distinct
"unsupported scheme" error rather than failing to parse.

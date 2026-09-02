# Working on umbrik

Conventions for anyone — human or agent — changing this repository. Read this before the first
edit; several rules below exist because breaking them produced containers no other CDOC2
implementation could read.

## The one rule that matters

**Never guess a cryptographic constant.** Every salt, info string, iteration count, hash choice
and byte range is published. If you cannot find a value in the specification or in
`open-eid/cdoc2-java-ref-impl`, stop and say so. Do not write a placeholder and do not "reason"
your way to a plausible value.

All constants are recorded with citations in [`docs/CRYPTO-CONSTANTS.md`](docs/CRYPTO-CONSTANTS.md).
Add to it rather than scattering literals through the code.

Four that look wrong but are not:

- HKDF is **HMAC-SHA-256 everywhere**, including the P-384 ECDH path. Habit says pair P-384 with
  SHA-384; the format does not.
- RSA-OAEP uses **SHA-256 for MGF1** as well as the digest. Defaulting MGF1 to SHA-1 is the
  classic interop failure.
- The **key label is a KDF input for SC05 and SC06** but not for SC01 or SC02. Editing a label
  breaks decryption for the first two and nothing for the last two.
- SC02 uses **no KDF at all** — the KEK is transported directly under RSA-OAEP. (Not
  implemented; the constants are recorded for anyone adding it back.)

## Verification

**A round trip proves nothing.** A constant applied consistently in both directions passes every
self-test. Only two things catch it:

```bash
tests/interop/run.sh    # round trips against the reference cdoc2-cli, both directions
cargo test              # includes a fixed-RNG golden file pinning our exact output
```

Run interop for any change touching cryptography, the container layout, or a dependency of
either. It is a required check on `main`.

**Do not trust the committed test vectors' pairings.** Three have drifted from the keys, labels
and passwords committed beside them. Verify a pairing with a test before relying on it; see
[`tests/vectors/PROVENANCE.md`](tests/vectors/PROVENANCE.md).

## Layering

- **L0 `header`** — framing and FlatBuffers codec. Pure; no traits, no I/O. Attacker-controlled
  input is parsed here *before* anything is authenticated, so it must never panic: no indexing,
  no slicing.
- **L1 `schemes`** — one KEK function per scheme. Pure and individually vector-testable.
- **L2 `container`** — orchestration; the only place traits and the RNG are injected.

`umbrik-core` must not depend on `cryptoki`, `reqwest`, `ldap3`, or any hardware or HTTP crate.
Hardware lives in `umbrik-pkcs11`, network in `umbrik-ldap`.

## Invariants worth preserving

- **The header MAC cannot be checked before the private-key operation** — its key descends from
  the FMK. `VerifiedHeader` encodes this: it is only constructible by passing the check, and is
  the only thing payload decryption accepts. Do not add a path around it.
- **The payload is one AEAD invocation.** Authentication completes before any plaintext exists,
  so nothing unauthenticated reaches disk. Do not introduce an incremental streaming API.
- **The RNG is a parameter, never a global.** This is what makes golden files possible.
- **`Limits` is a struct, not a trait**, enforced inside the reader. A trait would attract a
  permissive implementation.
- **`ErrorCode` discriminants are frozen** across major versions; they cross the C ABI. Add at
  the end, never reorder.

## Certificates

Validity dates are checked and a certificate outside its window is refused unless
`--allow-expired` is given. Chain and revocation checking are deliberately absent — they need a
trust store and an OCSP/CRL lookup, and add little where recipients come from an authenticated
directory or a file the user chose. Do not add a partial version that implies more than it
delivers.

## Out of scope

Do not implement without asking: **SC02** (RSA — pre-2018 cards; removing it dropped the `rsa`
crate and the project's only security advisory), **SC07** (key shares — 2.0 draft, needs an SK
relying-party contract, and could not be gated by interop), **SC03/SC04** (capsule server),
**CDOC1**. All parse into distinct "unsupported scheme" errors today; keep it that way.

## Licensing

umbrik is MIT. `libcdoc` and `cdoc2-capsule-server` are **LGPL-2.1**: read them to understand
behaviour, never copy or transliterate. Constants and wire formats are facts and may come from
anywhere; expression may not.

PKCS#11 modules (OpenSC, the Estonian eID module) are LGPL and are `dlopen`ed at runtime across a
stable C ABI. That is why linking is not an issue — never bundle or statically link one.

`cargo deny check` enforces the dependency side.

## Building

`flatc` must match the `flatbuffers` version pinned in `Cargo.toml`; a mismatch generates code
that does not compile. Use `scripts/install-flatc.sh`, not a distribution package.

The Python bindings are a workspace member but not a default one, so a plain `cargo build` needs
no Python interpreter. Build them with `cargo build -p umbrik-python` or via maturin, against
Python 3.10 or newer.

## Hardware notes

Learned against a real Estonian ID-card, and not reproducible with SoftHSM:

- A reader presents one card in **several slots** (PIN1 and PIN2 across two interfaces). Identity
  enumeration deduplicates by public key.
- A card carries an authentication *and* a signing certificate. Only the first can perform key
  agreement, so certificates are filtered on `keyUsage`. Offering the signing key would prompt
  for PIN2 and then fail.
- **PKCS#11 initialises process-wide.** Two live providers for one module can crash it rather
  than erroring; tests serialise access.
- Never prompt for a PIN speculatively. Recipient matching happens before `perform`, because a
  wrong PIN counts against a card's three-attempt limit.

## Changes

`main` is protected and takes no direct pushes. Every change goes through a PR that build,
interop, licences and CodeQL must pass; reviews are not required.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) — the
changelog is generated from them.

```bash
git switch -c fix-something
git push -u origin fix-something
gh pr create --fill
```

Releases are two-phase for the same reason: `scripts/release.sh <version>` opens a PR with the
bump and changelog, and `scripts/release.sh --tag <version>` tags it once merged.

See [`VERSIONING.md`](VERSIONING.md) for what a version bump means — note that a change to the
container bytes is breaking even when no signature changes — and
[`docs/MAINTENANCE.md`](docs/MAINTENANCE.md) for what runs automatically.

# Versioning

umbrik follows [Semantic Versioning](https://semver.org/). Every crate in the workspace, the
`umbrik` command-line tool, and the `umbrik` PyPI package share one version number.

## Why SemVer and not CalVer

Cargo's dependency resolver is *built on* SemVer semantics. A downstream `Cargo.toml` that asks
for `umbrik-core = "0.1"` is telling Cargo "anything compatible with 0.1", and Cargo decides what
compatible means from the version number alone.

A date-based version would mislead it. `2026.09.1 → 2026.10.1` looks like a compatible update to
the resolver, whether or not the API survived the month. CalVer suits software whose releases are
time-boxed and whose users are not asking about compatibility; a library's users are asking about
exactly that.

## The CDOC2 specification version is not the software version

umbrik currently implements CDOC2 **1.7**. That is recorded in `README.md` and
`docs/CRYPTO-CONSTANTS.md`, and deliberately *not* in the version number.

The two are independent: umbrik could break its Rust API twice while supporting the same
specification, or add support for a future specification without breaking anything. Encoding one
in the other would make both harder to read.

## What a bump means

While in `0.x`, Cargo treats a change to the second component as breaking, which is the
protection this project wants before its API has settled.

| Change | Bump |
|---|---|
| Breaking Rust API change | minor while `0.x`, major after `1.0` |
| **Any change to the container bytes umbrik writes** | as above — see below |
| Raising the minimum supported Rust version | minor |
| New scheme, new CLI flag, new binding function | minor |
| Bug fix, dependency update, documentation | patch |

### Wire format is part of the API

A change to the bytes umbrik writes is breaking even when every Rust signature is untouched.
Containers outlive the program that wrote them, and a recipient may be running a different
implementation entirely. Any such change must be justified in the commit and validated by the
interop job.

The fixed-RNG golden file exists to make this impossible to do by accident: an unintended change
to the container layout fails `sc05_golden_file_is_byte_identical` before it reaches a release.

### Error codes are frozen harder than SemVer

The discriminants in `ErrorCode` are stable **across major versions**. They cross the C ABI and
become Python exception classes and Go error values, so renumbering one silently breaks every
binding, in a way a version bump does not communicate. Add new codes at the end; never reuse or
reorder.

## Reaching 1.0

`1.0` will follow the C ABI settling, not the cryptography feeling finished. The Rust API can
still be improved after 1.0 through a major bump; an ABI that foreign callers have compiled
against cannot. That makes the FFI surface the real gate.

`1.0` asserts that the API is stable. It asserts nothing about auditing — umbrik is unaudited,
and the disclaimer in `README.md` stands independently of the version number.

## Minimum supported Rust version

Declared as `rust-version` in `Cargo.toml`. Raising it is a **minor** bump and never happens in a
patch release, so a patch update can always be taken by someone pinned to an older toolchain.

## Commit messages

New commits follow [Conventional Commits](https://www.conventionalcommits.org/) — `feat:`,
`fix:`, `docs:`, `ci:`, `deps:` — because the changelog is generated from them. A message written
carelessly becomes a changelog entry read by everyone.

History predating the convention is classified by pattern in `cliff.toml` rather than dumped into
"Other".

## Cutting a release

```bash
scripts/release.sh 0.2.0
git push origin main --follow-tags
```

The script verifies, bumps every manifest, regenerates `CHANGELOG.md`, and pauses for you to
read it before committing and tagging. It refuses to tag unless the whole suite passes —
**interop included**, because a release that has not been round-tripped against the reference
implementation is precisely the release that ships a wrong constant.

It deliberately builds and signs nothing locally. Pushing the tag is the trigger: CI builds every
target, generates the SBOM, and signs the artifacts with attestations that bind them to a
workflow run. A laptop cannot produce that provenance, so anything built here would be strictly
less trustworthy than what the tag produces. See [`docs/MAINTENANCE.md`](docs/MAINTENANCE.md).

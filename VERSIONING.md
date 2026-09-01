# Versioning

umbrik follows [Semantic Versioning](https://semver.org/). Every crate, the CLI and the PyPI
package share one version.

## SemVer, not CalVer

Cargo's resolver is built on SemVer: a dependency on `"0.1"` means "anything compatible with
0.1", and Cargo decides what compatible means from the version number alone. A date-based
version would report a release as compatible whether or not the API survived the month.

## The specification version is separate

umbrik implements CDOC2 **1.7**, recorded in `README.md` and `docs/CRYPTO-CONSTANTS.md` rather
than in the version number. The two are independent: the Rust API can break without the
specification changing, and vice versa.

## What a bump means

| Change | Bump |
|---|---|
| Breaking Rust API change | minor while `0.x`, major after `1.0` |
| Change to the container bytes umbrik writes | as above |
| Raising the minimum supported Rust version | minor |
| New scheme, CLI flag, or binding function | minor |
| Bug fix, dependency update, documentation | patch |

**Wire format is part of the API.** A change to the bytes umbrik writes is breaking even when
every signature is untouched: containers outlive the program that wrote them, and the recipient
may be running another implementation. The fixed-RNG golden file makes such a change impossible
to introduce accidentally.

**Error codes are frozen across major versions.** The `ErrorCode` discriminants cross the C ABI
into Python exceptions and Go error values, so renumbering one breaks every binding in a way a
version bump does not communicate. Add new codes at the end.

## Reaching 1.0

`1.0` follows the C ABI settling, not the cryptography feeling finished: the Rust API can be
changed after 1.0 through a major bump, but an ABI that foreign callers have compiled against
cannot. It asserts API stability and nothing about auditing — umbrik is unaudited regardless of
its version.

## Commit messages

New commits follow [Conventional Commits](https://www.conventionalcommits.org/), because the
changelog is generated from them. Earlier history is classified by pattern in `cliff.toml`.

## Cutting a release

```bash
scripts/release.sh 0.2.0
git push origin main --follow-tags
```

The script verifies, bumps every manifest, regenerates `CHANGELOG.md` and pauses for review
before tagging. It refuses to tag unless the suite passes, interop included.

It builds and signs nothing locally: pushing the tag is the trigger. CI then builds every target,
creates the GitHub release with the changelog section as its notes, attaches the binaries,
checksums and SBOM, and publishes the wheels to PyPI. Provenance binding an artifact to a
workflow run is not something a laptop can produce. See
[`docs/MAINTENANCE.md`](docs/MAINTENANCE.md).

# Maintenance

## Why automation matters here

Every dependency is pinned to an exact version, so nothing updates on its own. The automation
below is what keeps those pins from going stale.

## What runs

| What | When | Catches |
|---|---|---|
| CI | push, PR | build, clippy, fmt, tests, both feature configurations |
| Interop | push, PR | a wrong cryptographic constant — the only check that can |
| cargo-deny | push, PR | vulnerable, yanked, or wrongly-licensed dependencies |
| Dependency review | PR | a new bad dependency, before merge |
| CodeQL | push, PR, weekly | cryptographic misuse, injection, unsafe untrusted input |
| Dependabot | weekly | stale pins; security updates arrive separately |
| Scorecard | weekly | repository posture: branch protection, token scope, pinned actions |
| Release | `v*` tag | seven targets, SBOM, signatures |

## Dependabot

Minor and patch updates are grouped into one PR. Two deliberate exclusions:

- **Major bumps** are ignored and taken by hand. A major version of a cryptographic crate can
  change key derivation; only the interop job can judge whether it is safe, and reviewing several
  at once hides which change broke what.
- **Major base-image bumps** in `tests/interop` are ignored. That image builds the CDOC2
  reference implementation and should track the JDK that project supports.

Known limitation: Dependabot has had
[trouble with Cargo workspaces](https://github.com/dependabot/dependabot-core/issues/13833). If
PRs stop arriving, check there before assuming the pins are current; `cargo deny` catches
vulnerable versions either way.

## Actions are pinned by SHA

A tag is mutable, so pinning to one means running whatever it points at today. Every action is
pinned to a commit SHA with the version in a trailing comment; Dependabot updates both.

## flatc

`scripts/install-flatc.sh` installs the `flatc` matching the pinned `flatbuffers` crate, reading
the version from `Cargo.toml`. The two must agree: a mismatch generates code that does not
compile. Distribution packages lag and are not usable.

## Python wheels

Built against the stable ABI (`abi3-py310`): one wheel per platform, working on 3.10 and every
later version. `python.yml` installs that single wheel and runs the tests on 3.10 through 3.14,
so the claim is verified rather than assumed. Python 3.9 is excluded — end of life since
October 2025.

## Platforms

| Target | Features |
|---|---|
| `{x86_64,aarch64}-unknown-linux-gnu` | full |
| `{x86_64,aarch64}-apple-darwin` | full |
| `x86_64-pc-windows-msvc` | full |
| `{x86_64,aarch64}-unknown-linux-musl` | no default features |

musl builds are static and make no network connections: the eID directory lookup needs OpenSSL,
because SK's LDAP negotiates a cipher suite rustls will not offer. Windows uses schannel and
needs no OpenSSL. Every native target is smoke-tested before upload.

## Publishing

Tagging attaches everything to the GitHub release: CLI binaries for seven targets, Python wheels
and the sdist, `SHA256SUMS`, and the CycloneDX SBOM.

PyPI publishing is **off**. Setting the repository variable `PUBLISH_TO_PYPI` to `true` enables
it, once a trusted publisher exists for `livenson/umbrik` / `python.yml` / environment `pypi`.
That path uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — a short-lived
OIDC token exchanged for one valid fifteen minutes, so no long-lived credential — and emits
[PEP 740](https://peps.python.org/pep-0740/) attestations. Until then wheels are installable from
the release page.

`scripts/build-local.sh` builds the CLI and a wheel for the host platform only. Those are
unsigned: an attestation binds an artifact to a workflow run, which a laptop cannot produce.

Tagging `v*` creates a GitHub release whose notes are the matching `CHANGELOG.md` section, with
the binaries, `SHA256SUMS` and the CycloneDX SBOM attached. Everything is signed with GitHub
Artifact Attestations, which bind each artifact to the workflow run that built it:

```bash
gh attestation verify ./umbrik --repo livenson/umbrik
```

## Settings not held in this repository

- [x] Private vulnerability reporting — `SECURITY.md` links to the advisory form
- [x] Dependabot alerts and security updates
- [x] Secret scanning with push protection
- [x] Branch protection on `main`: build, interop, licences and CodeQL must pass; no force
      pushes or deletions; enforced for administrators too
- [ ] *(only to publish to PyPI)* a `pypi` deployment environment, a trusted publisher for
      `livenson/umbrik` / `python.yml` / `pypi`, and the repository variable `PUBLISH_TO_PYPI`
      set to `true`

## Changes go through pull requests

Branch protection is enforced for administrators, so `main` takes no direct pushes — including
from the owner. Every change, however small, goes through a PR that build, interop, licences and
CodeQL must pass.

Reviews are not required, so a solo maintainer can merge their own PR once it is green. The point
is not review; it is that nothing reaches `main` without the interop job having run against it.

```bash
git switch -c fix-something
# ... work, commit ...
git push -u origin fix-something
gh pr create --fill
gh pr merge --squash --delete-branch   # once checks pass
```

In a genuine emergency, protection can be lifted with
`gh api -X DELETE repos/livenson/umbrik/branches/main/protection` and restored afterwards. Doing
so means the next push is unverified, so restore it in the same sitting.

## Always manual

- **Interop failures after a dependency bump.** No tool decides whether the cryptography changed.
- **Bumping pinned upstream commits** in `tests/interop/Dockerfile` and `schema/PROVENANCE.md`,
  so "upstream changed" is never mistaken for "umbrik regressed".

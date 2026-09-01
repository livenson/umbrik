# Keeping umbrik healthy

What runs automatically, why it exists, and what still needs a person.

## Why this needs more than usual

umbrik pins every dependency to an exact version (`=x.y.z`). That is deliberate — a
cryptographic library should not silently change the code that derives its keys — but it means
nothing updates on its own, and a pinned version is a version that will eventually be
vulnerable. That has already happened once: a routine `cargo deny` run found
[CVE-2025-62518](https://rustsec.org/advisories/RUSTSEC-2025-0111) in the exact `tar` version
this project had pinned.

So the automation is not optional hygiene here. It is the thing that makes exact pinning safe.

## What runs, and when

| What | When | Catches |
|---|---|---|
| **CI** (`ci.yml`) | every push and PR | build, clippy, fmt, 110 tests, both feature configurations |
| **Interop** | every push and PR | a wrong constant — the only check that can |
| **cargo-deny** | every push and PR | vulnerable, yanked, or wrongly-licensed dependencies |
| **Dependency review** | every PR | a *new* dependency that is vulnerable or wrongly licensed, before merge |
| **CodeQL** | push, PR, weekly | cryptographic misuse, injection, unsafe handling of untrusted input |
| **Dependabot** | weekly | outdated pins; security updates arrive separately and immediately |
| **Scorecard** | weekly | the repository's own posture — branch protection, token scope, unpinned actions |
| **Release** | on a `v*` tag | builds four targets, generates an SBOM, signs everything |

### Dependabot

Grouped so a routine week is one reviewable PR. Two deliberate choices:

- **Security updates are never grouped with version updates** — that is Dependabot's own
  behaviour, and it is the right one: an advisory should not arrive buried in a batch.
- **Major bumps are ignored** and must be taken by hand. A major version of a cryptographic
  crate can change key derivation or defaults, and the interop job is what has to decide whether
  it is safe. Reviewing several at once hides which change broke what.

Known limitation: Dependabot has had
[trouble with Cargo workspaces](https://github.com/dependabot/dependabot-core/issues/13833).
If PRs stop arriving, check that issue before assuming everything is current — and note that
`cargo deny` in CI still catches vulnerable versions either way.

### CodeQL

Rust support became generally available in October 2025. It looks for a different class of
problem than clippy: cryptographic misuse and unsafe handling of untrusted data, which is
precisely umbrik's exposure — container bytes are attacker-controlled and parsed *before*
anything is authenticated, because the header MAC key descends from the FMK.

### Releases: SBOM and attestations

Tagging `v*` builds four targets, generates a CycloneDX SBOM from the resolved `Cargo.lock`, and
signs both with [GitHub Artifact Attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).

Attestations bind each artifact's SHA-256 digest to the workflow, repository and commit that
built it, signed through Sigstore with a short-lived certificate — there is no long-lived signing
key to store or leak. Anyone can verify:

```bash
gh attestation verify ./umbrik --repo livenson/umbrik
```

For an unaudited cryptographic tool this matters more than usual: it lets someone confirm the
binary they downloaded was built from the source they can read.

## Repository settings a person has to turn on

None of these can be set from a file in the repository:

- [ ] **Private vulnerability reporting** — Settings → Code security. `SECURITY.md` links
      directly to the advisory form, so until this is on, that link 404s.
- [ ] **Dependabot alerts and security updates** — Settings → Code security.
- [ ] **Secret scanning with push protection** — free for public repositories.
- [ ] **Branch protection on `main`** — require CI and interop to pass. Scorecard checks for
      this, and without it the interop gate can be bypassed by pushing straight to `main`.

## What is still manual, and always will be

- **Interop failures after a dependency bump.** If `cdoc2-cli` stops reading umbrik's output,
  something changed in the cryptography. No tool decides that for you.
- **Bumping the pinned upstream commits** in `tests/interop/Dockerfile` and
  `schema/PROVENANCE.md`. Deliberate, so that "upstream changed" is never mistaken for
  "umbrik regressed".
- **The accepted risk in `deny.toml`** (RUSTSEC-2023-0071, RSA timing). Revisit if a
  constant-time implementation appears.

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

### Python wheels

Wheels are built against PyO3's stable ABI (`abi3-py310`), which means **one wheel per platform**
rather than one per interpreter version, and it keeps working on Python versions released after
it was built. The `cp310-abi3` tag installs on 3.10 and everything later.

`python.yml` does not take that on trust: it builds a single wheel and then installs and tests
*that same wheel* on 3.10, 3.11, 3.12, 3.13 and 3.14. If abi3 ever stopped delivering what it
promises, the matrix fails.

Python 3.9 is deliberately excluded — it reached end of life in October 2025 and receives no
security fixes, which is not a base a cryptographic library should invite.

### Publishing to PyPI

Uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/), not an API token. The
workflow presents a short-lived OIDC token, PyPI verifies it against a configured publisher and
mints a token valid for fifteen minutes. There is no long-lived credential to store, leak or
rotate — the failure mode that has caused most package-index compromises simply does not exist.

Two further hardening steps, both applied:

- The publish job runs in a **deployment environment** (`pypi`). PyPI binds the trusted publisher
  to that environment name, so a workflow elsewhere in the repository cannot publish, and the
  environment can require a reviewer before any release goes out.
- `attestations: true` produces [PEP 740](https://peps.python.org/pep-0740/) attestations, so
  provenance travels with the package on the index instead of living only in this repository.
  GitHub artifact attestations are generated as well, covering the same artifacts from the other
  side.

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
- [ ] **A `pypi` deployment environment**, ideally with a required reviewer. The publish job
      names it, and PyPI's trusted publisher should be bound to it.
- [ ] **A PyPI trusted publisher** for `livenson/umbrik`, workflow `python.yml`, environment
      `pypi`. Until this exists, publishing fails — by design, rather than falling back to a
      token.

## What is still manual, and always will be

- **Interop failures after a dependency bump.** If `cdoc2-cli` stops reading umbrik's output,
  something changed in the cryptography. No tool decides that for you.
- **Bumping the pinned upstream commits** in `tests/interop/Dockerfile` and
  `schema/PROVENANCE.md`. Deliberate, so that "upstream changed" is never mistaken for
  "umbrik regressed".
- **The accepted risk in `deny.toml`** (RUSTSEC-2023-0071, RSA timing). Revisit if a
  constant-time implementation appears.

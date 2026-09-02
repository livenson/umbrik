# Changelog

All notable changes to umbrik are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/) — see [`VERSIONING.md`](VERSIONING.md).
Note that a change to the container wire format is breaking even when the API is untouched.

## [0.2.0] - 2026-09-02

### Breaking changes

- Drop SC02, and complete the RustCrypto 0.11 migration (#15)

### Added

- Add -v/--verbose diagnostics (#16)
- Explain which directory candidates were rejected, and why (#17)

### Fixed

- Attach wheels to the release, and stop repeating boilerplate in notes (#13)

## [0.1.0] - 2026-09-01

### Added

- Initial implementation: CDOC2 container format in Rust
- Python bindings, built for every supported interpreter and signed on publish
- Refuse certificates outside their validity window (#10)

### Fixed

- Build on Windows, and check every platform on every PR (#12)

### Security

- Automate maintenance: Dependabot, CodeQL, Scorecard, signed releases

### Changed

- Ignore Python bytecode caches
- Versioning policy, release tooling, and a wider build matrix

### Dependencies

- Update dependencies to latest compatible versions
- Bump the rust-dependencies group across 1 directory with 2 updates (#1)

### Documentation

- Cut prose, keep facts
- Record the branch protection now in place
- Branch protection is enforced for administrators
- Add AGENTS.md with the project's working rules (#6)
- Fix the install instructions and have CI run them (#9)



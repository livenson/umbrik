# Changelog

All notable changes to umbrik are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/) — see [`VERSIONING.md`](VERSIONING.md).
Note that a change to the container wire format is breaking even when the API is untouched.

## [0.3.1] - 2026-11-08

### Fixed

- Update crypto-bigint, ctutils, tokio for RUSTSEC-2026-0385/0386/0387 (#46)

### Dependencies

- Bump maven in /tests/interop (#44)
- Bump pytest from 9.1.1 to 9.2.0 in /bindings/python (#45)
- Bump sha2 (#41)
- Bump the actions group across 1 directory with 6 updates (#43)

## [0.3.0] - 2026-10-18

### Breaking changes

- Refuse to overwrite files or write outside flat names on decrypt (#39)

## [0.2.3] - 2026-10-18

### Fixed

- Decrypt to memory without a world-readable scratch directory (#37)

### Dependencies

- Bump the rust-dependencies group across 1 directory with 2 updates (#35)
- Bump the actions group across 1 directory with 7 updates (#36)

## [0.2.2] - 2026-10-03

### Fixed

- Replace yanked wnaf and patch cryptoki (RUSTSEC-2026-0286) (#26)
- Make scratch directory names unique within a process (#31)

### Dependencies

- Bump the actions group across 1 directory with 4 updates (#25)
- Bump the actions group with 4 updates (#28)
- Bump eclipse-temurin in /tests/interop (#30)
- Bump the rust-dependencies group across 1 directory with 3 updates (#29)

### Documentation

- Point the README at the release downloads (#24)

## [0.2.1] - 2026-09-02

### Fixed

- Strip terminal escapes from labels, entry names and directory records (#21)

## [0.2.0] - 2026-09-02

### Breaking changes

- Drop SC02, and complete the RustCrypto 0.11 migration (#15)
- Release 0.2.0 (#18)

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



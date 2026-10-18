# Changelog

All notable changes to umbrik are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/) — see [`VERSIONING.md`](VERSIONING.md).
Note that a change to the container wire format is breaking even when the API is untouched.

## [0.3.0] - 2026-10-18

### Breaking changes

- `decrypt` no longer lets a container's sender choose where files land or what they replace (#39):
  - Entry names must be a single file name: directory components, a leading dot and duplicate names are refused. Previously a container decrypted in a home directory could write `~/.ssh/authorized_keys` or `~/.zshenv`.
  - Existing files are not replaced unless `--force` is given (`Limits::allow_overwrite` in the library), and never through a symlink.
  - A failed extraction removes only files it created; it used to delete files that existed before.
  - Encrypting a file whose name starts with a dot is refused, so umbrik never writes a container it would not open.

## [0.2.3] - 2026-10-18

### Fixed

- `decrypt_to_memory` and the Python `umbrik.decrypt` no longer extract plaintext into a world-readable temporary directory; on a shared `/tmp`, other local users could read decrypted files (#37)

### Dependencies

- Bump zeroize to 1.9.1 and pyo3 to 0.29.3 (#35)
- Bump codeql-action to 4.38.3, upload-artifact to 7.0.2, download-artifact to 8.0.2 and scorecard-action to 2.5.0 (#36)

## [0.2.2] - 2026-10-03

### Fixed

- Replace yanked wnaf and patch cryptoki (RUSTSEC-2026-0286) (#26)
- Make scratch directory names unique within a process (#31)

### Dependencies

- Bump the actions group across 1 directory with 4 updates (#25)
- Bump the actions group with 4 updates (#28)
- Bump eclipse-temurin in /tests/interop (#30)
- Bump thiserror to 2.0.21, clap to 4.6.7 and rand to 0.10.3 (#29)

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



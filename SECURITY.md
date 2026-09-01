# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report through GitHub. There is no email channel for this project.

**Use private vulnerability reporting:** go to the
[Security tab](https://github.com/livenson/umbrik/security/advisories/new) of this repository and
open a draft advisory. This is the only channel that keeps the report private until a fix is
published, and it gives us a private fork to develop the fix in. It works for anyone with a
GitHub account — you do not need write access to the repository.

If that page is unavailable to you for any reason, open a public issue saying only that you have
a security report and would like a private channel, tagging **@livenson**. Include **no details
and no reproduction** in that issue — a maintainer will open an advisory and invite you to it.

In your report, please include the umbrik version or commit, what you observed versus expected,
and a minimal reproduction. A container that demonstrates the problem is ideal — but do not send
one holding real personal data; synthesise a fresh one.

### What to expect

This is a personal open-source project maintained in spare time, not a commercial product with
a staffed on-call rotation. Realistically:

- Acknowledgement within 7 days.
- An initial assessment within 30 days.
- Coordinated disclosure once a fix is available, crediting you unless you prefer otherwise.

If a report affects the CDOC2 format itself rather than umbrik's implementation of it, it should
go to the specification maintainers at [RIA](https://www.ria.ee/) as well. umbrik is an
independent implementation and cannot fix a format-level issue on its own.

## Scope

In scope:

- Cryptographic defects: wrong constants, misapplied AEAD, missing authentication, key material
  leaking into logs, errors, or memory that outlives its use.
- Container parsing: memory-safety issues, panics on malformed input, unbounded allocation.
- Extraction: path traversal, symlink escape, zip bombs, or any write outside the destination.
- Interoperability failures that cause umbrik to accept a container another implementation would
  reject as invalid.

Out of scope:

- Weaknesses inherent to the CDOC2 specification that umbrik implements faithfully. Report these
  upstream; we will document them.
- Anything requiring an attacker who already controls the machine or the user's private keys.
- Missing hardening in the deferred milestones (capsule server, SC07) that are not implemented.

## Known accepted risks

### RSA timing side channel (RUSTSEC-2023-0071, "Marvin Attack")

The `rsa` crate umbrik uses for SC02 does not implement a fully constant-time private-key
operation, and there is no fixed release to upgrade to.

**What is affected:** SC02 decryption using a *software* RSA private key.

**What is not:** SC02 with a smart card or token — RSA-OAEP then runs inside the PKCS#11 module
and the private key never reaches the crate, which is the path Estonian legacy RSA cards take.
SC01, SC05 and SC06 do not use RSA at all, and encryption is a public-key operation.

**What an attack requires:** a decryption oracle — the ability to have many attacker-chosen
containers decrypted while precisely timing each one. Decrypting a file you were sent does not
put you in that position. An automated service that decrypts untrusted containers on demand
does; such a service should hold RSA keys in a token rather than in software.

This is recorded as an explicit, documented exception in `deny.toml` rather than suppressed, so
it stays visible in CI. It will be revisited if a constant-time implementation appears.

## Status

**umbrik has not been independently audited.** It is an independent implementation of a
published specification. Treat it accordingly, and see the disclaimers in `README.md`.

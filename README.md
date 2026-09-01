# umbrik

A Rust implementation of **CDOC2**, the Estonian encrypted file container format, with a command
line tool and a library.

> [!IMPORTANT]
> Not affiliated with, endorsed by, or supported by RIA, Cybernetica or SK ID Solutions. An
> independent implementation of a published open specification.
>
> **Unaudited**, and provided without warranty — see [`LICENSE`](LICENSE). If you need a
> supported tool, use the official [DigiDoc](https://www.id.ee/) software.

## Status

Targets **CDOC2 specification 1.7**.

| Scheme | What it is | Status |
|---|---|---|
| SC05 | Pre-shared symmetric key | Implemented |
| SC06 | Password (PBKDF2) | Implemented |
| SC01 | ECDH, secp384r1 / secp256r1 | Implemented, software keys and PKCS#11 tokens |
| SC02 | RSA-OAEP, legacy RSA cards | Implemented, software keys and PKCS#11 tokens |
| SC03 / SC04 | Capsule-server variants | Deferred |
| SC07 | N-of-N key shares (Smart-ID / Mobile-ID) | Out of scope — 2.0 draft only |

CDOC1, the legacy XML-Encryption format, is out of scope including read support.

All four implemented schemes are round-tripped against the reference `cdoc2-cli` in both
directions on every commit. SC01 has also been verified against a physical Estonian ID-card in
both directions with DigiDoc4.

## Install

```bash
brew install flatbuffers                               # macOS
apt install flatbuffers-compiler libssl-dev pkg-config  # Debian/Ubuntu

cargo build --release        # binary at target/release/umbrik
```

`flatc` must match the `flatbuffers` version pinned in `Cargo.toml`; `scripts/install-flatc.sh`
fetches the right one. OpenSSL is needed only for the eID directory lookup — build with
`--no-default-features` for a binary with no network access at all.

## Use

```bash
# Encrypt with a password, a pre-shared key, a certificate, or an id code
umbrik encrypt -f secrets.cdoc2 --password "my-label:hunter2" report.pdf
umbrik encrypt -f secrets.cdoc2 --secret "my-label:base64,$(head -c32 /dev/urandom | base64)" report.pdf
umbrik encrypt -f secrets.cdoc2 -c recipient.pem report.pdf
umbrik encrypt -f secrets.cdoc2 -r 38001085718 report.pdf

# Recipient options combine and repeat; any one of them opens the container
umbrik encrypt -f shared.cdoc2 -r 38001085718 -c colleague.pem --password "backup:hunter2" report.pdf

# Inspect
umbrik recipients -f secrets.cdoc2                      # no key needed
umbrik list -f secrets.cdoc2 --password "my-label:hunter2"

# Decrypt
umbrik decrypt -f secrets.cdoc2 --password "my-label:hunter2" -o ./out
umbrik decrypt -f secrets.cdoc2 -k private-key.pem -o ./out
umbrik decrypt -f secrets.cdoc2 --pkcs11 /opt/homebrew/lib/opensc-pkcs11.so -o ./out
```

Omit the password value to be prompted rather than putting it in shell history.

### Encrypting to an id code

`-r <isikukood>` looks up the recipient's **authentication** certificate in the Estonian eID
directory and encrypts to it. No card is needed to encrypt — only to decrypt.

Two caveats. It is a query to a public directory, which discloses the intended recipient to that
directory's operator; umbrik prints a line to stderr for each lookup rather than doing it
silently. And umbrik does not validate certificate chains, expiry or revocation — if that is not
acceptable, fetch the certificate yourself and pass it with `-c`.

### Recipient labels

Labels are machine-readable `data:` strings that viewers parse to show who a container is for.
The two reference implementations disagree on the details, so umbrik matches whichever will read
the container: `-r` writes the libcdoc form that DigiDoc4 renders, everything else writes the
form `cdoc2-cli` produces. `umbrik recipients` reads both.

## Python

```bash
pip install umbrik
```

```python
import umbrik

blob = umbrik.encrypt({"notes.txt": b"tere"}, password=("my-label", "hunter2"))
files = umbrik.decrypt(blob, password="hunter2")     # -> {"notes.txt": b"tere"}
```

One wheel per platform covers Python 3.10 and every later version. See
[`bindings/python/README.md`](bindings/python/README.md).

## Library

```rust
use umbrik_core::{container, DecryptionKey, Limits, PayloadFile, Recipient};

let files = vec![PayloadFile { name: "notes.txt".into(), data: b"tere".to_vec() }];
let recipient = Recipient::Password {
    label: umbrik_core::keylabel::password("my-label"),
    password: "hunter2".to_string().into(),
};

let mut out = Vec::new();
container::encrypt(&mut out, &mut rand::rngs::OsRng, &files, &[recipient])?;

let key = DecryptionKey::Password("hunter2".to_string().into());
let files = container::decrypt_to_memory(&out, &key, &Limits::default())?;
# Ok::<(), umbrik_core::Error>(())
```

The RNG is a parameter rather than a global, which is what makes byte-identical golden-file tests
possible: a wrong constant applied consistently in both directions passes a round trip.

## How it works

```
FMK  = HKDF-Extract("CDOC20salt", CSRNG(64))     # File Master Key, per container
CEK  = HKDF-Expand(FMK, "CDOC20cek",  32)        # payload key
HHK  = HKDF-Expand(FMK, "CDOC20hmac", 32)        # header MAC key
payload = ChaCha20-Poly1305(CEK, nonce, zlib(tar(files)), AAD)
EncryptedFMK_i = FMK XOR KEK_i                   # one per recipient
```

Only KEK establishment differs between schemes. Every constant is documented with a source
citation in [`docs/CRYPTO-CONSTANTS.md`](docs/CRYPTO-CONSTANTS.md).

Two consequences worth knowing:

- **The header MAC cannot be checked before the private-key operation**, since its key descends
  from the FMK. umbrik encodes this in the type system: verification consumes the parsed header
  and yields a `VerifiedHeader`, which is the only thing payload decryption accepts.
- **The payload is a single AEAD invocation**, so authentication completes before any plaintext
  is released and nothing unauthenticated reaches disk. The cost is that container size is
  bounded by available memory.

## Safety

Extraction enforces `Limits` — compression ratio, entry count, uncompressed size, recipient
count, and a cumulative PBKDF2 iteration budget — and rejects path traversal, absolute paths and
symlinks. These live inside the reader rather than being delegated to callers.

Exceeding a limit reports the actual figures and which setting governs them;
`--max-compression-ratio` and friends raise them for a container you trust. The ratio default is
100 rather than the reference implementation's 10, which rejects ordinary log files.

Key material is held in `Zeroizing` wrappers and never appears in errors, logs or `Debug` output.
MAC and tag comparisons are constant time.

## Testing

```bash
cargo test              # unit, header vectors, round trips, hostile payloads
tests/interop/run.sh    # both directions against the reference cdoc2-cli in Docker
```

Interop is a CI gate. Vectors in `tests/vectors/` were produced by the reference implementation,
not by umbrik — see [`tests/vectors/PROVENANCE.md`](tests/vectors/PROVENANCE.md).

Releases ship a CycloneDX SBOM and are signed with GitHub Artifact Attestations:

```bash
gh attestation verify ./umbrik --repo livenson/umbrik
```

## Versioning

Semantic versioning shared across the crates, CLI and PyPI package. The container wire format is
treated as part of the public API. See [`VERSIONING.md`](VERSIONING.md).

## Acknowledgements

CDOC2 is specified and maintained by [RIA](https://www.ria.ee/) and Cybernetica. The
specification and the MIT-licensed reference implementation
([`open-eid/cdoc2-java-ref-impl`](https://github.com/open-eid/cdoc2-java-ref-impl)) are the
sources for umbrik's constants, schemas and test vectors.

## Contributing

[`AGENTS.md`](AGENTS.md) has the conventions for changing this repository — several exist because
breaking them produced containers no other implementation could read. `CLAUDE.md` is a symlink to
it.

## License

MIT — see [`LICENSE`](LICENSE). Security policy: [`SECURITY.md`](SECURITY.md), and
[`docs/MAINTENANCE.md`](docs/MAINTENANCE.md) for how the project is kept current.

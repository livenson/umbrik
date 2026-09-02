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
| SC02 | RSA-OAEP, pre-2018 RSA cards | **Not supported** — out of scope |
| SC03 / SC04 | Capsule-server variants | Deferred |
| SC07 | N-of-N key shares (Smart-ID / Mobile-ID) | Out of scope — 2.0 draft only |

CDOC1, the legacy XML-Encryption format, is out of scope including read support. So is SC02:
Estonian cards have been elliptic-curve since 2018, and dropping RSA removed the project's only
outstanding security advisory along with it. An SC02 container still parses and reports an
unsupported scheme rather than failing as malformed.

All three implemented schemes are round-tripped against the reference `cdoc2-cli` in both
directions on every commit. SC01 has also been verified against a physical Estonian ID-card in
both directions with DigiDoc4.

## Install

### Download a release

Every [release](https://github.com/livenson/umbrik/releases/latest) carries prebuilt binaries
for Linux (glibc and static musl, x86_64 and aarch64), macOS (Intel and Apple silicon) and
Windows, plus the Python wheels, a `SHA256SUMS` file and a CycloneDX SBOM. No toolchain is
needed:

```bash
curl -LO https://github.com/livenson/umbrik/releases/latest/download/umbrik-x86_64-unknown-linux-gnu
gh attestation verify ./umbrik-x86_64-unknown-linux-gnu --repo livenson/umbrik
chmod +x umbrik-x86_64-unknown-linux-gnu && mv umbrik-x86_64-unknown-linux-gnu ~/.local/bin/umbrik
```

Substitute `umbrik-aarch64-apple-darwin`, `umbrik-x86_64-pc-windows-msvc.exe`, or another
name from the release page; each release lists which file is which. The `musl` builds are
fully static and have no network features, so they cannot do the eID directory lookup. The
`gh attestation` line checks that the file was produced by this repository's release workflow
from the tagged commit; see [Testing](#testing).

### Build from source

Debian/Ubuntu:

<!-- ci:install-linux -->
```bash
sudo apt-get update && sudo apt-get install -y libssl-dev pkg-config
scripts/install-flatc.sh
cargo build --release        # binary at target/release/umbrik
```

macOS:

```bash
brew install openssl@3 pkg-config
scripts/install-flatc.sh
cargo build --release
```

**Do not install `flatc` from your distribution.** umbrik generates its FlatBuffers codec at
build time, and the compiler must match the `flatbuffers` version pinned in `Cargo.toml`; the
packaged one lags and produces code that will not compile. `scripts/install-flatc.sh` reads the
required version from `Cargo.toml` and fetches it.

OpenSSL is needed only for the eID directory lookup. `cargo build --release --no-default-features`
gives a binary that needs neither OpenSSL nor any network access.

The Linux block above is executed verbatim by CI on a clean runner, so these steps cannot rot.

## Use

```bash
# Encrypt with a password, a pre-shared key, a certificate, or an id code
umbrik encrypt -f secrets.cdoc2 --password "my-label:hunter2" report.pdf
umbrik encrypt -f secrets.cdoc2 --secret "my-label:base64,$(head -c32 /dev/urandom | base64)" report.pdf
umbrik encrypt -f secrets.cdoc2 -c recipient.pem report.pdf   # EC certificates only
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

### Seeing what happened

`-v` explains what umbrik is doing; `-vv` adds byte counts and offsets:

```
$ umbrik decrypt -f secrets.cdoc2 --password "my-label:hunter2" -vv -o ./out
    header 396 bytes, payload 113 bytes (12 nonce + ciphertext + 16 tag)
  2 recipient(s):
    #0 SC06       my-label (pw)
    #1 SC05       backup (secret)
  trying 2 key candidate(s)
    limits: ratio 100, entries 1000, bytes 17179869184
  opened by recipient #0 (SC06) my-label (pw)
```

Diagnostics go to stderr, so they do not disturb piped output, and they never include key
material, passwords, PINs or plaintext — everything printed is either already visible to anyone
holding the container, or local to your machine. Tests assert this by running the binary at `-vv`
with a distinctive password and searching the output for it.

### Encrypting to an id code

`-r <isikukood>` looks up the recipient's **authentication** certificate in the Estonian eID
directory and encrypts to it. No card is needed to encrypt — only to decrypt.

One caveat: it is a query to a public directory, which discloses the intended recipient to that
directory's operator. umbrik prints a line to stderr for each lookup rather than doing it
silently.

### What umbrik checks about a certificate

**Validity dates are checked.** A certificate outside its window is refused, because encrypting
to one usually means encrypting to a card that has been replaced — the container would be
unopenable. `--allow-expired` overrides it with a warning.

**Chains and revocation are not checked.** Both need infrastructure umbrik deliberately avoids: a
trust store of eID roots to keep current, and an OCSP or CRL lookup on every encryption. Neither
adds much where recipients actually come from — `-r` fetches over an authenticated TLS connection
to the directory that issued the certificate, and `-c` takes a file you chose. If you obtain a
certificate from an untrusted source, validate it before passing it here.

### Recipient labels

Labels are machine-readable `data:` strings that viewers parse to show who a container is for.
The two reference implementations disagree on the details, so umbrik matches whichever will read
the container: `-r` writes the libcdoc form that DigiDoc4 renders, everything else writes the
form `cdoc2-cli` produces. `umbrik recipients` reads both.

## Python

The package is not on PyPI yet. Download the wheel for your platform from the
[release page](https://github.com/livenson/umbrik/releases/latest) and install it:

```bash
pip install ./umbrik-*.whl
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

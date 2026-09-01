# umbrik

A Rust implementation of **CDOC2**, the Estonian encrypted file container format, with a command
line tool and a library.

> [!IMPORTANT]
> umbrik is **not affiliated with, endorsed by, or supported by** RIA (Estonian Information
> System Authority), Cybernetica, or SK ID Solutions. It is an independent implementation of a
> publicly published open specification.
>
> **It has not been independently audited.** It is provided without warranty of any kind — see
> [`LICENSE`](LICENSE). If you need a supported tool, use the official
> [DigiDoc](https://www.id.ee/) software.

## Status

Early. The container format and the two key-based schemes work and are verified against the
reference implementation in both directions on every commit.

| Scheme | What it is | Status |
|---|---|---|
| SC05 | Pre-shared symmetric key | Implemented |
| SC06 | Password (PBKDF2) | Implemented |
| SC01 | ECDH on secp384r1 / secp256r1 | Implemented, software keys and PKCS#11 tokens |
| SC02 | RSA-OAEP — legacy RSA cards | Implemented, software keys and PKCS#11 tokens |
| SC03 / SC04 | Capsule-server variants of SC01/SC02 | Deferred |
| SC07 | N-of-N key shares (Smart-ID / Mobile-ID) | Out of scope — spec 2.0 draft only |

All four implemented schemes are round-tripped against the reference `cdoc2-cli` in both
directions on every commit. SC01 has additionally been verified end to end against a physical
Estonian ID-card: DigiDoc4 opens a container umbrik encrypted to the card, and umbrik opens a
container DigiDoc4 encrypted to it.

CDOC1, the legacy XML-Encryption format, is out of scope, including read support.

Targets **CDOC2 specification 1.7**.

## Install

Building generates the FlatBuffers codec, so you need the FlatBuffers compiler. Its version must
match the `flatbuffers` crate version pinned in `Cargo.toml`.

```bash
brew install flatbuffers                              # macOS
apt install flatbuffers-compiler libssl-dev pkg-config # Debian/Ubuntu

cargo build --release             # binary at target/release/umbrik
```

The OpenSSL dependency is only for the eID directory lookup (`-r`). `esteid.ldap.sk.ee`
negotiates a TLS 1.2 cipher suite that rustls will not offer, so that code path needs native
TLS. Build with `--no-default-features` for a binary with no directory lookup and no network
access at all — it needs neither OpenSSL nor a network stack.

## Use

```bash
# Encrypt with a password
umbrik encrypt -f secrets.cdoc2 --password "my-label:hunter2" report.pdf notes.txt

# Encrypt with a pre-shared 32-byte key
umbrik encrypt -f secrets.cdoc2 --secret "my-label:base64,$(head -c32 /dev/urandom | base64)" report.pdf

# See who a container is addressed to — no key needed
umbrik recipients -f secrets.cdoc2

# Inspect contents without extracting
umbrik list -f secrets.cdoc2 --password "my-label:hunter2"

# Encrypt to a recipient's certificate (SC01 for EC keys, SC02 for RSA)
umbrik encrypt -f secrets.cdoc2 -c recipient.pem report.pdf

# Encrypt to an Estonian id code, resolving the certificate from the eID directory
umbrik encrypt -f secrets.cdoc2 -r 38001085718 report.pdf

# Decrypt
umbrik decrypt -f secrets.cdoc2 --password "my-label:hunter2" -o ./out
umbrik decrypt -f secrets.cdoc2 -k my-private-key.pem -o ./out

# Decrypt with a smart card or token (PIN is prompted, or read from stdin when piped)
umbrik decrypt -f secrets.cdoc2 --pkcs11 /Library/OpenSC/lib/opensc-pkcs11.so -o ./out
```

Omit the password value to be prompted rather than putting it in your shell history.

Recipient options combine and repeat, and every recipient can open the container:

```bash
umbrik encrypt -f shared.cdoc2 \
  -r 38001085718 \
  -c colleague.pem \
  --password "backup:correct horse battery staple" \
  report.pdf
```

### Recipient labels

Recipient labels are machine-readable, not free text: a `data:` URL scheme that viewers parse to
show who a container is addressed to.

**The two reference implementations disagree on the details**, and the specification does not pin
them down. They differ in key case, ordering, whether `serial_number` keeps its `PNOEE-` prefix,
and whether the certificate expiry is carried at all:

| | `cdoc2-java-ref-impl` | libcdoc / DigiDoc4 |
|---|---|---|
| key case | `V`, `CN`, `TYPE` | `v`, `cn`, `type` |
| ordering | sorted | `v` first, then insertion order |
| `serial_number` | id code alone | keeps `PNOEE-` prefix |
| expiry | absent | `server_exp` (certificate `notAfter`) |

umbrik matches whichever implementation will read the container:

- **`-r <isikukood>`** writes the libcdoc form, byte-identical to what DigiDoc4 itself produces —
  so DigiDoc4 shows the name, card type, and "Decryption is possible until …".
- **`-c`, `--pubkey`, `--password`, `--secret`** write the reference CLI's form, byte-identical
  to `cdoc2-cli` for the same input.

`umbrik recipients` reads both cases, so it decodes containers from either tool:

```
$ umbrik recipients -f secrets.cdoc2
SC01    TESTIJA,MARI,00000000000 (ID-card)
```

Plain labels from older containers are shown verbatim.

Note that `server_exp` is the only way a viewer can know when decryption stops being possible: a
CDOC2 capsule stores the raw public key, never the certificate, so the expiry is not otherwise
recoverable from the container.

Note that for SC05 and SC06 the label is an input to key derivation, so it is part of the
container's cryptography and not only its presentation.

### Encrypting to an id code

`-r <isikukood>` looks the recipient's **authentication** certificate up in the public Estonian
eID directory (`ldaps://ldap.eidpki.ee`) and encrypts to that key. No card or reader is needed to
*encrypt* — only to decrypt.

Two things to be aware of:

- **It is a network query to a public directory**, which discloses to that directory's operator
  who you are about to encrypt for. umbrik prints a line to stderr whenever it performs one
  rather than doing it silently. Build with `--no-default-features` for a binary that cannot
  make network connections at all.
- **umbrik does not validate certificate chains, expiry, or revocation.** It treats the directory
  as the authority on which key belongs to an id code. If that is not acceptable for your threat
  model, fetch and validate the certificate yourself and pass it with `-c`.

Decryption with a physical ID-card (PKCS#11, PIN1) is not implemented yet; `-k` currently takes a
software private key in PEM.

### Library

```rust
use umbrik_core::{container, DecryptionKey, Limits, PayloadFile, Recipient};

let files = vec![PayloadFile { name: "notes.txt".into(), data: b"tere".to_vec() }];
let recipient = Recipient::Password {
    label: "my-label".into(),
    password: "hunter2".to_string().into(),
};

let mut out = Vec::new();
container::encrypt(&mut out, &mut rand::rngs::OsRng, &files, &[recipient])?;

let key = DecryptionKey::Password("hunter2".to_string().into());
let files = container::decrypt_to_memory(&out, &key, &Limits::default())?;
# Ok::<(), umbrik_core::Error>(())
```

The RNG is a parameter rather than a global. That is what makes byte-identical golden-file tests
possible: a wrong constant applied consistently in both directions passes a round-trip test, and
only a golden file or a cross-implementation test will catch it.

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

Two consequences worth knowing about:

- **The header MAC cannot be checked before the private-key operation**, because the MAC key
  descends from the FMK. umbrik encodes this in the type system: verifying consumes the parsed
  header and yields a `VerifiedHeader`, and payload decryption accepts nothing else.
- **The payload is a single AEAD invocation**, not a framed stream, so authentication completes
  before any plaintext is released. umbrik therefore never writes unauthenticated bytes to disk.
  The cost is that container size is bounded by available memory.

## Safety

Extraction enforces `Limits` — compression ratio, entry count, uncompressed size, recipient
count, and a cumulative PBKDF2 iteration budget — and rejects path traversal, absolute paths,
and symlinks by default. These are enforced inside the reader rather than delegated to callers.

Limits fail with a message naming the actual figures and which setting governs them, and
`--max-compression-ratio`, `--max-uncompressed-bytes` and `--max-entries` raise them for a
container you trust. The compression-ratio default is 100 rather than the reference
implementation's 10: text and log files routinely compress past 20:1, and 10 rejects real
containers while a true zip bomb reaches 1000:1 and beyond.

Key material is held in `Zeroizing` wrappers and never appears in errors, logs, or `Debug`
output. MAC and tag comparisons are constant time.

## Testing

```bash
cargo test              # unit, header vectors, round trips, hostile payloads
tests/interop/run.sh    # both directions against the reference cdoc2-cli in Docker
```

Interop is a CI gate. Test vectors in `tests/vectors/` were produced by the reference
implementation, not by umbrik — see `tests/vectors/PROVENANCE.md`.

## Acknowledgements

CDOC2 is specified and maintained by [RIA](https://www.ria.ee/) and Cybernetica. The
specification and the MIT-licensed reference implementation
([`open-eid/cdoc2-java-ref-impl`](https://github.com/open-eid/cdoc2-java-ref-impl)) are the
sources for umbrik's constants, schemas, and test vectors.

## License

MIT — see [`LICENSE`](LICENSE). Security policy: [`SECURITY.md`](SECURITY.md).

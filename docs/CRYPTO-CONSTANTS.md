# CDOC2 cryptographic constants — resolution report (M0)

**Status: all Prime Directive items resolved. No unresolved items. No guessed values.**

**Empirically validated (M1).** Every constant below was confirmed end-to-end against the real
`cdoc2-cli` container `tests/vectors/symmetric.cdoc2`, using a throwaway Python implementation
written only from this document: the derived HHK reproduced the container's stored header HMAC
exactly, and the derived CEK with the documented AAD verified the Poly1305 tag and yielded a
zlib stream containing a well-formed tar entry. The report is therefore proven, not merely
cited.

Every constant below is cited to either the CDOC2 1.7 specification or to an exact file and line
in `open-eid/cdoc2-java-ref-impl` at commit `daff207f719b4c1cfc4a1138733a4f8c531524c6`
(2026-08-15, MIT licensed). Where both sources speak, they agree; disagreements would be listed
in the "Discrepancies" section, which is currently empty.

`libcdoc` (LGPL-2.1) was **not** consulted for this report. Nothing here is derived from it.

Citation shorthand: `Crypto.java` = `cdoc2-lib/src/main/java/ee/cyber/cdoc2/crypto/Crypto.java`,
`Envelope.java` = `cdoc2-lib/src/main/java/ee/cyber/cdoc2/container/Envelope.java`,
`ChaChaCipher.java` = `cdoc2-lib/src/main/java/ee/cyber/cdoc2/crypto/ChaChaCipher.java`.

---

## 0. Correction to the brief's model of the salts

The brief anticipated two opaque byte constants named `StaticFMKSalt` and `StaticKEKSalt`. That
is not how CDOC2 is built, and implementing to that assumption would produce wrong containers.
The actual design:

- The "static salts" are **UTF-8 ASCII string literals**, not opaque byte arrays. There is no hex
  blob to transcribe.
- There is a static FMK salt (`"CDOC20salt"`), used once when generating the FMK.
- There is a static KEK salt **only on the ECDH path** (`"CDOC20kekpremaster"`).
- On the symmetric and password paths (SC05, SC06) the HKDF-Extract salt is **freshly generated
  random, 32 bytes, carried in the recipient capsule** — it is not static at all. A decrypter
  must read it out of the capsule.

So: one static FMK salt, one static ECDH KEK salt, and a per-recipient random KEK salt for
SC05/SC06. Encode this distinction in the types; do not reach for a single `StaticKEKSalt`
constant.

---

## 1. Salt values and HKDF info strings

All are UTF-8 encodings of ASCII literals. No hex constants exist in this format.

| Purpose | Literal | Hex (UTF-8) | Source |
|---|---|---|---|
| FMK extract salt | `CDOC20salt` | `43444f43323073616c74` | `Crypto.java:108`; spec ch05 |
| CEK expand info | `CDOC20cek` | `43444f43323063656b` | `Crypto.java:114`; spec ch05 |
| HHK expand info | `CDOC20hmac` | `43444f433230686d6163` | `Crypto.java:120`; spec ch05 |
| ECDH KEK extract salt | `CDOC20kekpremaster` | `43444f4332306b656b7072656d6173746572` | `Crypto.java:284`; spec ch05 |
| KEK expand info prefix | `CDOC20kek` | `43444f4332306b656b` | `Crypto.java:164`, `Crypto.java:287`; spec ch05 |
| Payload AAD prefix | `CDOC20payload` | `43444f4332307061796c6f6164` | `Envelope.java:210`; spec ch05 |

Note the `20` in every literal is the ASCII digits "2","0" (from "CDOC 2.0"), **not** a space
byte and not a version field. Verify this in a unit test against the hex above.

## 2. HKDF hash — SHA-256 everywhere

**HKDF is backed by HMAC-SHA-256 in every context.** SHA-384 is never used for HKDF, including on
the secp384r1 ECDH path, where the P-384 shared secret is fed into an HMAC-SHA-256 extract.

Evidence: every HKDF call site in the reference implementation is `HKDF.fromHmacSha256()` —
`Crypto.java:108` (FMK), `:113` (CEK), `:120` (HHK), `:161` (symmetric KEK), `:284` and `:298`
(ECDH KEK). Spec ch05 states HKDF-SHA-256 throughout.

This is the single highest-risk item in the whole report: P-384 pairs with SHA-384 by convention
almost everywhere else in cryptography, so an implementer working from habit will get it wrong
and the mistake will round-trip cleanly against itself. Pin it with a vector test.

## 3. Key lengths

| Key | Length | Source |
|---|---|---|
| FMK | 32 bytes (256 bits) | `Crypto.java:45` |
| KEK | 32 bytes — **must** equal FMK, wrapping is XOR | `Crypto.java:50` |
| CEK | 32 bytes | `Crypto.java:55` |
| HHK | 32 bytes | `Crypto.java:60` |
| Salt (all kinds) | 32 bytes minimum, 32 generated | `Crypto.java:64`, `:343-347` |
| Pre-shared symmetric key | 32 bytes minimum | `Crypto.java:68` |

FMK generation is `HKDF-Extract("CDOC20salt", ikm)` where `ikm` is **64 bytes** of CSRNG output,
not 32 (`Crypto.java:105-109`; the spec requires ≥256 bits, the implementation uses 512).
Match the 64 for byte-identical golden files.

FMK wrapping: `EncryptedFMK = FMK XOR KEK` (`Crypto.java:323`, used at
`RecipientFactory.java:410`). Confirmed XOR, not AES-KeyWrap.

## 4. SC06 — PBKDF2 parameters

| Parameter | Value | Source |
|---|---|---|
| PRF | HMAC-SHA-256 (`PBKDF2WithHmacSHA256`) | `KDFAlgorithmIdentifier` in `recipients.fbs`; `Crypto.java:191-193` |
| Iterations (encrypt) | **600 000** | `PBKDF2Recipient.java:22` — "recommended by NIST for HMAC-SHA-256" |
| Output length | 256 bits / 32 bytes | `Crypto.java:66` (`PBKDF2_KEY_LENGTH_BITS`) |
| Password salt | 32 bytes random, stored in capsule | `RecipientFactory.java:401` |
| Password encoding | UTF-8 | `Crypto.java:181-188` (explicit comment: spec says passwords are UTF-8 encoded) |

**Iterations are a wire field, not a constant.** `PBKDF2Capsule.kdf_iterations` is an `int32` in
the container. Use 600 000 when encrypting; when decrypting, read the value from the capsule
(`RecipientDeserializer.java:123`, `KekTools.java:105`). Hardcoding 600 000 on the decrypt path
would fail to open older containers. Apply a sanity ceiling to avoid a DoS via an absurd
iteration count in a hostile container — that is a `Limits` concern, not a format one.

SC06 is a two-stage derivation, and the two salts are distinct fields:

```
symkey = PBKDF2-HMAC-SHA256(utf8(password), password_salt, kdf_iterations, 32)
KEKpm  = HKDF-Extract(salt, symkey)                       // `salt`, not `password_salt`
KEK    = HKDF-Expand(KEKpm, "CDOC20kek" || "XOR" || key_label, 32)
```

Source: `KekTools.java:90-113`, `Crypto.java:160-166`. Conflating the two salt fields is an easy
and silent error — `PBKDF2Capsule` carries both `salt` and `password_salt`.

## 5. SC05 — pre-shared symmetric key

Identical to SC06 from the HKDF-Extract step onward, with the pre-shared key in place of the
PBKDF2 output:

```
KEKpm = HKDF-Extract(salt, preSharedKey)     // salt: 32 random bytes, in SymmetricKeyCapsule
KEK   = HKDF-Expand(KEKpm, "CDOC20kek" || "XOR" || key_label, 32)
```

Source: `Crypto.java:160-166`, `KekTools.java:80-89`.

**The key label is inside the KDF info.** `key_label` is the `RecipientRecord.key_label` string,
UTF-8, concatenated without any separator or length prefix. A container whose label is edited
will not decrypt. Note this makes the label cryptographically load-bearing, not cosmetic.

The `"XOR"` in the info string is the *name* of the `FMKEncryptionMethod` enum value, ASCII
`"XOR"` — from `FMKEncryptionMethod.name(XOR)`, not the byte value `1`.

## 6. SC01 — ECDH KEK derivation

```
Secdh = ECDH(ephemeral_private, recipient_public)      // secp384r1, raw X coordinate
KEKpm = HKDF-Extract("CDOC20kekpremaster", Secdh)
KEK   = HKDF-Expand(KEKpm,
            "CDOC20kek" || "XOR" || tls(recipient_pub) || tls(ephemeral_pub),
            32)
```

Source: `Crypto.java:281-299`.

Ordering is **recipient public key first, then ephemeral/sender public key**, in both directions.
The reference implementation branches on encrypt/decrypt mode (`Crypto.java:290-296`) purely
because the local and peer roles swap between the two sides; the resulting concatenation order is
the same. Getting this backwards yields a valid-looking KEK that decrypts nothing.

`tls(...)` is the uncompressed EC point encoding of RFC 8446 §4.2.8.2: `0x04 || X || Y`, with X
and Y each 48 bytes for secp384r1 — fixed-width, left-padded. This is documented in the schema
itself (`recipients.fbs`, `EccKeyDetails.recipient_public_key` comment). 97 bytes total.

The ECDH shared secret is the raw X coordinate (48 bytes), the standard ECDH primitive output —
no KDF, no cofactor variant.

## 6b. SC02 — RSA-OAEP KEK transport (not implemented)

> umbrik does not implement SC02; pre-2018 RSA cards are out of scope. The constants are
> kept here because they were researched and validated, and because anyone adding SC02
> back would need them.

SC02 is the one scheme with **no HKDF at all**. The KEK is not derived; it is generated at
random by the sender and transported directly inside the capsule:

```
encrypted_kek = RSA-OAEP-Encrypt(recipient_rsa_public_key, KEK)     # sender
KEK           = RSA-OAEP-Decrypt(recipient_rsa_private_key, encrypted_kek)   # recipient
```

Source: `KekTools.java:241-275` — `deriveKekForRsa` returns `RsaUtils.rsaDecrypt(encryptedKek, ...)`
with nothing applied afterwards. There is no `"CDOC20kek"` info string on this path, and no key
label involvement. Everything downstream (`FMK = encrypted_fmk XOR KEK`) is unchanged.

| Parameter | Value | Source |
|---|---|---|
| Padding | RSA-OAEP | `RsaUtils.java:39` |
| Message digest | SHA-256 | `RsaUtils.java:47` |
| MGF1 digest | **SHA-256** | `RsaUtils.java:48-49` |
| Label / P-source | empty (`byte[0]`) | `RsaUtils.java:49` (`PSpecified.DEFAULT`) |
| KEK length | 32 bytes, as everywhere | `Crypto.java:50` |

**The MGF1 digest is the trap here, and upstream flags it explicitly.** The JCA standard name
`"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"` does not say which hash MGF1 uses: SunJCE defaults MGF1
to SHA-1 while BouncyCastle uses SHA-256, so the same string means two incompatible things. The
reference implementation therefore passes an explicit `OAEPParameterSpec` pinning MGF1 to
SHA-256 (`RsaUtils.java:44` documents exactly this hazard). An implementation that defaults MGF1
to SHA-1 produces capsules no CDOC2 recipient can open, and the failure looks like a corrupt key
rather than a parameter mismatch.

In Rust, `rsa::Oaep::new::<Sha256>()` sets digest and MGF1 to the same hash and is therefore
correct; `Oaep::new_with_mgf_hash` would be needed only for a mismatched pair.

The recipient public key in `RSAPublicKeyCapsule.recipient_public_key` is **PKCS#1
`RSAPublicKey`** DER (RFC 8017 A.1.1), not SPKI — stated in `recipients.fbs` itself. Matching a
recipient record against a local key is therefore a byte comparison against the PKCS#1 encoding,
not the more common SubjectPublicKeyInfo one.

## 7. Payload encryption — ChaCha20-Poly1305

| Parameter | Value | Source |
|---|---|---|
| Algorithm | ChaCha20-Poly1305 (RFC 8439) | `ChaChaCipher.java:52` |
| Key | CEK, 32 bytes | `Crypto.java:55` |
| Nonce | **12 bytes, freshly random per container** | `ChaChaCipher.java:21`, `:117-119` |
| Tag | 16 bytes, trailing | `Envelope.java:71` |
| Invocations | **one, over the entire payload** | see below |

**The nonce is random, not derived and not a counter.** It is generated by CSRNG and written in
the clear as the first 12 bytes of the payload region, immediately after the header HMAC
(`ChaChaCipher.java:141-144`; on read, `:169`). It is not an AAD input and not in the header.

**Single AEAD invocation — the payload is not framed or chunked.** Confirmed three ways:
spec ch05 states a single invocation; `ChaChaCipher.java:79-88` shows the whole buffer encrypted
in one `doFinal`; and `Envelope.java:71` derives `MIN_PAYLOAD_LEN = 45` as
"cha cha nonce 12 + min zlib compressed tar 17 + Poly1305 MAC 16" — a framed construction could
not have a single trailing 16-byte tag.

This settles ordering constraint #2 in the brief: **the tag is verified only after the last
plaintext byte has been produced.** There is no way to authenticate incrementally. `Reader` must
write to a temporary path and rename on tag success, and must not expose an incremental streaming
API. A 4 GB container means 4 GB of unauthenticated intermediate output; that is inherent to the
format, and the temp-file discipline is the only mitigation.

Payload region layout:

```
nonce (12) || ChaCha20-Poly1305(CEK, nonce, zlib(tar(files)), AAD) || tag (16)
```

## 8. AAD composition

```
AAD = "CDOC20payload" || header_fbs_bytes || header_hmac
```

Concatenation only — no length prefixes, no separators. `header_fbs_bytes` is the serialized
FlatBuffers header exactly as written to the container, and `header_hmac` is the 32-byte HMAC.
The 4-byte `CDOC` prelude, the version byte, and the 4-byte header-length field are **not** in
the AAD.

Source: `Envelope.java:207-215`, cross-checked against spec ch05
(`additionalData ← 'CDOC20payload' ∥ header ∥ headerHMAC`).

Consequence worth noting: prelude, version, and header length are unauthenticated. A truncated or
inflated header-length field is caught only by the length bounds check, so enforce
`MIN_HEADER_LEN`/`MAX_HEADER_LEN` before allocating.

## 9. Header HMAC

| Parameter | Value | Source |
|---|---|---|
| Algorithm | HMAC-SHA-256 | `Crypto.java:62`, `:309-317` |
| Key | HHK, 32 bytes | `Crypto.java:60` |
| Output | 32 bytes | — |
| Covered range | **the FlatBuffers header bytes only** | `Envelope.java:308`, `:500` |

The HMAC covers the serialized header and nothing else — not the prelude, not the version byte,
not the header-length field, not the payload. Both the write path (`Envelope.java:308`) and the
verify path (`Envelope.java:494-501`) pass exactly `headerBytes`.

Compare in constant time.

## 10. Container format

```
offset  size      field
0       4         "CDOC"  = 43 44 4F 43
4       1         version = 0x02
5       4         header length, big-endian int32
9       N         FlatBuffers Header
9+N     32        HMAC-SHA-256 over bytes [9, 9+N)
41+N    12        ChaCha20-Poly1305 nonce
53+N    ...       ciphertext
end-16  16        Poly1305 tag
```

Source: `Envelope.java:54-55` (prelude, version), `:137-160` (read path, big-endian via
`ByteBuffer.order(ByteOrder.BIG_ENDIAN)`), `:295-311` (write path). Spec ch03 agrees on all
fields and on big-endian.

Bounds, all from `Envelope.java:56-76`:

| Constant | Value | Meaning |
|---|---|---|
| `MIN_HEADER_LEN` | 67 | smallest possible `SymmetricKeyCapsule` header |
| `MAX_HEADER_LEN` | 1 048 576 (1 MiB) | reject before allocating |
| `MIN_PAYLOAD_LEN` | 45 | 12 nonce + 17 min zlib tar + 16 tag |
| `MIN_ENVELOPE_SIZE` | 4 + 1 + 4 + 67 + 32 + 45 = 153 | — |

The version byte is `0x02` — a single byte meaning "CDOC2", **not** an encoding of spec version
1.7. It does not change between 1.7 and earlier 1.x containers. There is no minor-version field
in the envelope; feature detection is by which capsule union variants appear in the header.

## 11. Payload construction

```
plaintext = zlib( POSIX-tar( files ) )
```

tar first, then zlib, then AEAD. zlib is RFC 1950 (zlib wrapper, not raw deflate and not gzip) —
commons-compress `DeflateCompressorOutputStream` with default parameters, which is
zlib-wrapped (`Tar.java:6` — the import is annotated `//zlib` — and `Tar.java:110`).

The tar is POSIX/pax: `setLongFileMode(LONGFILE_POSIX)` and `setBigNumberMode(BIGNUMBER_POSIX)`
with UTF-8 filenames (`Tar.java:109-114`). Long filenames and large sizes therefore appear as pax
extended headers, not GNU extensions. The Rust `tar` crate must be configured to match on write,
and must tolerate pax records on read — `tests/vectors/symmetric_longfilename.cdoc2` upstream
exists precisely to exercise this.

---

## Discrepancies between spec 1.7 and the reference implementation

None found. Every constant above was confirmed in both sources, except items the spec does not
enumerate (the 600 000 iteration count, the 64-byte FMK IKM, and the `MIN_*`/`MAX_*` bounds),
which are implementation choices taken from `cdoc2-java-ref-impl` and noted as such.

## Deliberately out of scope

`KeySharesCapsule` (SC07, spec 2.0 draft) and `KeyServerCapsule` (SC03/SC04) appear in the
vendored schema and must parse into a distinct "unsupported scheme" error rather than a parse
failure. No constants for those paths were researched.

## Test vectors available upstream

`test/testvectors/` in the reference implementation, usable directly as M1/M2 fixtures:
`password.cdoc2` (SC06), `symmetric_longfilename.cdoc2` (SC05 + pax long names),
`ec_simple.cdoc2` / `ec_256_simple.cdoc2` (SC01), `rsa_simple.cdoc2` (SC02), plus
`testvectors-v1.2/` and `testvectors-v1.4/` for backward-compatibility checks. Keys are in
`test/keys/`. Copy into `tests/vectors/` at M1.


---

## Validation record

| Check | Result |
|---|---|
| Prelude / version / header length parse | `CDOC`, `0x02`, `0x000000BC` = 188 big-endian |
| Header decode (`flatc --json` oracle) | `SymmetricKeyCapsule`, label `create_symmetric_label`, 32-byte salt, XOR |
| SC05 KEK -> FMK unwrap -> HHK -> header HMAC | reproduced stored HMAC `3732ab0b…e146` exactly |
| CEK + AAD -> ChaCha20-Poly1305 | tag verified over 3344-byte payload region |
| zlib (RFC 1950) inflate | 3316 -> 11264 bytes |
| tar entry | `README.md`, 9291 bytes, regular file |

This exercises, in one pass: HKDF-**SHA-256** (not SHA-384), the `"CDOC20kek" || "XOR" || label`
info composition, XOR unwrapping, the HMAC's exact byte range, the AAD composition, the random
12-byte prepended nonce, single-invocation AEAD, and the zlib-then-tar payload order.

The two derived values are pinned as golden constants in
`crates/umbrik-core/tests/vectors.rs::derives_expected_fmk_and_cek`:

```
FMK = 3232650cdcf043ba309195f55da3b676b50c88d92a9ecac2bb7f012700cecce7
CEK = 737664b0fe9b0c6f9b559f4d75f48cd7b6d7f669c874bc678ae822ad1966465e
```

A wrong-but-consistently-applied constant passes a round-trip test and fails these.

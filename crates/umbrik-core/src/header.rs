//! L0 — container framing and the FlatBuffers header codec.
//!
//! Pure decoding into owned types. No traits, no I/O, no cryptography. Every constant here is
//! sourced in `docs/CRYPTO-CONSTANTS.md`.

use crate::error::{Error, Result};

// flatc emits `root_as_*_unchecked` helpers that are `unsafe fn`. umbrik never calls them —
// decoding goes through the verifying `flatbuffers::root` — but their mere presence trips the
// crate-level `deny(unsafe_code)`, so generated code gets a scoped exception. Hand-written
// umbrik code remains unsafe-free.
#[allow(
    unsafe_code,
    dead_code,
    unused_imports,
    clippy::all,
    clippy::pedantic,
    non_snake_case,
    non_camel_case_types
)]
mod fbs {
    include!(concat!(env!("OUT_DIR"), "/header_generated.rs"));
}

use fbs::ee::cyber::cdoc_2::fbs::header as fbs_header;
use fbs::ee::cyber::cdoc_2::fbs::recipients as fbs_recipients;

/// Container magic. `Envelope.java:54`.
pub const PRELUDE: [u8; 4] = *b"CDOC";
/// Format version byte. Means "CDOC2"; unrelated to the 1.7 spec revision. `Envelope.java:55`.
pub const VERSION: u8 = 0x02;
/// `PRELUDE` + version + big-endian u32 header length.
pub const ENVELOPE_PREFIX_LEN: usize = PRELUDE.len() + 1 + 4;
/// HMAC-SHA-256 output.
pub const HMAC_LEN: usize = 32;
/// Smallest possible header: a `SymmetricKeyCapsule`. `Envelope.java:56`.
pub const MIN_HEADER_LEN: usize = 67;
/// Reject before allocating. `Envelope.java:73`.
pub const MAX_HEADER_LEN: usize = 1024 * 1024;
/// 12-byte nonce + 17-byte minimum zlib-compressed tar + 16-byte tag. `Envelope.java:71`.
pub const MIN_PAYLOAD_LEN: usize = 45;

/// A parsed container envelope: the framing around the header, borrowed from the input.
///
/// Parsing does not authenticate anything. The header HMAC cannot be checked until the FMK has
/// been unwrapped, which needs a private-key operation — see [`crate::keys::VerifiedHeader`].
#[derive(Debug, Clone, Copy)]
pub struct Envelope<'a> {
    header_bytes: &'a [u8],
    header_hmac: &'a [u8; HMAC_LEN],
    payload: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Split a container into header, HMAC, and payload.
    ///
    /// The prelude, version byte, and header-length field are *not* covered by the header HMAC
    /// or the payload AAD, so the bounds checks here are the only thing standing between a
    /// hostile length field and a large allocation. They run before anything is copied.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        // Destructure the fixed prefix rather than indexing, so this function is total for
        // every possible input. It is the fuzz entry point and must never panic.
        let prefix: &[u8; ENVELOPE_PREFIX_LEN] = buf
            .get(..ENVELOPE_PREFIX_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Truncated {
                expected: ENVELOPE_PREFIX_LEN as u64,
                found: buf.len() as u64,
            })?;
        let [m0, m1, m2, m3, version, l0, l1, l2, l3] = *prefix;

        if [m0, m1, m2, m3] != PRELUDE {
            return Err(Error::BadPrelude);
        }
        if version != VERSION {
            return Err(Error::UnsupportedVersion {
                found: version,
                supported: VERSION,
            });
        }

        // Big-endian u32, widened to u64 so an out-of-range value is reported, not wrapped.
        let header_len = u64::from(u32::from_be_bytes([l0, l1, l2, l3]));
        if header_len < MIN_HEADER_LEN as u64 || header_len > MAX_HEADER_LEN as u64 {
            return Err(Error::HeaderLengthOutOfRange {
                found: header_len,
                min: MIN_HEADER_LEN,
                max: MAX_HEADER_LEN,
            });
        }
        // Bounded by MAX_HEADER_LEN above, so this cannot truncate.
        let header_len = header_len as usize;

        let truncated = |expected: usize| Error::Truncated {
            expected: expected as u64,
            found: buf.len() as u64,
        };

        let rest = buf
            .get(ENVELOPE_PREFIX_LEN..)
            .ok_or_else(|| truncated(ENVELOPE_PREFIX_LEN))?;
        let header_bytes = rest
            .get(..header_len)
            .ok_or_else(|| truncated(ENVELOPE_PREFIX_LEN + header_len))?;
        let after_header = rest
            .get(header_len..)
            .ok_or_else(|| truncated(ENVELOPE_PREFIX_LEN + header_len))?;

        let header_hmac: &[u8; HMAC_LEN] = after_header
            .get(..HMAC_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| truncated(ENVELOPE_PREFIX_LEN + header_len + HMAC_LEN))?;
        let payload = after_header
            .get(HMAC_LEN..)
            .ok_or_else(|| truncated(ENVELOPE_PREFIX_LEN + header_len + HMAC_LEN))?;

        if payload.len() < MIN_PAYLOAD_LEN {
            return Err(truncated(
                ENVELOPE_PREFIX_LEN + header_len + HMAC_LEN + MIN_PAYLOAD_LEN,
            ));
        }

        Ok(Envelope {
            header_bytes,
            header_hmac,
            payload,
        })
    }

    /// The serialized FlatBuffers header, exactly as stored. This is the byte range the header
    /// HMAC covers and the middle third of the payload AAD.
    pub fn header_bytes(&self) -> &'a [u8] {
        self.header_bytes
    }

    pub fn header_hmac(&self) -> &'a [u8; HMAC_LEN] {
        self.header_hmac
    }

    /// Nonce, ciphertext, and trailing tag.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Decode the header into owned types.
    pub fn decode_header(&self) -> Result<Header> {
        Header::decode(self.header_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEncryptionMethod {
    ChaCha20Poly1305,
    Unknown(i8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FmkEncryptionMethod {
    /// The only defined method. KEK length must equal FMK length.
    Xor,
    Unknown(i8),
}

impl FmkEncryptionMethod {
    /// The ASCII name used inside the KEK derivation info string — `"XOR"`, not the byte `1`.
    /// See `docs/CRYPTO-CONSTANTS.md` §5.
    pub fn kdf_name(&self) -> Result<&'static str> {
        match self {
            FmkEncryptionMethod::Xor => Ok("XOR"),
            FmkEncryptionMethod::Unknown(v) => Err(Error::UnsupportedFmkEncryptionMethod(*v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    Secp384r1,
    Secp256r1,
    Secp521r1,
    Unknown(i8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    Pbkdf2WithHmacSha256,
    Unknown(i8),
}

/// A recipient's key-encapsulation data. One variant per CDOC2 encryption scheme.
///
/// Variants for schemes umbrik does not implement are present so that a container using them
/// still *parses*; selecting one yields [`Error::UnsupportedCapsule`]. Failing to parse and
/// failing to support are different conditions and must not share an error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capsule {
    /// SC05 — pre-shared symmetric key. `salt` is per-recipient random, not a static constant.
    SymmetricKey { salt: Vec<u8> },
    /// SC06 — password. Two distinct salts: `salt` feeds HKDF-Extract, `password_salt` feeds
    /// PBKDF2. Conflating them fails silently; see `docs/CRYPTO-CONSTANTS.md` §4.
    Pbkdf2 {
        salt: Vec<u8>,
        password_salt: Vec<u8>,
        kdf_algorithm: KdfAlgorithm,
        /// Read from the container, never assumed. Encryption uses 600_000.
        kdf_iterations: i32,
    },
    /// SC01 — ECDH. Public keys are TLS uncompressed points (`0x04 || X || Y`).
    EccPublicKey {
        curve: EllipticCurve,
        recipient_public_key: Vec<u8>,
        sender_public_key: Vec<u8>,
    },
    /// SC02 — RSA-OAEP.
    RsaPublicKey {
        recipient_public_key: Vec<u8>,
        encrypted_kek: Vec<u8>,
    },
    /// SC03/SC04 — capsule server. Deferred to M5.
    KeyServer,
    /// SC07 — N-of-N key shares (spec 2.0 draft). Out of scope.
    KeyShares,
    /// A union tag this build does not know.
    Unknown(u8),
}

impl Capsule {
    /// Human-readable scheme tag, for diagnostics. Contains no secret material.
    pub fn scheme(&self) -> &'static str {
        match self {
            Capsule::SymmetricKey { .. } => "SC05",
            Capsule::Pbkdf2 { .. } => "SC06",
            Capsule::EccPublicKey { .. } => "SC01",
            Capsule::RsaPublicKey { .. } => "SC02",
            Capsule::KeyServer => "SC03/SC04",
            Capsule::KeyShares => "SC07",
            Capsule::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecord {
    /// Cryptographically load-bearing: the label is an input to KEK derivation for SC05/SC06.
    /// Editing it makes the container undecryptable.
    pub key_label: String,
    pub encrypted_fmk: Vec<u8>,
    pub fmk_encryption_method: FmkEncryptionMethod,
    pub capsule: Capsule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub recipients: Vec<RecipientRecord>,
    pub payload_encryption_method: PayloadEncryptionMethod,
}

impl Header {
    /// Decode a serialized FlatBuffers header.
    ///
    /// Goes through the FlatBuffers verifier, so malformed input returns an error rather than
    /// panicking or reading out of bounds. This is the fuzz target.
    pub fn decode(buf: &[u8]) -> Result<Header> {
        let root = flatbuffers::root::<fbs_header::Header>(buf)
            .map_err(|_| Error::MalformedHeader("flatbuffers verification failed"))?;

        let fbs_recipients_vec = root
            .recipients()
            .ok_or(Error::MalformedHeader("header has no recipients vector"))?;
        if fbs_recipients_vec.is_empty() {
            return Err(Error::MalformedHeader("header has no recipient records"));
        }

        let mut recipients = Vec::with_capacity(fbs_recipients_vec.len());
        for rec in fbs_recipients_vec.iter() {
            recipients.push(Self::decode_recipient(&rec)?);
        }

        let payload_encryption_method = match root.payload_encryption_method() {
            fbs_header::PayloadEncryptionMethod::CHACHA20POLY1305 => {
                PayloadEncryptionMethod::ChaCha20Poly1305
            }
            other => PayloadEncryptionMethod::Unknown(other.0),
        };

        Ok(Header {
            recipients,
            payload_encryption_method,
        })
    }

    fn decode_recipient(rec: &fbs_header::RecipientRecord<'_>) -> Result<RecipientRecord> {
        let fmk_encryption_method = match rec.fmk_encryption_method() {
            fbs_header::FMKEncryptionMethod::XOR => FmkEncryptionMethod::Xor,
            other => FmkEncryptionMethod::Unknown(other.0),
        };

        let capsule = match rec.capsule_type() {
            fbs_header::Capsule::recipients_SymmetricKeyCapsule => {
                let c = rec
                    .capsule_as_recipients_symmetric_key_capsule()
                    .ok_or(Error::MalformedHeader("symmetric capsule union mismatch"))?;
                Capsule::SymmetricKey {
                    salt: c.salt().bytes().to_vec(),
                }
            }
            fbs_header::Capsule::recipients_PBKDF2Capsule => {
                let c = rec
                    .capsule_as_recipients_pbkdf2_capsule()
                    .ok_or(Error::MalformedHeader("pbkdf2 capsule union mismatch"))?;
                let kdf_algorithm = match c.kdf_algorithm_identifier() {
                    fbs_recipients::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256 => {
                        KdfAlgorithm::Pbkdf2WithHmacSha256
                    }
                    other => KdfAlgorithm::Unknown(other.0),
                };
                Capsule::Pbkdf2 {
                    salt: c.salt().bytes().to_vec(),
                    password_salt: c.password_salt().bytes().to_vec(),
                    kdf_algorithm,
                    kdf_iterations: c.kdf_iterations(),
                }
            }
            fbs_header::Capsule::recipients_ECCPublicKeyCapsule => {
                let c = rec
                    .capsule_as_recipients_eccpublic_key_capsule()
                    .ok_or(Error::MalformedHeader("ecc capsule union mismatch"))?;
                let curve = match c.curve() {
                    fbs_recipients::EllipticCurve::secp384r1 => EllipticCurve::Secp384r1,
                    fbs_recipients::EllipticCurve::secp256r1 => EllipticCurve::Secp256r1,
                    fbs_recipients::EllipticCurve::secp521r1 => EllipticCurve::Secp521r1,
                    other => EllipticCurve::Unknown(other.0),
                };
                Capsule::EccPublicKey {
                    curve,
                    recipient_public_key: c.recipient_public_key().bytes().to_vec(),
                    sender_public_key: c.sender_public_key().bytes().to_vec(),
                }
            }
            fbs_header::Capsule::recipients_RSAPublicKeyCapsule => {
                let c = rec
                    .capsule_as_recipients_rsapublic_key_capsule()
                    .ok_or(Error::MalformedHeader("rsa capsule union mismatch"))?;
                Capsule::RsaPublicKey {
                    recipient_public_key: c.recipient_public_key().bytes().to_vec(),
                    encrypted_kek: c.encrypted_kek().bytes().to_vec(),
                }
            }
            fbs_header::Capsule::recipients_KeyServerCapsule => Capsule::KeyServer,
            fbs_header::Capsule::recipients_KeySharesCapsule => Capsule::KeyShares,
            other => Capsule::Unknown(other.0),
        };

        Ok(RecipientRecord {
            key_label: rec.key_label().to_string(),
            encrypted_fmk: rec.encrypted_fmk().bytes().to_vec(),
            fmk_encryption_method,
            capsule,
        })
    }
}

impl Header {
    /// Serialize to FlatBuffers.
    ///
    /// Only capsule types umbrik implements can be written; attempting to serialize a
    /// deferred or out-of-scope scheme is an error rather than a silent omission.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.recipients.is_empty() {
            return Err(Error::MalformedHeader("header has no recipient records"));
        }

        let mut b = flatbuffers::FlatBufferBuilder::new();
        let mut records = Vec::with_capacity(self.recipients.len());

        for rec in &self.recipients {
            let (capsule_type, capsule) = match &rec.capsule {
                Capsule::SymmetricKey { salt } => {
                    let salt = b.create_vector(salt);
                    let c = fbs_recipients::SymmetricKeyCapsule::create(
                        &mut b,
                        &fbs_recipients::SymmetricKeyCapsuleArgs { salt: Some(salt) },
                    );
                    (
                        fbs_header::Capsule::recipients_SymmetricKeyCapsule,
                        c.as_union_value(),
                    )
                }
                Capsule::Pbkdf2 {
                    salt,
                    password_salt,
                    kdf_algorithm,
                    kdf_iterations,
                } => {
                    let kdf_algorithm_identifier = match kdf_algorithm {
                        KdfAlgorithm::Pbkdf2WithHmacSha256 => {
                            fbs_recipients::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256
                        }
                        KdfAlgorithm::Unknown(_) => {
                            return Err(Error::MalformedHeader("unknown KDF algorithm"))
                        }
                    };
                    let salt = b.create_vector(salt);
                    let password_salt = b.create_vector(password_salt);
                    let c = fbs_recipients::PBKDF2Capsule::create(
                        &mut b,
                        &fbs_recipients::PBKDF2CapsuleArgs {
                            salt: Some(salt),
                            password_salt: Some(password_salt),
                            kdf_algorithm_identifier,
                            kdf_iterations: *kdf_iterations,
                        },
                    );
                    (
                        fbs_header::Capsule::recipients_PBKDF2Capsule,
                        c.as_union_value(),
                    )
                }
                Capsule::EccPublicKey {
                    curve,
                    recipient_public_key,
                    sender_public_key,
                } => {
                    let fbs_curve = match curve {
                        EllipticCurve::Secp384r1 => fbs_recipients::EllipticCurve::secp384r1,
                        EllipticCurve::Secp256r1 => fbs_recipients::EllipticCurve::secp256r1,
                        EllipticCurve::Secp521r1 => fbs_recipients::EllipticCurve::secp521r1,
                        EllipticCurve::Unknown(_) => {
                            return Err(Error::InvalidKeyMaterial("unknown elliptic curve"))
                        }
                    };
                    let recipient = b.create_vector(recipient_public_key);
                    let sender = b.create_vector(sender_public_key);
                    let c = fbs_recipients::ECCPublicKeyCapsule::create(
                        &mut b,
                        &fbs_recipients::ECCPublicKeyCapsuleArgs {
                            curve: fbs_curve,
                            recipient_public_key: Some(recipient),
                            sender_public_key: Some(sender),
                        },
                    );
                    (
                        fbs_header::Capsule::recipients_ECCPublicKeyCapsule,
                        c.as_union_value(),
                    )
                }
                Capsule::RsaPublicKey {
                    recipient_public_key,
                    encrypted_kek,
                } => {
                    let recipient = b.create_vector(recipient_public_key);
                    let kek = b.create_vector(encrypted_kek);
                    let c = fbs_recipients::RSAPublicKeyCapsule::create(
                        &mut b,
                        &fbs_recipients::RSAPublicKeyCapsuleArgs {
                            recipient_public_key: Some(recipient),
                            encrypted_kek: Some(kek),
                        },
                    );
                    (
                        fbs_header::Capsule::recipients_RSAPublicKeyCapsule,
                        c.as_union_value(),
                    )
                }
                other => {
                    return Err(Error::UnsupportedCapsule(match other {
                        Capsule::KeyServer => "SC03/SC04 capsule-server schemes are deferred",
                        Capsule::KeyShares => "SC07 key-shares scheme is out of scope",
                        _ => "unsupported capsule",
                    }))
                }
            };

            let fmk_encryption_method = match rec.fmk_encryption_method {
                FmkEncryptionMethod::Xor => fbs_header::FMKEncryptionMethod::XOR,
                FmkEncryptionMethod::Unknown(v) => {
                    return Err(Error::UnsupportedFmkEncryptionMethod(v))
                }
            };

            let key_label = b.create_string(&rec.key_label);
            let encrypted_fmk = b.create_vector(&rec.encrypted_fmk);
            records.push(fbs_header::RecipientRecord::create(
                &mut b,
                &fbs_header::RecipientRecordArgs {
                    capsule_type,
                    capsule: Some(capsule),
                    key_label: Some(key_label),
                    encrypted_fmk: Some(encrypted_fmk),
                    fmk_encryption_method,
                },
            ));
        }

        let payload_encryption_method = match self.payload_encryption_method {
            PayloadEncryptionMethod::ChaCha20Poly1305 => {
                fbs_header::PayloadEncryptionMethod::CHACHA20POLY1305
            }
            PayloadEncryptionMethod::Unknown(v) => {
                return Err(Error::UnsupportedPayloadEncryptionMethod(v))
            }
        };

        let recipients = b.create_vector(&records);
        let header = fbs_header::Header::create(
            &mut b,
            &fbs_header::HeaderArgs {
                recipients: Some(recipients),
                payload_encryption_method,
            },
        );
        b.finish_minimal(header);

        let bytes = b.finished_data().to_vec();
        if bytes.len() > MAX_HEADER_LEN {
            return Err(Error::LimitExceeded(
                "serialized header exceeds 1 MiB".to_string(),
            ));
        }
        Ok(bytes)
    }
}

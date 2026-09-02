//! L2 — container orchestration. The only layer where traits and RNG are injected.

use std::io::Write;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand_core::CryptoRng;
use sha2::Sha256;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::{
    Capsule, Envelope, FmkEncryptionMethod, Header, KdfAlgorithm, PayloadEncryptionMethod,
    RecipientRecord, HMAC_LEN, PRELUDE, VERSION,
};
use crate::keys::{Cek, Fmk, Kek, VerifiedHeader, FMK_SALT, SALT_LEN};
use crate::limits::Limits;
use crate::payload::{self, ArchiveEntry, PayloadFile};
use crate::provider::{EcPublicKey, KeyOp, KeyProvider, PublicKeyRef};
use crate::schemes::{sc01, sc05, sc06};

/// Input keying material length for FMK generation.
///
/// The spec requires at least 256 bits; the reference implementation uses 512 and umbrik
/// matches it so that a fixed RNG reproduces reference-shaped output. `Crypto.java:105-109`.
pub const FMK_IKM_LEN: usize = 64;

/// ChaCha20-Poly1305 nonce length. Random per container, stored in the clear.
pub const NONCE_LEN: usize = 12;

/// A recipient to encrypt to.
#[derive(Clone)]
#[non_exhaustive]
pub enum Recipient {
    /// SC06.
    Password {
        label: String,
        password: Zeroizing<String>,
    },
    /// SC05.
    Symmetric {
        label: String,
        secret: Zeroizing<Vec<u8>>,
    },
    /// SC01 (EC) or SC02 (RSA), selected by the key type.
    ///
    /// Unlike SC05/SC06, the label is *not* an input to KEK derivation here, so it is free to
    /// choose and editing it does not break decryption.
    PublicKey { label: String, key: PublicKeyRef },
}

impl std::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Recipient::Password { label, .. } => {
                f.write_fmt(format_args!("Password {{ label: {label:?}, .. }}"))
            }
            Recipient::Symmetric { label, .. } => {
                f.write_fmt(format_args!("Symmetric {{ label: {label:?}, .. }}"))
            }
            Recipient::PublicKey { label, .. } => {
                f.write_fmt(format_args!("PublicKey {{ label: {label:?}, .. }}"))
            }
        }
    }
}

/// Key material offered when opening a container.
#[derive(Clone)]
#[non_exhaustive]
pub enum DecryptionKey<'a> {
    Password(Zeroizing<String>),
    Symmetric(Zeroizing<Vec<u8>>),
    /// SC01/SC02. The provider performs the private-key operation; umbrik never sees the key.
    Provider(&'a dyn KeyProvider),
}

impl std::fmt::Debug for DecryptionKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DecryptionKey::Password(_) => "Password([redacted])",
            DecryptionKey::Symmetric(_) => "Symmetric([redacted])",
            DecryptionKey::Provider(_) => "Provider(..)",
        })
    }
}

/// Generate a File Master Key: `HKDF-Extract("CDOC20salt", CSRNG(64))`.
fn generate_fmk(rng: &mut dyn CryptoRng) -> Result<Fmk> {
    let mut ikm = Zeroizing::new([0u8; FMK_IKM_LEN]);
    rng.fill_bytes(ikm.as_mut_slice());
    let (prk, _) = Hkdf::<Sha256>::extract(Some(FMK_SALT), ikm.as_slice());
    Fmk::try_from_slice(&prk)
}

fn random_salt(rng: &mut dyn CryptoRng) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    Ok(salt)
}

/// Build one recipient record, wrapping the FMK under a freshly derived KEK.
fn build_recipient_record(
    recipient: &Recipient,
    fmk: &Fmk,
    rng: &mut dyn CryptoRng,
) -> Result<RecipientRecord> {
    let fmk_enc = FmkEncryptionMethod::Xor;
    let fmk_enc_name = fmk_enc.kdf_name()?;

    let (capsule, kek, label) = match recipient {
        Recipient::Symmetric { label, secret } => {
            let salt = random_salt(rng)?;
            let kek = sc05::kek(secret, &salt, fmk_enc_name, label)?;
            (Capsule::SymmetricKey { salt }, kek, label.clone())
        }
        Recipient::Password { label, password } => {
            let salt = random_salt(rng)?;
            let password_salt = random_salt(rng)?;
            let kek = sc06::kek(
                password,
                &salt,
                &password_salt,
                sc06::ITERATIONS,
                fmk_enc_name,
                label,
            )?;
            (
                Capsule::Pbkdf2 {
                    salt,
                    password_salt,
                    kdf_algorithm: KdfAlgorithm::Pbkdf2WithHmacSha256,
                    kdf_iterations: sc06::ITERATIONS as i32,
                },
                kek,
                label.clone(),
            )
        }
        Recipient::PublicKey { label, key } => {
            let (capsule, kek) = match key {
                PublicKeyRef::Ec(peer) => build_ecc_record(label, peer, fmk, fmk_enc_name, rng)?,
            };
            (capsule, kek, label.clone())
        }
    };

    Ok(RecipientRecord {
        key_label: label,
        encrypted_fmk: fmk.wrap_xor(&kek).to_vec(),
        fmk_encryption_method: fmk_enc,
        capsule,
    })
}

/// SC01: generate an ephemeral key pair, do ECDH against the recipient, derive the KEK.
///
/// A fresh ephemeral key per recipient, drawn from the injected RNG so golden-file tests stay
/// reproducible.
fn build_ecc_record(
    label: &str,
    peer: &EcPublicKey,
    fmk: &Fmk,
    fmk_enc_name: &str,
    rng: &mut dyn CryptoRng,
) -> Result<(Capsule, Kek)> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::elliptic_curve::Generate;

    let (shared, sender_point) = match peer.curve {
        crate::header::EllipticCurve::Secp384r1 => {
            let peer_pub = p384::PublicKey::from_sec1_bytes(&peer.tls_point)
                .map_err(|_| Error::InvalidKeyMaterial("invalid recipient EC point"))?;
            let ephemeral = p384::SecretKey::generate_from_rng(rng);
            let shared =
                p384::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), peer_pub.as_affine());
            let point = ephemeral.public_key().to_sec1_point(false);
            (
                Zeroizing::new(shared.raw_secret_bytes().to_vec()),
                point.as_bytes().to_vec(),
            )
        }
        crate::header::EllipticCurve::Secp256r1 => {
            let peer_pub = p256::PublicKey::from_sec1_bytes(&peer.tls_point)
                .map_err(|_| Error::InvalidKeyMaterial("invalid recipient EC point"))?;
            let ephemeral = p256::SecretKey::generate_from_rng(rng);
            let shared =
                p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), peer_pub.as_affine());
            let point = ephemeral.public_key().to_sec1_point(false);
            (
                Zeroizing::new(shared.raw_secret_bytes().to_vec()),
                point.as_bytes().to_vec(),
            )
        }
        _ => {
            return Err(Error::InvalidKeyMaterial(
                "unsupported curve for encryption",
            ))
        }
    };

    let kek = sc01::kek(&shared, &peer.tls_point, &sender_point, fmk_enc_name)?;
    let _ = (label, fmk);
    Ok((
        Capsule::EccPublicKey {
            curve: peer.curve,
            recipient_public_key: peer.tls_point.clone(),
            sender_public_key: sender_point,
        },
        kek,
    ))
}

/// Encrypt `files` to `recipients` and write a complete container to `out`.
///
/// `rng` is a parameter rather than a global so that a fixed RNG produces a byte-identical
/// container. Round-trip tests cannot catch a wrong constant applied consistently in both
/// directions; golden files can.
pub fn encrypt(
    out: &mut dyn Write,
    rng: &mut dyn CryptoRng,
    files: &[PayloadFile],
    recipients: &[Recipient],
) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::InvalidKeyMaterial("no recipients"));
    }

    let fmk = generate_fmk(rng)?;
    let records = recipients
        .iter()
        .map(|r| build_recipient_record(r, &fmk, rng))
        .collect::<Result<Vec<_>>>()?;

    let header = Header {
        recipients: records,
        payload_encryption_method: PayloadEncryptionMethod::ChaCha20Poly1305,
    };
    let header_bytes = header.encode()?;

    // HMAC covers the FlatBuffers header only: not the prelude, version, or length field.
    let hhk = fmk.derive_hhk()?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(hhk.as_bytes())
        .map_err(|_| Error::KeyDerivation("HHK length"))?;
    mac.update(&header_bytes);
    let hmac_bytes = mac.finalize().into_bytes();
    let hmac_arr: [u8; HMAC_LEN] = hmac_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Internal("HMAC length"))?;

    let plaintext = Zeroizing::new(payload::pack(files)?);
    let aad = crate::keys::build_aad(&header_bytes, &hmac_arr);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let cek = fmk.derive_cek()?;
    let cipher = <ChaCha20Poly1305 as AeadKeyInit>::new_from_slice(cek.as_bytes())
        .map_err(|_| Error::KeyDerivation("CEK length"))?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::Internal("payload encryption failed"))?;

    let header_len: u32 = header_bytes
        .len()
        .try_into()
        .map_err(|_| Error::LimitExceeded("header too large".to_string()))?;

    out.write_all(&PRELUDE).map_err(Error::Io)?;
    out.write_all(&[VERSION]).map_err(Error::Io)?;
    out.write_all(&header_len.to_be_bytes())
        .map_err(Error::Io)?;
    out.write_all(&header_bytes).map_err(Error::Io)?;
    out.write_all(&hmac_arr).map_err(Error::Io)?;
    out.write_all(&nonce_bytes).map_err(Error::Io)?;
    out.write_all(&ciphertext).map_err(Error::Io)?;
    Ok(())
}

/// Try to establish a KEK for one recipient record with the supplied key material.
///
/// Returns `Ok(None)` when the record is simply for a different scheme or key — that is not an
/// error, just a non-match.
fn try_kek(
    record: &RecipientRecord,
    key: &DecryptionKey,
    kdf_budget: &mut u64,
) -> Result<Option<Kek>> {
    let fmk_enc_name = match record.fmk_encryption_method.kdf_name() {
        Ok(name) => name,
        // A record using an FMK encryption method we don't know cannot match; keep looking.
        Err(_) => return Ok(None),
    };

    match (&record.capsule, key) {
        (Capsule::SymmetricKey { salt }, DecryptionKey::Symmetric(secret)) => Ok(Some(sc05::kek(
            secret,
            salt,
            fmk_enc_name,
            &record.key_label,
        )?)),
        (Capsule::EccPublicKey { .. }, DecryptionKey::Provider(provider)) => {
            provider_kek(record, *provider, fmk_enc_name)
        }
        (
            Capsule::Pbkdf2 {
                salt,
                password_salt,
                kdf_algorithm,
                kdf_iterations,
            },
            DecryptionKey::Password(password),
        ) => {
            if *kdf_algorithm != KdfAlgorithm::Pbkdf2WithHmacSha256 {
                return Ok(None);
            }
            let iterations: u32 = (*kdf_iterations)
                .try_into()
                .map_err(|_| Error::InvalidKeyMaterial("negative PBKDF2 iteration count"))?;

            // Charge the budget before doing the work, not after.
            *kdf_budget =
                kdf_budget
                    .checked_sub(u64::from(iterations))
                    .ok_or(Error::LimitExceeded(
                        "container exceeds the total PBKDF2 iteration budget".to_string(),
                    ))?;

            Ok(Some(sc06::kek(
                password,
                salt,
                password_salt,
                iterations,
                fmk_enc_name,
                &record.key_label,
            )?))
        }
        _ => Ok(None),
    }
}

/// Establish a KEK via a [`KeyProvider`] (SC01 or SC02).
///
/// Identity matching happens *before* `perform` is called. That ordering is the whole reason
/// `KeyProvider::identities` exists: a container addressed to someone else must not cost the
/// user a PIN entry, and repeated wrong-PIN attempts can lock a card. A non-match returns
/// `Ok(None)`, never a prompt.
fn provider_kek(
    record: &RecipientRecord,
    provider: &dyn KeyProvider,
    fmk_enc_name: &str,
) -> Result<Option<Kek>> {
    let identities = provider.identities()?;
    let Some(identity) = identities.iter().find(|id| id.matches(&record.capsule)) else {
        return Ok(None);
    };

    match &record.capsule {
        Capsule::EccPublicKey {
            curve,
            recipient_public_key,
            sender_public_key,
        } => {
            // The peer for ECDH is the sender's ephemeral key.
            let peer = EcPublicKey {
                curve: *curve,
                tls_point: sender_public_key.clone(),
            };
            let shared = provider.perform(identity, KeyOp::Ecdh { peer: &peer })?;
            sc01::kek(
                &shared,
                recipient_public_key,
                sender_public_key,
                fmk_enc_name,
            )
            .map(Some)
        }
        _ => Ok(None),
    }
}

/// Unwrap the FMK and authenticate the header.
///
/// Recipient selection is decided by the header HMAC rather than by matching labels: a candidate
/// record is accepted only if the FMK it yields derives an HHK that authenticates the header.
/// That is exactly what the HMAC is for, and it avoids guessing at label semantics.
fn open_header(
    envelope: &Envelope<'_>,
    key: &DecryptionKey,
    limits: &Limits,
) -> Result<(VerifiedHeader, Fmk)> {
    let header = envelope.decode_header()?;

    if header.recipients.len() as u64 > limits.max_recipients {
        return Err(Error::LimitExceeded(
            "too many recipient records".to_string(),
        ));
    }

    let mut kdf_budget = limits.max_total_kdf_iterations;
    let mut saw_candidate = false;
    let mut unsupported: Option<Error> = None;

    for record in &header.recipients {
        match &record.capsule {
            Capsule::RsaPublicKey { .. }
            | Capsule::KeyServer
            | Capsule::KeyShares
            | Capsule::Unknown(_) => {
                if unsupported.is_none() {
                    unsupported = Some(Error::UnsupportedCapsule(match record.capsule {
                        Capsule::RsaPublicKey { .. } => "SC02 RSA is not supported",
                        Capsule::KeyServer => "SC03/SC04 capsule-server schemes are deferred",
                        Capsule::KeyShares => "SC07 key-shares scheme is out of scope",
                        _ => "unknown capsule type",
                    }));
                }
                continue;
            }
            _ => {}
        }

        let Some(kek) = try_kek(record, key, &mut kdf_budget)? else {
            continue;
        };
        saw_candidate = true;

        let fmk = Fmk::unwrap_xor(&record.encrypted_fmk, &kek)?;
        let hhk = fmk.derive_hhk()?;
        if let Ok(verified) = VerifiedHeader::verify(envelope, header.clone(), &hhk) {
            return Ok((verified, fmk));
        }
    }

    // A wrong password and a container addressed to someone else are indistinguishable here,
    // and deliberately so: reporting which one it was would be an oracle.
    if saw_candidate {
        return Err(Error::HeaderHmacMismatch);
    }
    Err(unsupported.unwrap_or(Error::NoMatchingRecipient))
}

/// Decrypt and authenticate the payload, returning the compressed tar bytes.
///
/// The AEAD is a single invocation over the whole payload, so the Poly1305 tag is verified
/// before any plaintext is returned. Nothing unauthenticated is ever handed to a caller.
fn decrypt_payload(
    envelope: &Envelope<'_>,
    verified: &VerifiedHeader,
    fmk: &Fmk,
) -> Result<Zeroizing<Vec<u8>>> {
    if verified.header().payload_encryption_method != PayloadEncryptionMethod::ChaCha20Poly1305 {
        return match verified.header().payload_encryption_method {
            PayloadEncryptionMethod::Unknown(v) => {
                Err(Error::UnsupportedPayloadEncryptionMethod(v))
            }
            PayloadEncryptionMethod::ChaCha20Poly1305 => Err(Error::Internal("unreachable")),
        };
    }

    let payload = envelope.payload();
    let nonce = payload.get(..NONCE_LEN).ok_or(Error::Truncated {
        expected: NONCE_LEN as u64,
        found: payload.len() as u64,
    })?;
    let ciphertext = payload.get(NONCE_LEN..).ok_or(Error::Truncated {
        expected: NONCE_LEN as u64,
        found: payload.len() as u64,
    })?;

    let cek: Cek = fmk.derive_cek()?;
    let cipher = <ChaCha20Poly1305 as AeadKeyInit>::new_from_slice(cek.as_bytes())
        .map_err(|_| Error::KeyDerivation("CEK length"))?;
    let plaintext = cipher
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| Error::Truncated {
                expected: NONCE_LEN as u64,
                found: nonce.len() as u64,
            })?,
            Payload {
                msg: ciphertext,
                aad: verified.aad(),
            },
        )
        .map_err(|_| Error::PayloadAuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// Everything a successful open produces.
#[derive(Debug)]
#[non_exhaustive]
pub struct Opened {
    pub entries: Vec<ArchiveEntry>,
}

/// Decrypt a container and extract its files into `dest`.
pub fn decrypt_to_dir(
    container: &[u8],
    key: &DecryptionKey,
    limits: &Limits,
    dest: &Path,
) -> Result<Opened> {
    let envelope = Envelope::parse(container)?;
    let (verified, fmk) = open_header(&envelope, key, limits)?;
    let compressed = decrypt_payload(&envelope, &verified, &fmk)?;
    let entries = payload::unpack_to_dir(&compressed, dest, limits)?;
    Ok(Opened { entries })
}

/// Decrypt a container and return its files in memory.
pub fn decrypt_to_memory(
    container: &[u8],
    key: &DecryptionKey,
    limits: &Limits,
) -> Result<Vec<PayloadFile>> {
    let dir = tempdir_in_system()?;
    let result = (|| {
        let opened = decrypt_to_dir(container, key, limits, dir.as_path())?;
        let mut files = Vec::with_capacity(opened.entries.len());
        for entry in opened.entries {
            let path = dir.as_path().join(&entry.name);
            files.push(PayloadFile {
                name: entry.name,
                data: std::fs::read(&path).map_err(Error::Io)?,
            });
        }
        Ok(files)
    })();
    let _ = std::fs::remove_dir_all(dir.as_path());
    result
}

/// List a container's entries without writing files.
pub fn list(container: &[u8], key: &DecryptionKey, limits: &Limits) -> Result<Vec<ArchiveEntry>> {
    let envelope = Envelope::parse(container)?;
    let (verified, fmk) = open_header(&envelope, key, limits)?;
    let compressed = decrypt_payload(&envelope, &verified, &fmk)?;
    payload::list(&compressed, limits)
}

/// A scratch directory removed on drop.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir_in_system() -> Result<ScratchDir> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Internal("system clock before epoch"))?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("umbrik-{nanos}-{}", std::process::id()));
    std::fs::create_dir_all(&path).map_err(Error::Io)?;
    Ok(ScratchDir(path))
}

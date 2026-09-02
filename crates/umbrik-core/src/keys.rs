//! The shared key hierarchy, and the type that enforces verify-before-decrypt.
//!
//! ```text
//! FMK = HKDF-Extract("CDOC20salt", CSRNG(64))
//! CEK = HKDF-Expand(FMK, "CDOC20cek",  32)
//! HHK = HKDF-Expand(FMK, "CDOC20hmac", 32)
//! ```
//!
//! HKDF is HMAC-SHA-256 in every context, including the P-384 ECDH path. See
//! `docs/CRYPTO-CONSTANTS.md` §2 — this is the constant most likely to be guessed wrong,
//! because P-384 conventionally pairs with SHA-384.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::{Envelope, Header, HMAC_LEN};

/// HKDF-Extract salt for the FMK. UTF-8 `"CDOC20salt"`. The `20` is ASCII "2","0".
pub const FMK_SALT: &[u8] = b"CDOC20salt";
/// HKDF-Expand info for the CEK.
pub const CEK_INFO: &[u8] = b"CDOC20cek";
/// HKDF-Expand info for the HHK.
pub const HHK_INFO: &[u8] = b"CDOC20hmac";
/// HKDF-Expand info prefix for every KEK derivation.
pub const KEK_INFO_PREFIX: &[u8] = b"CDOC20kek";
/// HKDF-Extract salt for the ECDH pre-master. The only *static* KEK salt; SC05 and SC06 use a
/// per-recipient random salt carried in the capsule instead.
pub const ECDH_KEK_PREMASTER_SALT: &[u8] = b"CDOC20kekpremaster";
/// AAD prefix for the payload AEAD.
pub const PAYLOAD_AAD_PREFIX: &[u8] = b"CDOC20payload";

pub const FMK_LEN: usize = 32;
pub const CEK_LEN: usize = 32;
pub const HHK_LEN: usize = 32;
/// KEK length must equal FMK length: the FMK is wrapped by XOR, not a key-wrap primitive.
pub const KEK_LEN: usize = FMK_LEN;
/// Minimum salt length, and the length umbrik generates. `Crypto.java:64`.
pub const SALT_LEN: usize = 32;

macro_rules! secret_key {
    ($name:ident, $len:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name(Zeroizing<[u8; $len]>);

        impl $name {
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
                let arr: [u8; $len] = bytes.try_into().map_err(|_| {
                    Error::InvalidKeyMaterial(concat!(stringify!($name), " length"))
                })?;
                Ok(Self(Zeroizing::new(arr)))
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        // Never print key material, not even a prefix.
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

secret_key!(
    Fmk,
    FMK_LEN,
    "File Master Key. Root of the per-container hierarchy."
);
secret_key!(Cek, CEK_LEN, "Content Encryption Key for the payload AEAD.");
secret_key!(Hhk, HHK_LEN, "Header HMAC Key.");
secret_key!(Kek, KEK_LEN, "Key Encryption Key. Wraps the FMK by XOR.");

impl Fmk {
    /// `HKDF-Expand(FMK, "CDOC20cek", 32)`.
    pub fn derive_cek(&self) -> Result<Cek> {
        let mut out = [0u8; CEK_LEN];
        Hkdf::<Sha256>::from_prk(self.as_bytes())
            .map_err(|_| Error::KeyDerivation("FMK is not a valid HKDF PRK"))?
            .expand(CEK_INFO, &mut out)
            .map_err(|_| Error::KeyDerivation("CEK expand"))?;
        Ok(Cek::from_bytes(out))
    }

    /// `HKDF-Expand(FMK, "CDOC20hmac", 32)`.
    pub fn derive_hhk(&self) -> Result<Hhk> {
        let mut out = [0u8; HHK_LEN];
        Hkdf::<Sha256>::from_prk(self.as_bytes())
            .map_err(|_| Error::KeyDerivation("FMK is not a valid HKDF PRK"))?
            .expand(HHK_INFO, &mut out)
            .map_err(|_| Error::KeyDerivation("HHK expand"))?;
        Ok(Hhk::from_bytes(out))
    }

    /// Unwrap an encrypted FMK: `FMK = EncryptedFMK XOR KEK`.
    ///
    /// XOR wrapping is why `KEK_LEN == FMK_LEN`; a length mismatch is rejected rather than
    /// truncated.
    pub fn unwrap_xor(encrypted_fmk: &[u8], kek: &Kek) -> Result<Fmk> {
        if encrypted_fmk.len() != FMK_LEN {
            return Err(Error::InvalidKeyMaterial("encrypted FMK length"));
        }
        let mut out = [0u8; FMK_LEN];
        for ((slot, enc), k) in out
            .iter_mut()
            .zip(encrypted_fmk.iter())
            .zip(kek.as_bytes().iter())
        {
            *slot = enc ^ k;
        }
        Ok(Fmk::from_bytes(out))
    }

    /// Wrap an FMK for a recipient: `EncryptedFMK = FMK XOR KEK`.
    pub fn wrap_xor(&self, kek: &Kek) -> [u8; FMK_LEN] {
        let mut out = [0u8; FMK_LEN];
        for ((slot, fmk), k) in out
            .iter_mut()
            .zip(self.as_bytes().iter())
            .zip(kek.as_bytes().iter())
        {
            *slot = fmk ^ k;
        }
        out
    }
}

/// A header whose HMAC has been checked against a key derived from the unwrapped FMK.
///
/// This type exists to make an ordering constraint unrepresentable-if-violated. The HHK descends
/// from the FMK, so the header cannot be authenticated until after the private-key operation:
///
/// ```text
/// parse header -> select recipient -> KeyProvider::perform -> unwrap FMK
///   -> derive HHK -> verify header HMAC -> derive CEK -> decrypt payload
/// ```
///
/// Payload decryption accepts a `VerifiedHeader` and nothing else, so the check cannot be
/// skipped or reordered by a caller.
#[derive(Debug, Clone)]
pub struct VerifiedHeader {
    header: Header,
    aad: Vec<u8>,
}

impl VerifiedHeader {
    /// Verify the header HMAC, consuming the parsed header.
    ///
    /// The MAC covers the FlatBuffers header bytes only — not the prelude, version byte, or
    /// header-length field. Comparison is constant time.
    pub fn verify(envelope: &Envelope<'_>, header: Header, hhk: &Hhk) -> Result<VerifiedHeader> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(hhk.as_bytes())
            .map_err(|_| Error::KeyDerivation("HHK length"))?;
        mac.update(envelope.header_bytes());
        let calculated = mac.finalize().into_bytes();

        if calculated
            .as_slice()
            .ct_eq(envelope.header_hmac().as_slice())
            .unwrap_u8()
            != 1
        {
            return Err(Error::HeaderHmacMismatch);
        }

        Ok(VerifiedHeader {
            header,
            aad: build_aad(envelope.header_bytes(), envelope.header_hmac()),
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// `"CDOC20payload" || header || headerHMAC`, ready for the payload AEAD.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }
}

/// `AAD = "CDOC20payload" || header || headerHMAC` — concatenation only, no length prefixes.
pub fn build_aad(header_bytes: &[u8], header_hmac: &[u8; HMAC_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PAYLOAD_AAD_PREFIX.len() + header_bytes.len() + HMAC_LEN);
    aad.extend_from_slice(PAYLOAD_AAD_PREFIX);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(header_hmac);
    aad
}

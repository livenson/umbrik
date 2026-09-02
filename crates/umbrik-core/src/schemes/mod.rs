//! L1 — one KEK-establishment function per CDOC2 encryption scheme.
//!
//! Pure functions over byte slices: no traits, no I/O, no global RNG. Each is individually
//! testable against the constants in `docs/CRYPTO-CONSTANTS.md`.
//!
//! Only KEK establishment differs between schemes. Everything downstream of the KEK — FMK
//! unwrapping, CEK/HHK derivation, the payload AEAD — is shared and lives in [`crate::keys`].

pub mod sc01;
pub mod sc05;
pub mod sc06;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::keys::{Kek, KEK_INFO_PREFIX, KEK_LEN};

/// The symmetric KEK derivation shared by SC05 and SC06.
///
/// ```text
/// KEKpm = HKDF-Extract(salt, secret)
/// KEK   = HKDF-Expand(KEKpm, "CDOC20kek" || fmk_enc_name || key_label, 32)
/// ```
///
/// `salt` is the per-recipient random salt from the capsule — **not** a static constant. Only
/// the ECDH path (SC01) has a static KEK salt.
///
/// `fmk_enc_name` is the ASCII *name* of the FMK encryption method (`"XOR"`), not its enum byte.
/// `key_label` is the recipient record's label, UTF-8, appended with no separator or length
/// prefix — which makes the label cryptographically load-bearing.
pub(crate) fn derive_symmetric_kek(
    secret: &[u8],
    salt: &[u8],
    fmk_enc_name: &str,
    key_label: &str,
) -> Result<Kek> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), secret);

    let mut info = Vec::with_capacity(KEK_INFO_PREFIX.len() + fmk_enc_name.len() + key_label.len());
    info.extend_from_slice(KEK_INFO_PREFIX);
    info.extend_from_slice(fmk_enc_name.as_bytes());
    info.extend_from_slice(key_label.as_bytes());

    let mut kek = [0u8; KEK_LEN];
    hk.expand(&info, &mut kek)
        .map_err(|_| Error::KeyDerivation("KEK expand"))?;
    Ok(Kek::from_bytes(kek))
}

//! SC05 — pre-shared symmetric key.

use crate::error::{Error, Result};
use crate::keys::{Kek, SALT_LEN};

/// Minimum pre-shared key length. `Crypto.java:68`.
pub const MIN_SECRET_LEN: usize = 32;

/// Derive the KEK from a pre-shared secret.
///
/// `salt` comes from the recipient's `SymmetricKeyCapsule` when decrypting, and is freshly
/// generated when encrypting.
pub fn kek(secret: &[u8], salt: &[u8], fmk_enc_name: &str, key_label: &str) -> Result<Kek> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(Error::InvalidKeyMaterial(
            "pre-shared key must be at least 32 bytes",
        ));
    }
    if salt.len() < SALT_LEN {
        return Err(Error::InvalidKeyMaterial("salt must be at least 32 bytes"));
    }
    super::derive_symmetric_kek(secret, salt, fmk_enc_name, key_label)
}

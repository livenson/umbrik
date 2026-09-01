//! SC02 — RSA-OAEP.
//!
//! The only scheme with no key derivation at all. The sender generates a random KEK and
//! transports it under RSA-OAEP; the recipient decrypts it and uses it directly:
//!
//! ```text
//! encrypted_kek = RSA-OAEP-Encrypt(recipient_public, KEK)
//! KEK           = RSA-OAEP-Decrypt(recipient_private, encrypted_kek)
//! ```
//!
//! There is no `"CDOC20kek"` info string and no key label on this path. See
//! `docs/CRYPTO-CONSTANTS.md` §6b.

use crate::error::{Error, Result};
use crate::keys::{Kek, KEK_LEN};

/// Wrap a decrypted KEK, checking its length.
///
/// The plaintext coming back from RSA-OAEP is attacker-influenced in a hostile container, so its
/// length is validated rather than assumed. XOR wrapping requires exactly `KEK_LEN`.
pub fn kek_from_decrypted(decrypted: &[u8]) -> Result<Kek> {
    if decrypted.len() != KEK_LEN {
        return Err(Error::InvalidKeyMaterial(
            "RSA-OAEP plaintext is not a 32-byte KEK",
        ));
    }
    Kek::try_from_slice(decrypted)
}

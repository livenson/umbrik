//! SC01 — ECDH.
//!
//! ```text
//! Secdh = ECDH(sender_ephemeral_private, recipient_public)   # raw X coordinate
//! KEKpm = HKDF-Extract("CDOC20kekpremaster", Secdh)
//! KEK   = HKDF-Expand(KEKpm, "CDOC20kek" || "XOR" || tls(recipient_pub) || tls(sender_pub), 32)
//! ```
//!
//! Two things differ from SC05/SC06 and are easy to get wrong:
//!
//! - **The key label is not an input.** SC05 and SC06 append it; SC01 appends the two public
//!   keys instead. See `docs/CRYPTO-CONSTANTS.md` §6.
//! - **HKDF is HMAC-SHA-256, not SHA-384**, even though the curve is P-384. Habit says pair
//!   P-384 with SHA-384; the format does not, and the mistake round-trips cleanly against
//!   itself while interoperating with nothing.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::keys::{Kek, ECDH_KEK_PREMASTER_SALT, KEK_INFO_PREFIX, KEK_LEN};

/// Derive the KEK from an ECDH shared secret.
///
/// `shared_secret` is the raw ECDH output — the X coordinate only, exactly as PKCS#11's
/// `CKM_ECDH1_DERIVE` returns it. Do not pre-hash it.
///
/// Public keys are TLS uncompressed points (`0x04 || X || Y`). Order is **recipient first,
/// then sender**, in both directions; reversing them yields a valid-looking KEK that decrypts
/// nothing.
pub fn kek(
    shared_secret: &[u8],
    recipient_public_key: &[u8],
    sender_public_key: &[u8],
    fmk_enc_name: &str,
) -> Result<Kek> {
    if shared_secret.is_empty() {
        return Err(Error::InvalidKeyMaterial("empty ECDH shared secret"));
    }

    let (_, hk) = Hkdf::<Sha256>::extract(Some(ECDH_KEK_PREMASTER_SALT), shared_secret);

    let mut info = Vec::with_capacity(
        KEK_INFO_PREFIX.len()
            + fmk_enc_name.len()
            + recipient_public_key.len()
            + sender_public_key.len(),
    );
    info.extend_from_slice(KEK_INFO_PREFIX);
    info.extend_from_slice(fmk_enc_name.as_bytes());
    info.extend_from_slice(recipient_public_key);
    info.extend_from_slice(sender_public_key);

    let mut kek = [0u8; KEK_LEN];
    hk.expand(&info, &mut kek)
        .map_err(|_| Error::KeyDerivation("SC01 KEK expand"))?;
    Ok(Kek::from_bytes(kek))
}

/// Expected TLS uncompressed point length for a curve: `1 + 2 * coordinate_size`.
pub fn tls_point_len(curve: crate::header::EllipticCurve) -> Option<usize> {
    use crate::header::EllipticCurve as C;
    match curve {
        C::Secp256r1 => Some(65),
        C::Secp384r1 => Some(97),
        C::Secp521r1 => Some(133),
        C::Unknown(_) => None,
    }
}

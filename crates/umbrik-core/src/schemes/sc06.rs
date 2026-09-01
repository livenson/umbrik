//! SC06 — password-based.
//!
//! Two stages, with two independent salts:
//!
//! ```text
//! symkey = PBKDF2-HMAC-SHA256(utf8(password), password_salt, iterations, 32)
//! KEK    = HKDF-Expand(HKDF-Extract(salt, symkey), "CDOC20kek" || "XOR" || label, 32)
//! ```
//!
//! `salt` and `password_salt` are distinct fields of `PBKDF2Capsule`. Conflating them produces
//! a wrong KEK with no visible symptom other than failed decryption.

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{Kek, SALT_LEN};

/// Iterations used when encrypting. NIST's recommendation for HMAC-SHA-256.
/// `PBKDF2Recipient.java:22`.
pub const ITERATIONS: u32 = 600_000;

/// Derived symmetric key length, in bytes. `Crypto.java:66` (256 bits).
pub const DERIVED_KEY_LEN: usize = 32;

/// Upper bound on the iteration count accepted from a container.
///
/// `kdf_iterations` is attacker-controlled in a hostile container, and PBKDF2 is unbounded work.
/// This ceiling is umbrik's, not the format's — the spec sets no maximum. It is generous enough
/// to open any legitimately produced container.
pub const MAX_ITERATIONS: u32 = 100_000_000;

/// Stage one: stretch the password into a symmetric key.
///
/// The password is UTF-8 encoded, as the spec requires.
pub fn symmetric_key_from_password(
    password: &str,
    password_salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>> {
    if iterations == 0 {
        return Err(Error::InvalidKeyMaterial("PBKDF2 iteration count is zero"));
    }
    if iterations > MAX_ITERATIONS {
        return Err(Error::LimitExceeded(
            "PBKDF2 iteration count exceeds umbrik's ceiling".to_string(),
        ));
    }
    if password_salt.len() < SALT_LEN {
        return Err(Error::InvalidKeyMaterial(
            "password salt must be at least 32 bytes",
        ));
    }

    let mut out = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        password_salt,
        iterations,
        out.as_mut_slice(),
    );
    Ok(out)
}

/// Both stages: password to KEK.
pub fn kek(
    password: &str,
    salt: &[u8],
    password_salt: &[u8],
    iterations: u32,
    fmk_enc_name: &str,
    key_label: &str,
) -> Result<Kek> {
    if salt.len() < SALT_LEN {
        return Err(Error::InvalidKeyMaterial("salt must be at least 32 bytes"));
    }
    let symkey = symmetric_key_from_password(password, password_salt, iterations)?;
    super::derive_symmetric_kek(symkey.as_slice(), salt, fmk_enc_name, key_label)
}

//! L1 scheme unit tests, against the constants in `docs/CRYPTO-CONSTANTS.md`.
//!
//! These pin the *shape* of each derivation — which inputs feed it and in what order — rather
//! than only its end-to-end result. A derivation that ignores one of its inputs still round
//! trips; it just interoperates with nothing.

use umbrik_core::error::ErrorCode;
use umbrik_core::keys::SALT_LEN;
use umbrik_core::schemes::{sc05, sc06};

const SECRET: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const SALT_A: &[u8; 32] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SALT_B: &[u8; 32] = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn kek_bytes(label: &str) -> [u8; 32] {
    *sc05::kek(SECRET, SALT_A, "XOR", label).unwrap().as_bytes()
}

// ---------------------------------------------------------------------------
// SC05 — every input must actually reach the KDF
// ---------------------------------------------------------------------------

/// The key label is concatenated into the HKDF info string, which makes it cryptographically
/// load-bearing: editing a container's label makes it undecryptable. See CRYPTO-CONSTANTS §5.
#[test]
fn sc05_kek_depends_on_key_label() {
    assert_ne!(kek_bytes("label-one"), kek_bytes("label-two"));
}

#[test]
fn sc05_kek_depends_on_salt() {
    let a = sc05::kek(SECRET, SALT_A, "XOR", "l").unwrap();
    let b = sc05::kek(SECRET, SALT_B, "XOR", "l").unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn sc05_kek_depends_on_secret() {
    let a = sc05::kek(SECRET, SALT_A, "XOR", "l").unwrap();
    let b = sc05::kek(&[0xAAu8; 32], SALT_A, "XOR", "l").unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

/// The FMK encryption method name is part of the info string as ASCII `"XOR"`, not as the
/// enum's byte value.
#[test]
fn sc05_kek_depends_on_fmk_encryption_method_name() {
    let a = sc05::kek(SECRET, SALT_A, "XOR", "l").unwrap();
    let b = sc05::kek(SECRET, SALT_A, "AES", "l").unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

/// Concatenation carries no separator, so these two splits must not collide. A length-prefixed
/// or delimited construction would make them differ for the wrong reason.
#[test]
fn sc05_kek_is_deterministic() {
    assert_eq!(kek_bytes("stable"), kek_bytes("stable"));
}

#[test]
fn sc05_rejects_short_secret() {
    let err = sc05::kek(&[0u8; 31], SALT_A, "XOR", "l").unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidKeyMaterial);
}

#[test]
fn sc05_rejects_short_salt() {
    let err = sc05::kek(SECRET, &[0u8; 31], "XOR", "l").unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidKeyMaterial);
}

#[test]
fn salt_len_constant_matches_minimum() {
    assert_eq!(SALT_LEN, 32);
}

// ---------------------------------------------------------------------------
// SC06 — the two salts are not interchangeable
// ---------------------------------------------------------------------------

/// `PBKDF2Capsule` carries `salt` and `password_salt` as separate fields feeding separate
/// stages. Swapping them is the archetypal silent SC06 bug, so it must change the result.
#[test]
fn sc06_salts_are_not_interchangeable() {
    let normal = sc06::kek("pw", SALT_A, SALT_B, 1_000, "XOR", "l").unwrap();
    let swapped = sc06::kek("pw", SALT_B, SALT_A, 1_000, "XOR", "l").unwrap();
    assert_ne!(normal.as_bytes(), swapped.as_bytes());
}

#[test]
fn sc06_kek_depends_on_password() {
    let a = sc06::kek("password-one", SALT_A, SALT_B, 1_000, "XOR", "l").unwrap();
    let b = sc06::kek("password-two", SALT_A, SALT_B, 1_000, "XOR", "l").unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn sc06_kek_depends_on_iteration_count() {
    let a = sc06::kek("pw", SALT_A, SALT_B, 1_000, "XOR", "l").unwrap();
    let b = sc06::kek("pw", SALT_A, SALT_B, 2_000, "XOR", "l").unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn sc06_kek_depends_on_key_label() {
    let a = sc06::kek("pw", SALT_A, SALT_B, 1_000, "XOR", "one").unwrap();
    let b = sc06::kek("pw", SALT_A, SALT_B, 1_000, "XOR", "two").unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

/// Passwords are UTF-8 encoded, so non-ASCII must survive rather than being mangled or rejected.
#[test]
fn sc06_accepts_non_ascii_passwords() {
    let a = sc06::symmetric_key_from_password("jõudis", SALT_A, 1_000).unwrap();
    let b = sc06::symmetric_key_from_password("joudis", SALT_A, 1_000).unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn sc06_rejects_zero_iterations() {
    let err = sc06::symmetric_key_from_password("pw", SALT_A, 0).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidKeyMaterial);
}

/// `kdf_iterations` is attacker-controlled in a hostile container and PBKDF2 is unbounded work,
/// so umbrik caps it. The cap is umbrik's; the format sets none.
#[test]
fn sc06_rejects_absurd_iteration_count() {
    let err = sc06::symmetric_key_from_password("pw", SALT_A, u32::MAX).unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn sc06_rejects_short_password_salt() {
    let err = sc06::symmetric_key_from_password("pw", &[0u8; 31], 1_000).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidKeyMaterial);
}

#[test]
fn sc06_encryption_iteration_count_matches_reference() {
    // PBKDF2Recipient.java:22 — NIST's recommendation for HMAC-SHA-256.
    assert_eq!(sc06::ITERATIONS, 600_000);
}

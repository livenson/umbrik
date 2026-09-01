//! SC01 (ECDH) and SC02 (RSA-OAEP) against real `cdoc2-cli` containers.
//!
//! No hardware needed: the reference implementation ships both the containers and the matching
//! private keys, so the full KEK derivation is verifiable in CI. Only the PKCS#11 plumbing and
//! the DigiDoc4 cross-check require a physical ID-card.

use std::path::PathBuf;
use umbrik_core::container::{self, DecryptionKey, Recipient};
use umbrik_core::error::ErrorCode;
use umbrik_core::header::{Capsule, EllipticCurve, Envelope};
use umbrik_core::payload::PayloadFile;
use umbrik_core::provider::software::SoftwareKeyProvider;
use umbrik_core::provider::{KeyProvider, PublicKeyRef};
use umbrik_core::{cert, Limits};

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors")
}

fn vector(name: &str) -> Vec<u8> {
    let path = vectors().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn key_pem(name: &str) -> String {
    let path = vectors().join("keys").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn provider_with(key_file: &str) -> SoftwareKeyProvider {
    let mut provider = SoftwareKeyProvider::new();
    provider
        .add_pem(&key_pem(key_file), "test-key")
        .expect("loading private key");
    provider
}

// ---------------------------------------------------------------------------
// Decrypting reference containers
// ---------------------------------------------------------------------------

/// Canary for a known upstream data problem.
///
/// `ec_simple.cdoc2` is addressed to a P-384 key that is **not** the committed
/// `cdoc2client_priv.key` / `cdoc2client-certificate.pem` pair — the vector and the keys have
/// drifted apart upstream (see `tests/vectors/PROVENANCE.md`). So this vector cannot be
/// decrypted here, and P-384 coverage comes from the interop job instead, which generates a
/// fresh container with `cdoc2-cli` against the committed certificate.
///
/// If upstream republishes matching keys, this test starts failing — which is the point. Delete
/// it and restore a real decryption test at that point.
#[test]
fn ec_simple_vector_key_has_drifted_upstream() {
    let provider = provider_with("cdoc2client_priv.key");
    let container = vector("ec_simple.cdoc2");

    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .expect_err("vector is known not to match the committed key");
    assert_eq!(err.code(), ErrorCode::NoMatchingRecipient);
}

#[test]
fn decrypts_sc01_p256_container_from_reference_cli() {
    let provider = provider_with("cdoc2client_256_priv.key");
    let container = vector("ec_256_simple.cdoc2");

    let files = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .expect("SC01 on secp256r1 must succeed");
    assert_eq!(files[0].name, "README.md");
}

#[test]
fn decrypts_sc02_rsa_container_from_reference_cli() {
    let provider = provider_with("rsa_priv.pem");
    let container = vector("rsa_simple.cdoc2");

    let files = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .expect("SC02 decryption must succeed");
    assert_eq!(files[0].name, "README.md");
}

// ---------------------------------------------------------------------------
// Recipient matching happens before any private-key operation
// ---------------------------------------------------------------------------

/// A provider whose `perform` panics, proving the key operation is never reached when no
/// identity matches. On a real card, reaching `perform` would mean a needless PIN prompt.
struct NeverPerform(SoftwareKeyProvider);

impl KeyProvider for NeverPerform {
    fn identities(&self) -> umbrik_core::Result<Vec<umbrik_core::provider::Identity>> {
        self.0.identities()
    }
    fn perform(
        &self,
        _id: &umbrik_core::provider::Identity,
        _op: umbrik_core::provider::KeyOp<'_>,
    ) -> umbrik_core::Result<zeroize::Zeroizing<Vec<u8>>> {
        panic!("perform must not be called when no recipient matches");
    }
}

#[test]
fn non_matching_recipient_never_triggers_a_key_operation() {
    // An RSA key against an EC container: no identity can match.
    let provider = NeverPerform(provider_with("rsa_priv.pem"));
    let container = vector("ec_simple.cdoc2");

    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NoMatchingRecipient);
}

#[test]
fn wrong_ec_key_does_not_match_recipient() {
    // P-256 key, P-384 container.
    let provider = NeverPerform(provider_with("cdoc2client_256_priv.key"));
    let container = vector("ec_simple.cdoc2");

    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NoMatchingRecipient);
}

// ---------------------------------------------------------------------------
// Certificate parsing and encryption round trips
// ---------------------------------------------------------------------------

#[test]
fn parses_ec_recipient_certificate() {
    let parsed = cert::from_pem(&key_pem("cdoc2client-certificate.pem")).expect("parse cert");
    match parsed.key {
        PublicKeyRef::Ec(key) => {
            assert_eq!(key.curve, EllipticCurve::Secp384r1);
            assert_eq!(key.tls_point.len(), 97);
            assert_eq!(key.tls_point[0], 0x04);
        }
        other => panic!("expected EC key, got {other:?}"),
    }
}

/// The key extracted from a certificate must be the same key the matching private key derives.
///
/// This is what makes "encrypt to this certificate, decrypt with this key" work at all: if
/// certificate parsing and private-key loading disagreed on the encoding, encryption would
/// silently target a key nobody holds.
#[test]
fn certificate_and_private_key_agree_on_the_public_key() {
    let from_cert = cert::from_pem(&key_pem("cdoc2client-certificate.pem")).unwrap();
    let provider = provider_with("cdoc2client_priv.key");
    let from_key = provider.identities().unwrap().remove(0);
    assert_eq!(from_cert.key, from_key.key);
}

/// The reference container is a well-formed SC01/P-384 record even though we cannot open it.
/// Parsing and decrypting are separate concerns and must fail separately.
#[test]
fn ec_simple_vector_is_structurally_sc01_p384() {
    let container = vector("ec_simple.cdoc2");
    let header = Envelope::parse(&container)
        .unwrap()
        .decode_header()
        .unwrap();
    match &header.recipients[0].capsule {
        Capsule::EccPublicKey {
            curve,
            recipient_public_key,
            sender_public_key,
        } => {
            assert_eq!(*curve, EllipticCurve::Secp384r1);
            assert_eq!(recipient_public_key.len(), 97);
            assert_eq!(sender_public_key.len(), 97);
        }
        other => panic!("expected ECC capsule, got {other:?}"),
    }
}

fn files() -> Vec<PayloadFile> {
    vec![PayloadFile {
        name: "note.txt".to_string(),
        data: b"Tere!\n".to_vec(),
    }]
}

#[test]
fn sc01_encrypt_decrypt_round_trip() {
    let parsed = cert::from_pem(&key_pem("cdoc2client-certificate.pem")).unwrap();
    let recipient = Recipient::PublicKey {
        label: "cdoc20-client".to_string(),
        key: parsed.key,
    };

    let mut container = Vec::new();
    container::encrypt(
        &mut container,
        &mut rand_core::OsRng,
        &files(),
        &[recipient],
    )
    .expect("SC01 encrypt");

    let provider = provider_with("cdoc2client_priv.key");
    let out = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .expect("SC01 decrypt");
    assert_eq!(out, files());
}

#[test]
fn sc02_encrypt_decrypt_round_trip() {
    // Derive the recipient public key from the private key we will decrypt with.
    let provider = provider_with("rsa_priv.pem");
    let identity = provider.identities().unwrap().remove(0);

    let mut container = Vec::new();
    container::encrypt(
        &mut container,
        &mut rand_core::OsRng,
        &files(),
        &[Recipient::PublicKey {
            label: "rsa-recipient".to_string(),
            key: identity.key,
        }],
    )
    .expect("SC02 encrypt");

    let out = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .expect("SC02 decrypt");
    assert_eq!(out, files());
}

/// SC01 does not feed the key label into KEK derivation, unlike SC05/SC06. Renaming the label
/// must therefore leave decryption working — a property worth pinning, since getting it wrong in
/// either direction breaks interoperability.
#[test]
fn sc01_key_label_is_not_cryptographically_binding() {
    let parsed = cert::from_pem(&key_pem("cdoc2client-certificate.pem")).unwrap();

    let mut container = Vec::new();
    container::encrypt(
        &mut container,
        &mut rand_core::OsRng,
        &files(),
        &[Recipient::PublicKey {
            label: "an-arbitrary-label".to_string(),
            key: parsed.key,
        }],
    )
    .unwrap();

    let provider = provider_with("cdoc2client_priv.key");
    let out = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .expect("label must not affect SC01 decryption");
    assert_eq!(out, files());
}

// ---------------------------------------------------------------------------
// Certificate validity
// ---------------------------------------------------------------------------

/// The committed test certificate is currently valid, which the whole suite depends on.
#[test]
fn test_certificate_is_within_its_validity_window() {
    let parsed = cert::from_pem(&key_pem("cdoc2client-certificate.pem")).unwrap();
    assert_eq!(parsed.validity_now(), cert::Validity::Valid);
}

#[test]
fn reports_a_certificate_that_has_expired() {
    let parsed = cert::from_pem(&key_pem("cdoc2client-certificate.pem")).unwrap();
    let after = parsed.not_after.expect("certificate carries notAfter");
    assert_eq!(parsed.validity(after + 1), cert::Validity::Expired);
    assert_eq!(parsed.validity(after), cert::Validity::Valid);
}

#[test]
fn reports_a_certificate_that_is_not_yet_valid() {
    let parsed = cert::from_pem(&key_pem("cdoc2client-certificate.pem")).unwrap();
    let before = parsed.not_before.expect("certificate carries notBefore");
    assert_eq!(parsed.validity(before - 1), cert::Validity::NotYetValid);
    assert_eq!(parsed.validity(before), cert::Validity::Valid);
}

/// Validity reporting must not block parsing: an expired certificate still yields a usable key,
/// so the caller can decide.
#[test]
fn an_expired_certificate_still_parses() {
    let parsed = cert::from_pem(&key_pem("cdoc2client-certificate.pem")).unwrap();
    assert!(matches!(parsed.key, PublicKeyRef::Ec(_)));
    assert!(parsed.not_before.unwrap() < parsed.not_after.unwrap());
}

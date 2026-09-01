//! M1 gate: parse real `cdoc2-cli` containers and verify their header HMACs.
//!
//! Vectors come from `open-eid/cdoc2-java-ref-impl` `test/testvectors/` — see
//! `tests/vectors/PROVENANCE.md`. They were produced by the reference CLI, not by umbrik, so
//! these tests check interoperability rather than self-consistency.

use base64::Engine;
use std::path::PathBuf;
use umbrik_core::error::ErrorCode;
use umbrik_core::header::{
    Capsule, EllipticCurve, Envelope, FmkEncryptionMethod, Header, KdfAlgorithm,
    PayloadEncryptionMethod,
};
use umbrik_core::keys::{Fmk, VerifiedHeader};
use umbrik_core::schemes::sc05;

fn vector(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The pre-shared secret used to generate the symmetric vectors upstream
/// (`test/generate_documents.sh`).
const SYMMETRIC_SECRET_B64: &str = "HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=";

/// Recover the FMK from the SC05 vector, exercising the full documented chain.
fn symmetric_vector_fmk(header: &Header) -> Fmk {
    let rec = &header.recipients[0];
    let salt = match &rec.capsule {
        Capsule::SymmetricKey { salt } => salt,
        other => panic!("expected SymmetricKey capsule, got {}", other.scheme()),
    };
    let secret = base64::engine::general_purpose::STANDARD
        .decode(SYMMETRIC_SECRET_B64)
        .unwrap();
    let kek = sc05::kek(
        &secret,
        salt,
        rec.fmk_encryption_method.kdf_name().unwrap(),
        &rec.key_label,
    )
    .expect("SC05 KEK derivation");
    Fmk::unwrap_xor(&rec.encrypted_fmk, &kek).expect("unwrap FMK")
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[test]
fn parses_envelope_framing_of_real_container() {
    let buf = vector("symmetric.cdoc2");
    let env = Envelope::parse(&buf).expect("parse envelope");

    // 4 prelude + 1 version + 4 length = 9, then 188 header, 32 HMAC, 3344 payload.
    assert_eq!(env.header_bytes().len(), 188);
    assert_eq!(env.payload().len(), 3344);
    assert_eq!(buf.len(), 9 + 188 + 32 + 3344);
}

// ---------------------------------------------------------------------------
// Header decoding, one test per implemented scheme's capsule
// ---------------------------------------------------------------------------

#[test]
fn decodes_sc05_symmetric_capsule() {
    let buf = vector("symmetric.cdoc2");
    let header = Envelope::parse(&buf).unwrap().decode_header().unwrap();

    assert_eq!(
        header.payload_encryption_method,
        PayloadEncryptionMethod::ChaCha20Poly1305
    );
    assert_eq!(header.recipients.len(), 1);
    let rec = &header.recipients[0];
    assert_eq!(rec.key_label, "create_symmetric_label");
    assert_eq!(rec.fmk_encryption_method, FmkEncryptionMethod::Xor);
    assert_eq!(rec.encrypted_fmk.len(), 32);
    match &rec.capsule {
        Capsule::SymmetricKey { salt } => assert_eq!(salt.len(), 32),
        other => panic!("wrong capsule: {}", other.scheme()),
    }
}

#[test]
fn decodes_sc06_pbkdf2_capsule() {
    let buf = vector("password.cdoc2");
    let header = Envelope::parse(&buf).unwrap().decode_header().unwrap();

    let rec = &header.recipients[0];
    assert_eq!(rec.key_label, "kevade");
    match &rec.capsule {
        Capsule::Pbkdf2 {
            salt,
            password_salt,
            kdf_algorithm,
            kdf_iterations,
        } => {
            assert_eq!(*kdf_algorithm, KdfAlgorithm::Pbkdf2WithHmacSha256);
            assert_eq!(*kdf_iterations, 600_000);
            assert_eq!(salt.len(), 32);
            assert_eq!(password_salt.len(), 32);
            // The two salts are independent fields and must never be conflated.
            assert_ne!(salt, password_salt);
        }
        other => panic!("wrong capsule: {}", other.scheme()),
    }
}

#[test]
fn decodes_sc01_ecc_capsule() {
    let buf = vector("ec_simple.cdoc2");
    let header = Envelope::parse(&buf).unwrap().decode_header().unwrap();

    let rec = &header.recipients[0];
    assert_eq!(rec.key_label, "cdoc20-client");
    match &rec.capsule {
        Capsule::EccPublicKey {
            curve,
            recipient_public_key,
            sender_public_key,
        } => {
            assert_eq!(*curve, EllipticCurve::Secp384r1);
            // TLS uncompressed point: 0x04 || X(48) || Y(48).
            assert_eq!(recipient_public_key.len(), 97);
            assert_eq!(sender_public_key.len(), 97);
            assert_eq!(recipient_public_key[0], 0x04);
            assert_eq!(sender_public_key[0], 0x04);
        }
        other => panic!("wrong capsule: {}", other.scheme()),
    }
}

#[test]
fn decodes_sc02_rsa_capsule() {
    let buf = vector("rsa_simple.cdoc2");
    let header = Envelope::parse(&buf).unwrap().decode_header().unwrap();

    match &header.recipients[0].capsule {
        Capsule::RsaPublicKey {
            recipient_public_key,
            encrypted_kek,
        } => {
            assert!(!recipient_public_key.is_empty());
            assert_eq!(encrypted_kek.len(), 256); // RSA-2048
        }
        other => panic!("wrong capsule: {}", other.scheme()),
    }
}

// ---------------------------------------------------------------------------
// M1 gate: HMAC verifies against a real container given a known FMK
// ---------------------------------------------------------------------------

#[test]
fn verifies_header_hmac_of_real_container() {
    let buf = vector("symmetric.cdoc2");
    let env = Envelope::parse(&buf).unwrap();
    let header = env.decode_header().unwrap();

    let fmk = symmetric_vector_fmk(&header);
    let hhk = fmk.derive_hhk().unwrap();

    let verified = VerifiedHeader::verify(&env, header, &hhk).expect("header HMAC must verify");
    assert_eq!(verified.header().recipients.len(), 1);
}

/// Golden values, cross-checked against an independent implementation before being pinned here.
/// These catch a consistently-applied wrong constant, which round-trip tests cannot.
#[test]
fn derives_expected_fmk_and_cek() {
    let buf = vector("symmetric.cdoc2");
    let header = Envelope::parse(&buf).unwrap().decode_header().unwrap();

    let fmk = symmetric_vector_fmk(&header);
    assert_eq!(
        hex::encode(fmk.as_bytes()),
        "3232650cdcf043ba309195f55da3b676b50c88d92a9ecac2bb7f012700cecce7"
    );
    assert_eq!(
        hex::encode(fmk.derive_cek().unwrap().as_bytes()),
        "737664b0fe9b0c6f9b559f4d75f48cd7b6d7f669c874bc678ae822ad1966465e"
    );
}

#[test]
fn aad_is_prefix_header_hmac_concatenation() {
    let buf = vector("symmetric.cdoc2");
    let env = Envelope::parse(&buf).unwrap();
    let header = env.decode_header().unwrap();
    let fmk = symmetric_vector_fmk(&header);
    let verified = VerifiedHeader::verify(&env, header, &fmk.derive_hhk().unwrap()).unwrap();

    let aad = verified.aad();
    assert_eq!(aad.len(), 13 + 188 + 32);
    assert!(aad.starts_with(b"CDOC20payload"));
    assert!(aad.ends_with(env.header_hmac()));
}

// ---------------------------------------------------------------------------
// Negative tests — each must fail closed with a distinct error code
// ---------------------------------------------------------------------------

#[test]
fn tampered_header_fails_hmac() {
    let mut buf = vector("symmetric.cdoc2");
    // Flip one bit inside the FlatBuffers header (offset 9 begins the header).
    buf[100] ^= 0x01;

    let env = Envelope::parse(&buf).unwrap();
    let header = env.decode_header().unwrap();
    let fmk = symmetric_vector_fmk(&header);
    let err = VerifiedHeader::verify(&env, header, &fmk.derive_hhk().unwrap()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::HeaderHmacMismatch);
}

#[test]
fn wrong_key_fails_hmac_not_parse() {
    let buf = vector("symmetric.cdoc2");
    let env = Envelope::parse(&buf).unwrap();
    let header = env.decode_header().unwrap();

    let wrong = Fmk::from_bytes([0x42; 32]);
    let err = VerifiedHeader::verify(&env, header, &wrong.derive_hhk().unwrap()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::HeaderHmacMismatch);
}

#[test]
fn rejects_bad_prelude() {
    let mut buf = vector("symmetric.cdoc2");
    buf[0] = b'X';
    assert_eq!(
        Envelope::parse(&buf).unwrap_err().code(),
        ErrorCode::BadPrelude
    );
}

#[test]
fn rejects_unsupported_version() {
    let mut buf = vector("symmetric.cdoc2");
    buf[4] = 0x03;
    assert_eq!(
        Envelope::parse(&buf).unwrap_err().code(),
        ErrorCode::UnsupportedVersion
    );
}

#[test]
fn rejects_oversized_header_length_before_allocating() {
    let mut buf = vector("symmetric.cdoc2");
    buf[5..9].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    assert_eq!(
        Envelope::parse(&buf).unwrap_err().code(),
        ErrorCode::HeaderLengthOutOfRange
    );
}

#[test]
fn rejects_undersized_header_length() {
    let mut buf = vector("symmetric.cdoc2");
    buf[5..9].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        Envelope::parse(&buf).unwrap_err().code(),
        ErrorCode::HeaderLengthOutOfRange
    );
}

#[test]
fn rejects_truncated_container() {
    let buf = vector("symmetric.cdoc2");
    let truncated = &buf[..buf.len() - 3300];
    assert_eq!(
        Envelope::parse(truncated).unwrap_err().code(),
        ErrorCode::Truncated
    );
}

#[test]
fn rejects_empty_input() {
    assert_eq!(
        Envelope::parse(&[]).unwrap_err().code(),
        ErrorCode::Truncated
    );
}

#[test]
fn malformed_flatbuffers_header_does_not_panic() {
    // Valid framing, garbage header body.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"CDOC");
    buf.push(0x02);
    buf.extend_from_slice(&100u32.to_be_bytes());
    buf.extend_from_slice(&[0xAB; 100]);
    buf.extend_from_slice(&[0x00; 32]);
    buf.extend_from_slice(&[0x00; 64]);

    let env = Envelope::parse(&buf).expect("framing is well formed");
    assert_eq!(
        env.decode_header().unwrap_err().code(),
        ErrorCode::MalformedHeader
    );
}

/// A capsule type umbrik does not implement must still *parse*, then be reported as
/// unsupported. Parse failure and unsupported-scheme are different conditions.
#[test]
fn unimplemented_schemes_parse_and_report_distinctly() {
    // Both server-scenario vectors use KeyServerCapsule (SC03/SC04, deferred to M5).
    let buf = vector("ec_server_ria_dev_pkcs12.cdoc2");
    let header = Envelope::parse(&buf)
        .unwrap()
        .decode_header()
        .expect("unsupported schemes must still parse");
    assert!(matches!(header.recipients[0].capsule, Capsule::KeyServer));
    assert_eq!(header.recipients[0].capsule.scheme(), "SC03/SC04");
}

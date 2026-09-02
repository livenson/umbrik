//! M2: SC05 and SC06 encrypt/decrypt, golden-file determinism, and fail-closed behaviour.

use rand_core::{TryCryptoRng, TryRng};
use std::path::PathBuf;
use umbrik_core::container::{self, DecryptionKey, Recipient};
use umbrik_core::error::ErrorCode;
use umbrik_core::payload::PayloadFile;
use umbrik_core::Limits;

/// A deterministic RNG for golden-file tests.
///
/// Not a CSPRNG — it exists purely so `encrypt` produces byte-identical output across runs.
/// `encrypt` takes the RNG as a parameter precisely so this substitution is possible; a global
/// RNG would make golden files impossible and leave a consistently-wrong constant undetectable.
struct FixedRng(u64);

impl FixedRng {
    fn new() -> Self {
        FixedRng(0x0123_4567_89AB_CDEF)
    }
}

impl FixedRng {
    /// SplitMix64. Kept byte-for-byte identical across the rand_core 0.10 migration: the golden
    /// file pins umbrik's output under this exact stream, so a change here would look like a
    /// change in the container format.
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// rand_core 0.10 moved the implementation point to `TryRng`; `Rng` and `CryptoRng` follow from
// blanket impls once the error type is `Infallible`.
impl TryRng for FixedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok((self.step() >> 32) as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.step())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.step().to_le_bytes();
            for (slot, byte) in chunk.iter_mut().zip(bytes.iter()) {
                *slot = *byte;
            }
        }
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

const SECRET: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const PASSWORD: &str = "correct-horse-battery-staple-õäöü";

fn files() -> Vec<PayloadFile> {
    vec![
        PayloadFile {
            name: "hello.txt".to_string(),
            data: b"Tere, maailm!\n".to_vec(),
        },
        PayloadFile {
            name: "notes.md".to_string(),
            data: b"# notes\n\nsecond entry\n".to_vec(),
        },
    ]
}

fn symmetric_recipient() -> Recipient {
    Recipient::Symmetric {
        label: "test-label".to_string(),
        secret: SECRET.to_vec().into(),
    }
}

fn password_recipient() -> Recipient {
    Recipient::Password {
        label: "pw-label".to_string(),
        password: PASSWORD.to_string().into(),
    }
}

fn encrypt_to_vec(recipients: &[Recipient], files: &[PayloadFile]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rng = FixedRng::new();
    container::encrypt(&mut out, &mut rng, files, recipients).expect("encrypt");
    out
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn sc05_round_trip() {
    let container = encrypt_to_vec(&[symmetric_recipient()], &files());
    let key = DecryptionKey::Symmetric(SECRET.to_vec().into());
    let out = container::decrypt_to_memory(&container, &key, &Limits::default()).unwrap();
    assert_eq!(out, files());
}

#[test]
fn sc06_round_trip() {
    let container = encrypt_to_vec(&[password_recipient()], &files());
    let key = DecryptionKey::Password(PASSWORD.to_string().into());
    let out = container::decrypt_to_memory(&container, &key, &Limits::default()).unwrap();
    assert_eq!(out, files());
}

/// Multiple recipients share one FMK; either key must open the container.
#[test]
fn multi_recipient_container_opens_with_either_key() {
    let container = encrypt_to_vec(&[symmetric_recipient(), password_recipient()], &files());

    let by_secret = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &Limits::default(),
    )
    .unwrap();
    let by_password = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Password(PASSWORD.to_string().into()),
        &Limits::default(),
    )
    .unwrap();

    assert_eq!(by_secret, files());
    assert_eq!(by_password, files());
}

#[test]
fn container_uses_expected_framing() {
    let container = encrypt_to_vec(&[symmetric_recipient()], &files());
    assert_eq!(&container[0..4], b"CDOC");
    assert_eq!(container[4], 0x02);

    // umbrik's own output must satisfy umbrik's parser.
    let env = umbrik_core::header::Envelope::parse(&container).unwrap();
    let header = env.decode_header().unwrap();
    assert_eq!(header.recipients.len(), 1);
    assert_eq!(header.recipients[0].key_label, "test-label");
}

// ---------------------------------------------------------------------------
// Golden file: fixed RNG in, byte-identical container out
// ---------------------------------------------------------------------------

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/golden")
        .join(name)
}

/// Pin umbrik's output byte-for-byte under a fixed RNG.
///
/// This catches silent drift in header field ordering, tar metadata, or compression settings —
/// changes a round-trip test cannot see because both sides move together. It does *not* prove
/// interoperability; only the interop job against `cdoc2-cli` does that.
///
/// Regenerate deliberately with `UMBRIK_WRITE_GOLDEN=1 cargo test`, and treat any diff as a
/// wire-format change needing interop re-validation.
#[test]
fn sc05_golden_file_is_byte_identical() {
    let container = encrypt_to_vec(&[symmetric_recipient()], &files());
    let path = golden_path("sc05_fixed_rng.cdoc2");

    if std::env::var("UMBRIK_WRITE_GOLDEN").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &container).unwrap();
    }

    let expected = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden file {}: {e}\nregenerate with UMBRIK_WRITE_GOLDEN=1 cargo test",
            path.display()
        )
    });
    assert_eq!(
        container, expected,
        "container output drifted from the committed golden file"
    );

    // And the pinned bytes must still decrypt.
    let out = container::decrypt_to_memory(
        &expected,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(out, files());
}

#[test]
fn fixed_rng_is_reproducible() {
    let a = encrypt_to_vec(&[symmetric_recipient()], &files());
    let b = encrypt_to_vec(&[symmetric_recipient()], &files());
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Negative tests — each fails closed with a distinct code
// ---------------------------------------------------------------------------

#[test]
fn wrong_password_is_rejected() {
    let container = encrypt_to_vec(&[password_recipient()], &files());
    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Password("not-the-password".to_string().into()),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::HeaderHmacMismatch);
}

#[test]
fn wrong_secret_is_rejected() {
    let container = encrypt_to_vec(&[symmetric_recipient()], &files());
    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(vec![0xAA; 32].into()),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::HeaderHmacMismatch);
}

/// Offering a password for a container that has only a symmetric recipient is a non-match,
/// not a MAC failure.
#[test]
fn key_of_wrong_kind_reports_no_matching_recipient() {
    let container = encrypt_to_vec(&[symmetric_recipient()], &files());
    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Password(PASSWORD.to_string().into()),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NoMatchingRecipient);
}

#[test]
fn tampered_ciphertext_fails_aead_not_hmac() {
    let mut container = encrypt_to_vec(&[symmetric_recipient()], &files());
    let last = container.len() - 20;
    container[last] ^= 0xFF;

    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PayloadAuthenticationFailed);
}

#[test]
fn tampered_tag_fails_aead() {
    let mut container = encrypt_to_vec(&[symmetric_recipient()], &files());
    let last = container.len() - 1;
    container[last] ^= 0x01;

    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PayloadAuthenticationFailed);
}

#[test]
fn tampered_nonce_fails_aead() {
    let container = encrypt_to_vec(&[symmetric_recipient()], &files());
    let env = umbrik_core::header::Envelope::parse(&container).unwrap();
    let nonce_offset = container.len() - env.payload().len();

    let mut tampered = container.clone();
    tampered[nonce_offset] ^= 0x01;

    let err = container::decrypt_to_memory(
        &tampered,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PayloadAuthenticationFailed);
}

// ---------------------------------------------------------------------------
// Hostile payload handling
// ---------------------------------------------------------------------------

/// Defence in depth on the write side: umbrik refuses to *build* a container whose entry names
/// would be rejected on extraction. The reader-side defence — which is what actually matters,
/// since hostile containers come from elsewhere — is tested in `hostile_payload.rs`.
#[test]
fn refuses_to_create_unsafe_entry_names() {
    for name in [
        "../escaped.txt",
        "a/../../escaped.txt",
        "./../escaped.txt",
        "/etc/passwd",
        "",
    ] {
        let mut out = Vec::new();
        let mut rng = FixedRng::new();
        let err = container::encrypt(
            &mut out,
            &mut rng,
            &[PayloadFile {
                name: name.to_string(),
                data: b"payload".to_vec(),
            }],
            &[symmetric_recipient()],
        )
        .unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::UnsafeArchiveEntry,
            "entry name {name:?} must be refused at encrypt time"
        );
    }
}

#[test]
fn rejects_zip_bomb_by_ratio() {
    // 4 MiB of zeros compresses far past the default ratio of 10.
    let container = encrypt_to_vec(
        &[symmetric_recipient()],
        &[PayloadFile {
            name: "bomb".to_string(),
            data: vec![0u8; 4 * 1024 * 1024],
        }],
    );
    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn small_files_are_not_mistaken_for_zip_bombs() {
    // A tar is padded to ~10 KiB, so one tiny file trivially exceeds a naive ratio check.
    let container = encrypt_to_vec(
        &[symmetric_recipient()],
        &[PayloadFile {
            name: "tiny.txt".to_string(),
            data: b"hi".to_vec(),
        }],
    );
    let out = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].data, b"hi");
}

#[test]
fn rejects_too_many_entries() {
    let many: Vec<PayloadFile> = (0..20)
        .map(|i| PayloadFile {
            name: format!("f{i}.txt"),
            data: b"x".to_vec(),
        })
        .collect();
    let container = encrypt_to_vec(&[symmetric_recipient()], &many);

    let limits = Limits::default().with_max_entries(5);
    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn rejects_payload_over_absolute_byte_cap() {
    let container = encrypt_to_vec(
        &[symmetric_recipient()],
        &[PayloadFile {
            name: "big.txt".to_string(),
            data: vec![b'a'; 200 * 1024],
        }],
    );
    let limits = Limits::default().with_max_uncompressed_bytes(1024);
    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn encrypting_to_no_recipients_is_rejected() {
    let mut out = Vec::new();
    let mut rng = FixedRng::new();
    let err = container::encrypt(&mut out, &mut rng, &files(), &[]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidKeyMaterial);
}

#[test]
fn short_pre_shared_key_is_rejected() {
    let mut out = Vec::new();
    let mut rng = FixedRng::new();
    let err = container::encrypt(
        &mut out,
        &mut rng,
        &files(),
        &[Recipient::Symmetric {
            label: "short".to_string(),
            secret: vec![0u8; 16].into(),
        }],
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidKeyMaterial);
}

// ---------------------------------------------------------------------------
// Work bounds: a hostile container must not be able to buy unbounded CPU
// ---------------------------------------------------------------------------

/// PBKDF2 cost is `iterations x recipients`, both attacker-chosen. Capping one capsule is not
/// enough, so the budget is cumulative across candidates.
#[test]
fn rejects_container_over_kdf_iteration_budget() {
    let container = encrypt_to_vec(&[password_recipient()], &files());
    let limits = Limits::default().with_max_total_kdf_iterations(1_000);

    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Password(PASSWORD.to_string().into()),
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn default_kdf_budget_admits_a_normal_container() {
    // One SC06 recipient at 600 000 iterations must comfortably fit the default budget.
    let container = encrypt_to_vec(&[password_recipient()], &files());
    let out = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Password(PASSWORD.to_string().into()),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(out, files());
}

#[test]
fn rejects_container_with_too_many_recipients() {
    let container = encrypt_to_vec(&[symmetric_recipient(), password_recipient()], &files());
    let limits = Limits::default().with_max_recipients(1);

    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Symmetric(SECRET.to_vec().into()),
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

/// The budget must be charged before the work, so a single absurd capsule cannot run first and
/// only then be rejected.
#[test]
fn kdf_budget_is_charged_before_the_work() {
    let container = encrypt_to_vec(&[password_recipient()], &files());
    let limits = Limits::default().with_max_total_kdf_iterations(0);

    let start = std::time::Instant::now();
    let err = container::decrypt_to_memory(
        &container,
        &DecryptionKey::Password(PASSWORD.to_string().into()),
        &limits,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
    // 600 000 PBKDF2 iterations take far longer than this; failing fast proves none ran.
    assert!(
        start.elapsed() < std::time::Duration::from_millis(100),
        "rejection should precede the PBKDF2 work"
    );
}

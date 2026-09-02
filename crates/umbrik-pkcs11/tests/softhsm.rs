//! PKCS#11 provider against a SoftHSM2 software token.
//!
//! Prepare a token and run:
//!
//! ```bash
//! eval "$(crates/umbrik-pkcs11/tests/setup-softhsm.sh)"
//! cargo test -p umbrik-pkcs11
//! ```
//!
//! Without that environment the tests skip rather than fail, so `cargo test` stays green on a
//! machine with no PKCS#11 module. CI runs the setup script, so the skip never hides a
//! regression there.
//!
//! What this covers: module loading, slot and token enumeration, reading certificates without a
//! login, `CKA_ID` pairing, PIN login, and `CKM_ECDH1_DERIVE` feeding a real SC01 decryption.
//! What it cannot cover is how a smart card differs — see the `CARD-SPECIFIC` notes in the
//! crate source.

use umbrik_core::container::{self, DecryptionKey, Recipient};
use umbrik_core::payload::PayloadFile;
use umbrik_core::provider::KeyProvider;
use umbrik_core::Limits;
use umbrik_pkcs11::{Pkcs11KeyProvider, StaticPin};

/// PKCS#11 modules initialise process-wide, so two providers must never be alive at once —
/// concurrent `C_Initialize`/`C_Finalize` from parallel tests segfaults the module rather than
/// returning an error. Every test holds this lock for as long as it holds a provider.
static PKCS11: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Poisoning is irrelevant here: the mutex guards no data, only module lifetime.
fn serialised() -> std::sync::MutexGuard<'static, ()> {
    PKCS11
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Returns `None` when no token is configured, so the caller can skip.
fn provider() -> Option<Pkcs11KeyProvider> {
    let module = std::env::var("UMBRIK_PKCS11_MODULE").ok()?;
    let pin = std::env::var("UMBRIK_PKCS11_PIN").unwrap_or_else(|_| "648219".to_string());

    match Pkcs11KeyProvider::open(&module, Box::new(StaticPin::new(pin))) {
        Ok(provider) => Some(provider),
        Err(e) => panic!("UMBRIK_PKCS11_MODULE is set but the token would not open: {e}"),
    }
}

macro_rules! token_or_skip {
    () => {
        match provider() {
            Some(provider) => provider,
            None => {
                eprintln!("skipping: UMBRIK_PKCS11_MODULE not set (run tests/setup-softhsm.sh)");
                return;
            }
        }
    };
}

fn files() -> Vec<PayloadFile> {
    vec![PayloadFile {
        name: "on-token.txt".to_string(),
        data: b"decrypted with a key that never left the token\n".to_vec(),
    }]
}

#[test]
fn enumerates_identities_without_a_pin() {
    let _guard = serialised();
    let provider = token_or_skip!();

    // Constructing the provider and listing identities must not have needed the PIN: recipient
    // matching happens before any user interaction, so an unrelated container never costs a
    // PIN entry — and on a real card, never risks the retry counter.
    let identities = provider.identities().expect("listing identities");
    assert!(
        !identities.is_empty(),
        "token should expose at least one key"
    );
    assert!(
        identities.iter().any(|id| id.label.contains("UMBRIK TEST")),
        "expected the test certificate, got {:?}",
        identities.iter().map(|i| &i.label).collect::<Vec<_>>()
    );
}

#[test]
fn sc01_round_trip_through_the_token() {
    let _guard = serialised();
    let provider = token_or_skip!();
    let identity = provider.identities().unwrap().remove(0);

    // Encrypt to the token's public key, exactly as a sender would.
    let mut sealed = Vec::new();
    container::encrypt(
        &mut sealed,
        &mut rand::rng(),
        &files(),
        &[Recipient::PublicKey {
            label: identity.label.clone(),
            key: identity.key.clone(),
        }],
    )
    .expect("encrypt to token key");

    // Decrypt with ECDH performed on the token.
    let out = container::decrypt_to_memory(
        &sealed,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .expect("decrypt via PKCS#11");

    assert_eq!(out, files());
}

/// A container addressed to somebody else must be reported as a non-match, and must never reach
/// the token. On a card, reaching it would mean a needless PIN prompt.
#[test]
fn container_for_another_recipient_does_not_match() {
    let _guard = serialised();
    let provider = token_or_skip!();

    let mut sealed = Vec::new();
    container::encrypt(
        &mut sealed,
        &mut rand::rng(),
        &files(),
        &[Recipient::Password {
            label: "someone-else".to_string(),
            password: "not-for-the-token".to_string().into(),
        }],
    )
    .unwrap();

    let err = container::decrypt_to_memory(
        &sealed,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(
        err.code(),
        umbrik_core::error::ErrorCode::NoMatchingRecipient
    );
}

#[test]
fn wrong_pin_is_reported_as_a_provider_error() {
    let _guard = serialised();
    if std::env::var("UMBRIK_PKCS11_MODULE").is_err() {
        eprintln!("skipping: UMBRIK_PKCS11_MODULE not set");
        return;
    }
    let module = std::env::var("UMBRIK_PKCS11_MODULE").unwrap();

    // Enumeration reads certificates and needs no login, so opening still succeeds.
    let provider = Pkcs11KeyProvider::open(&module, Box::new(StaticPin::new("000000")))
        .expect("opening a token does not require a valid PIN");
    let identity = provider.identities().unwrap().remove(0);

    let mut sealed = Vec::new();
    container::encrypt(
        &mut sealed,
        &mut rand::rng(),
        &files(),
        &[Recipient::PublicKey {
            label: identity.label.clone(),
            key: identity.key.clone(),
        }],
    )
    .unwrap();

    let err = container::decrypt_to_memory(
        &sealed,
        &DecryptionKey::Provider(&provider),
        &Limits::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), umbrik_core::error::ErrorCode::KeyProvider);

    // The message must name the failure without leaking the PIN.
    let message = err.to_string();
    assert!(
        !message.contains("000000"),
        "PIN leaked into error: {message}"
    );
}

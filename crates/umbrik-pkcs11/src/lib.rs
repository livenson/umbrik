//! PKCS#11 [`KeyProvider`] — ID-cards, smart cards, and software tokens.
//!
//! # Licensing
//!
//! umbrik is MIT. PKCS#11 modules frequently are not: OpenSC and the Estonian eID module are
//! LGPL-2.1. That is fine here, and the reason is linkage. `cryptoki` loads a module at runtime
//! with `dlopen`, across the stable PKCS#11 C ABI, from a path the *user* supplies. umbrik
//! neither links nor distributes any module. This stays true only as long as no module is ever
//! bundled, vendored, or statically linked into this crate — don't.
//!
//! # One provider per process
//!
//! PKCS#11 modules are initialised process-wide: `C_Initialize` may be called once, and
//! `C_Finalize` tears down state shared by every handle in the process. Creating a second
//! [`Pkcs11KeyProvider`] for the same module while another is alive — or dropping one while
//! another is in use — can crash the module, not merely return an error.
//!
//! Construct one provider per module and share it. This crate cannot enforce that: the
//! constraint lives in the loaded C library, outside Rust's ownership model.
//!
//! # What is verified, and what is not
//!
//! Everything here is exercised against **SoftHSM2** in CI: session handling, login, object
//! discovery, and `CKM_ECDH1_DERIVE`. What SoftHSM cannot tell us is how a *particular smart
//! card* behaves, and tokens differ in ways that matter. The assumptions that need validating
//! against real hardware are marked `CARD-SPECIFIC` throughout.

use std::path::Path;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use umbrik_core::cert;
use umbrik_core::error::{Error, Result};
use umbrik_core::provider::{Identity, KeyOp, KeyProvider};
use zeroize::Zeroizing;

/// Where a PIN comes from.
///
/// Deliberately separate from [`KeyProvider`]: a PIN is a property of one kind of token, not of
/// the key abstraction, and `umbrik-core` has no concept of one. Implement this to prompt
/// interactively, read an environment variable in tests, or pull from a keychain.
pub trait PinSource {
    /// Supply the user PIN for a token.
    ///
    /// `token_label` identifies which token is asking, so a caller with several readers can
    /// prompt for the right one.
    fn pin(&self, token_label: &str) -> Result<Zeroizing<String>>;
}

/// A fixed PIN. Convenient for tests and non-interactive use.
///
/// Holding a PIN in memory for the life of a provider is a deliberate trade-off; prefer an
/// interactive [`PinSource`] where a human is present.
pub struct StaticPin(Zeroizing<String>);

impl StaticPin {
    pub fn new(pin: impl Into<String>) -> Self {
        StaticPin(Zeroizing::new(pin.into()))
    }
}

impl PinSource for StaticPin {
    fn pin(&self, _token_label: &str) -> Result<Zeroizing<String>> {
        Ok(self.0.clone())
    }
}

/// One usable key on a token.
struct TokenKey {
    identity: Identity,
    slot: Slot,
    token_label: String,
    /// `CKA_ID`, which ties a certificate to its private key on the same token.
    cka_id: Vec<u8>,
}

/// A [`KeyProvider`] backed by a PKCS#11 module.
pub struct Pkcs11KeyProvider {
    context: Pkcs11,
    pin_source: Box<dyn PinSource>,
    keys: Vec<TokenKey>,
}

impl std::fmt::Debug for Pkcs11KeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11KeyProvider")
            .field("keys", &self.keys.len())
            .finish()
    }
}

fn provider_err(context: &str, e: impl std::fmt::Display) -> Error {
    // PKCS#11 errors can name objects but never contain key material or PINs.
    Error::KeyProvider(format!("{context}: {e}"))
}

impl Pkcs11KeyProvider {
    /// Load a PKCS#11 module and enumerate the keys it offers.
    ///
    /// Enumeration reads *certificates*, which tokens expose without a login, so constructing a
    /// provider never prompts for a PIN. That is what lets `Reader` match recipient records
    /// before any user interaction — see [`KeyProvider::identities`].
    pub fn open(module: impl AsRef<Path>, pin_source: Box<dyn PinSource>) -> Result<Self> {
        let context =
            Pkcs11::new(module.as_ref()).map_err(|e| provider_err("loading PKCS#11 module", e))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| provider_err("initialising PKCS#11", e))?;

        let mut provider = Pkcs11KeyProvider {
            context,
            pin_source,
            keys: Vec::new(),
        };
        provider.keys = provider.discover()?;
        Ok(provider)
    }

    /// Scan every token for certificates whose keys umbrik can use.
    fn discover(&self) -> Result<Vec<TokenKey>> {
        let slots = self
            .context
            .get_slots_with_token()
            .map_err(|e| provider_err("listing slots", e))?;

        let mut keys = Vec::new();
        for slot in slots {
            // A token that fails to open is skipped rather than fatal: an unrelated empty or
            // broken reader must not stop a working card from being found.
            let Ok(session) = self.context.open_ro_session(slot) else {
                continue;
            };
            let token_label = self
                .context
                .get_token_info(slot)
                .map(|info| info.label().trim().to_string())
                .unwrap_or_default();

            if let Ok(found) = Self::certificates_on(&session, slot, &token_label) {
                // A reader commonly presents the same card in several slots — an Estonian card
                // typically appears four times, as PIN1 and PIN2 across two interfaces. Keep
                // the first slot offering each key so a card is listed once, not once per slot.
                for key in found {
                    if !keys
                        .iter()
                        .any(|known: &TokenKey| known.identity.key == key.identity.key)
                    {
                        keys.push(key);
                    }
                }
            }
        }
        Ok(keys)
    }

    fn certificates_on(session: &Session, slot: Slot, token_label: &str) -> Result<Vec<TokenKey>> {
        let handles = session
            .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
            .map_err(|e| provider_err("finding certificates", e))?;

        let mut keys = Vec::new();
        for handle in handles {
            let attributes =
                match session.get_attributes(handle, &[AttributeType::Value, AttributeType::Id]) {
                    Ok(attributes) => attributes,
                    Err(_) => continue,
                };

            let mut der = None;
            let mut cka_id = None;
            for attribute in attributes {
                match attribute {
                    Attribute::Value(value) => der = Some(value),
                    Attribute::Id(id) => cka_id = Some(id),
                    _ => {}
                }
            }

            let (Some(der), Some(cka_id)) = (der, cka_id) else {
                continue;
            };
            // A token may hold certificates umbrik cannot use — an unsupported curve, say.
            // Skip them rather than failing the whole enumeration.
            let Ok(parsed) = cert::from_der(&der) else {
                continue;
            };

            // An Estonian card exposes both `Isikutuvastus` (authentication) and
            // `Allkirjastamine` (signing). Only the first can perform key agreement; offering
            // the signing key would prompt for PIN2 and then fail.
            if !parsed.can_establish_key {
                continue;
            }

            keys.push(TokenKey {
                identity: Identity {
                    label: parsed
                        .common_name
                        .clone()
                        .unwrap_or_else(|| parsed.subject.clone()),
                    key: parsed.key,
                },
                slot,
                token_label: token_label.to_string(),
                cka_id,
            });
        }
        Ok(keys)
    }

    fn key_for(&self, id: &Identity) -> Result<&TokenKey> {
        self.keys
            .iter()
            .find(|known| known.identity.key == id.key)
            .ok_or_else(|| Error::KeyProvider("identity is not on any connected token".into()))
    }

    /// Open a session and log in. This is the call that costs a PIN entry.
    fn login(&self, key: &TokenKey) -> Result<Session> {
        let session = self
            .context
            .open_ro_session(key.slot)
            .map_err(|e| provider_err("opening session", e))?;

        let pin = self.pin_source.pin(&key.token_label)?;
        session
            .login(UserType::User, Some(&AuthPin::new(pin.as_str().into())))
            .map_err(|e| provider_err("PIN verification failed", e))?;
        Ok(session)
    }

    /// Find the private key matching a certificate, by `CKA_ID`.
    fn private_key(&self, session: &Session, key: &TokenKey) -> Result<ObjectHandle> {
        session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(key.cka_id.clone()),
            ])
            .map_err(|e| provider_err("finding private key", e))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                Error::KeyProvider("no private key on the token matches this certificate".into())
            })
    }

    /// ECDH on the token. The private key never leaves it.
    fn ecdh(
        &self,
        session: &Session,
        private_key: ObjectHandle,
        peer_point: &[u8],
        secret_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // CARD-SPECIFIC: the encoding of the peer's public point.
        //
        // PKCS#11 v2.40 §2.3.7 says CKA_EC_POINT-style raw octets (`0x04 || X || Y`), but some
        // tokens expect it wrapped in a DER OCTET STRING. SoftHSM accepts the raw form. If a
        // real card rejects this, that wrapping is the first thing to try.
        let params = Ecdh1DeriveParams::new(EcKdf::null(), peer_point);

        // CK_ULONG is `unsigned long`, which is 64-bit on Unix but **32-bit on Win64**, so
        // `Ulong` converts from a different primitive per platform. Going through `c_ulong`
        // rather than a fixed-width integer keeps this compiling everywhere.
        let value_len = std::os::raw::c_ulong::try_from(secret_len)
            .map_err(|_| Error::Internal("ECDH secret length does not fit CK_ULONG"))?;

        // CARD-SPECIFIC: the derive template.
        //
        // `CKA_VALUE_LEN` is required by some tokens and rejected by others, and a card may
        // refuse to mark a derived secret extractable at all — in which case the shared secret
        // cannot be read back and this approach does not work on that card.
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(value_len.into()),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Token(false),
        ];

        let derived = session
            .derive_key(&Mechanism::Ecdh1Derive(params), private_key, &template)
            .map_err(|e| provider_err("ECDH derivation", e))?;

        let attributes = session
            .get_attributes(derived, &[AttributeType::Value])
            .map_err(|e| provider_err("reading derived secret", e))?;

        for attribute in attributes {
            if let Attribute::Value(value) = attribute {
                // The raw X coordinate. CDOC2 feeds this straight into HKDF-Extract with no
                // pre-hashing — see docs/CRYPTO-CONSTANTS.md section 6.
                return Ok(Zeroizing::new(value));
            }
        }
        Err(Error::KeyProvider(
            "token would not release the derived secret".into(),
        ))
    }
}

impl KeyProvider for Pkcs11KeyProvider {
    fn identities(&self) -> Result<Vec<Identity>> {
        Ok(self.keys.iter().map(|key| key.identity.clone()).collect())
    }

    fn perform(&self, id: &Identity, op: KeyOp<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.key_for(id)?;
        let session = self.login(key)?;
        let private_key = self.private_key(&session, key)?;

        match op {
            KeyOp::Ecdh { peer } => {
                // The ECDH shared secret is one coordinate wide: half the point, minus the
                // 0x04 uncompressed-point marker.
                let secret_len = peer.tls_point.len().saturating_sub(1) / 2;
                if secret_len == 0 {
                    return Err(Error::InvalidKeyMaterial("empty peer EC point"));
                }
                self.ecdh(&session, private_key, &peer.tls_point, secret_len)
            }
            KeyOp::RsaOaep { ciphertext } => {
                // CARD-SPECIFIC: OAEP parameters must be SHA-256 digest *and* SHA-256 MGF1.
                // See docs/CRYPTO-CONSTANTS.md section 6b — defaulting MGF1 to SHA-1 is the
                // classic interop failure, and some tokens do exactly that.
                use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
                use cryptoki::mechanism::MechanismType;

                let params = PkcsOaepParams::new(
                    MechanismType::SHA256,
                    PkcsMgfType::MGF1_SHA256,
                    PkcsOaepSource::empty(),
                );
                let plaintext = session
                    .decrypt(&Mechanism::RsaPkcsOaep(params), private_key, ciphertext)
                    .map_err(|e| provider_err("RSA-OAEP decryption", e))?;
                Ok(Zeroizing::new(plaintext))
            }
            _ => Err(Error::KeyProvider(
                "unsupported operation for a PKCS#11 key".into(),
            )),
        }
    }
}

/// Strip the DER `OCTET STRING` wrapper some tokens put around `CKA_EC_POINT`.
///
/// A raw uncompressed point starts with `0x04`, and so does a DER OCTET STRING tag, so the two
/// are told apart by length rather than by the leading byte alone.
pub fn unwrap_ec_point(raw: &[u8]) -> &[u8] {
    match raw {
        // DER: tag 0x04, short-form length, then the point.
        [0x04, len, rest @ ..] if *len as usize == rest.len() && rest.first() == Some(&0x04) => {
            rest
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_through_a_raw_uncompressed_point() {
        let mut point = vec![0x04];
        point.extend_from_slice(&[0xAB; 96]); // secp384r1: 1 + 48 + 48
        assert_eq!(unwrap_ec_point(&point), point.as_slice());
    }

    #[test]
    fn strips_a_der_octet_string_wrapper() {
        let mut point = vec![0x04];
        point.extend_from_slice(&[0xCD; 96]);

        let mut wrapped = vec![0x04, 97];
        wrapped.extend_from_slice(&point);

        assert_eq!(unwrap_ec_point(&wrapped), point.as_slice());
    }

    #[test]
    fn leaves_unrecognised_encodings_alone() {
        assert_eq!(unwrap_ec_point(&[]), &[] as &[u8]);
        assert_eq!(unwrap_ec_point(&[0x04]), &[0x04]);
    }
}

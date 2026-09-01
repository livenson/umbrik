//! Injection points: private-key operations, and capsule-server transport.
//!
//! These are the only two places umbrik-core admits an implementation it does not own. Both are
//! object safe, so `umbrik-ffi` can hold a `Box<dyn _>` and foreign callers can supply their own
//! via a C function pointer.
//!
//! `umbrik-core` deliberately depends on no hardware or HTTP crate. A PKCS#11 token, a remote
//! signer, or an in-memory test key all arrive through [`KeyProvider`].

use zeroize::Zeroizing;

use crate::error::Result;
use crate::header::{Capsule, EllipticCurve};

pub mod software;

/// An EC public key in the TLS uncompressed point encoding of RFC 8446 §4.2.8.2:
/// `0x04 || X || Y`, each coordinate fixed-width (48 bytes for secp384r1).
///
/// Deliberately a plain byte vector rather than a curve-crate type: it keeps this trait free of
/// a cryptography dependency and lets it cross the C ABI unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcPublicKey {
    pub curve: EllipticCurve,
    pub tls_point: Vec<u8>,
}

/// A public key in whatever encoding the matching capsule stores.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKeyRef {
    Ec(EcPublicKey),
    /// PKCS#1 `RSAPublicKey` DER (RFC 8017 A.1.1) — **not** SPKI. This is what
    /// `RSAPublicKeyCapsule.recipient_public_key` holds, so matching is a byte comparison
    /// against that encoding.
    Rsa {
        pkcs1_der: Vec<u8>,
    },
}

/// A key the provider can operate with.
///
/// Exists so that a `Reader` can match recipient records *before* triggering a PIN prompt.
/// Never prompt speculatively: a container addressed to someone else must not cost the user a
/// PIN entry, and repeated wrong-PIN prompts can lock a card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Human-readable, for prompts and diagnostics. Never contains secret material.
    pub label: String,
    pub key: PublicKeyRef,
}

impl Identity {
    /// Whether this identity is the recipient a capsule is addressed to.
    ///
    /// Byte equality on the stored public key. No parsing, so a malformed capsule simply fails
    /// to match rather than erroring.
    pub fn matches(&self, capsule: &Capsule) -> bool {
        match (&self.key, capsule) {
            (
                PublicKeyRef::Ec(mine),
                Capsule::EccPublicKey {
                    curve,
                    recipient_public_key,
                    ..
                },
            ) => mine.curve == *curve && mine.tls_point == *recipient_public_key,
            (
                PublicKeyRef::Rsa { pkcs1_der },
                Capsule::RsaPublicKey {
                    recipient_public_key,
                    ..
                },
            ) => pkcs1_der == recipient_public_key,
            _ => false,
        }
    }
}

/// A private-key operation.
///
/// One method rather than one per algorithm: it stays object safe, collapses to a single C
/// callback for foreign callers, and extends to future primitives without a breaking change.
#[derive(Debug)]
#[non_exhaustive]
pub enum KeyOp<'a> {
    /// SC01 and SC03. Returns the raw ECDH shared secret — the X coordinate, 48 bytes for
    /// secp384r1. No KDF is applied by the provider.
    Ecdh { peer: &'a EcPublicKey },
    /// SC02 and SC04. Returns the decrypted KEK.
    ///
    /// OAEP parameters are fixed by the format: SHA-256 digest, **SHA-256 MGF1**, empty label.
    /// Providers that expose an OAEP knob must pin all three; defaulting MGF1 to SHA-1 is the
    /// classic interop failure here.
    RsaOaep { ciphertext: &'a [u8] },
}

/// A source of private-key operations: a PKCS#11 token, a software key, a remote signer.
///
/// PIN handling is deliberately absent. A PIN is a property of a particular token, not of the
/// abstraction, so it belongs in the concrete provider's constructor (`Pkcs11KeyProvider` takes
/// a `PinSource`). `umbrik-core` has no concept of a PIN.
pub trait KeyProvider {
    /// Keys available, for matching against recipient records before any user interaction.
    fn identities(&self) -> Result<Vec<Identity>>;

    /// Perform a private-key operation. This is the call that may prompt for a PIN.
    fn perform(&self, id: &Identity, op: KeyOp<'_>) -> Result<Zeroizing<Vec<u8>>>;
}

/// Opaque capsule identifier returned by a capsule server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleId(pub String);

/// A capsule to store on a server (SC03/SC04).
#[derive(Debug, Clone)]
pub struct CapsuleUpload {
    pub recipient: PublicKeyRef,
    pub payload: Vec<u8>,
}

/// Capsule server transport.
///
/// Synchronous on purpose: async traits make cgo and PyO3 materially worse, and callers who
/// want async can wrap this on their own executor.
///
/// SC07's key-shares flow is deliberately **not** modelled here. Retrieving a share is
/// nonce → SD-JWT auth ticket → share, repeated across N servers — a different shape that would
/// distort this trait. It gets its own trait in a future crate if it is ever implemented.
pub trait CapsuleTransport {
    fn put(&self, capsule: &CapsuleUpload) -> Result<CapsuleId>;
    fn get(&self, id: &CapsuleId) -> Result<Vec<u8>>;
}

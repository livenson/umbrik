//! A [`KeyProvider`](super::KeyProvider) backed by in-memory private keys.
//!
//! Used for PEM key files and for testing the SC01/SC02 derivations without hardware. The
//! PKCS#11 provider in `umbrik-pkcs11` implements the same trait, so everything above this
//! layer is identical whether the key lives in a file or on a card.

use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

use super::{EcPublicKey, Identity, KeyOp, KeyProvider, PublicKeyRef};
use crate::error::{Error, Result};
use crate::header::EllipticCurve;

/// A single software private key.
enum SecretKind {
    P256(Box<p256::SecretKey>),
    P384(Box<p384::SecretKey>),
}

/// Holds private keys in memory and performs ECDH or RSA-OAEP with them.
pub struct SoftwareKeyProvider {
    entries: Vec<(Identity, SecretKind)>,
}

impl std::fmt::Debug for SoftwareKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareKeyProvider")
            .field("identities", &self.entries.len())
            .finish()
    }
}

impl SoftwareKeyProvider {
    pub fn new() -> Self {
        SoftwareKeyProvider {
            entries: Vec::new(),
        }
    }

    /// Add an EC or RSA private key from PEM.
    ///
    /// Accepts SEC1 `EC PRIVATE KEY`, PKCS#8 `PRIVATE KEY`, and PKCS#1 `RSA PRIVATE KEY`. The
    /// curve is taken from the key itself, not guessed.
    pub fn add_pem(&mut self, pem: &str, label: impl Into<String>) -> Result<()> {
        let label = label.into();

        if let Ok(sk) = p384::SecretKey::from_sec1_pem(pem) {
            return self.push_p384(sk, label);
        }
        if let Ok(sk) = p256::SecretKey::from_sec1_pem(pem) {
            return self.push_p256(sk, label);
        }
        // PKCS#8 wrapping, tried after the more specific format.
        {
            use p384::pkcs8::DecodePrivateKey;
            if let Ok(sk) = p384::SecretKey::from_pkcs8_pem(pem) {
                return self.push_p384(sk, label);
            }
            if let Ok(sk) = p256::SecretKey::from_pkcs8_pem(pem) {
                return self.push_p256(sk, label);
            }
        }

        Err(Error::InvalidKeyMaterial(
            "unrecognised private key PEM (expected an EC key on secp256r1 or secp384r1)",
        ))
    }

    fn push_p384(&mut self, sk: p384::SecretKey, label: String) -> Result<()> {
        let point = sk.public_key().to_sec1_point(false);
        let identity = Identity {
            label,
            key: PublicKeyRef::Ec(EcPublicKey {
                curve: EllipticCurve::Secp384r1,
                tls_point: point.as_bytes().to_vec(),
            }),
        };
        self.entries
            .push((identity, SecretKind::P384(Box::new(sk))));
        Ok(())
    }

    fn push_p256(&mut self, sk: p256::SecretKey, label: String) -> Result<()> {
        let point = sk.public_key().to_sec1_point(false);
        let identity = Identity {
            label,
            key: PublicKeyRef::Ec(EcPublicKey {
                curve: EllipticCurve::Secp256r1,
                tls_point: point.as_bytes().to_vec(),
            }),
        };
        self.entries
            .push((identity, SecretKind::P256(Box::new(sk))));
        Ok(())
    }

    fn secret_for(&self, id: &Identity) -> Result<&SecretKind> {
        self.entries
            .iter()
            .find(|(known, _)| known.key == id.key)
            .map(|(_, secret)| secret)
            .ok_or(Error::KeyProvider(
                "identity is not held by this provider".to_string(),
            ))
    }
}

impl Default for SoftwareKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for SoftwareKeyProvider {
    fn identities(&self) -> Result<Vec<Identity>> {
        Ok(self.entries.iter().map(|(id, _)| id.clone()).collect())
    }

    fn perform(&self, id: &Identity, op: KeyOp<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let secret = self.secret_for(id)?;

        match (secret, op) {
            (SecretKind::P384(sk), KeyOp::Ecdh { peer }) => {
                if peer.curve != EllipticCurve::Secp384r1 {
                    return Err(Error::KeyProvider("curve mismatch for ECDH".to_string()));
                }
                let peer_pub = p384::PublicKey::from_sec1_bytes(&peer.tls_point)
                    .map_err(|_| Error::InvalidKeyMaterial("invalid peer EC point"))?;
                let shared =
                    p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pub.as_affine());
                // Raw X coordinate, exactly as CKM_ECDH1_DERIVE returns it. No KDF here.
                Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
            }
            (SecretKind::P256(sk), KeyOp::Ecdh { peer }) => {
                if peer.curve != EllipticCurve::Secp256r1 {
                    return Err(Error::KeyProvider("curve mismatch for ECDH".to_string()));
                }
                let peer_pub = p256::PublicKey::from_sec1_bytes(&peer.tls_point)
                    .map_err(|_| Error::InvalidKeyMaterial("invalid peer EC point"))?;
                let shared =
                    p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pub.as_affine());
                Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
            }
        }
    }
}

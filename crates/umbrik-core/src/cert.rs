//! X.509 certificate parsing, for encrypting to a recipient.
//!
//! # What is and is not checked
//!
//! **Validity dates are checked** — see [`CertificateRecipient::validity`]. Encrypting to an
//! expired certificate usually means encrypting to a card that has been replaced, producing a
//! container the recipient cannot open. That is worth catching, and costs nothing: the dates are
//! in the certificate already.
//!
//! **Chain and revocation are not.** Both need infrastructure umbrik deliberately does not carry:
//! a trust store of eID root certificates that would have to be kept current, and an OCSP or CRL
//! lookup on every encryption. More importantly, neither would add much where recipients
//! actually come from. A certificate fetched with `-r` arrives over an authenticated TLS
//! connection to the directory that issued it, and one passed with `-c` is a file the user chose.
//! The case they would protect — a certificate from an untrusted third party — is better served
//! by the user validating it themselves than by umbrik implying a guarantee it only partly makes.
//!
//! If you need chain validation, do it before calling here.

use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::ext::pkix::KeyUsage;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

use crate::error::{Error, Result};
use crate::header::EllipticCurve;
use crate::provider::{EcPublicKey, PublicKeyRef};

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_SECP256R1: &str = "1.2.840.10045.3.1.7";
const OID_SECP384R1: &str = "1.3.132.0.34";
const OID_SECP521R1: &str = "1.3.132.0.35";

/// A recipient parsed from a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRecipient {
    /// The certificate's full subject DN.
    pub subject: String,
    /// The subject's `CN`. For Estonian eID certificates this is `LASTNAME,FIRSTNAME,IDCODE`
    /// and is what a viewer displays as the recipient's name.
    pub common_name: Option<String>,
    /// `serialNumber` from the subject DN, without its `PNOEE-` prefix, when present. For
    /// Estonian eID certificates this is the isikukood.
    pub id_code: Option<String>,
    /// The certificate's `notBefore`, as seconds since the Unix epoch.
    pub not_before: Option<i64>,
    /// The certificate's `notAfter`, as seconds since the Unix epoch.
    ///
    /// Written into eID key labels as `server_exp`, which is how a viewer can show
    /// "Decryption is possible until …" — a CDOC2 capsule stores only the raw public key, so
    /// the expiry is not otherwise recoverable from the container.
    pub not_after: Option<i64>,
    /// Lowercase hex SHA-1 of the DER certificate, for the `CERT_SHA1` key label parameter.
    ///
    /// SHA-1 is used here purely as an identifier for display, matching the reference
    /// implementation's label format. It carries no security weight — nothing is authenticated
    /// by it — so its collision weakness is not relevant.
    pub sha1: String,
    pub key: PublicKeyRef,
    /// Whether the certificate's `keyUsage` permits establishing a key — `keyAgreement` for EC,
    /// `keyEncipherment` for RSA.
    ///
    /// This is what separates an authentication certificate from a signing one. An Estonian
    /// card carries both: `Isikutuvastus` (authentication, `Digital Signature, Key Agreement`)
    /// and `Allkirjastamine` (signing, `Non Repudiation`). Encrypting to the signing
    /// certificate produces a container the holder can never open, because the signing key
    /// cannot perform key agreement at all.
    ///
    /// `true` when the extension is absent: `keyUsage` is optional, and refusing every
    /// certificate that omits it would reject valid recipients.
    pub can_establish_key: bool,
}

/// Parse a PEM-encoded certificate.
pub fn from_pem(pem: &str) -> Result<CertificateRecipient> {
    let cert = Certificate::from_pem(pem)
        .map_err(|_| Error::InvalidKeyMaterial("not a valid PEM certificate"))?;
    // Re-encode so the fingerprint is over the DER, whatever the input encoding was.
    let der = cert
        .to_der()
        .map_err(|_| Error::InvalidKeyMaterial("cannot re-encode certificate"))?;
    from_certificate(&cert, &der)
}

/// Parse a DER-encoded certificate.
pub fn from_der(der: &[u8]) -> Result<CertificateRecipient> {
    let cert = Certificate::from_der(der)
        .map_err(|_| Error::InvalidKeyMaterial("not a valid DER certificate"))?;
    from_certificate(&cert, der)
}

/// Parse a bare PEM public key (`-----BEGIN PUBLIC KEY-----`, SPKI).
///
/// Useful for recipients who publish a key rather than a certificate. Carries no subject, so
/// the caller supplies the label.
pub fn public_key_from_pem(pem: &str) -> Result<PublicKeyRef> {
    let spki = SubjectPublicKeyInfoOwned::from_pem(pem)
        .map_err(|_| Error::InvalidKeyMaterial("not a valid PEM public key"))?;
    public_key_from_spki(&spki)
}

fn from_certificate(cert: &Certificate, der: &[u8]) -> Result<CertificateRecipient> {
    use sha1::Digest;

    let key = public_key_from_spki(&cert.tbs_certificate.subject_public_key_info)?;
    let subject = cert.tbs_certificate.subject.to_string();
    let sha1 = format!("{:x}", sha1::Sha1::digest(der));
    let to_unix = |t: &x509_cert::time::Time| i64::try_from(t.to_unix_duration().as_secs()).ok();
    let not_before = to_unix(&cert.tbs_certificate.validity.not_before);
    let not_after = to_unix(&cert.tbs_certificate.validity.not_after);

    Ok(CertificateRecipient {
        can_establish_key: permits_key_establishment(cert),
        not_before,
        common_name: extract_rdn(&subject, "CN"),
        not_after,
        id_code: extract_id_code(&subject),
        sha1,
        subject,
        key,
    })
}

/// Where a certificate sits relative to its validity window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Valid,
    /// `notBefore` is in the future.
    NotYetValid,
    /// `notAfter` has passed.
    Expired,
    /// The certificate carries no usable dates, so nothing can be concluded.
    Unknown,
}

impl CertificateRecipient {
    /// Where this certificate sits relative to `now`, in seconds since the Unix epoch.
    ///
    /// Reports rather than decides: whether to refuse an expired certificate is the caller's
    /// choice. An expired *authentication* certificate does not always mean the key is gone —
    /// but it usually means the card has been replaced, and the container would be unopenable.
    pub fn validity(&self, now_unix: i64) -> Validity {
        match (self.not_before, self.not_after) {
            (Some(before), _) if now_unix < before => Validity::NotYetValid,
            (_, Some(after)) if now_unix > after => Validity::Expired,
            (None, None) => Validity::Unknown,
            _ => Validity::Valid,
        }
    }

    /// Convenience wrapper around [`Self::validity`] using the system clock.
    ///
    /// Returns [`Validity::Unknown`] if the clock is before the Unix epoch, rather than
    /// guessing.
    pub fn validity_now(&self) -> Validity {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs())
                .map(|now| self.validity(now))
                .unwrap_or(Validity::Unknown),
            Err(_) => Validity::Unknown,
        }
    }
}

/// OID of the `keyUsage` extension.
const OID_KEY_USAGE: &str = "2.5.29.15";

/// Whether `keyUsage` allows this certificate's key to establish a shared key.
///
/// Absent extension means unrestricted, so this returns `true`. A malformed extension is
/// treated the same way: `keyUsage` is advisory metadata, and failing to parse it should not
/// silently exclude an otherwise valid recipient.
fn permits_key_establishment(cert: &Certificate) -> bool {
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return true;
    };
    let Some(extension) = extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == OID_KEY_USAGE)
    else {
        return true;
    };
    let Ok(usage) = KeyUsage::from_der(extension.extn_value.as_bytes()) else {
        return true;
    };

    // EC keys agree; RSA keys encipher. A signing-only certificate has neither.
    usage.key_agreement() || usage.key_encipherment()
}

/// Pull a named RDN value out of a subject DN.
///
/// Escaped commas (`\,`) inside a value are respected, which matters because Estonian common
/// names are themselves comma-separated: `CN=TESTIJA\,MARI\,00000000000`.
fn extract_rdn(subject: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let mut fields: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for ch in subject.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ',' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    fields.push(current);

    fields
        .into_iter()
        .map(|field| field.trim().to_string())
        .find_map(|field| field.strip_prefix(&prefix).map(str::to_string))
}

fn public_key_from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<PublicKeyRef> {
    let algorithm = spki.algorithm.oid.to_string();

    let key = if algorithm == OID_EC_PUBLIC_KEY {
        let params = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or(Error::InvalidKeyMaterial("EC key without curve parameters"))?;
        let curve_oid: ObjectIdentifier = params
            .decode_as()
            .map_err(|_| Error::InvalidKeyMaterial("unreadable EC curve parameters"))?;

        let curve = match curve_oid.to_string().as_str() {
            OID_SECP384R1 => EllipticCurve::Secp384r1,
            OID_SECP256R1 => EllipticCurve::Secp256r1,
            OID_SECP521R1 => EllipticCurve::Secp521r1,
            _ => return Err(Error::InvalidKeyMaterial("unsupported elliptic curve")),
        };

        // Already the TLS uncompressed point: 0x04 || X || Y.
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Error::InvalidKeyMaterial(
                "EC public key is not byte aligned",
            ))?;
        if point.first() != Some(&0x04) {
            return Err(Error::InvalidKeyMaterial(
                "EC public key is not an uncompressed point",
            ));
        }
        PublicKeyRef::Ec(EcPublicKey {
            curve,
            tls_point: point.to_vec(),
        })
    } else if algorithm == OID_RSA_ENCRYPTION {
        // SPKI wraps PKCS#1 RSAPublicKey, which is the encoding the capsule stores.
        let der = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Error::InvalidKeyMaterial(
                "RSA public key is not byte aligned",
            ))?;
        PublicKeyRef::Rsa {
            pkcs1_der: der.to_vec(),
        }
    } else {
        return Err(Error::InvalidKeyMaterial("key is neither EC nor RSA"));
    };

    Ok(key)
}

/// Pull the isikukood out of a subject DN.
///
/// Estonian eID certificates carry `serialNumber=PNOEE-38001085718`. The `PNOEE-` prefix is an
/// ETSI EN 319 412-1 semantics identifier: `PNO` for a personal number, `EE` for the country.
fn extract_id_code(subject: &str) -> Option<String> {
    extract_rdn(subject, "SERIALNUMBER")
        .or_else(|| extract_rdn(subject, "serialNumber"))
        .map(|value| value.strip_prefix("PNOEE-").unwrap_or(&value).to_string())
}

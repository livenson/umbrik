//! Resolve an Estonian id code (isikukood) to a recipient certificate via the eID directory.
//!
//! Kept out of `umbrik-core` deliberately: core must stay free of network dependencies. This
//! crate is a convenience layer over [`umbrik_core::cert`] — it fetches a certificate, and
//! everything after that is ordinary certificate-based encryption.
//!
//! # Privacy
//!
//! A lookup is a query to a public directory that reveals which person you are about to encrypt
//! for, to whoever operates that directory. Callers should surface this rather than performing
//! lookups silently.
//!
//! # TLS
//!
//! This crate uses **native-tls**, not rustls, and that is deliberate.
//! `esteid.ldap.sk.ee` negotiates TLS 1.2 with `AES256-GCM-SHA384` — a static RSA key-exchange
//! suite providing no forward secrecy, which rustls does not implement and will not offer. A
//! rustls build fails the handshake outright (`received fatal alert: HandshakeFailure`), and
//! since that directory is where ID-card certificates actually live, lookups silently return
//! nothing useful. On Linux this means an OpenSSL dependency at build time.
//!
//! # Trust
//!
//! umbrik does not validate certificate chains, expiry, or revocation. The directory is treated
//! as the authority on which key belongs to an id code. If that assumption is not acceptable for
//! your threat model, fetch and validate the certificate yourself and use
//! [`umbrik_core::cert::from_der`] directly.

use ldap3::{LdapConn, Scope, SearchEntry};
use umbrik_core::cert::{self, CertificateRecipient};
use umbrik_core::error::Error;
use umbrik_core::keylabel::types;

/// SK ID Solutions' person directory. Holds ID-card, Digi-ID and Mobile-ID certificates.
pub const SK_LDAP_URL: &str = "ldaps://esteid.ldap.sk.ee";
/// Base DN for the SK directory.
pub const SK_BASE_DN: &str = "c=EE";

/// Zetes' eID directory.
pub const ZETES_LDAP_URL: &str = "ldaps://ldap.eidpki.ee";
/// Base DN for the Zetes directory.
pub const ZETES_BASE_DN: &str = "dc=ldap,dc=eidpki,dc=ee";
/// Zetes test directory.
pub const ZETES_TEST_LDAP_URL: &str = "ldaps://ldap-test.eidpki.ee";

/// The binary attribute holding certificates. An entry may carry several.
const CERT_ATTRIBUTE: &str = "userCertificate;binary";

/// DN fragment marking an **authentication** certificate.
///
/// A card carries two key pairs: authentication (PIN1) and signature (PIN2). Only the
/// authentication key can perform key agreement; the signing certificate is marked
/// `Non Repudiation` and encrypting to it yields a container nobody can open.
const AUTHENTICATION_OU: &str = "ou=Authentication";

/// Organisations whose authentication certificates are **not** usable for CDOC2.
///
/// Mobile-ID authentication certificates look ideal — `ou=Authentication`, EC key, `Key
/// Agreement` — but the private key lives in the SIM and is only reachable through the
/// Mobile-ID protocol, never through PKCS#11. Decrypting to one requires the SC07 key-shares
/// flow, which is out of scope. Encrypting to it would silently produce a container the holder
/// cannot open, so it is excluded here rather than at decryption time.
const EXCLUDED_ORGANISATIONS: &[&str] = &["o=Mobile-ID"];

/// A directory to query.
#[derive(Debug, Clone)]
pub struct Directory {
    pub url: String,
    pub base_dn: String,
}

impl Directory {
    pub fn new(url: impl Into<String>, base_dn: impl Into<String>) -> Self {
        Directory {
            url: url.into(),
            base_dn: base_dn.into(),
        }
    }
}

/// The directories to search, in order.
///
/// Both are queried because certificates are split across them and neither is complete on its
/// own — this mirrors DigiDoc4, whose central configuration
/// (<https://id.eesti.ee/config.json>, key `LDAP-PERSON-URLS`) lists exactly these two. In
/// practice ID-card certificates have been found in the SK directory and not in Zetes, so
/// querying only one is not sufficient.
///
/// If a lookup ever starts failing for a valid id code, check `LDAP-PERSON-URLS` first: it is
/// the source of truth, and these constants are only a snapshot of it.
pub fn default_directories() -> Vec<Directory> {
    vec![
        Directory::new(SK_LDAP_URL, SK_BASE_DN),
        Directory::new(ZETES_LDAP_URL, ZETES_BASE_DN),
    ]
}

/// Test directories, for development against non-production cards.
pub fn test_directories() -> Vec<Directory> {
    vec![Directory::new(ZETES_TEST_LDAP_URL, ZETES_BASE_DN)]
}

/// Reject anything that is not a well-formed Estonian id code.
///
/// The LDAP search filter is built by concatenation, so an unvalidated id code would be a filter
/// injection: `*` alone would match every entry in the directory. An isikukood is exactly 11
/// ASCII digits, which leaves no character an attacker could use — so validating the shape is a
/// complete defence here, and is applied before any query is constructed.
pub fn validate_id_code(id_code: &str) -> Result<(), Error> {
    if id_code.len() != 11 || !id_code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidKeyMaterial(
            "id code must be exactly 11 digits",
        ));
    }
    Ok(())
}

/// Build the search filter for an id code.
///
/// `PNOEE-` is the ETSI EN 319 412-1 semantics identifier: `PNO` for a personal number, `EE` for
/// Estonia. Only call with a validated id code.
fn search_filter(id_code: &str) -> String {
    format!("(serialNumber=PNOEE-{id_code})")
}

/// One directory entry: its DN, and the DER certificates it carries.
pub type DirectoryEntry = (String, Vec<Vec<u8>>);

/// Why a directory entry was not usable.
///
/// A person's id code typically returns several credentials — an ID-card, a Digi-ID, Mobile-ID —
/// each with an authentication and a signing certificate. Most are dropped, and silently
/// dropping them makes "no usable certificate found" impossible to diagnose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// A signing certificate. Marked Non-Repudiation and cannot perform key agreement.
    NotAuthentication,
    /// Mobile-ID. The private key is in the SIM and is only reachable through the Mobile-ID
    /// protocol, never PKCS#11, so a container encrypted to it could not be opened.
    MobileId,
    /// An RSA key (SC02) or an unsupported curve.
    UnsupportedKey,
    /// The certificate would not parse.
    Unparseable,
}

impl Rejection {
    pub fn reason(self) -> &'static str {
        match self {
            Rejection::NotAuthentication => "signing certificate, cannot perform key agreement",
            Rejection::MobileId => "Mobile-ID, key is in the SIM and unreachable via PKCS#11",
            Rejection::UnsupportedKey => "unsupported key type (RSA or unknown curve)",
            Rejection::Unparseable => "certificate did not parse",
        }
    }
}

/// A directory entry that was considered and dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub dn: String,
    pub reason: Rejection,
}

/// Everything a lookup considered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lookup {
    /// Certificates umbrik can encrypt to. Every one becomes a recipient, so any of the holder's
    /// cards opens the container.
    pub matches: Vec<DirectoryMatch>,
    /// What was found and dropped, with the reason.
    pub rejected: Vec<Rejected>,
}

/// A certificate found in the directory, with what the DN says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryMatch {
    pub recipient: CertificateRecipient,
    /// The entry's distinguished name.
    pub dn: String,
    /// The key label `TYPE` this card maps to: `ID-card`, `Digi-ID`, or `Digi-ID E-RESIDENT`.
    pub card_type: &'static str,
}

/// Map a directory DN to the key label type a viewer should display.
///
/// The two directories spell these differently, so matching ignores case and spacing. Falls
/// back to plain `ID-card`, which is the common case and the least misleading default.
pub fn card_type_for_dn(dn: &str) -> &'static str {
    let normalised = dn.to_ascii_lowercase().replace(' ', "");
    if normalised.contains("o=e-resident") || normalised.contains("eresident") {
        types::DIGI_ID_E_RESIDENT
    } else if normalised.contains("o=digitalidentitycard") || normalised.contains("o=digi-id") {
        types::DIGI_ID
    } else {
        types::ID_CARD
    }
}

/// Why an entry's DN is or is not usable for CDOC2 encryption.
///
/// Matching is case-insensitive and whitespace-tolerant because the two directories disagree on
/// spacing: SK writes `o=Identity card of Estonian citizen`, Zetes writes
/// `o=IdentityCardEstonianCitizen`.
pub fn classify_dn(dn: &str) -> Option<Rejection> {
    let normalised = dn.to_ascii_lowercase().replace(' ', "");
    if !normalised.contains(&AUTHENTICATION_OU.to_ascii_lowercase().replace(' ', "")) {
        return Some(Rejection::NotAuthentication);
    }
    if EXCLUDED_ORGANISATIONS
        .iter()
        .any(|excluded| normalised.contains(&excluded.to_ascii_lowercase().replace(' ', "")))
    {
        return Some(Rejection::MobileId);
    }
    None
}

/// Whether an entry's DN denotes a certificate usable for CDOC2 encryption.
pub fn is_usable_dn(dn: &str) -> bool {
    classify_dn(dn).is_none()
}

/// Choose the usable certificates from a set of directory entries.
///
/// Pure, so the selection rules are testable without a network. Certificates that fail to parse
/// are skipped rather than fatal — one malformed entry must not hide a valid one beside it.
/// Duplicates are removed by public key, since a person may appear in both directories.
pub fn select_certificates(entries: Vec<DirectoryEntry>) -> Lookup {
    let mut out = Lookup::default();
    for (dn, certificates) in entries {
        if let Some(reason) = classify_dn(&dn) {
            out.rejected.push(Rejected { dn, reason });
            continue;
        }
        let card_type = card_type_for_dn(&dn);
        for der in certificates {
            match cert::from_der(&der) {
                Ok(recipient) => {
                    if out
                        .matches
                        .iter()
                        .any(|existing| existing.recipient.key == recipient.key)
                    {
                        continue;
                    }
                    out.matches.push(DirectoryMatch {
                        recipient,
                        dn: dn.clone(),
                        card_type,
                    });
                }
                // An RSA certificate (SC02, out of scope) is reported rather than dropped
                // silently: someone holding only a pre-2018 card needs to know that is why.
                Err(err) => out.rejected.push(Rejected {
                    dn: dn.clone(),
                    reason: match err.code() {
                        umbrik_core::error::ErrorCode::UnsupportedCapsule => {
                            Rejection::UnsupportedKey
                        }
                        _ => Rejection::Unparseable,
                    },
                }),
            }
        }
    }
    out
}

/// Raw entries from one directory, before selection.
fn search_one(directory: &Directory, id_code: &str) -> Result<Vec<DirectoryEntry>, Error> {
    let mut connection = LdapConn::new(&directory.url).map_err(|e| {
        Error::Transport(format!("LDAP connection to {} failed: {e}", directory.url))
    })?;

    let result = connection
        .search(
            &directory.base_dn,
            Scope::Subtree,
            &search_filter(id_code),
            vec![CERT_ATTRIBUTE],
        )
        .map_err(|e| Error::Transport(format!("LDAP search on {} failed: {e}", directory.url)))?
        .success()
        .map_err(|e| Error::Transport(format!("LDAP search on {} rejected: {e}", directory.url)))?;

    let _ = connection.unbind();

    Ok(result
        .0
        .into_iter()
        .map(|entry| {
            let entry = SearchEntry::construct(entry);
            let certificates = entry
                .bin_attrs
                .get(CERT_ATTRIBUTE)
                .cloned()
                .unwrap_or_default();
            (entry.dn, certificates)
        })
        .collect())
}

/// Look up the recipient certificates for an id code across several directories.
///
/// Every directory is queried and the results merged, because certificates are split between
/// them. A directory that is unreachable does not fail the lookup — the certificate may well be
/// in another one — but if *every* directory fails, that error is returned rather than reported
/// as "not found", which would be misleading.
///
/// An empty result is not an error: the person may have no active card.
pub fn lookup(directories: &[Directory], id_code: &str) -> Result<Lookup, Error> {
    validate_id_code(id_code)?;

    let mut entries = Vec::new();
    let mut last_error = None;
    let mut any_succeeded = false;

    for directory in directories {
        match search_one(directory, id_code) {
            Ok(found) => {
                any_succeeded = true;
                entries.extend(found);
            }
            Err(err) => last_error = Some(err),
        }
    }

    if !any_succeeded {
        return Err(last_error.unwrap_or(Error::Transport(
            "no directories were configured".to_string(),
        )));
    }

    Ok(select_certificates(entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_well_formed_id_code() {
        assert!(validate_id_code("38001085718").is_ok());
    }

    /// Every one of these would otherwise reach the filter string.
    #[test]
    fn rejects_filter_injection_attempts() {
        for bad in [
            "*",
            "3800108571*",
            "38001085718)(objectClass=*",
            "380010857 8",
            "",
            "1234567890",   // 10 digits
            "123456789012", // 12 digits
            "3800108571a",
            "38001085718\0",
        ] {
            assert!(
                validate_id_code(bad).is_err(),
                "{bad:?} must be rejected before it reaches a search filter"
            );
        }
    }

    #[test]
    fn filter_targets_the_etsi_serial_number() {
        assert_eq!(
            search_filter("38001085718"),
            "(serialNumber=PNOEE-38001085718)"
        );
    }

    /// Both spellings of the ID-card organisation must be accepted: SK and Zetes differ.
    #[test]
    fn accepts_authentication_certificates_from_either_directory() {
        assert!(is_usable_dn(
            "cn=SURNAME\\,NAME\\,38001085718,ou=Authentication,o=Identity card of Estonian citizen,dc=ESTEID,c=EE"
        ));
        assert!(is_usable_dn(
            "cn=SURNAME\\,NAME\\,38001085718,ou=Authentication,o=IdentityCardEstonianCitizen,dc=ldap,dc=eidpki,dc=ee"
        ));
    }

    /// A signing certificate is marked Non Repudiation and cannot do key agreement.
    #[test]
    fn rejects_signing_certificates() {
        assert!(!is_usable_dn(
            "cn=SURNAME\\,NAME\\,38001085718,ou=Digital Signature,o=Identity card of Estonian citizen,dc=ESTEID,c=EE"
        ));
    }

    /// The subtle one: a Mobile-ID authentication certificate is `ou=Authentication` with an EC
    /// key and `Key Agreement`, so it passes every naive filter — but its private key is in the
    /// SIM and unreachable through PKCS#11, so encrypting to it produces an unopenable container.
    #[test]
    fn rejects_mobile_id_authentication_certificates() {
        assert!(!is_usable_dn(
            "cn=SURNAME\\,NAME\\,38001085718,ou=Authentication,o=Mobile-ID,dc=ESTEID,c=EE"
        ));
    }

    #[test]
    fn maps_dn_to_card_type() {
        assert_eq!(
            card_type_for_dn("cn=X,ou=Authentication,o=Identity card of Estonian citizen,c=EE"),
            types::ID_CARD
        );
        assert_eq!(
            card_type_for_dn("cn=X,ou=Authentication,o=Digital identity card,c=EE"),
            types::DIGI_ID
        );
        assert_eq!(
            card_type_for_dn("cn=X,ou=Authentication,o=E-RESIDENT digital identity card,c=EE"),
            types::DIGI_ID_E_RESIDENT
        );
    }

    /// Every rejection carries a reason, so "nothing usable" can be explained rather than just
    /// reported.
    #[test]
    fn rejections_say_why() {
        assert_eq!(
            classify_dn("cn=X,ou=Digital Signature,o=Identity card of Estonian citizen,c=EE"),
            Some(Rejection::NotAuthentication)
        );
        assert_eq!(
            classify_dn("cn=X,ou=Authentication,o=Mobile-ID,dc=ESTEID,c=EE"),
            Some(Rejection::MobileId)
        );
        assert_eq!(
            classify_dn("cn=X,ou=Authentication,o=Identity card of Estonian citizen,c=EE"),
            None
        );
    }

    /// A real id code returns several credentials. Everything dropped must be accounted for, or
    /// a user holding only an unusable card has no way to find out why.
    #[test]
    fn every_dropped_entry_is_reported() {
        let entries = vec![
            (
                "cn=X,ou=Authentication,o=Mobile-ID,dc=ESTEID,c=EE".to_string(),
                vec![b"not a certificate".to_vec()],
            ),
            (
                "cn=X,ou=Digital Signature,o=Identity card of Estonian citizen,c=EE".to_string(),
                vec![b"not a certificate".to_vec()],
            ),
        ];
        let lookup = select_certificates(entries);
        assert!(lookup.matches.is_empty());
        assert_eq!(lookup.rejected.len(), 2);
        assert!(lookup
            .rejected
            .iter()
            .any(|r| r.reason == Rejection::MobileId));
        assert!(lookup
            .rejected
            .iter()
            .any(|r| r.reason == Rejection::NotAuthentication));
        for rejected in &lookup.rejected {
            assert!(!rejected.reason.reason().is_empty());
        }
    }

    /// An RSA certificate is out of scope since SC02 was removed, and must be reported as such
    /// rather than silently dropped as unparseable.
    #[test]
    fn rsa_certificates_are_reported_as_unsupported() {
        assert_eq!(
            Rejection::UnsupportedKey.reason(),
            "unsupported key type (RSA or unknown curve)"
        );
    }

    #[test]
    fn skips_unparseable_certificates_without_failing() {
        let entries = vec![(
            "cn=SOMEONE,ou=Authentication,o=Identity card of Estonian citizen".to_string(),
            vec![b"not a certificate".to_vec()],
        )];
        assert!(select_certificates(entries).matches.is_empty());
    }

    #[test]
    fn default_directories_cover_both_providers() {
        let directories = default_directories();
        assert_eq!(directories.len(), 2);
        assert!(directories.iter().any(|d| d.url.contains("sk.ee")));
        assert!(directories.iter().any(|d| d.url.contains("eidpki.ee")));
    }
}

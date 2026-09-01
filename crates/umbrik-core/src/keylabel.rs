//! Machine-readable recipient key labels.
//!
//! CDOC2 recipient labels are not free text. They use a `data:` URL scheme so that a viewer can
//! show a recipient meaningfully — "TESTIJA,MARI,00000000000 / ID-card" rather than an opaque
//! string:
//!
//! ```text
//! data:,CN=cdoc2-client&FILE=cert.pem&TYPE=cert&V=1
//! data:,LABEL=mylabel&TYPE=pw&V=1
//! ```
//!
//! Structure, matching what the reference CLI emits:
//!
//! - the literal prefix `data:,`
//! - `KEY=value` pairs joined by `&`, **sorted by key**
//! - values encoded as `application/x-www-form-urlencoded` (space becomes `+`)
//! - `V=1` and a `TYPE` on every label
//!
//! A plain, unformatted label is still legal and older containers use them, so [`parse`] returns
//! `None` for those and [`display`] falls back to showing them verbatim.
//!
//! # Labels are cryptographically binding for SC05 and SC06
//!
//! The label is an input to KEK derivation for the symmetric and password schemes, so the exact
//! bytes written here are part of the container's cryptography, not just its presentation.
//! Changing how a label is formatted changes the derived key. This stays interoperable only
//! because every implementation derives from the label *stored in the container* rather than
//! from one it reconstructs.

use std::collections::BTreeMap;

/// Label format version.
pub const VERSION: &str = "1";

/// The `data:` scheme prefix, including the empty media-type comma.
const PREFIX: &str = "data:,";

/// `TYPE` values.
pub mod types {
    pub const PASSWORD: &str = "pw";
    pub const SECRET: &str = "secret";
    pub const CERTIFICATE: &str = "cert";
    pub const PUBLIC_KEY: &str = "pub_key";
    pub const ID_CARD: &str = "ID-card";
    pub const DIGI_ID: &str = "Digi-ID";
    pub const DIGI_ID_E_RESIDENT: &str = "Digi-ID E-RESIDENT";
}

/// A label under construction.
///
/// Backed by a `BTreeMap` so parameters serialise in sorted order without the caller having to
/// remember to sort them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLabel {
    params: BTreeMap<String, String>,
}

impl KeyLabel {
    /// Start a label of the given `TYPE`, at the current version.
    pub fn new(label_type: &str) -> Self {
        let mut params = BTreeMap::new();
        params.insert("V".to_string(), VERSION.to_string());
        params.insert("TYPE".to_string(), label_type.to_string());
        KeyLabel { params }
    }

    /// Add a parameter. Empty values are dropped rather than written as `KEY=`.
    pub fn with(mut self, key: &str, value: impl AsRef<str>) -> Self {
        let value = value.as_ref();
        if !value.is_empty() {
            self.params.insert(key.to_string(), value.to_string());
        }
        self
    }

    /// Add a parameter if present.
    pub fn with_opt(self, key: &str, value: Option<impl AsRef<str>>) -> Self {
        match value {
            Some(value) => self.with(key, value),
            None => self,
        }
    }

    /// Render to the string stored in the container.
    pub fn format(&self) -> String {
        let body = self
            .params
            .iter()
            .map(|(key, value)| format!("{key}={}", form_urlencode(value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{PREFIX}{body}")
    }
}

impl std::fmt::Display for KeyLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.format())
    }
}

/// Label for a password recipient (SC06).
pub fn password(label: &str) -> String {
    KeyLabel::new(types::PASSWORD).with("LABEL", label).format()
}

/// Label for a pre-shared key recipient (SC05).
pub fn secret(label: &str) -> String {
    KeyLabel::new(types::SECRET).with("LABEL", label).format()
}

/// Label for a recipient given as a certificate file.
///
/// `cert_sha1` is the hex SHA-1 of the DER certificate; `file` is the file's base name, which
/// helps a sender recognise which certificate they used.
pub fn certificate(
    common_name: Option<&str>,
    cert_sha1: Option<&str>,
    file: Option<&str>,
) -> String {
    KeyLabel::new(types::CERTIFICATE)
        .with_opt("CN", common_name)
        .with_opt("CERT_SHA1", cert_sha1)
        .with_opt("FILE", file)
        .format()
}

/// Label for a recipient given as a bare public key.
pub fn public_key(file: Option<&str>) -> String {
    KeyLabel::new(types::PUBLIC_KEY)
        .with_opt("FILE", file)
        .format()
}

/// Label for an eID recipient, in the form DigiDoc4 (libcdoc) writes and renders.
///
/// libcdoc and the Java reference CLI disagree on this format, and neither is "wrong" — the
/// spec does not pin it. They differ in three ways:
///
/// | | reference CLI | libcdoc / DigiDoc4 |
/// |---|---|---|
/// | key case | `V`, `CN`, `TYPE` | `v`, `cn`, `type` |
/// | ordering | sorted | `v` first, then insertion order |
/// | `serial_number` | id code alone | keeps the `PNOEE-` prefix |
/// | expiry | absent | `server_exp`, the certificate's `notAfter` |
///
/// umbrik uses this form for directory-resolved eID recipients, because the party who has to
/// *read* such a container is overwhelmingly using DigiDoc4, and this is what makes it render
/// the recipient's name, card type and "Decryption is possible until" correctly. Certificate
/// files (`-c`) keep the reference CLI's form instead — see [`certificate`].
///
/// The label is not an input to KEK derivation for SC01/SC02, so this choice is presentational
/// only and cannot affect whether a container decrypts.
pub fn eid_digidoc(
    label_type: &str,
    common_name: &str,
    serial_number: Option<&str>,
    not_after_unix: Option<i64>,
) -> String {
    let (last_name, first_name) = split_common_name(common_name);

    // Insertion order is part of matching libcdoc's output, so this is built as an ordered
    // list rather than through the sorted `KeyLabel` builder.
    let mut params: Vec<(&str, String)> = vec![("v", VERSION.to_string())];
    params.push(("cn", common_name.to_string()));
    if let Some(first_name) = first_name {
        params.push(("first_name", first_name.to_string()));
    }
    if let Some(last_name) = last_name {
        params.push(("last_name", last_name.to_string()));
    }
    if let Some(serial_number) = serial_number {
        params.push(("serial_number", serial_number.to_string()));
    }
    params.push(("type", label_type.to_string()));
    if let Some(not_after) = not_after_unix {
        params.push(("server_exp", not_after.to_string()));
    }

    let body = params
        .iter()
        .map(|(key, value)| format!("{key}={}", form_urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{PREFIX}{body}")
}

/// Label for an eID recipient resolved from a directory.
///
/// `label_type` is one of [`types::ID_CARD`], [`types::DIGI_ID`] or
/// [`types::DIGI_ID_E_RESIDENT`]. First and last name are split out of the common name so a
/// viewer can show them separately.
pub fn eid(label_type: &str, common_name: &str, serial_number: Option<&str>) -> String {
    let (last_name, first_name) = split_common_name(common_name);
    KeyLabel::new(label_type)
        .with("CN", common_name)
        .with_opt("SERIAL_NUMBER", serial_number)
        .with_opt("FIRST_NAME", first_name)
        .with_opt("LAST_NAME", last_name)
        .format()
}

/// Split `LASTNAME,FIRSTNAME,IDCODE` into its name parts.
///
/// Returns `(None, None)` for a common name that does not have this shape rather than guessing;
/// a wrong split is worse than an absent one.
fn split_common_name(common_name: &str) -> (Option<&str>, Option<&str>) {
    let mut parts = common_name.split(',');
    match (parts.next(), parts.next()) {
        (Some(last), Some(first)) if !last.is_empty() && !first.is_empty() => {
            (Some(last), Some(first))
        }
        _ => (None, None),
    }
}

/// Parse a formatted label into its parameters.
///
/// Returns `None` for a plain label, which is legal and used by older containers.
pub fn parse(label: &str) -> Option<BTreeMap<String, String>> {
    let body = label.strip_prefix(PREFIX)?;
    let mut params = BTreeMap::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=')?;
        params.insert(key.to_string(), form_urldecode(value));
    }
    Some(params)
}

/// A human-readable one-line rendering of a label.
///
/// Falls back to the raw string for plain labels, so this is always safe to show.
pub fn display(label: &str) -> String {
    let Some(params) = parse(label) else {
        return label.to_string();
    };

    // Both implementations' key cases are accepted: the reference CLI writes upper case,
    // libcdoc writes lower case, and a reader should not care which produced the container.
    let get = |key: &str| {
        params
            .get(&key.to_ascii_uppercase())
            .or_else(|| params.get(&key.to_ascii_lowercase()))
    };

    // The most identifying field available, in descending order of usefulness.
    let name = get("CN")
        .or_else(|| get("LABEL"))
        .or_else(|| get("FILE"))
        .or_else(|| get("SERIAL_NUMBER"));

    match (name, get("TYPE")) {
        (Some(name), Some(label_type)) => format!("{name} ({label_type})"),
        (Some(name), None) => name.clone(),
        (None, Some(label_type)) => format!("({label_type})"),
        (None, None) => label.to_string(),
    }
}

/// `application/x-www-form-urlencoded`, matching Java's `URLEncoder`.
///
/// Java keeps `A-Z a-z 0-9 . - * _` unescaped and maps space to `+`; everything else becomes
/// uppercase percent-escapes. Commas are escaped, which matters because Estonian common names
/// are comma-separated.
fn form_urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => {
                out.push(*byte as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Inverse of [`form_urlencode`]. Invalid escapes are passed through rather than failing: a
/// label is display metadata, and a malformed one must not break parsing of the container.
fn form_urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'+') => {
                out.push(b' ');
                i += 1;
            }
            Some(b'%') => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|slice| std::str::from_utf8(slice).ok());
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(decoded) => {
                        out.push(decoded);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            Some(byte) => {
                out.push(*byte);
                i += 1;
            }
            None => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

//! Key label formatting, pinned against strings the reference CLI actually produced.
//!
//! The expected values here were captured from `cdoc2-cli` runs, not derived from reading its
//! source — labels are cryptographically binding for SC05/SC06, so matching the real output
//! matters more than matching the documentation.

use umbrik_core::keylabel::{self, types};

#[test]
fn password_label_matches_reference_output() {
    assert_eq!(
        keylabel::password("testlabel"),
        "data:,LABEL=testlabel&TYPE=pw&V=1"
    );
}

#[test]
fn secret_label_matches_reference_output() {
    assert_eq!(
        keylabel::secret("seclabel"),
        "data:,LABEL=seclabel&TYPE=secret&V=1"
    );
}

#[test]
fn certificate_label_matches_reference_output() {
    assert_eq!(
        keylabel::certificate(
            Some("cdoc2-client"),
            Some("9460be97b0f67a2fb98f0d73821293879804ab5e"),
            Some("cdoc2client-certificate.pem"),
        ),
        "data:,CERT_SHA1=9460be97b0f67a2fb98f0d73821293879804ab5e\
         &CN=cdoc2-client&FILE=cdoc2client-certificate.pem&TYPE=cert&V=1"
    );
}

/// Parameters must serialise sorted regardless of the order they were added.
#[test]
fn parameters_are_sorted() {
    let label = keylabel::certificate(Some("z"), Some("a"), Some("m"));
    let body = label.strip_prefix("data:,").unwrap();
    let keys: Vec<&str> = body
        .split('&')
        .map(|p| p.split('=').next().unwrap())
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted);
}

/// Estonian common names are comma-separated, and commas must be escaped — otherwise the
/// parameter separator and the name run together.
#[test]
fn eid_label_escapes_commas_in_the_common_name() {
    let label = keylabel::eid(
        types::ID_CARD,
        "TESTIJA,MARI,00000000000",
        Some("00000000000"),
    );

    assert!(label.contains("CN=TESTIJA%2CMARI%2C00000000000"), "{label}");
    assert!(label.contains("TYPE=ID-card"), "{label}");
    assert!(label.contains("SERIAL_NUMBER=00000000000"), "{label}");
    assert!(label.contains("FIRST_NAME=MARI"), "{label}");
    assert!(label.contains("LAST_NAME=TESTIJA"), "{label}");
}

#[test]
fn eid_label_round_trips_through_parse() {
    let label = keylabel::eid(
        types::ID_CARD,
        "TESTIJA,MARI,00000000000",
        Some("00000000000"),
    );
    let params = keylabel::parse(&label).expect("must parse as formatted");

    assert_eq!(params.get("CN").unwrap(), "TESTIJA,MARI,00000000000");
    assert_eq!(params.get("TYPE").unwrap(), "ID-card");
    assert_eq!(params.get("V").unwrap(), "1");
}

/// A common name that is not `LAST,FIRST,CODE` must not be split at all — a wrong split is
/// worse than an absent one.
#[test]
fn unusual_common_names_are_not_split() {
    let label = keylabel::eid(types::ID_CARD, "SingleName", None);
    assert!(!label.contains("FIRST_NAME"), "{label}");
    assert!(!label.contains("LAST_NAME"), "{label}");
}

#[test]
fn spaces_encode_as_plus_like_java() {
    let label = keylabel::eid(types::DIGI_ID_E_RESIDENT, "SMITH,JOHN PAUL,1", Some("1"));
    assert!(label.contains("FIRST_NAME=JOHN+PAUL"), "{label}");
    assert!(label.contains("TYPE=Digi-ID+E-RESIDENT"), "{label}");
}

// ---------------------------------------------------------------------------
// Reading labels back
// ---------------------------------------------------------------------------

#[test]
fn plain_labels_are_not_formatted_and_display_verbatim() {
    assert!(keylabel::parse("kevade").is_none());
    assert_eq!(keylabel::display("kevade"), "kevade");
    assert_eq!(
        keylabel::display("create_symmetric_label"),
        "create_symmetric_label"
    );
}

#[test]
fn display_prefers_the_most_identifying_field() {
    let eid = keylabel::eid(
        types::ID_CARD,
        "TESTIJA,MARI,00000000000",
        Some("00000000000"),
    );
    assert_eq!(
        keylabel::display(&eid),
        "TESTIJA,MARI,00000000000 (ID-card)"
    );
    assert_eq!(
        keylabel::display(&keylabel::password("mylabel")),
        "mylabel (pw)"
    );
}

/// A malformed label is display metadata; it must never break reading a container.
#[test]
fn malformed_labels_do_not_panic() {
    for label in [
        "data:,",
        "data:,=",
        "data:,TYPE",
        "data:,CN=%",
        "data:,CN=%ZZ",
        "data:,CN=%2",
        "",
    ] {
        let _ = keylabel::parse(label);
        let _ = keylabel::display(label);
    }
}

// ---------------------------------------------------------------------------
// DigiDoc4 / libcdoc compatibility
// ---------------------------------------------------------------------------

/// The exact shape of a label taken from a CDOC2 container produced by DigiDoc4 4.10.0
/// (libcdoc 0.5.0), with a synthetic identity substituted for the real one. The *format* —
/// key case, ordering, the `PNOEE-` prefix, `server_exp` — was captured from a real container
/// rather than derived from documentation:
/// libcdoc and the Java reference CLI disagree on case, ordering, the `PNOEE-` prefix and the
/// presence of `server_exp`, so only observed output settles it.
#[test]
fn eid_label_matches_digidoc4_output_exactly() {
    let label = keylabel::eid_digidoc(
        types::ID_CARD,
        "TESTIJA,MARI,00000000000",
        Some("PNOEE-00000000000"),
        Some(1_833_487_199),
    );
    assert_eq!(
        label,
        "data:,v=1&cn=TESTIJA%2CMARI%2C00000000000&first_name=MARI&last_name=TESTIJA\
         &serial_number=PNOEE-00000000000&type=ID-card&server_exp=1833487199"
    );
}

/// `v` must come first and the rest keep insertion order — libcdoc does not sort.
#[test]
fn digidoc_label_is_not_sorted() {
    let label = keylabel::eid_digidoc(types::ID_CARD, "B,A,1", Some("PNOEE-1"), Some(1));
    let body = label.strip_prefix("data:,").unwrap();
    let keys: Vec<&str> = body
        .split('&')
        .map(|p| p.split('=').next().unwrap())
        .collect();
    assert_eq!(
        keys,
        vec![
            "v",
            "cn",
            "first_name",
            "last_name",
            "serial_number",
            "type",
            "server_exp"
        ]
    );
}

/// A container without an expiry is still valid; `server_exp` is simply omitted.
#[test]
fn digidoc_label_omits_absent_expiry() {
    let label = keylabel::eid_digidoc(types::ID_CARD, "B,A,1", Some("PNOEE-1"), None);
    assert!(!label.contains("server_exp"), "{label}");
}

/// Both implementations' key cases must display, since either may have written the container.
#[test]
fn display_handles_both_key_cases() {
    let digidoc = keylabel::eid_digidoc(
        types::ID_CARD,
        "TESTIJA,MARI,00000000000",
        Some("PNOEE-00000000000"),
        Some(1_833_487_199),
    );
    assert_eq!(
        keylabel::display(&digidoc),
        "TESTIJA,MARI,00000000000 (ID-card)"
    );

    let reference = keylabel::certificate(Some("cdoc2-client"), Some("aa"), Some("c.pem"));
    assert_eq!(keylabel::display(&reference), "cdoc2-client (cert)");
}

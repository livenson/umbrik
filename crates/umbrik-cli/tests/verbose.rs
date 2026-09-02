//! Verbose output must never disclose secret material.
//!
//! Diagnostics in a cryptographic tool are a standing hazard: the useful values and the dangerous
//! ones sit next to each other in the same functions. These tests run the real binary at its
//! loudest setting and assert that the password, the pre-shared key and the file contents do not
//! appear anywhere in what it prints.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_umbrik");

/// Distinctive enough that a substring search cannot miss them.
const PASSWORD: &str = "Tr0ubador-SECRET-PASSPHRASE-do-not-log";
const SECRET_B64: &str = "c3VwZXItc2VjcmV0LTMyLWJ5dGUta2V5LW1hdGVyaWFsIQ==";
/// What `SECRET_B64` decodes to. Checking only the base64 form would miss a leak of the decoded
/// bytes, which is the value the library actually holds.
const SECRET_PLAIN: &str = "super-secret-32-byte-key-material!";
const PLAINTEXT: &str = "CONFIDENTIAL-PAYLOAD-CONTENTS";

struct Fixture {
    dir: std::path::PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("umbrik-verbose-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("secret.txt"), PLAINTEXT).unwrap();
        Fixture { dir }
    }
    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Combined stdout and stderr, which is where diagnostics go.
fn run(args: &[&str]) -> String {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("running umbrik");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_no_secrets(output: &str, context: &str) {
    // Every representation a leak could plausibly take: the value as given, the decoded bytes as
    // text, their hex, and their Debug form. A check for only the base64 input would pass while
    // the raw key was being printed.
    let secret_hex: String = SECRET_PLAIN.bytes().map(|b| format!("{b:02x}")).collect();
    let secret_debug = format!("{:?}", SECRET_PLAIN.as_bytes());
    let password_debug = format!("{:?}", PASSWORD.as_bytes());

    let forbidden: Vec<(&str, &str)> = vec![
        ("the password", PASSWORD),
        ("the password as bytes", &password_debug),
        ("the pre-shared key (base64)", SECRET_B64),
        ("the pre-shared key (decoded)", SECRET_PLAIN),
        ("the pre-shared key (hex)", &secret_hex),
        ("the pre-shared key (bytes)", &secret_debug),
        ("the plaintext", PLAINTEXT),
    ];

    for (what, needle) in forbidden {
        assert!(
            !output.contains(needle),
            "{context}: {what} appeared in diagnostic output\n--- output ---\n{output}"
        );
    }
}

#[test]
fn verbose_output_never_contains_secrets() {
    let fixture = Fixture::new("roundtrip");
    let container = fixture.path("c.cdoc2");

    for flag in ["-v", "-vv"] {
        let encrypt = run(&[
            "encrypt",
            "-f",
            &container,
            "--password",
            &format!("pw-label:{PASSWORD}"),
            "--secret",
            &format!("sk-label:base64,{SECRET_B64}"),
            flag,
            &fixture.path("secret.txt"),
        ]);
        assert_no_secrets(&encrypt, &format!("encrypt {flag}"));

        let decrypt = run(&[
            "decrypt",
            "-f",
            &container,
            "--password",
            &format!("pw-label:{PASSWORD}"),
            flag,
            "-o",
            &fixture.path("out"),
        ]);
        assert_no_secrets(&decrypt, &format!("decrypt {flag}"));

        let list = run(&[
            "list",
            "-f",
            &container,
            "--password",
            &format!("pw-label:{PASSWORD}"),
            flag,
        ]);
        assert_no_secrets(&list, &format!("list {flag}"));
    }
}

/// A failed decryption is the most likely place for a secret to escape, because the error path
/// has the offending value in hand.
#[test]
fn failed_decryption_never_echoes_the_key_material() {
    let fixture = Fixture::new("failure");
    let container = fixture.path("c.cdoc2");

    run(&[
        "encrypt",
        "-f",
        &container,
        "--password",
        "pw-label:a-different-password",
        &fixture.path("secret.txt"),
    ]);

    let output = run(&[
        "decrypt",
        "-f",
        &container,
        "--password",
        &format!("pw-label:{PASSWORD}"),
        "-vv",
        "-o",
        &fixture.path("out"),
    ]);
    assert_no_secrets(&output, "failed decrypt");
    assert!(
        output.to_lowercase().contains("hmac") || output.to_lowercase().contains("verification"),
        "expected a MAC failure to be reported, got:\n{output}"
    );
}

/// Verbosity must be additive: without the flag, output is unchanged.
#[test]
fn quiet_by_default() {
    let fixture = Fixture::new("quiet");
    let container = fixture.path("c.cdoc2");

    run(&[
        "encrypt",
        "-f",
        &container,
        "--password",
        &format!("pw-label:{PASSWORD}"),
        &fixture.path("secret.txt"),
    ]);
    let quiet = run(&[
        "decrypt",
        "-f",
        &container,
        "--password",
        &format!("pw-label:{PASSWORD}"),
        "-o",
        &fixture.path("out"),
    ]);
    assert_eq!(quiet.trim(), "secret.txt");
}

/// The diagnostics have to be worth printing, or the flag is decoration.
#[test]
fn verbose_reports_which_recipient_opened_the_container() {
    let fixture = Fixture::new("which");
    let container = fixture.path("c.cdoc2");

    run(&[
        "encrypt",
        "-f",
        &container,
        "--secret",
        &format!("sk-label:base64,{SECRET_B64}"),
        "--password",
        &format!("pw-label:{PASSWORD}"),
        &fixture.path("secret.txt"),
    ]);
    let output = run(&[
        "decrypt",
        "-f",
        &container,
        "--secret",
        &format!("sk-label:base64,{SECRET_B64}"),
        "-vv",
        "-o",
        &fixture.path("out"),
    ]);

    assert!(
        output.contains("recipient"),
        "no recipient summary:\n{output}"
    );
    assert!(
        output.contains("SC05"),
        "matched scheme not reported:\n{output}"
    );
    assert!(
        output.contains("sk-label"),
        "matched label not reported:\n{output}"
    );
    assert_no_secrets(&output, "verbose decrypt");
}

/// Labels and entry names are chosen by whoever made the container, and printed on the terminal
/// of whoever opens it. A control character in either is a terminal escape waiting for a
/// victim: this label rewrites the window title, the entry name erases the line it is on.
#[test]
fn untrusted_text_is_printed_without_control_characters() {
    let fixture = Fixture::new("escapes");
    let container = fixture.path("c.cdoc2");
    let label = "innocent\x1b]0;pwned\x07label";
    let password = format!("{label}:{PASSWORD}");

    // NTFS refuses control characters in file names, so this half runs only where a file can
    // carry one.
    #[cfg(unix)]
    let hostile_file = {
        let name = "report\x1b[2K\rmalware.pdf";
        std::fs::write(fixture.dir.join(name), b"x").unwrap();
        Some(fixture.path(name))
    };
    #[cfg(not(unix))]
    let hostile_file: Option<String> = None;
    let inputs: Vec<String> = std::iter::once(fixture.path("secret.txt"))
        .chain(hostile_file)
        .collect();

    let mut args = vec!["encrypt", "-f", &container, "--password", &password, "-vv"];
    args.extend(inputs.iter().map(String::as_str));
    let encrypt = run(&args);

    let out = fixture.path("out");
    let outputs = [
        ("encrypt -vv", encrypt),
        ("recipients", run(&["recipients", "-f", &container])),
        (
            "list -vv",
            run(&["list", "-f", &container, "--password", &password, "-vv"]),
        ),
        (
            "decrypt -vv",
            run(&[
                "decrypt",
                "-f",
                &container,
                "--password",
                &password,
                "-vv",
                "-o",
                &out,
            ]),
        ),
    ];
    for (context, output) in outputs {
        // Newlines and the tab that separates columns are the only control characters the CLI
        // has any business emitting.
        let escaped: Vec<char> = output
            .chars()
            .filter(|c| c.is_control() && !matches!(c, '\n' | '\t'))
            .collect();
        assert!(
            escaped.is_empty(),
            "{context}: control characters {escaped:?} reached the terminal\n--- output ---\n{output}"
        );
        assert!(
            output.contains("innocent"),
            "{context}: the label was dropped rather than sanitised\n--- output ---\n{output}"
        );
    }
}

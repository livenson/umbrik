//! `decrypt` must not replace files already in the output directory unless asked to.
//!
//! The output directory defaults to the current one, and the sender chooses the names.

use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_umbrik");
const PASSWORD: &str = "overwrite-test-Password";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("running umbrik")
}

#[test]
fn decrypt_refuses_to_overwrite_without_force() {
    let dir = std::env::temp_dir().join(format!("umbrik-overwrite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("in")).unwrap();
    std::fs::create_dir_all(dir.join("out")).unwrap();
    let input = dir.join("in").join("letter.txt");
    let container = dir.join("letter.cdoc2");
    let output = dir.join("out");
    let existing = output.join("letter.txt");
    std::fs::write(&input, b"from the container").unwrap();
    std::fs::write(&existing, b"already here").unwrap();

    let password = format!("pw:{PASSWORD}");
    let encrypted = run(&[
        "encrypt",
        "-f",
        container.to_str().unwrap(),
        "--password",
        &password,
        input.to_str().unwrap(),
    ]);
    assert!(encrypted.status.success(), "{encrypted:?}");

    let decrypt = |extra: &[&str]| {
        let mut args = vec![
            "decrypt",
            "-f",
            container.to_str().unwrap(),
            "--password",
            &password,
            "-o",
            output.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        run(&args)
    };

    let refused = decrypt(&[]);
    let kept = std::fs::read(&existing).unwrap();
    let forced = decrypt(&["--force"]);
    let replaced = std::fs::read(&existing).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !refused.status.success(),
        "decrypt replaced an existing file"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("refusing to overwrite"),
        "{refused:?}"
    );
    assert_eq!(kept, b"already here");
    assert!(forced.status.success(), "{forced:?}");
    assert_eq!(replaced, b"from the container");
}

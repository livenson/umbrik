use std::path::{Path, PathBuf};
use std::process::Command;

/// Runs `flatc` over the vendored schemas in `schema/`.
///
/// The schemas are deliberately vendored rather than submoduled (see schema/PROVENANCE.md),
/// so a schema change is always an explicit, reviewable commit.
fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let schema_dir = manifest
        .parent()
        .and_then(Path::parent)
        .expect("crate is nested two levels below the workspace root")
        .join("schema");
    let header_fbs = schema_dir.join("header.fbs");
    let recipients_fbs = schema_dir.join("recipients.fbs");

    println!("cargo:rerun-if-changed={}", header_fbs.display());
    println!("cargo:rerun-if-changed={}", recipients_fbs.display());
    println!("cargo:rerun-if-env-changed=FLATC");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let flatc = std::env::var("FLATC").unwrap_or_else(|_| "flatc".to_string());

    // --gen-all pulls recipients.fbs (included by header.fbs) into a single generated
    // module, which avoids having to wire up cross-file `mod` paths by hand.
    let output = Command::new(&flatc)
        .arg("--rust")
        .arg("--gen-all")
        .arg("-o")
        .arg(&out_dir)
        .arg(&header_fbs)
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => panic!(
            "failed to run `{flatc}`: {e}\n\
             umbrik generates its FlatBuffers codec at build time and needs the FlatBuffers \
             compiler.\n  macOS:  brew install flatbuffers\n  Debian: apt install flatbuffers-compiler\n\
             Or set FLATC=/path/to/flatc.\n\
             The `flatc` version must match the `flatbuffers` crate version pinned in Cargo.toml."
        ),
    };

    if !output.status.success() {
        panic!(
            "flatc failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let generated = out_dir.join("header_generated.rs");
    if !generated.exists() {
        panic!(
            "flatc reported success but {} is missing",
            generated.display()
        );
    }
}

//! `decrypt_to_memory` must write nothing to disk.
//!
//! The Python `umbrik.decrypt` is built on it and promises a mapping of names to contents, so a
//! caller has no reason to expect anything on disk. It used to extract into a scratch directory
//! under the system temporary directory, mode 0755 with files 0644: on a shared `/tmp`, any
//! local user could watch for it and read the plaintext.
//!
//! This test plays that user: a thread watches the temporary directory while decryption runs
//! and records every path it sees, with its permission bits and whether it held the plaintext.
//!
//! Kept in its own test binary because it points `TMPDIR` at a private directory, and the
//! environment is process-wide.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use umbrik_core::container::{self, DecryptionKey, Recipient};
use umbrik_core::payload::PayloadFile;
use umbrik_core::Limits;

const SECRET: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const MARKER: &[u8] = b"UMBRIK-PLAINTEXT-MARKER";

struct Sighting {
    path: PathBuf,
    mode: u32,
    leaked_plaintext: bool,
}

fn scan(root: &Path, seen: &Mutex<Vec<Sighting>>) {
    let Ok(dirs) = std::fs::read_dir(root) else {
        return;
    };
    for dir in dirs.flatten() {
        let path = dir.path();
        if let Ok(meta) = std::fs::metadata(&path) {
            record(&path, meta.permissions().mode(), false, seen);
        }
        let Ok(files) = std::fs::read_dir(&path) else {
            continue;
        };
        for file in files.flatten() {
            let file_path = file.path();
            let Ok(meta) = std::fs::metadata(&file_path) else {
                continue;
            };
            let leaked = std::fs::read(&file_path)
                .map(|data| data.windows(MARKER.len()).any(|w| w == MARKER))
                .unwrap_or(false);
            record(&file_path, meta.permissions().mode(), leaked, seen);
        }
    }
}

fn record(path: &Path, mode: u32, leaked: bool, seen: &Mutex<Vec<Sighting>>) {
    let mut seen = seen.lock().unwrap();
    match seen.iter_mut().find(|s| s.path == path) {
        Some(s) => s.leaked_plaintext |= leaked,
        None => seen.push(Sighting {
            path: path.to_path_buf(),
            mode: mode & 0o777,
            leaked_plaintext: leaked,
        }),
    }
}

#[test]
fn decrypt_to_memory_exposes_nothing_to_other_users() {
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("scratch-exposure-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::env::set_var("TMPDIR", &tmp);
    assert_eq!(std::env::temp_dir(), tmp);

    // Large enough that writing and reading it back takes a measurable time, and incompressible
    // so it stays under the compression-ratio limit.
    let mut data = MARKER.to_vec();
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    while data.len() < 4 * 1024 * 1024 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        data.extend_from_slice(&state.to_le_bytes());
    }
    let files = vec![PayloadFile {
        name: "letter.txt".to_string(),
        data,
    }];
    let recipients = [Recipient::Symmetric {
        label: "scratch".to_string(),
        secret: SECRET.to_vec().into(),
    }];
    let mut container_bytes = Vec::new();
    container::encrypt(&mut container_bytes, &mut rand::rng(), &files, &recipients).unwrap();
    let key = DecryptionKey::Symmetric(SECRET.to_vec().into());

    let seen = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (seen, stop, tmp) = (seen.clone(), stop.clone(), tmp.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                scan(&tmp, &seen);
            }
        })
    };

    for _ in 0..5 {
        let out = container::decrypt_to_memory(&container_bytes, &key, &Limits::default()).unwrap();
        assert!(out[0].data.starts_with(MARKER));
    }
    stop.store(true, Ordering::Relaxed);
    watcher.join().unwrap();
    let _ = std::fs::remove_dir_all(&tmp);

    // Requiring nothing at all, rather than nothing readable by others: the watcher runs as the
    // same user, so permission bits are the only evidence it could gather of exposure, and a
    // directory that never exists needs none.
    let seen: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| {
            format!(
                "{:o} {} plaintext={}",
                s.mode,
                s.path.display(),
                s.leaked_plaintext
            )
        })
        .collect();
    assert!(
        seen.is_empty(),
        "decrypt_to_memory wrote to the temporary directory:\n{}",
        seen.join("\n")
    );
}

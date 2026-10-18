//! Reader-side defences against hostile payloads.
//!
//! These craft tar archives byte by byte rather than going through umbrik's writer. That is the
//! point: umbrik's writer refuses to produce these, but a hostile container is built by someone
//! else's tool, and the extraction path is what has to hold. Testing only through our own
//! encoder would test the wrong side of the boundary.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;
use umbrik_core::error::ErrorCode;
use umbrik_core::payload;
use umbrik_core::Limits;

const BLOCK: usize = 512;

/// Build a raw ustar header plus data blocks, bypassing every safety check a tar library
/// would apply.
fn tar_entry(name: &str, data: &[u8], typeflag: u8) -> Vec<u8> {
    let mut header = [0u8; BLOCK];

    let write_at = |h: &mut [u8; BLOCK], offset: usize, bytes: &[u8]| {
        h[offset..offset + bytes.len()].copy_from_slice(bytes);
    };

    write_at(&mut header, 0, name.as_bytes()); // name[100]
    write_at(&mut header, 100, b"0000644\0"); // mode
    write_at(&mut header, 108, b"0000000\0"); // uid
    write_at(&mut header, 116, b"0000000\0"); // gid
    write_at(
        &mut header,
        124,
        format!("{:011o}\0", data.len()).as_bytes(),
    ); // size
    write_at(&mut header, 136, b"00000000000\0"); // mtime
    header[148..156].fill(b' '); // checksum field is spaces while summing
    header[156] = typeflag;
    write_at(&mut header, 257, b"ustar\0"); // magic
    write_at(&mut header, 263, b"00"); // version

    let checksum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    write_at(&mut header, 148, format!("{checksum:06o}\0 ").as_bytes());

    let mut out = header.to_vec();
    out.extend_from_slice(data);
    // Pad the data to a block boundary.
    let rem = data.len() % BLOCK;
    if rem != 0 {
        out.resize(out.len() + (BLOCK - rem), 0);
    }
    out
}

/// Finish an archive: two zero blocks, then zlib.
fn seal(mut tar: Vec<u8>) -> Vec<u8> {
    tar.extend_from_slice(&[0u8; BLOCK * 2]);
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

/// A directory no other test shares. Tests run in parallel, and a timestamp alone collides on
/// macOS, whose clock has microsecond resolution: one test's cleanup then deletes the
/// directory another is extracting into, which surfaces as a spurious `Io` error.
fn scratch() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("umbrik-hostile-{}-{seq}", std::process::id()))
}

/// Unpack to a directory and to memory, and require both paths to reach the same verdict.
///
/// They share no extraction loop, so every hostile input below has to be refused by each.
fn unpack(compressed: &[u8], limits: &Limits) -> umbrik_core::Result<Vec<payload::ArchiveEntry>> {
    let dir = scratch();
    let on_disk = payload::unpack_to_dir(compressed, &dir, limits);
    let _ = std::fs::remove_dir_all(&dir);

    let in_memory = payload::unpack_to_memory(compressed, limits);
    match (&on_disk, &in_memory) {
        (Ok(entries), Ok(files)) => {
            let described: Vec<(&str, u64)> = files
                .iter()
                .map(|f| (f.name.as_str(), f.data.len() as u64))
                .collect();
            let expected: Vec<(&str, u64)> =
                entries.iter().map(|e| (e.name.as_str(), e.size)).collect();
            assert_eq!(
                described, expected,
                "in-memory unpack disagrees with on-disk"
            );
        }
        (Err(a), Err(b)) => assert_eq!(a.code(), b.code(), "{a} vs {b}"),
        _ => panic!("on-disk {on_disk:?} but in-memory {in_memory:?}"),
    }
    on_disk
}

#[test]
fn sanity_hand_built_tar_is_readable() {
    // If this fails, the other tests in this file prove nothing.
    let compressed = seal(tar_entry("ok.txt", b"hello", b'0'));
    let entries = unpack(&compressed, &Limits::default()).expect("hand-built tar must parse");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "ok.txt");
    assert_eq!(entries[0].size, 5);
}

#[test]
fn rejects_parent_directory_traversal() {
    for name in [
        "../escaped.txt",
        "../../escaped.txt",
        "a/../../escaped.txt",
        "./../escaped.txt",
        "dir/../../../etc/passwd",
    ] {
        let compressed = seal(tar_entry(name, b"pwned", b'0'));
        let err = unpack(&compressed, &Limits::default()).unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::UnsafeArchiveEntry,
            "traversal {name:?} must be rejected"
        );
    }
}

#[test]
fn rejects_absolute_paths() {
    for name in ["/etc/passwd", "/tmp/umbrik-should-not-exist"] {
        let compressed = seal(tar_entry(name, b"pwned", b'0'));
        let err = unpack(&compressed, &Limits::default()).unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::UnsafeArchiveEntry,
            "absolute path {name:?} must be rejected"
        );
    }
}

#[test]
fn traversal_writes_nothing_outside_destination() {
    let marker = std::env::temp_dir().join("umbrik-traversal-canary.txt");
    let _ = std::fs::remove_file(&marker);

    // Aim an entry at the canary path via traversal from a nested scratch directory.
    let dir = scratch().join("nested");
    let compressed = seal(tar_entry(
        "../../umbrik-traversal-canary.txt",
        b"pwned",
        b'0',
    ));
    let err = payload::unpack_to_dir(&compressed, &dir, &Limits::default()).unwrap_err();
    let _ = std::fs::remove_dir_all(scratch());

    assert_eq!(err.code(), ErrorCode::UnsafeArchiveEntry);
    assert!(
        !marker.exists(),
        "traversal entry escaped the destination directory"
    );
}

#[test]
fn rejects_directory_components() {
    // The reference implementation refuses these too. Allowing them is what lets a container
    // reach `~/.ssh/authorized_keys` when decrypted in the home directory.
    for name in [
        "docs/letter.txt",
        "a/b/c.txt",
        ".ssh/authorized_keys",
        "./nested/x.txt",
    ] {
        let compressed = seal(tar_entry(name, b"pwned", b'0'));
        let err = unpack(&compressed, &Limits::default()).unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::UnsafeArchiveEntry,
            "nested name {name:?} must be rejected"
        );
    }
}

#[test]
fn rejects_dot_prefixed_names() {
    // A new `~/.zshenv` runs at every shell start, and needs no existing file to replace.
    for name in [".zshenv", ".bashrc", "./.profile", ".."] {
        let compressed = seal(tar_entry(name, b"pwned", b'0'));
        let err = unpack(&compressed, &Limits::default()).unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::UnsafeArchiveEntry,
            "dotfile {name:?} must be rejected"
        );
    }
}

#[test]
fn accepts_dots_inside_a_name() {
    let compressed = seal(tar_entry("report.v2.pdf", b"ok", b'0'));
    let entries = unpack(&compressed, &Limits::default()).unwrap();
    assert_eq!(entries[0].name, "report.v2.pdf");
}

#[test]
fn rejects_duplicate_names() {
    let mut tar = tar_entry("letter.txt", b"first", b'0');
    tar.extend_from_slice(&tar_entry("./letter.txt", b"second", b'0'));
    let err = unpack(&seal(tar), &Limits::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::UnsafeArchiveEntry);
}

#[test]
fn refuses_to_overwrite_an_existing_file() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("letter.txt"), b"original").unwrap();

    let compressed = seal(tar_entry("letter.txt", b"replaced", b'0'));
    let err = payload::unpack_to_dir(&compressed, &dir, &Limits::default()).unwrap_err();
    let kept = std::fs::read(dir.join("letter.txt")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(err.code(), ErrorCode::Io);
    let cause = std::error::Error::source(&err).map(ToString::to_string);
    assert!(
        cause
            .as_deref()
            .unwrap_or("")
            .contains("refusing to overwrite"),
        "{err}: {cause:?}"
    );
    assert_eq!(kept, b"original");
}

#[test]
fn overwrites_when_allowed() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("letter.txt"),
        b"original, and longer than the new one",
    )
    .unwrap();

    let compressed = seal(tar_entry("letter.txt", b"replaced", b'0'));
    let limits = Limits::default().with_overwrite_allowed(true);
    payload::unpack_to_dir(&compressed, &dir, &limits).unwrap();
    let written = std::fs::read(dir.join("letter.txt")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(written, b"replaced");
}

#[test]
fn failed_unpack_removes_only_files_it_created() {
    // Cleanup used to remove every path it had written to, including a file the user already
    // had: a container could truncate a file and then fail on purpose to delete it.
    let dir = scratch();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("existing.txt"), b"original").unwrap();

    let mut tar = tar_entry("existing.txt", b"replaced", b'0');
    tar.extend_from_slice(&tar_entry("new.txt", b"new", b'0'));
    tar.extend_from_slice(&tar_entry("../escape.txt", b"fail here", b'0'));
    let limits = Limits::default().with_overwrite_allowed(true);
    let err = payload::unpack_to_dir(&seal(tar), &dir, &limits).unwrap_err();
    let existing_survives = dir.join("existing.txt").exists();
    let new_removed = !dir.join("new.txt").exists();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(err.code(), ErrorCode::UnsafeArchiveEntry);
    assert!(existing_survives, "a file that existed before was deleted");
    assert!(new_removed, "a file this call created was left behind");
}

#[cfg(unix)]
#[test]
fn never_writes_through_an_existing_symlink() {
    let dir = scratch();
    std::fs::create_dir_all(dir.join("out")).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, b"original").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("out").join("letter.txt")).unwrap();

    let compressed = seal(tar_entry("letter.txt", b"replaced", b'0'));
    // Even with overwriting allowed: the user agreed to replace files, not to follow links.
    let limits = Limits::default().with_overwrite_allowed(true);
    let err = payload::unpack_to_dir(&compressed, &dir.join("out"), &limits).unwrap_err();
    let kept = std::fs::read(&outside).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(err.code(), ErrorCode::UnsafeArchiveEntry);
    assert_eq!(kept, b"original");
}

#[test]
fn rejects_symlink_entries_by_default() {
    // typeflag '2' is a symbolic link.
    let compressed = seal(tar_entry("link", b"", b'2'));
    let err = unpack(&compressed, &Limits::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::UnsafeArchiveEntry);
}

#[test]
fn rejects_hard_link_entries_by_default() {
    // typeflag '1' is a hard link.
    let compressed = seal(tar_entry("link", b"", b'1'));
    let err = unpack(&compressed, &Limits::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::UnsafeArchiveEntry);
}

#[test]
fn rejects_character_device_entries() {
    // typeflag '3' is a character device.
    let compressed = seal(tar_entry("dev", b"", b'3'));
    let err = unpack(&compressed, &Limits::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::UnsafeArchiveEntry);
}

#[test]
fn rejects_zip_bomb_from_hand_built_archive() {
    let compressed = seal(tar_entry("bomb", &vec![0u8; 8 * 1024 * 1024], b'0'));
    let err = unpack(&compressed, &Limits::default()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn rejects_entry_count_over_limit() {
    let mut tar = Vec::new();
    for i in 0..10 {
        tar.extend_from_slice(&tar_entry(&format!("f{i}.txt"), b"x", b'0'));
    }
    let compressed = seal(tar);
    let err = unpack(&compressed, &Limits::default().with_max_entries(3)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
}

#[test]
fn garbage_payload_does_not_panic() {
    for junk in [
        vec![],
        vec![0u8; 16],
        vec![0xFFu8; 1024],
        b"not zlib at all".to_vec(),
    ] {
        // Any outcome is acceptable except a panic.
        let _ = unpack(&junk, &Limits::default());
    }
}

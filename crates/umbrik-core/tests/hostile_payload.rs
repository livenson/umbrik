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

fn scratch() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("umbrik-hostile-{nanos}"))
}

fn unpack(compressed: &[u8], limits: &Limits) -> umbrik_core::Result<Vec<payload::ArchiveEntry>> {
    let dir = scratch();
    let result = payload::unpack_to_dir(compressed, &dir, limits);
    let _ = std::fs::remove_dir_all(&dir);
    result
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

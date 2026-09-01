//! Payload packing and unpacking: POSIX tar, then zlib (RFC 1950).
//!
//! Order is tar first, then compress, then AEAD. On the way out: AEAD, then decompress, then
//! untar. All the hostile-input handling lives here — a container's payload is attacker
//! controlled once the AEAD tag has verified, because the tag only proves the sender knew the
//! CEK, not that they were honest.

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

use crate::error::{Error, Result};
use crate::limits::Limits;

/// One file to place in a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// A tar entry described without extracting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// The entry's path relative to the extraction directory, after validation. Joining this to
    /// the destination always yields the file that was written.
    pub name: String,
    pub size: u64,
}

/// Fixed tar metadata, so that identical inputs produce identical containers.
///
/// Real mtimes and ownership would make output non-reproducible and leak information about the
/// sender's machine. Neither is part of what CDOC2 protects, so both are normalised away.
const FIXED_MTIME: u64 = 0;
const FIXED_MODE: u32 = 0o644;

/// `zlib(tar(files))`.
pub fn pack(files: &[PayloadFile]) -> Result<Vec<u8>> {
    if files.is_empty() {
        return Err(Error::InvalidKeyMaterial("no files to encrypt"));
    }

    // Defence in depth: refuse to *create* a container whose entry names would be rejected on
    // the way out. The tar crate also refuses these, but with an opaque io error.
    let write_limits = Limits::default();
    for file in files {
        safe_relative_path(&file.name, &write_limits)?;
    }

    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for file in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(file.data.len() as u64);
            header.set_mode(FIXED_MODE);
            header.set_mtime(FIXED_MTIME);
            header.set_uid(0);
            header.set_gid(0);
            header.set_entry_type(tar::EntryType::Regular);
            builder
                .append_data(&mut header, &file.name, file.data.as_slice())
                .map_err(Error::Io)?;
        }
        builder.finish().map_err(Error::Io)?;
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).map_err(Error::Io)?;
    encoder.finish().map_err(Error::Io)
}

/// A reader that fails once its source has produced too many bytes.
///
/// Wraps the *decompressed* side of the zlib stream, so a zip bomb is stopped as it inflates
/// rather than after.
struct LimitedReader<R> {
    inner: R,
    read: u64,
    max: u64,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read = self.read.saturating_add(n as u64);
        if self.read > self.max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed payload exceeds configured limit",
            ));
        }
        Ok(n)
    }
}

/// Below this many uncompressed bytes, the compression-ratio check does not apply.
///
/// A tar archive is padded to a 10 KiB minimum, so a container holding one small file inflates
/// to ~10 KiB regardless of content and trivially exceeds any sane ratio. The reference
/// implementation sidesteps this by checking the ratio after each entry, before the trailing
/// padding is read; umbrik inflates as a stream and so needs an explicit floor instead.
///
/// This does not weaken zip-bomb protection: 64 KiB is far below any payload that could exhaust
/// memory or disk, and the absolute `max_uncompressed_bytes` cap still applies underneath it.
const RATIO_CHECK_FLOOR_BYTES: u64 = 64 * 1024;

/// The decompressed-size ceiling for a given compressed length.
///
/// The tighter of the absolute byte cap and the compression-ratio cap, with the ratio cap
/// floored at [`RATIO_CHECK_FLOOR_BYTES`].
fn inflate_ceiling(compressed_len: usize, limits: &Limits) -> u64 {
    let ratio_cap = (compressed_len as u64)
        .saturating_mul(limits.max_compression_ratio)
        .max(RATIO_CHECK_FLOOR_BYTES);
    ratio_cap.min(limits.max_uncompressed_bytes)
}

/// Reject anything that could write outside the destination directory.
///
/// Rejected: absolute paths, `..` components, Windows drive prefixes and root components, empty
/// names. Accepted names are relative and contain only normal components.
fn safe_relative_path(name: &str, limits: &Limits) -> Result<PathBuf> {
    if name.is_empty() {
        return Err(Error::UnsafeArchiveEntry("entry name is empty"));
    }

    let raw = Path::new(name);
    if raw.is_absolute() && !limits.allow_absolute_paths {
        return Err(Error::UnsafeArchiveEntry("entry name is an absolute path"));
    }

    let mut safe = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(part) => safe.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(Error::UnsafeArchiveEntry(
                    "entry name contains a '..' component",
                ))
            }
            Component::RootDir | Component::Prefix(_) => {
                if !limits.allow_absolute_paths {
                    return Err(Error::UnsafeArchiveEntry(
                        "entry name contains a root or drive component",
                    ));
                }
            }
        }
    }

    if safe.as_os_str().is_empty() {
        return Err(Error::UnsafeArchiveEntry(
            "entry name has no usable components",
        ));
    }
    Ok(safe)
}

fn check_entry_type(entry_type: tar::EntryType, limits: &Limits) -> Result<()> {
    if entry_type.is_symlink() || entry_type.is_hard_link() {
        if !limits.allow_symlinks {
            return Err(Error::UnsafeArchiveEntry("entry is a symlink or hard link"));
        }
        return Ok(());
    }
    if entry_type.is_dir() || entry_type.is_file() {
        return Ok(());
    }
    // pax/GNU metadata entries are consumed by the tar reader and never surface here.
    Err(Error::UnsafeArchiveEntry("entry has an unsupported type"))
}

/// Map an inflate error back to a limit violation.
///
/// `LimitedReader` can only surface its refusal through `io::Error`, and the tar reader wraps it
/// further, so the distinction is recovered here rather than being reported as generic I/O.
///
/// `ceiling` and `compressed_len` are known before reading starts, so the message can say what
/// the limit was and which setting to change — a bare "too large" leaves a user with a
/// legitimate container and no idea what to do.
fn classify_unpack_error(err: std::io::Error, compressed_len: usize, limits: &Limits) -> Error {
    if err.kind() == std::io::ErrorKind::InvalidData
        && err.to_string().contains("exceeds configured limit")
    {
        let ceiling = inflate_ceiling(compressed_len, limits);
        return Error::LimitExceeded(format!(
            "payload inflates past {ceiling} bytes (compressed {compressed_len} bytes, \
             max_compression_ratio {}, max_uncompressed_bytes {}). Raise whichever limit \
             applies if the container is trusted.",
            limits.max_compression_ratio, limits.max_uncompressed_bytes
        ));
    }
    Error::Io(err)
}

/// List entries without writing anything to disk.
pub fn list(compressed: &[u8], limits: &Limits) -> Result<Vec<ArchiveEntry>> {
    let reader = LimitedReader {
        inner: ZlibDecoder::new(compressed),
        read: 0,
        max: inflate_ceiling(compressed.len(), limits),
    };
    let mut archive = tar::Archive::new(reader);

    let mut out = Vec::new();
    let entries = archive
        .entries()
        .map_err(|e| classify_unpack_error(e, compressed.len(), limits))?;
    for entry in entries {
        let entry = entry.map_err(|e| classify_unpack_error(e, compressed.len(), limits))?;
        if out.len() as u64 >= limits.max_entries {
            return Err(Error::LimitExceeded("too many archive entries".to_string()));
        }
        check_entry_type(entry.header().entry_type(), limits)?;
        let path = entry.path().map_err(Error::Io)?;
        // Validate even when only listing: a caller may act on these names.
        let relative = safe_relative_path(&path.to_string_lossy(), limits)?;
        out.push(ArchiveEntry {
            name: relative.to_string_lossy().into_owned(),
            size: entry.header().size().map_err(Error::Io)?,
        });
    }
    Ok(out)
}

/// Unpack into `dest`.
///
/// The caller must have already verified the AEAD tag — the payload passed here is
/// authenticated plaintext. Because CDOC2 uses a single AEAD invocation over the whole payload,
/// authentication necessarily completes before the first byte reaches this function, so no
/// unauthenticated data can ever be written to disk.
///
/// Authenticated does not mean trustworthy: the sender chose these paths. Every entry is still
/// checked against [`Limits`].
///
/// On failure, files created by this call are removed.
pub fn unpack_to_dir(compressed: &[u8], dest: &Path, limits: &Limits) -> Result<Vec<ArchiveEntry>> {
    std::fs::create_dir_all(dest).map_err(Error::Io)?;

    let mut created: Vec<PathBuf> = Vec::new();
    match unpack_inner(compressed, dest, limits, &mut created) {
        Ok(entries) => Ok(entries),
        Err(err) => {
            for path in created.iter().rev() {
                let _ = std::fs::remove_file(path);
            }
            Err(err)
        }
    }
}

fn unpack_inner(
    compressed: &[u8],
    dest: &Path,
    limits: &Limits,
    created: &mut Vec<PathBuf>,
) -> Result<Vec<ArchiveEntry>> {
    let reader = LimitedReader {
        inner: ZlibDecoder::new(compressed),
        read: 0,
        max: inflate_ceiling(compressed.len(), limits),
    };
    let mut archive = tar::Archive::new(reader);

    let mut out = Vec::new();
    let entries = archive
        .entries()
        .map_err(|e| classify_unpack_error(e, compressed.len(), limits))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| classify_unpack_error(e, compressed.len(), limits))?;
        if out.len() as u64 >= limits.max_entries {
            return Err(Error::LimitExceeded("too many archive entries".to_string()));
        }

        let entry_type = entry.header().entry_type();
        check_entry_type(entry_type, limits)?;

        let raw_path = entry.path().map_err(Error::Io)?;
        let relative = safe_relative_path(&raw_path.to_string_lossy(), limits)?;
        let name = relative.to_string_lossy().into_owned();
        let target = dest.join(&relative);

        if entry_type.is_dir() {
            std::fs::create_dir_all(&target).map_err(Error::Io)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }

        let size = entry.header().size().map_err(Error::Io)?;
        let mut file = std::fs::File::create(&target).map_err(Error::Io)?;
        created.push(target.clone());
        std::io::copy(&mut entry, &mut file)
            .map_err(|e| classify_unpack_error(e, compressed.len(), limits))?;

        out.push(ArchiveEntry { name, size });
    }
    Ok(out)
}

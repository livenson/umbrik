//! Errors, and the stable integer codes they flatten to across the C ABI.

/// Stable numeric error codes.
///
/// These values are **API frozen**. They cross the C ABI in `umbrik-ffi` and become Python
/// exception classes and Go error values; renumbering one is a silent ABI break for every
/// downstream binding. Add new codes at the end, never reuse or reorder.
///
/// [`Error`] itself carries context (strings, sources) and so cannot be `#[repr(i32)]` while
/// staying ergonomic in Rust. The stability contract lives here instead, and [`Error::code`]
/// is the total mapping between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
#[non_exhaustive]
pub enum ErrorCode {
    Io = 1,
    /// Container does not start with the `CDOC` prelude.
    BadPrelude = 2,
    UnsupportedVersion = 3,
    /// Declared header length outside `[MIN_HEADER_LEN, MAX_HEADER_LEN]`.
    HeaderLengthOutOfRange = 4,
    /// Container ended before a declared field did.
    Truncated = 5,
    /// FlatBuffers verification failed, or a required field was absent.
    MalformedHeader = 6,
    /// A recipient uses a capsule type this build does not implement (SC03/SC04/SC07).
    UnsupportedCapsule = 7,
    UnsupportedFmkEncryptionMethod = 8,
    UnsupportedPayloadEncryptionMethod = 9,
    /// No recipient record matched the supplied key material.
    NoMatchingRecipient = 10,
    /// Header HMAC did not verify. The header has been tampered with, or the key is wrong.
    HeaderHmacMismatch = 11,
    /// Payload Poly1305 tag did not verify.
    PayloadAuthenticationFailed = 12,
    KeyDerivation = 13,
    InvalidKeyMaterial = 14,
    /// A `Limits` bound was exceeded (compression ratio, entry count, byte count).
    LimitExceeded = 15,
    /// A tar entry tried to escape the output directory, or was a symlink.
    UnsafeArchiveEntry = 16,
    /// A `KeyProvider` implementation failed.
    KeyProvider = 17,
    /// A `CapsuleTransport` implementation failed.
    Transport = 18,
    /// Invariant violation inside umbrik. Always a bug.
    Internal = 19,
}

impl ErrorCode {
    /// The stable wire value. Use this at the FFI boundary rather than casting.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// The error type for all umbrik operations.
///
/// Messages must never contain key material, PINs, or plaintext. Anything that could carry
/// secret bytes belongs in a variant's structure as a length or a code, not in a formatted
/// string.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("io error")]
    Io(#[from] std::io::Error),

    #[error("not a CDOC2 container: missing CDOC prelude")]
    BadPrelude,

    #[error("unsupported container version {found} (this build supports {supported})")]
    UnsupportedVersion { found: u8, supported: u8 },

    #[error("declared header length {found} outside supported range {min}..={max}")]
    HeaderLengthOutOfRange { found: u64, min: usize, max: usize },

    #[error("container truncated: expected at least {expected} bytes, found {found}")]
    Truncated { expected: u64, found: u64 },

    #[error("malformed header: {0}")]
    MalformedHeader(&'static str),

    #[error("unsupported recipient capsule: {0}")]
    UnsupportedCapsule(&'static str),

    #[error("unsupported FMK encryption method (raw value {0})")]
    UnsupportedFmkEncryptionMethod(i8),

    #[error("unsupported payload encryption method (raw value {0})")]
    UnsupportedPayloadEncryptionMethod(i8),

    #[error("no recipient in this container matches the supplied key material")]
    NoMatchingRecipient,

    #[error("header HMAC verification failed")]
    HeaderHmacMismatch,

    #[error("payload authentication failed")]
    PayloadAuthenticationFailed,

    #[error("key derivation failed: {0}")]
    KeyDerivation(&'static str),

    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(&'static str),

    #[error("limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("unsafe archive entry: {0}")]
    UnsafeArchiveEntry(&'static str),

    #[error("key provider failed: {0}")]
    KeyProvider(String),

    #[error("transport failed: {0}")]
    Transport(String),

    #[error("internal error: {0}")]
    Internal(&'static str),
}

impl Error {
    /// Map to the stable numeric code. Total by construction: adding an `Error` variant
    /// without a code here is a compile error.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Io(_) => ErrorCode::Io,
            Error::BadPrelude => ErrorCode::BadPrelude,
            Error::UnsupportedVersion { .. } => ErrorCode::UnsupportedVersion,
            Error::HeaderLengthOutOfRange { .. } => ErrorCode::HeaderLengthOutOfRange,
            Error::Truncated { .. } => ErrorCode::Truncated,
            Error::MalformedHeader(_) => ErrorCode::MalformedHeader,
            Error::UnsupportedCapsule(_) => ErrorCode::UnsupportedCapsule,
            Error::UnsupportedFmkEncryptionMethod(_) => ErrorCode::UnsupportedFmkEncryptionMethod,
            Error::UnsupportedPayloadEncryptionMethod(_) => {
                ErrorCode::UnsupportedPayloadEncryptionMethod
            }
            Error::NoMatchingRecipient => ErrorCode::NoMatchingRecipient,
            Error::HeaderHmacMismatch => ErrorCode::HeaderHmacMismatch,
            Error::PayloadAuthenticationFailed => ErrorCode::PayloadAuthenticationFailed,
            Error::KeyDerivation(_) => ErrorCode::KeyDerivation,
            Error::InvalidKeyMaterial(_) => ErrorCode::InvalidKeyMaterial,
            Error::LimitExceeded(_) => ErrorCode::LimitExceeded,
            Error::UnsafeArchiveEntry(_) => ErrorCode::UnsafeArchiveEntry,
            Error::KeyProvider(_) => ErrorCode::KeyProvider,
            Error::Transport(_) => ErrorCode::Transport,
            Error::Internal(_) => ErrorCode::Internal,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

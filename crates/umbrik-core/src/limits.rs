//! Resource and safety bounds enforced during decryption.

/// Bounds applied while unpacking a container's payload.
///
/// Deliberately a plain struct and not a trait. A trait invites a permissive implementation,
/// and these limits are the only thing standing between a hostile container and the filesystem.
/// `Reader` enforces them itself rather than delegating to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum `uncompressed / compressed` ratio before the payload is treated as a zip bomb.
    pub max_compression_ratio: u64,
    /// Maximum number of tar entries.
    pub max_entries: u64,
    /// Maximum total uncompressed bytes.
    pub max_uncompressed_bytes: u64,
    /// Symlink and hardlink entries. Off by default: a link can point outside the output
    /// directory, and resolving that safely is subtle.
    pub allow_symlinks: bool,
    /// Absolute paths in tar entry names. Off by default.
    pub allow_absolute_paths: bool,
    /// Maximum recipient records considered when opening a container.
    ///
    /// Each candidate record costs a KEK derivation, and for SC06 that is a full PBKDF2 run.
    /// A hostile container can declare arbitrarily many.
    pub max_recipients: u64,
    /// Total PBKDF2 iterations umbrik will spend opening one container, across all candidate
    /// recipients.
    ///
    /// `kdf_iterations` is attacker-controlled per recipient, and PBKDF2 is unbounded work by
    /// design. Capping a single capsule is not enough — the cost is the product of iteration
    /// count and recipient count, so the budget has to be cumulative.
    pub max_total_kdf_iterations: u64,
}

impl Limits {
    /// Maximum `uncompressed / compressed` ratio before a payload is treated as a zip bomb.
    ///
    /// The reference implementation uses 10, which is too tight for real data: plain text and
    /// log files routinely compress past 20:1, and a container of logs produced by DigiDoc4 was
    /// rejected outright at that setting. Refusing to open legitimate containers is its own
    /// kind of failure.
    ///
    /// 100 still leaves a wide margin against actual zip bombs, which reach 1000:1 and beyond,
    /// and [`Limits::max_uncompressed_bytes`] remains the hard ceiling underneath it.
    pub const DEFAULT_MAX_COMPRESSION_RATIO: u64 = 100;
    pub const DEFAULT_MAX_ENTRIES: u64 = 1000;
    pub const DEFAULT_MAX_UNCOMPRESSED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
    pub const DEFAULT_MAX_RECIPIENTS: u64 = 64;
    /// Roughly 80x a normal single-recipient open (600 000 iterations).
    pub const DEFAULT_MAX_TOTAL_KDF_ITERATIONS: u64 = 50_000_000;
}

impl Limits {
    /// Set the maximum `uncompressed / compressed` ratio.
    pub fn with_max_compression_ratio(mut self, ratio: u64) -> Self {
        self.max_compression_ratio = ratio;
        self
    }

    /// Set the maximum number of archive entries.
    pub fn with_max_entries(mut self, entries: u64) -> Self {
        self.max_entries = entries;
        self
    }

    /// Set the maximum total uncompressed size.
    pub fn with_max_uncompressed_bytes(mut self, bytes: u64) -> Self {
        self.max_uncompressed_bytes = bytes;
        self
    }

    /// Permit symlink and hardlink entries. Off by default; a link can point outside the
    /// output directory.
    pub fn with_symlinks_allowed(mut self, allow: bool) -> Self {
        self.allow_symlinks = allow;
        self
    }

    /// Permit absolute paths in entry names. Off by default.
    pub fn with_absolute_paths_allowed(mut self, allow: bool) -> Self {
        self.allow_absolute_paths = allow;
        self
    }

    /// Set the maximum number of recipient records considered when opening a container.
    pub fn with_max_recipients(mut self, recipients: u64) -> Self {
        self.max_recipients = recipients;
        self
    }

    /// Set the cumulative PBKDF2 iteration budget for opening one container.
    pub fn with_max_total_kdf_iterations(mut self, iterations: u64) -> Self {
        self.max_total_kdf_iterations = iterations;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_compression_ratio: Self::DEFAULT_MAX_COMPRESSION_RATIO,
            max_entries: Self::DEFAULT_MAX_ENTRIES,
            max_uncompressed_bytes: Self::DEFAULT_MAX_UNCOMPRESSED_BYTES,
            allow_symlinks: false,
            allow_absolute_paths: false,
            max_recipients: Self::DEFAULT_MAX_RECIPIENTS,
            max_total_kdf_iterations: Self::DEFAULT_MAX_TOTAL_KDF_ITERATIONS,
        }
    }
}

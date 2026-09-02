//! `umbrik` — command-line interface for CDOC2 containers.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::{ArgAction, Args, Parser, Subcommand};
use umbrik_core::cert;
use umbrik_core::container::{DecryptionKey, Recipient};
use umbrik_core::keylabel;
use umbrik_core::payload::PayloadFile;
use umbrik_core::provider::software::SoftwareKeyProvider;
use umbrik_core::provider::KeyProvider;
use umbrik_core::Limits;

#[derive(Parser)]
#[command(
    name = "umbrik",
    version,
    about = "Encrypt and decrypt CDOC2 containers",
    long_about = "An independent implementation of the CDOC2 container format (spec 1.7).\n\
                  Not affiliated with or endorsed by RIA or Cybernetica. Unaudited."
)]
struct Cli {
    /// Explain what is happening. Repeat for more detail (`-vv`).
    ///
    /// Diagnostics go to stderr and never include key material, passwords or PINs — see
    /// `Verbosity`.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

/// Diagnostic output.
///
/// Everything printed here is derived from what an attacker holding the container can already
/// see — scheme names, labels, byte lengths — or from the local environment, such as a PKCS#11
/// slot. Nothing derived from key material passes through it.
///
/// The type has no method that takes a secret, which is the point: making a leak require adding
/// a new method is a stronger guarantee than remembering not to call an existing one. The test
/// `verbose_output_never_contains_secrets` checks the result.
#[derive(Clone, Copy)]
struct Verbosity(u8);

impl Verbosity {
    /// First level: what umbrik is doing and why.
    fn say(&self, args: std::fmt::Arguments<'_>) {
        if self.0 >= 1 {
            eprintln!("  {args}");
        }
    }

    /// Second level: byte offsets, lengths, and other detail useful when something is wrong.
    fn detail(&self, args: std::fmt::Arguments<'_>) {
        if self.0 >= 2 {
            eprintln!("    {args}");
        }
    }

    fn enabled(&self) -> bool {
        self.0 >= 1
    }
}

macro_rules! say {
    ($v:expr, $($arg:tt)*) => { $v.say(format_args!($($arg)*)) };
}
macro_rules! detail {
    ($v:expr, $($arg:tt)*) => { $v.detail(format_args!($($arg)*)) };
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt files into a container.
    ///
    /// Recipient options may be combined and repeated; every recipient can open the container.
    Encrypt {
        /// Output container path.
        #[arg(short = 'f', long = "file")]
        file: PathBuf,
        /// Password recipient (SC06), as `label:password`. Give only `label` to be prompted.
        #[arg(long = "password", value_name = "LABEL[:PASSWORD]")]
        password: Option<String>,
        /// Pre-shared key recipient (SC05), as `label:base64,<key>`. Repeatable.
        #[arg(long = "secret", value_name = "LABEL:base64,KEY")]
        secrets: Vec<String>,
        /// Encrypt to a certificate whose validity window has passed, or not yet begun.
        ///
        /// Refused by default: an expired certificate usually means the card has been replaced,
        /// and the container would be one the recipient cannot open.
        #[arg(long = "allow-expired")]
        allow_expired: bool,
        /// Recipient X.509 certificate, PEM or DER (SC01 for EC keys, SC02 for RSA). Repeatable.
        #[arg(short = 'c', long = "cert", value_name = "FILE")]
        certs: Vec<PathBuf>,
        /// Recipient public key, PEM (SPKI), as `label:file`. Repeatable.
        #[arg(short = 'p', long = "pubkey", value_name = "[LABEL:]FILE")]
        pubkeys: Vec<String>,
        /// Recipient Estonian id code (isikukood). Looks the certificate up in the public eID
        /// directory, which reveals to its operator who you are encrypting for. Repeatable.
        #[cfg(feature = "ldap")]
        #[arg(short = 'r', long = "recipient", value_name = "ISIKUKOOD")]
        recipients: Vec<String>,
        /// Use the eID test directory instead of production.
        #[cfg(feature = "ldap")]
        #[arg(long = "ldap-test")]
        ldap_test: bool,
        /// Files to encrypt.
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    /// Decrypt a container.
    Decrypt {
        #[arg(short = 'f', long = "file")]
        file: PathBuf,
        #[arg(long = "password", value_name = "[LABEL:]PASSWORD")]
        password: Option<String>,
        #[arg(long = "secret", value_name = "[LABEL:]base64,KEY")]
        secret: Option<String>,
        /// Private key file, PEM (EC or RSA).
        #[arg(short = 'k', long = "key", value_name = "FILE")]
        key: Option<PathBuf>,
        /// PKCS#11 module to decrypt with a smart card or token, e.g.
        /// /Library/OpenSC/lib/opensc-pkcs11.so. The PIN is prompted for.
        #[cfg(feature = "pkcs11")]
        #[arg(long = "pkcs11", value_name = "MODULE")]
        pkcs11: Option<PathBuf>,
        /// Read the PKCS#11 PIN from a file rather than prompting.
        ///
        /// For environments with no terminal. Prefer the prompt where one exists, and delete
        /// the file afterwards.
        #[cfg(feature = "pkcs11")]
        #[arg(long = "pin-file", value_name = "FILE")]
        pin_file: Option<PathBuf>,
        #[command(flatten)]
        limits: LimitArgs,
        /// Output directory.
        #[arg(short = 'o', long = "output", default_value = ".")]
        output: PathBuf,
    },
    /// List the keys a token or key file offers.
    ///
    /// Reads certificates only, so it never asks for a PIN — useful for checking that a card is
    /// visible before attempting a decryption.
    Identities {
        /// PKCS#11 module to enumerate.
        #[cfg(feature = "pkcs11")]
        #[arg(long = "pkcs11", value_name = "MODULE")]
        pkcs11: Option<PathBuf>,
        /// Private key file, PEM.
        #[arg(short = 'k', long = "key", value_name = "FILE")]
        key: Option<PathBuf>,
    },
    /// Show who a container is addressed to.
    ///
    /// Recipient records are not encrypted, so this needs no key and no password.
    Recipients {
        #[arg(short = 'f', long = "file")]
        file: PathBuf,
    },
    /// List a container's contents without extracting.
    List {
        #[arg(short = 'f', long = "file")]
        file: PathBuf,
        #[arg(long = "password", value_name = "[LABEL:]PASSWORD")]
        password: Option<String>,
        #[arg(long = "secret", value_name = "[LABEL:]base64,KEY")]
        secret: Option<String>,
        #[arg(short = 'k', long = "key", value_name = "FILE")]
        key: Option<PathBuf>,
        #[cfg(feature = "pkcs11")]
        #[arg(long = "pkcs11", value_name = "MODULE")]
        pkcs11: Option<PathBuf>,
        #[cfg(feature = "pkcs11")]
        #[arg(long = "pin-file", value_name = "FILE")]
        pin_file: Option<PathBuf>,
        #[command(flatten)]
        limits: LimitArgs,
    },
}

/// Extraction limits, overridable per invocation.
///
/// The defaults are deliberately conservative. Raising one is a decision about a specific
/// container you trust, which is why it is an explicit flag rather than a config file.
#[derive(Args, Debug, Clone)]
struct LimitArgs {
    /// Maximum uncompressed/compressed ratio before a payload is treated as a zip bomb.
    #[arg(long, value_name = "N")]
    max_compression_ratio: Option<u64>,
    /// Maximum total uncompressed size, in bytes.
    #[arg(long, value_name = "BYTES")]
    max_uncompressed_bytes: Option<u64>,
    /// Maximum number of files in the container.
    #[arg(long, value_name = "N")]
    max_entries: Option<u64>,
}

impl LimitArgs {
    fn to_limits(&self) -> Limits {
        let mut limits = Limits::default();
        if let Some(ratio) = self.max_compression_ratio {
            limits = limits.with_max_compression_ratio(ratio);
        }
        if let Some(bytes) = self.max_uncompressed_bytes {
            limits = limits.with_max_uncompressed_bytes(bytes);
        }
        if let Some(entries) = self.max_entries {
            limits = limits.with_max_entries(entries);
        }
        limits
    }
}

/// Split a `label:value` argument. cdoc2-cli uses this shape, so umbrik accepts it too.
fn split_label(spec: &str) -> (Option<String>, String) {
    match spec.split_once(':') {
        Some((label, value)) if !label.is_empty() => (Some(label.to_string()), value.to_string()),
        _ => (None, spec.to_string()),
    }
}

/// Passwords to try when opening a container, most likely first.
///
/// `--password` is conventionally `label:password`, but a password may itself contain a colon,
/// in which case splitting on the first one silently truncates it. Rather than guess, try both
/// readings: the container's header MAC decides which is correct. The label is not needed for
/// decryption — recipient selection is by MAC, not by label — so it is only ever stripped.
fn password_candidates(spec: &str) -> Vec<String> {
    match spec.split_once(':') {
        Some((label, rest)) if !label.is_empty() && !rest.is_empty() => {
            vec![rest.to_string(), spec.to_string()]
        }
        _ => vec![spec.to_string()],
    }
}

/// Decode a `base64,<data>` secret value.
fn decode_secret(value: &str) -> Result<Vec<u8>> {
    let encoded = value
        .strip_prefix("base64,")
        .context("secret must be given as `base64,<key>`")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("secret is not valid base64")?;
    if bytes.len() < 32 {
        bail!(
            "pre-shared key must be at least 32 bytes ({} given)",
            bytes.len()
        );
    }
    Ok(bytes)
}

fn collect_files(inputs: &[PathBuf]) -> Result<Vec<PayloadFile>> {
    let mut files = Vec::with_capacity(inputs.len());
    for path in inputs {
        let name = path
            .file_name()
            .with_context(|| format!("{} has no file name", path.display()))?
            .to_string_lossy()
            .into_owned();
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        files.push(PayloadFile { name, data });
    }
    Ok(files)
}

/// Refuse a certificate outside its validity window unless the caller opted in.
///
/// This is a check umbrik can make cheaply and usefully. Chain and revocation checking are
/// deliberately absent — see the note in `umbrik_core::cert`.
fn check_validity(
    parsed: &cert::CertificateRecipient,
    describe: &str,
    allow_expired: bool,
) -> Result<()> {
    use umbrik_core::cert::Validity;

    let what = match parsed.validity_now() {
        Validity::Valid | Validity::Unknown => return Ok(()),
        Validity::Expired => "has expired",
        Validity::NotYetValid => "is not valid yet",
    };

    if allow_expired {
        eprintln!("  warning: the certificate for {describe} {what}");
        return Ok(());
    }
    bail!(
        "the certificate for {describe} {what}.\n\
         Encrypting to it would most likely produce a container the recipient cannot open, \
         because the card has been replaced. Pass --allow-expired to do it anyway."
    )
}

/// Parse a certificate from PEM or DER, deciding by content rather than extension.
fn load_certificate(path: &Path) -> Result<cert::CertificateRecipient> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let parsed = match std::str::from_utf8(&bytes) {
        Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => cert::from_pem(text),
        _ => cert::from_der(&bytes),
    };
    parsed.map_err(|e| anyhow::anyhow!("{e}").context(format!("parsing {}", path.display())))
}

/// A key source held for the lifetime of a command.
///
/// `DecryptionKey::Provider` borrows, so the concrete provider has to outlive the keys built
/// from it; this owns it.
enum LoadedProvider {
    Software(SoftwareKeyProvider),
    #[cfg(feature = "pkcs11")]
    Token(umbrik_pkcs11::Pkcs11KeyProvider),
}

impl LoadedProvider {
    fn as_key_provider(&self) -> &dyn KeyProvider {
        match self {
            LoadedProvider::Software(provider) => provider,
            #[cfg(feature = "pkcs11")]
            LoadedProvider::Token(provider) => provider,
        }
    }
}

/// Prompts for a PIN on the terminal.
///
/// Deliberately not cached: each private-key operation asks again, so a PIN is never held in
/// memory longer than one use.
#[cfg(feature = "pkcs11")]
struct PromptPin {
    /// Read the PIN from this file instead of prompting. For environments with no terminal.
    pin_file: Option<PathBuf>,
}

#[cfg(feature = "pkcs11")]
impl umbrik_pkcs11::PinSource for PromptPin {
    fn pin(&self, token_label: &str) -> umbrik_core::Result<zeroize::Zeroizing<String>> {
        let prompt = if token_label.is_empty() {
            "PIN: ".to_string()
        } else {
            format!("PIN for {token_label}: ")
        };

        // A PIN file wins outright: it is the only option that works with no terminal at all.
        if let Some(path) = &self.pin_file {
            let contents = std::fs::read_to_string(path)
                .map_err(|e| umbrik_core::Error::KeyProvider(format!("reading PIN file: {e}")))?;
            return finish(contents.trim_end_matches(['\r', '\n']).to_string());
        }

        // Try the controlling terminal first. `rpassword` opens /dev/tty directly, so it works
        // even when stdin is a pipe — which is why this must be attempted before any check on
        // stdin. Only if there is no terminal at all do we fall back to reading stdin.
        if let Ok(pin) = rpassword::prompt_password(&prompt) {
            return finish(pin);
        }

        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| umbrik_core::Error::KeyProvider(format!("reading PIN: {e}")))?;
        finish(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

/// Reject an empty PIN with advice rather than sending it to the card.
///
/// An empty PIN would still count against the card's retry limit, and Estonian cards block
/// PIN1 after three failures.
#[cfg(feature = "pkcs11")]
fn finish(pin: String) -> umbrik_core::Result<zeroize::Zeroizing<String>> {
    if pin.is_empty() {
        return Err(umbrik_core::Error::KeyProvider(
            "no PIN supplied. Run this in a terminal so the PIN can be prompted for, or pass \
             --pin-file with a file containing it (and delete the file afterwards)."
                .into(),
        ));
    }
    Ok(zeroize::Zeroizing::new(pin))
}

/// Load a private key file into a provider.
fn load_key(path: &Path) -> Result<SoftwareKeyProvider> {
    let pem =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut provider = SoftwareKeyProvider::new();
    provider
        .add_pem(&pem, path.to_string_lossy())
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("loading key from {}", path.display()))?;
    Ok(provider)
}

/// Run `op` against each candidate key, returning the first success.
///
/// Reports the first candidate's error on total failure: it corresponds to the conventional
/// `label:password` reading and so gives the most useful message.
fn try_keys<T>(
    keys: &[DecryptionKey<'_>],
    op: impl Fn(&DecryptionKey<'_>) -> umbrik_core::Result<T>,
) -> Result<T> {
    let mut first_error = None;
    for key in keys {
        match op(key) {
            Ok(value) => return Ok(value),
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }
    match first_error {
        Some(err) => Err(anyhow::anyhow!("{err}")),
        None => bail!("no key material supplied"),
    }
}

/// Build the key material to try, in order. The provider is borrowed, so it must outlive this.
fn decryption_keys<'a>(
    password: Option<&str>,
    secret: Option<&str>,
    provider: Option<&'a LoadedProvider>,
) -> Result<Vec<DecryptionKey<'a>>> {
    let mut keys: Vec<DecryptionKey<'a>> = Vec::new();

    if let Some(provider) = provider {
        keys.push(DecryptionKey::Provider(provider.as_key_provider()));
    }
    if let Some(spec) = secret {
        let (_, value) = split_label(spec);
        keys.push(DecryptionKey::Symmetric(decode_secret(&value)?.into()));
    }
    if let Some(spec) = password {
        keys.extend(
            password_candidates(spec)
                .into_iter()
                .map(|p| DecryptionKey::Password(p.into())),
        );
    }

    if keys.is_empty() {
        let entered = rpassword::prompt_password("Password: ").context("reading password")?;
        keys.push(DecryptionKey::Password(entered.into()));
    }
    Ok(keys)
}

/// Everything `encrypt` needs, grouped so the recipient sources can grow without the signature
/// growing with them.
struct EncryptRequest<'a> {
    file: &'a Path,
    password: Option<&'a str>,
    secrets: &'a [String],
    certs: &'a [PathBuf],
    allow_expired: bool,
    pubkeys: &'a [String],
    #[cfg(feature = "ldap")]
    id_codes: &'a [String],
    #[cfg(feature = "ldap")]
    ldap_test: bool,
    inputs: &'a [PathBuf],
    v: Verbosity,
}

fn run_encrypt(req: EncryptRequest<'_>) -> Result<()> {
    let EncryptRequest {
        file,
        password,
        secrets,
        certs,
        allow_expired,
        pubkeys,
        #[cfg(feature = "ldap")]
        id_codes,
        #[cfg(feature = "ldap")]
        ldap_test,
        inputs,
        v,
    } = req;
    #[cfg(feature = "ldap")]
    let directories = if ldap_test {
        umbrik_ldap::test_directories()
    } else {
        umbrik_ldap::default_directories()
    };

    let mut recipients: Vec<Recipient> = Vec::new();

    if let Some(spec) = password {
        // `label:password` sets both. A bare `label` prompts, so the password never has to
        // appear in shell history.
        let (label, value) = match spec.split_once(':') {
            Some((label, password)) if !label.is_empty() && !password.is_empty() => {
                (label.to_string(), password.to_string())
            }
            _ => {
                let label = spec.trim_end_matches(':').to_string();
                if label.is_empty() {
                    bail!("--password needs a label, as `label:password` or `label`");
                }
                let entered =
                    rpassword::prompt_password("Password: ").context("reading password")?;
                if entered.is_empty() {
                    bail!("password must not be empty");
                }
                (label, entered)
            }
        };
        recipients.push(Recipient::Password {
            label: keylabel::password(&label),
            password: value.into(),
        });
    }

    for spec in secrets {
        let (label, value) = split_label(spec);
        let label = label.context("--secret must be given as `label:base64,<key>`")?;
        recipients.push(Recipient::Symmetric {
            label: keylabel::secret(&label),
            secret: decode_secret(&value)?.into(),
        });
    }

    for spec in pubkeys {
        let (label, path) = split_label(spec);
        let pem = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
        let key = cert::public_key_from_pem(&pem)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("parsing {path}"))?;
        let file_name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        recipients.push(Recipient::PublicKey {
            label: match label {
                Some(label) => keylabel::certificate(Some(&label), None, file_name.as_deref()),
                None => keylabel::public_key(file_name.as_deref()),
            },
            key,
        });
    }

    #[cfg(feature = "ldap")]
    for id_code in id_codes {
        // Validate before announcing anything, so a rejected id code does not claim a lookup
        // that never happened.
        umbrik_ldap::validate_id_code(id_code)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("id code {id_code}"))?;

        // The lookup is a network query to public directories. Say so rather than doing it
        // silently: it discloses the intended recipient to whoever runs them.
        let urls: Vec<&str> = directories.iter().map(|d| d.url.as_str()).collect();
        eprintln!(
            "Looking up {id_code} in the eID directories ({})…",
            urls.join(", ")
        );

        let found = umbrik_ldap::lookup(&directories, id_code)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("looking up id code {id_code}"))?;
        // Everything considered and dropped, so "nothing usable" is diagnosable rather than
        // merely disappointing.
        if v.enabled() && !found.rejected.is_empty() {
            say!(v, "{} certificate(s) not usable:", found.rejected.len());
            for rejected in &found.rejected {
                let credential = rejected
                    .dn
                    .split(',')
                    .find(|part| part.trim_start().starts_with("o="))
                    .unwrap_or("?")
                    .trim();
                detail!(v, "{credential}: {}", rejected.reason.reason());
            }
        }

        if found.matches.is_empty() {
            let mut why = String::new();
            for reason in [
                umbrik_ldap::Rejection::MobileId,
                umbrik_ldap::Rejection::UnsupportedKey,
                umbrik_ldap::Rejection::NotAuthentication,
            ] {
                let n = found.rejected.iter().filter(|r| r.reason == reason).count();
                if n > 0 {
                    why.push_str(&format!("\n  {n} rejected: {}", reason.reason()));
                }
            }
            if why.is_empty() {
                why.push_str("\n  the directory returned nothing for this id code");
            }
            bail!(
                "no usable authentication certificate for id code {id_code}.{why}\n\
                 umbrik encrypts to elliptic-curve authentication keys on a physical card. \
                 Pre-2018 RSA cards (SC02) and Mobile-ID are out of scope. Run with -v to see \
                 every certificate considered."
            );
        }
        for found_match in found.matches {
            let parsed = found_match.recipient;
            check_validity(&parsed, id_code, allow_expired)?;
            let common_name = parsed
                .common_name
                .clone()
                .unwrap_or_else(|| id_code.clone());
            eprintln!("  found: {common_name} ({})", found_match.card_type);

            // libcdoc keeps the ETSI `PNOEE-` prefix on serial_number; the reference CLI
            // strips it. Directory-resolved recipients follow libcdoc so DigiDoc4 renders them.
            let serial_number = parsed
                .id_code
                .as_deref()
                .map(|code| format!("PNOEE-{code}"))
                .unwrap_or_else(|| format!("PNOEE-{id_code}"));

            recipients.push(Recipient::PublicKey {
                label: keylabel::eid_digidoc(
                    found_match.card_type,
                    &common_name,
                    Some(&serial_number),
                    parsed.not_after,
                ),
                key: parsed.key,
            });
        }
    }

    for path in certs {
        let parsed = load_certificate(path)?;
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned());

        // `TYPE=cert`, matching what the reference CLI writes for `-c` — including for eID
        // certificates. The `TYPE=ID-card` form is reserved for the directory lookup path,
        // where the card type is actually known from the directory entry rather than guessed
        // from the certificate contents.
        check_validity(&parsed, &path.display().to_string(), allow_expired)?;

        let label = keylabel::certificate(
            parsed.common_name.as_deref(),
            Some(&parsed.sha1),
            file_name.as_deref(),
        );
        eprintln!("  recipient: {}", keylabel::display(&label));

        recipients.push(Recipient::PublicKey {
            label,
            key: parsed.key,
        });
    }

    if recipients.is_empty() {
        bail!("at least one recipient is required (--password, --secret, --cert, --pubkey or -r)");
    }

    let files = collect_files(inputs)?;
    if v.enabled() {
        let total: usize = files.iter().map(|f| f.data.len()).sum();
        say!(
            v,
            "{} file(s), {total} bytes before compression",
            files.len()
        );
        for file in &files {
            detail!(v, "{:<32} {} bytes", file.name, file.data.len());
        }
        say!(v, "{} recipient(s):", recipients.len());
        for recipient in &recipients {
            // Recipient is non_exhaustive, so an unrecognised kind still gets a line.
            let described = match recipient {
                Recipient::Password { label, .. } => format!("SC06  {}", keylabel::display(label)),
                Recipient::Symmetric { label, .. } => format!("SC05  {}", keylabel::display(label)),
                Recipient::PublicKey { label, .. } => format!("SC01  {}", keylabel::display(label)),
                _ => "unknown recipient kind".to_string(),
            };
            detail!(v, "{described}");
        }
    }

    let mut out =
        std::fs::File::create(file).with_context(|| format!("creating {}", file.display()))?;
    let mut rng = rand::rng();

    umbrik_core::encrypt(&mut out, &mut rng, &files, &recipients)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("encrypting {}", file.display()))?;

    if v.enabled() {
        if let Ok(meta) = std::fs::metadata(file) {
            say!(v, "wrote {} bytes", meta.len());
        }
    }
    println!("{}", file.display());
    Ok(())
}

/// Build the key provider a command asked for, if any.
fn open_provider(
    key: Option<&Path>,
    #[cfg(feature = "pkcs11")] pkcs11: Option<&Path>,
    #[cfg(feature = "pkcs11")] pin_file: Option<&Path>,
) -> Result<Option<LoadedProvider>> {
    #[cfg(feature = "pkcs11")]
    if let Some(module) = pkcs11 {
        if key.is_some() {
            bail!("give either --key or --pkcs11, not both");
        }
        let pin_source = PromptPin {
            pin_file: pin_file.map(Path::to_path_buf),
        };
        let provider = umbrik_pkcs11::Pkcs11KeyProvider::open(module, Box::new(pin_source))
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("opening PKCS#11 module {}", module.display()))?;
        return Ok(Some(LoadedProvider::Token(provider)));
    }

    match key {
        Some(path) => Ok(Some(LoadedProvider::Software(load_key(path)?))),
        None => Ok(None),
    }
}

/// Describe a container's structure. Everything here is readable by anyone holding the file.
fn describe_container(container: &[u8], v: Verbosity) {
    if !v.enabled() {
        return;
    }
    let Ok(envelope) = umbrik_core::header::Envelope::parse(container) else {
        say!(v, "container does not parse");
        return;
    };
    detail!(
        v,
        "header {} bytes, payload {} bytes (12 nonce + ciphertext + 16 tag)",
        envelope.header_bytes().len(),
        envelope.payload().len()
    );
    let Ok(header) = envelope.decode_header() else {
        say!(v, "header does not decode");
        return;
    };
    say!(v, "{} recipient(s):", header.recipients.len());
    for (i, record) in header.recipients.iter().enumerate() {
        detail!(
            v,
            "#{i} {:<10} {}",
            record.capsule.scheme(),
            keylabel::display(&record.key_label)
        );
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let v = Verbosity(cli.verbose);
    match &cli.command {
        Command::Encrypt {
            file,
            password,
            secrets,
            certs,
            allow_expired,
            pubkeys,
            #[cfg(feature = "ldap")]
            recipients,
            #[cfg(feature = "ldap")]
            ldap_test,
            inputs,
        } => run_encrypt(EncryptRequest {
            file,
            password: password.as_deref(),
            secrets,
            certs,
            allow_expired: *allow_expired,
            pubkeys,
            #[cfg(feature = "ldap")]
            id_codes: recipients,
            #[cfg(feature = "ldap")]
            ldap_test: *ldap_test,
            inputs,
            v,
        }),

        Command::Decrypt {
            file,
            password,
            secret,
            key,
            #[cfg(feature = "pkcs11")]
            pkcs11,
            #[cfg(feature = "pkcs11")]
            pin_file,
            limits,
            output,
        } => {
            let provider = open_provider(
                key.as_deref(),
                #[cfg(feature = "pkcs11")]
                pkcs11.as_deref(),
                #[cfg(feature = "pkcs11")]
                pin_file.as_deref(),
            )?;
            let keys = decryption_keys(password.as_deref(), secret.as_deref(), provider.as_ref())?;
            let container =
                std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
            describe_container(&container, v);
            let limits = limits.to_limits();
            if v.enabled() {
                say!(v, "trying {} key candidate(s)", keys.len());
                detail!(
                    v,
                    "limits: ratio {}, entries {}, bytes {}",
                    limits.max_compression_ratio,
                    limits.max_entries,
                    limits.max_uncompressed_bytes
                );
            }

            let opened = try_keys(&keys, |key| {
                umbrik_core::decrypt_to_dir(&container, key, &limits, output)
            })
            .with_context(|| format!("decrypting {}", file.display()))?;

            say!(
                v,
                "opened by recipient #{} ({}) {}",
                opened.recipient.index,
                opened.recipient.scheme,
                keylabel::display(&opened.recipient.label)
            );
            for entry in &opened.entries {
                detail!(v, "{:<40} {} bytes", entry.name, entry.size);
                println!("{}", entry.name);
            }
            Ok(())
        }

        Command::Identities {
            #[cfg(feature = "pkcs11")]
            pkcs11,
            key,
        } => {
            let provider = open_provider(
                key.as_deref(),
                #[cfg(feature = "pkcs11")]
                pkcs11.as_deref(),
                #[cfg(feature = "pkcs11")]
                None,
            )?
            .context("give either --pkcs11 or --key")?;

            let identities = provider
                .as_key_provider()
                .identities()
                .map_err(|e| anyhow::anyhow!("{e}"))
                .context("listing identities")?;

            if identities.is_empty() {
                bail!("no usable keys found");
            }
            for identity in &identities {
                let kind = match &identity.key {
                    umbrik_core::provider::PublicKeyRef::Ec(key) => {
                        format!("EC {:?}", key.curve)
                    }
                    _ => "unknown".to_string(),
                };
                println!("{kind}\t{}", identity.label);
            }
            Ok(())
        }

        Command::Recipients { file } => {
            let container =
                std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
            let header = umbrik_core::header::Envelope::parse(&container)
                .and_then(|envelope| envelope.decode_header())
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("reading {}", file.display()))?;

            for recipient in &header.recipients {
                println!(
                    "{}\t{}",
                    recipient.capsule.scheme(),
                    keylabel::display(&recipient.key_label)
                );
            }
            Ok(())
        }

        Command::List {
            file,
            password,
            secret,
            key,
            #[cfg(feature = "pkcs11")]
            pkcs11,
            #[cfg(feature = "pkcs11")]
            pin_file,
            limits,
        } => {
            let provider = open_provider(
                key.as_deref(),
                #[cfg(feature = "pkcs11")]
                pkcs11.as_deref(),
                #[cfg(feature = "pkcs11")]
                pin_file.as_deref(),
            )?;
            let keys = decryption_keys(password.as_deref(), secret.as_deref(), provider.as_ref())?;
            let container =
                std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
            describe_container(&container, v);
            let entries = try_keys(&keys, |key| {
                umbrik_core::container::list(&container, key, &limits.to_limits())
            })
            .with_context(|| format!("reading {}", file.display()))?;
            for entry in &entries {
                println!("{}\t{}", entry.size, entry.name);
            }
            Ok(())
        }
    }
}

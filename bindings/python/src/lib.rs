//! Python bindings for umbrik.
//!
//! Built against PyO3's stable ABI (`abi3-py310`), so one wheel per platform serves every
//! supported CPython rather than needing a wheel per interpreter version.
//!
//! Errors map onto a small exception hierarchy rather than a single opaque type: whether a
//! container was addressed to somebody else, whether the password was wrong, and whether it
//! tripped a safety limit are different situations a caller will want to handle differently.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use umbrik_core::container::{self, DecryptionKey, Recipient};
use umbrik_core::error::ErrorCode;
use umbrik_core::payload::PayloadFile;
use umbrik_core::provider::software::SoftwareKeyProvider;
use umbrik_core::{cert, keylabel, Limits};

create_exception!(
    umbrik,
    UmbrikError,
    PyException,
    "Base class for umbrik errors."
);
create_exception!(
    umbrik,
    ContainerError,
    UmbrikError,
    "The container is malformed, truncated, or not a CDOC2 file."
);
create_exception!(
    umbrik,
    WrongKeyError,
    UmbrikError,
    "The key or password did not open the container."
);
create_exception!(
    umbrik,
    NoMatchingRecipientError,
    UmbrikError,
    "The container is not addressed to the supplied key."
);
create_exception!(
    umbrik,
    AuthenticationError,
    UmbrikError,
    "The container's contents failed authentication; it has been tampered with."
);
create_exception!(
    umbrik,
    LimitExceededError,
    UmbrikError,
    "A safety limit was exceeded, such as the compression ratio or entry count."
);
create_exception!(
    umbrik,
    UnsafeArchiveError,
    UmbrikError,
    "An entry tried to escape the output directory, or was a symlink."
);
create_exception!(
    umbrik,
    UnsupportedSchemeError,
    UmbrikError,
    "The container uses an encryption scheme umbrik does not implement."
);

/// Map a core error onto the closest Python exception.
///
/// The distinctions are the ones a caller can act on. A wrong password and a container meant for
/// someone else are deliberately kept apart from a malformed file, but *not* from each other
/// where the format cannot tell them apart either.
fn to_py_err(err: umbrik_core::Error) -> PyErr {
    let message = err.to_string();
    match err.code() {
        ErrorCode::BadPrelude
        | ErrorCode::UnsupportedVersion
        | ErrorCode::HeaderLengthOutOfRange
        | ErrorCode::Truncated
        | ErrorCode::MalformedHeader => ContainerError::new_err(message),
        ErrorCode::HeaderHmacMismatch => WrongKeyError::new_err(message),
        ErrorCode::NoMatchingRecipient => NoMatchingRecipientError::new_err(message),
        ErrorCode::PayloadAuthenticationFailed => AuthenticationError::new_err(message),
        ErrorCode::LimitExceeded => LimitExceededError::new_err(message),
        ErrorCode::UnsafeArchiveEntry => UnsafeArchiveError::new_err(message),
        ErrorCode::UnsupportedCapsule
        | ErrorCode::UnsupportedFmkEncryptionMethod
        | ErrorCode::UnsupportedPayloadEncryptionMethod => UnsupportedSchemeError::new_err(message),
        _ => UmbrikError::new_err(message),
    }
}

/// Safety limits applied while unpacking.
#[pyclass(name = "Limits", module = "umbrik", from_py_object)]
#[derive(Clone)]
struct PyLimits {
    #[pyo3(get, set)]
    max_compression_ratio: u64,
    #[pyo3(get, set)]
    max_entries: u64,
    #[pyo3(get, set)]
    max_uncompressed_bytes: u64,
    #[pyo3(get, set)]
    max_recipients: u64,
    #[pyo3(get, set)]
    max_total_kdf_iterations: u64,
}

#[pymethods]
impl PyLimits {
    #[new]
    #[pyo3(signature = (
        max_compression_ratio = None,
        max_entries = None,
        max_uncompressed_bytes = None,
        max_recipients = None,
        max_total_kdf_iterations = None,
    ))]
    fn new(
        max_compression_ratio: Option<u64>,
        max_entries: Option<u64>,
        max_uncompressed_bytes: Option<u64>,
        max_recipients: Option<u64>,
        max_total_kdf_iterations: Option<u64>,
    ) -> Self {
        let d = Limits::default();
        PyLimits {
            max_compression_ratio: max_compression_ratio.unwrap_or(d.max_compression_ratio),
            max_entries: max_entries.unwrap_or(d.max_entries),
            max_uncompressed_bytes: max_uncompressed_bytes.unwrap_or(d.max_uncompressed_bytes),
            max_recipients: max_recipients.unwrap_or(d.max_recipients),
            max_total_kdf_iterations: max_total_kdf_iterations
                .unwrap_or(d.max_total_kdf_iterations),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Limits(max_compression_ratio={}, max_entries={}, max_uncompressed_bytes={}, \
             max_recipients={}, max_total_kdf_iterations={})",
            self.max_compression_ratio,
            self.max_entries,
            self.max_uncompressed_bytes,
            self.max_recipients,
            self.max_total_kdf_iterations
        )
    }
}

impl PyLimits {
    fn to_core(&self) -> Limits {
        Limits::default()
            .with_max_compression_ratio(self.max_compression_ratio)
            .with_max_entries(self.max_entries)
            .with_max_uncompressed_bytes(self.max_uncompressed_bytes)
            .with_max_recipients(self.max_recipients)
            .with_max_total_kdf_iterations(self.max_total_kdf_iterations)
    }
}

/// A recipient a container is addressed to.
#[pyclass(name = "Recipient", module = "umbrik", frozen)]
struct PyRecipient {
    /// The encryption scheme, e.g. "SC01" or "SC06".
    #[pyo3(get)]
    scheme: String,
    /// The label as stored, which may be a machine-readable `data:` string.
    #[pyo3(get)]
    label: String,
    /// The label rendered for a human, e.g. "TESTIJA,MARI,00000000000 (ID-card)".
    #[pyo3(get)]
    display: String,
}

#[pymethods]
impl PyRecipient {
    fn __repr__(&self) -> String {
        format!(
            "Recipient(scheme={:?}, display={:?})",
            self.scheme, self.display
        )
    }
}

fn build_files(files: &Bound<'_, PyDict>) -> PyResult<Vec<PayloadFile>> {
    let mut out = Vec::with_capacity(files.len());
    for (name, data) in files.iter() {
        out.push(PayloadFile {
            name: name.extract::<String>()?,
            data: data.extract::<Vec<u8>>()?,
        });
    }
    if out.is_empty() {
        return Err(UmbrikError::new_err("no files to encrypt"));
    }
    Ok(out)
}

/// Encrypt files into a CDOC2 container.
///
/// `files` maps entry name to contents. At least one recipient is required; several may be
/// given, and any one of them can open the result.
#[pyfunction]
#[pyo3(signature = (files, *, password = None, secret = None, certificate = None))]
fn encrypt<'py>(
    py: Python<'py>,
    files: &Bound<'py, PyDict>,
    password: Option<(String, String)>,
    secret: Option<(String, Vec<u8>)>,
    certificate: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let payload = build_files(files)?;
    let mut recipients: Vec<Recipient> = Vec::new();

    if let Some((label, value)) = password {
        recipients.push(Recipient::Password {
            label: keylabel::password(&label),
            password: value.into(),
        });
    }
    if let Some((label, key)) = secret {
        recipients.push(Recipient::Symmetric {
            label: keylabel::secret(&label),
            secret: key.into(),
        });
    }
    if let Some(bytes) = certificate {
        // Accept PEM or DER, deciding by content rather than making the caller say which.
        let parsed = match std::str::from_utf8(&bytes) {
            Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => cert::from_pem(text),
            _ => cert::from_der(&bytes),
        }
        .map_err(to_py_err)?;

        recipients.push(Recipient::PublicKey {
            label: keylabel::certificate(parsed.common_name.as_deref(), Some(&parsed.sha1), None),
            key: parsed.key,
        });
    }

    if recipients.is_empty() {
        return Err(UmbrikError::new_err(
            "at least one of password, secret or certificate is required",
        ));
    }

    let mut out = Vec::new();
    // Releasing the GIL matters here: SC06 runs 600 000 PBKDF2 iterations and would otherwise
    // block every other thread in the interpreter.
    py.detach(|| {
        let mut rng = rand::rngs::OsRng;
        container::encrypt(&mut out, &mut rng, &payload, &recipients)
    })
    .map_err(to_py_err)?;

    Ok(PyBytes::new(py, &out))
}

/// Decrypt a container, returning a mapping of entry name to contents.
#[pyfunction]
#[pyo3(signature = (container_bytes, *, password = None, secret = None, key = None, limits = None))]
fn decrypt<'py>(
    py: Python<'py>,
    container_bytes: Vec<u8>,
    password: Option<String>,
    secret: Option<Vec<u8>>,
    key: Option<String>,
    limits: Option<PyLimits>,
) -> PyResult<Bound<'py, PyDict>> {
    let limits = limits.map(|l| l.to_core()).unwrap_or_default();

    // A PEM private key needs a provider that outlives the borrow below.
    let provider = match &key {
        Some(pem) => {
            let mut provider = SoftwareKeyProvider::new();
            provider.add_pem(pem, "python").map_err(to_py_err)?;
            Some(provider)
        }
        None => None,
    };

    // The GIL is released only for the password and secret paths. Those run PBKDF2 — 600 000
    // iterations for SC06 — and would otherwise block every other thread in the interpreter.
    // The key path cannot release it, because `KeyProvider` is not `Sync`; it also does not
    // need to, since an ECDH or RSA operation takes milliseconds rather than a third of a
    // second. Requiring `Sync` of every provider to shave that would be the wrong trade: a
    // PKCS#11 token is inherently single-threaded.
    let files = if let Some(provider) = provider.as_ref() {
        container::decrypt_to_memory(
            &container_bytes,
            &DecryptionKey::Provider(provider),
            &limits,
        )
    } else if let Some(password) = password {
        // Built inside the closure: `DecryptionKey` is not `Sync` as a whole because of its
        // provider variant, even though this one holds only a String.
        py.detach(|| {
            let key = DecryptionKey::Password(password.into());
            container::decrypt_to_memory(&container_bytes, &key, &limits)
        })
    } else if let Some(secret) = secret {
        py.detach(|| {
            let key = DecryptionKey::Symmetric(secret.into());
            container::decrypt_to_memory(&container_bytes, &key, &limits)
        })
    } else {
        return Err(UmbrikError::new_err(
            "one of password, secret or key is required",
        ));
    }
    .map_err(to_py_err)?;

    let out = PyDict::new(py);
    for file in files {
        out.set_item(file.name, PyBytes::new(py, &file.data))?;
    }
    Ok(out)
}

/// List who a container is addressed to.
///
/// Recipient records are not encrypted, so this needs no key.
#[pyfunction]
fn recipients(container_bytes: Vec<u8>) -> PyResult<Vec<PyRecipient>> {
    let header = umbrik_core::header::Envelope::parse(&container_bytes)
        .and_then(|envelope| envelope.decode_header())
        .map_err(to_py_err)?;

    Ok(header
        .recipients
        .iter()
        .map(|record| PyRecipient {
            scheme: record.capsule.scheme().to_string(),
            label: record.key_label.clone(),
            display: keylabel::display(&record.key_label),
        })
        .collect())
}

#[pymodule]
fn umbrik(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(recipients, m)?)?;
    m.add_class::<PyLimits>()?;
    m.add_class::<PyRecipient>()?;

    m.add("UmbrikError", m.py().get_type::<UmbrikError>())?;
    m.add("ContainerError", m.py().get_type::<ContainerError>())?;
    m.add("WrongKeyError", m.py().get_type::<WrongKeyError>())?;
    m.add(
        "NoMatchingRecipientError",
        m.py().get_type::<NoMatchingRecipientError>(),
    )?;
    m.add(
        "AuthenticationError",
        m.py().get_type::<AuthenticationError>(),
    )?;
    m.add(
        "LimitExceededError",
        m.py().get_type::<LimitExceededError>(),
    )?;
    m.add(
        "UnsafeArchiveError",
        m.py().get_type::<UnsafeArchiveError>(),
    )?;
    m.add(
        "UnsupportedSchemeError",
        m.py().get_type::<UnsupportedSchemeError>(),
    )?;
    Ok(())
}

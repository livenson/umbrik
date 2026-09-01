//! umbrik-core — CDOC2 container format.
//!
//! An independent implementation of the published CDOC2 specification (v1.7). Not affiliated
//! with or endorsed by RIA or Cybernetica. Unaudited.
//!
//! Layering:
//! - **L0 [`header`]** — framing and FlatBuffers codec. Pure, no I/O, no traits.
//! - **L1 `schemes`** — one KEK function per encryption scheme. Pure, vector-testable. (M2+)
//! - **L2 `Reader`/`Writer`** — orchestration; the only place traits are injected. (M2+)
//!
//! Every cryptographic constant is sourced in `docs/CRYPTO-CONSTANTS.md`.

#![deny(unsafe_code)]
#![deny(clippy::indexing_slicing)]

pub mod cert;
pub mod container;
pub mod error;
pub mod header;
pub mod keylabel;
pub mod keys;
pub mod limits;
pub mod payload;
pub mod provider;
pub mod schemes;

pub use container::{decrypt_to_dir, decrypt_to_memory, encrypt, DecryptionKey, Recipient};
pub use error::{Error, ErrorCode, Result};
pub use limits::Limits;
pub use payload::{ArchiveEntry, PayloadFile};

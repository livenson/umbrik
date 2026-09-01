#![no_main]
//! Container framing must never panic, and must reject before allocating.
//!
//! The prelude, version byte, and header-length field are outside both the header MAC and the
//! payload AAD, so nothing authenticates them. The bounds checks in `Envelope::parse` are the
//! only defence against a hostile length field.

use libfuzzer_sys::fuzz_target;
use umbrik_core::header::Envelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = Envelope::parse(data) {
        // Parsing succeeded, so decoding the header must also be panic-free.
        let _ = envelope.decode_header();
    }
});

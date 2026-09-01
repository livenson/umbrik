#![no_main]
//! The FlatBuffers header decoder must never panic on malformed input.
//!
//! Header bytes are fully attacker controlled and are parsed *before* anything is
//! authenticated — the header MAC cannot be checked until the FMK has been unwrapped, which
//! needs the header first. This decoder is therefore the most exposed code in umbrik.

use libfuzzer_sys::fuzz_target;
use umbrik_core::header::Header;

fuzz_target!(|data: &[u8]| {
    // Any Result is fine. A panic, an out-of-bounds read, or an unbounded allocation is not.
    let _ = Header::decode(data);
});

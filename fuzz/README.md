# Fuzzing

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run header
cargo +nightly fuzz run envelope
```

Two targets, both on the pre-authentication attack surface:

- `header` — the FlatBuffers decoder, reached with fully attacker-controlled bytes.
- `envelope` — container framing, including the unauthenticated header-length field.

Neither may panic, read out of bounds, or allocate unboundedly on any input. `Envelope::parse`
is written without indexing or slicing for exactly this reason; `Header::decode` goes through
the FlatBuffers verifier rather than the `_unchecked` accessors.

Add any crashing input to `tests/vectors/` as a regression case.

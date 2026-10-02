# cnvl — Envelope

## Scope

### Purpose

Seals and opens the private profile with established authenticated encryption bound to its context.

### Owns

A one-use key per envelope, a fresh nonce, a bounded wire format, and authenticated context covering format, suite, community, owner, profile and schema revision, and key generation. An opening-only read key may be wrapped for storage or delivered over an already authorized encrypted peer channel.

### Never

Decides who receives keys; sends keys through `cfrm`; accepts ciphertext bound to another community, profile, or revision; returns an unchecked profile as admitted; compresses or pads data; implements a cryptographic primitive.

### States

Empty becomes Sealed for a given revision and key generation; opening yields authenticated bytes or a refusal. The ports are `seal`, `open`, `from_bytes`, and read-key `wrap`, `unwrap`, and `deliver`.

### Test obligations

Native and browser builds share identical test vectors with full line and branch coverage. Tests prove fresh keys and nonces, reject modified context, tags, or ciphertext, preserve exact signed bytes, prevent old ciphertext from being swapped under a newer publication, and keep private values and keys out of server fixtures and error output.

## Implementation

Keys supplies the CSPRNG and vault wrapping capability. `SealKey` is an opaque,
one-use per-envelope key; `ReadKey` can only open, wrap or deliver through an
authorized transport. RustCrypto XChaCha20-Poly1305 performs VLD0-compatible AEAD.
See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Independent acceptance review remains required.

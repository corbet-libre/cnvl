# cnvl — Envelope

## Scope

**Purpose and home.** Seal and open exact signed private-profile bytes with
established authenticated encryption, under `cmsg → cbrd → cnvl`.

**Owns.** A one-use key per envelope, fresh nonce, bounded wire format and context
binding for format, suite, community, owner, profile revision, schema revision and
key generation. An opening-only read key may be wrapped for storage or delivered
through an already authorized encrypted peer channel.

**Never.** Decides key recipients; sends keys through the forum; accepts ciphertext
for another community, profile or revision; admits an unchecked profile; compresses
or pads; implements a cryptographic primitive.

**States and ports.** Empty → Sealed(revision, key generation); opening yields
AuthenticatedBytes or Refused. Ports are `seal`, `open`, `from_bytes`, and read-key
`wrap`, `unwrap`, `deliver`. Access decisions belong to Exchange. Profile supplies
already compressed and padded bytes.

**Invariants and tests.** Private values and keys never enter forum traffic.
Native and actual browser vectors preserve exact signed bytes, prevent key/nonce
reuse and refuse changed context, tag or ciphertext and old-publication splicing.
Reachable source lines and branches require full coverage.

## Implementation

Keys supplies the CSPRNG and vault wrapping capability. `SealKey` is an opaque,
one-use per-envelope key; `ReadKey` can only open, wrap or deliver through an
authorized transport. RustCrypto XChaCha20-Poly1305 performs VLD0-compatible AEAD.
See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Independent acceptance review remains required.

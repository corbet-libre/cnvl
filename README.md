# cnvl — Envelope

## Scope

**Purpose and home.** Seal and open exact signed private-profile bytes with
established authenticated encryption, under `cmsg → cbrd → cnvl`.

**Owns.** A one-use key per envelope, fresh nonce, bounded wire format and context
binding for format, suite, community, owner, profile revision, schema revision and
key generation. An opening-only read key is bound to immutable borrowed custody. Maintained authenticated HPKE seals it directly to an original Guard-verified recipient.

**Never.** Decides key recipients; sends keys through the forum; accepts ciphertext
for another community, profile or revision; admits an unchecked profile; compresses
or pads; implements a cryptographic primitive.

**States and ports.** Empty → Sealed(revision, key generation); opening yields
AuthenticatedBytes or Refused. Ports are `Custodian::seal/restore/receive`, `open`, bounded byte codecs, and read-key `wrap/release`. Access decisions belong to Exchange. Profile supplies
already compressed and padded bytes.

**Invariants and tests.** Private values and keys never enter forum traffic.
Native and actual browser vectors preserve exact signed bytes, prevent key/nonce
reuse and refuse changed context, tag or ciphertext and old-publication splicing.
Reachable source lines and branches require full coverage.

## Implementation

Keys lends immutable HPKE and separate common-root wrapping custody. Envelope generates fresh per-publication keys/nonces internally. ReadKey cannot escape that lifetime or accept a replacement wrapping key. Legacy raw receive/generic delivery callbacks are removed. Maintained hpke performs RFC9180 Auth mode; RustCrypto XChaCha20-Poly1305 preserves the original content wire.
See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Independent acceptance review remains required.

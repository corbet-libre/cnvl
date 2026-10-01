# Envelope contract

Input is exact signed full-profile bytes after the caller's compression and Padmé
padding. Envelope neither decompresses nor changes signed bytes. The caller checks
both public and full cgrd projections against current credentials/schema; the peer
opens, performs bounded expansion and invokes the same guard. Opening alone never
admits a member or establishes device authority.

`SealKey::generate` gives trusted custody one opaque random per-envelope key.
`seal` consumes it, binds format/suite/community/owner/profile revision/schema
revision/key generation as AAD, and draws a fresh 192-bit nonce. There is no public
caller-selected nonce, clone/serialization of a sealing key, or conversion from an
opening key back to a sealing key. CSPRNG correctness is a trusted port obligation.
XChaCha20-Poly1305 comes directly from RustCrypto, matching VLD0's AEAD primitive.
The versioned profile envelope is application framing, not a DHT record encoding.

Only an opening `ReadKey` survives sealing. It is pinned to its exact context and
can be wrapped by Keys' opaque StoreCipher for storage. `unwrap` preserves that
opening-only capability. `deliver` hands only that narrow profile key to an injected
encrypted peer transport after Exchange's real rule/identity check. That trusted
adapter must not expose plaintext keys through a server or public door. There is
no root/device/PRF key getter and no access-policy decision in this library.

`Envelope::from_bytes` bounds encoded bytes before serde, rejects unknown/duplicate
fields, requires version 1, positive revisions and bounded identifiers/ciphertext.
Plaintext is at most 1 MiB. AEAD verifies before any plaintext is returned; errors
and Debug omit contents and identities. Plaintext and owned key buffers zeroize on
drop; custody/transport callers must wipe their own copies.

Outer Profile signatures bind the exact serialized Envelope bytes; on decrypt the
expected publication context comes from separately verified current authority.
Ciphertext cannot be relabelled under a new profile, schema or generation.

Tests execute identical real crypto vectors natively and in Chrome Wasm. Independent
security review and production custody/G3/Exchange integration remain acceptance
gates. Compression/padding are the existing cprz owner's responsibility; no codec
or substitute policy implementation is supplied here.

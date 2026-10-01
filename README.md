# cnvl

## Scope

Authenticated encryption of exact signed private profile bytes; context and nonce binding. Compression and padding belong to cprz; access rules belong to Exchange.

Implementation in progress; no completed acceptance claim.

Keys supplies the CSPRNG and vault wrapping capability. `SealKey` is an opaque,
one-use per-envelope key; `ReadKey` can only open, wrap for storage or deliver through
an already-authorized encrypted transport. RustCrypto XChaCha20-Poly1305 performs
VLD0-compatible AEAD. Envelope implements no primitive or access-policy evaluator.

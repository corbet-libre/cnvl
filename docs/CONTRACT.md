# Envelope custody contract

Envelope is a pure lower leaf, below Keys. It depends on maintained hpke/RustCrypto,
getrandom and original Guard recipient types, never Keys, Store, Profile or Wallet.
Keys derives and lends immutable device HPKE + separate common-root wrapping
material through Custodian's borrowed lifetime. No private key or HPKE receiver
context getter exists. Profile/Exchange decide authority and persistence.

Custodian::seal generates the per-publication key internally and preserves the
original v1 XChaCha profile-content format. ReadKey borrows its creating custody,
has no raw receive/deliver/serializer, and wrap() accepts NO caller cipher/key.
WrappedReadKey is encrypted v2 local persistence, bounded to73bytes; restoring
under another purpose/member/community or changed context refuses. Paired
credentials derive the same common-root wrapping purpose. Keys callback lifetimes
prevent retaining decrypted ReadKey beyond fresh custody. Profile can retain only
wrapped bytes in its actual original compound Store commit.

ReadKey::release requires original sender/recipient Guard VerifiedRecipient values
and uses maintained RFC9180 Auth mode, X25519/HKDF-SHA256/ChaCha20-Poly1305, matching
Keys' existing suite. Only the original profile owner may release. Recipient
Custodian::receive authenticates the original sender and opens into its own bound
ReadKey. Neither method exposes raw32 or accepts a generic decrypt/key callback.

TransferContext binds community/peers, exact two signed publications/revisions,
original signed Guard bundles and the existing offer nonce. It is framing, not
consent/currentness. Exchange must validate outer Profile signatures, actual current
Guard/Contacts/G3 before/after awaits and adopt nonce/key/outbox in the SAME Store
CAS with original receipt. Crypto alone is stateless and does not reject replay.
The source tests explicitly demonstrate that distinction; no process-only replay
flag or accepting callback substitutes for the original Exchange transaction.

Migration: original v1 content ciphertext is unchanged. Keys privately supplies
its former StoreCipher wrapping key to Custodian::restore_legacy_store; only the
exact72byte prior nonce/ciphertext with original AAD can open. The result is bound
to new custody and exposes only wrap() for v2 storage. Keys::migrate_profile_key
returns only that encrypted result; Profile must persist it atomically. No public
raw profile-key import/export is needed, and old records are not silently dropped.

All production input bounds, context/version checks, fresh independent CSPRNG
nonces and original signature verification remain. New native/browser vectors
are source-only until actual allocated CI executes them. No full acceptance claim.

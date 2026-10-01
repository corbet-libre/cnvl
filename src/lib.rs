//! Bounded VLD0 private-profile envelopes. Compression and padding precede sealing;
//! signature/guard validation follows opening. Neither operation grants admission.
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ckmg::{Entropy, passkey::StoreCipher};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Maximum packed/padded profile bytes before AEAD.
pub const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
/// Maximum encoded envelope, checked before parsing.
pub const MAX_ENVELOPE_BYTES: usize = MAX_PLAINTEXT_BYTES * 4 + 4096;
const DOMAIN: &str = "cnvl.profile.v1";

/// Coarse refusal; no private values, keys or identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid or mismatched context/format.
    Context,
    /// Input exceeds a bound.
    Limit,
    /// Entropy unavailable.
    Randomness,
    /// Authentication or wrapping failed.
    Authentication,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "envelope: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Exact publication context authenticated by AEAD. Identity is a pseudonym,
/// supplied by the owner; this data alone is not device or member authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    /// Community scope.
    pub community: String,
    /// Community member pseudonym.
    pub owner: String,
    /// Positive profile publication revision.
    pub profile_revision: u64,
    /// Positive current profile schema revision.
    pub schema_revision: u64,
    /// Positive owner-selected profile key generation.
    pub key_generation: u64,
}
impl Context {
    fn aad(&self) -> Result<Vec<u8>, Error> {
        if self.community.is_empty()
            || self.owner.is_empty()
            || self.community.len() > 256
            || self.owner.len() > 256
            || self.profile_revision == 0
            || self.schema_revision == 0
            || self.key_generation == 0
        {
            return Err(Error::Context);
        }
        serde_json::to_vec(&(DOMAIN, "VLD0", self)).map_err(|_| Error::Context)
    }
}
impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Context([redacted])")
    }
}

/// One-use profile sealing capability. Custody creates it, Envelope consumes it.
/// It cannot be cloned, serialized or reused for a second encryption.
/// ```compile_fail
/// fn reuse(key: cnvl::SealKey) { let _first = key; let _second = key; }
/// ```
pub struct SealKey(Zeroizing<[u8; 32]>);
impl SealKey {
    /// Generate an independent per-envelope purpose key inside trusted custody.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut secret = Zeroizing::new([0; 32]);
        entropy
            .fill(secret.as_mut())
            .map_err(|_| Error::Randomness)?;
        Ok(Self(secret))
    }
}

/// An opening-only capability pinned to exactly one publication context.
/// Its bytes are available only to an injected encrypted peer-key transport.
pub struct ReadKey {
    secret: Zeroizing<[u8; 32]>,
    context: Context,
}
impl ReadKey {
    /// Accept one key already decrypted by the peer-key transport. This performs no
    /// access-rule evaluation; Exchange must authenticate and authorize that transport.
    pub fn receive(secret: Zeroizing<[u8; 32]>, context: Context) -> Result<Self, Error> {
        context.aad()?;
        Ok(Self { secret, context })
    }
    /// Wrap for vault persistence using Keys' opaque capability.
    pub fn wrap(&self, cipher: &StoreCipher, entropy: &mut impl Entropy) -> Result<Vec<u8>, Error> {
        cipher
            .seal(entropy, &self.context.aad()?, self.secret.as_slice())
            .map_err(|_| Error::Authentication)
    }
    /// Restore an opening capability for an exact context. It cannot seal new content.
    pub fn unwrap(cipher: &StoreCipher, context: Context, wrapped: &[u8]) -> Result<Self, Error> {
        if wrapped.len() != 72 {
            return Err(Error::Limit);
        }
        let bytes = cipher
            .open(&context.aad()?, wrapped)
            .map_err(|_| Error::Authentication)?;
        let secret = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Authentication)?,
        );
        Ok(Self { secret, context })
    }
    /// Hand this narrowly scoped key to an authorized encrypted peer transport.
    /// No root, PRF or general-purpose storage secret is available to this port.
    pub fn deliver<T: KeyRecipient>(&self, recipient: &mut T) -> Result<T::Output, Error> {
        recipient.seal_key(&self.context, &self.secret)
    }
}
impl std::fmt::Debug for ReadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadKey([redacted])")
    }
}
/// Trusted peer transport capability. The implementation must encrypt to the
/// already-authorized requester; Envelope neither grants nor checks access rules.
pub trait KeyRecipient {
    /// Encrypted transport result, never a plaintext key in a public door response.
    type Output;
    /// Seal this one profile key, bound to its complete publication context.
    fn seal_key(&mut self, context: &Context, key: &[u8; 32]) -> Result<Self::Output, Error>;
}

/// An authenticated envelope after `open`, or untrusted ciphertext before it.
/// Decoding is possible only through the bounded constructor.
/// ```compile_fail
/// let _: cnvl::Envelope = serde_json::from_slice(b"{}").unwrap();
/// ```
pub struct Envelope(Wire);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u8,
    context: Context,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Envelope([redacted])")
    }
}
impl Envelope {
    /// Check the complete authenticated-header context before retaining a publication.
    /// This does not authenticate ciphertext or grant permission to open it.
    pub fn matches_context(&self, expected: &Context) -> bool {
        &self.0.context == expected
    }
    /// Serialize for publication. The outer profile signature binds these exact bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.0).map_err(|_| Error::Context)
    }
    /// Bound before deserialization; unknown or duplicate fields fail closed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Limit);
        }
        let envelope: Wire = serde_json::from_slice(bytes).map_err(|_| Error::Context)?;
        envelope.validate()?;
        Ok(Self(envelope))
    }
}
impl Wire {
    fn validate(&self) -> Result<(), Error> {
        if self.version != 1 {
            return Err(Error::Context);
        }
        self.context.aad()?;
        if self.ciphertext.len() < 16 || self.ciphertext.len() > MAX_PLAINTEXT_BYTES + 16 {
            return Err(Error::Limit);
        }
        Ok(())
    }
}
/// Consume a one-use key and authenticate exact packed/padded signed bytes. A fresh
/// 192-bit nonce comes from trusted CSPRNG entropy; no caller-selected nonce exists.
pub fn seal(
    key: SealKey,
    context: Context,
    bytes: &[u8],
    entropy: &mut impl Entropy,
) -> Result<(Envelope, ReadKey), Error> {
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::Limit);
    }
    let aad = context.aad()?;
    let mut nonce = [0; 24];
    entropy.fill(&mut nonce).map_err(|_| Error::Randomness)?;
    let cipher = XChaCha20Poly1305::new(&(*key.0).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: bytes,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    let reader = ReadKey {
        secret: key.0,
        context: context.clone(),
    };
    Ok((
        Envelope(Wire {
            version: 1,
            context,
            nonce,
            ciphertext,
        }),
        reader,
    ))
}
/// Authenticate before returning any bytes. The caller then performs bounded
/// expansion and verifies the exact full cgrd bundle; this is never an admission.
pub fn open(
    envelope: &Envelope,
    key: &ReadKey,
    expected: &Context,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    envelope.0.validate()?;
    if &envelope.0.context != expected || &key.context != expected {
        return Err(Error::Context);
    }
    let aad = expected.aad()?;
    let cipher = XChaCha20Poly1305::new(&(*key.secret).into());
    cipher
        .decrypt(
            &XNonce::from(envelope.0.nonce),
            Payload {
                msg: &envelope.0.ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

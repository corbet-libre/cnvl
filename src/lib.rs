//! Bounded VLD0 private-profile envelopes. Compression and padding precede sealing;
//! signature/guard validation follows opening. Neither operation grants admission.
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
mod custody;
pub use custody::{Custodian, KeyTransfer, RoomHandover, TransferContext, WrappedReadKey};
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

/// A private opening capability bound to the Keys-lent custody that created or
/// restored it. Neither raw import/export nor caller-selected wrapping is exposed.
///
/// ```compile_fail
/// fn extract(key: &cnvl::ReadKey<'_>) { let _ = &key.secret; }
/// ```
/// ```compile_fail
/// fn rekey(key: &cnvl::ReadKey<'_>, chosen: &[u8; 32]) { key.wrap(chosen); }
/// ```
/// ```compile_fail
/// let _ = cnvl::ReadKey::receive(zeroize::Zeroizing::new([7; 32]));
/// ```
pub struct ReadKey<'key> {
    secret: Zeroizing<[u8; 32]>,
    context: Context,
    custody: custody::Binding<'key>,
}
impl std::fmt::Debug for ReadKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadKey([redacted])")
    }
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
fn seal_bound<'key>(
    custody: custody::Binding<'key>,
    context: Context,
    bytes: &[u8],
) -> Result<(Envelope, ReadKey<'key>), Error> {
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::Limit);
    }
    let aad = context.aad()?;
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(secret.as_mut()).map_err(|_| Error::Randomness)?;
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    let ciphertext = XChaCha20Poly1305::new(&(*secret).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: bytes,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    let reader = ReadKey {
        secret,
        context: context.clone(),
        custody,
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
    key: &ReadKey<'_>,
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

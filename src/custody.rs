//! Immutable key custody and maintained RFC9180 authenticated profile-key transfer.
use crate::{Context, Envelope, Error, ReadKey};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type AeadSuite = hpke::aead::ChaCha20Poly1305;
const INFO: &[u8] = b"cnvl.profile-key.hpke-auth.v1";
const MAX_PUBLICATION_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub(crate) struct Binding<'key> {
    hpke: &'key [u8; 32],
    wrapping: &'key [u8; 32],
    community: String,
    member: String,
    device: [u8; 32],
    public: [u8; 32],
}

/// Keys-lent, immutable custody. No private-key getter, generic decryption,
/// receiver context, caller-selected rekey, Clone or serialization exists.
/// Keys keeps initialization buffers zeroizing and lends this only inside its
/// fresh-authorized synchronous callback. The borrowed lifetime cannot escape.
pub struct Custodian<'key>(Binding<'key>);
impl<'key> Custodian<'key> {
    /// Initialize inside Keys with actual device X25519 material and a distinct
    /// common-root Envelope storage purpose. This constructor confers NO admission.
    pub fn from_keys(
        hpke: &'key [u8; 32],
        wrapping: &'key [u8; 32],
        community: &str,
        member: &str,
        device: [u8; 32],
    ) -> Result<Self, Error> {
        for value in [community, member] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(Error::Context);
            }
        }
        let secret =
            <Kem as hpke::Kem>::PrivateKey::from_bytes(hpke).map_err(|_| Error::Authentication)?;
        let public = Kem::sk_to_pk(&secret)
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| Error::Authentication)?;
        Ok(Self(Binding {
            hpke,
            wrapping,
            community: community.into(),
            member: member.into(),
            device,
            public,
        }))
    }

    /// Public recipient key for the original signed Profile bundle.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.public
    }

    /// Generate the independent profile key internally and seal original packed
    /// bytes. Only this member can publish under this custody.
    pub fn seal(&self, context: Context, bytes: &[u8]) -> Result<(Envelope, ReadKey<'key>), Error> {
        self.0.scope(&context)?;
        if context.owner != self.0.member {
            return Err(Error::Context);
        }
        crate::seal_bound(self.0.clone(), context, bytes)
    }

    /// Restore only under this immutable storage purpose and original context.
    /// A caller-created Custodian cannot rewrap or open another custody's ReadKey.
    pub fn restore(
        &self,
        context: Context,
        wrapped: &WrappedReadKey,
    ) -> Result<ReadKey<'key>, Error> {
        self.0.scope(&context)?;
        let aad = self.0.wrap_aad(&context)?;
        let plain = open_wrapped(self.0.wrapping, &aad, &wrapped.0[1..])?;
        self.reader(context, plain)
    }

    /// Adopt a profile key a member handed to a room as an MLS application
    /// message. `sender` is the MLS sender's pseudonym, authenticated by the
    /// group; the key is accepted only if it belongs to exactly that member and
    /// this community. Epoch and room membership are the caller's checks. The
    /// returned key is stored with [`ReadKey::wrap_room`] only: a room-scoped
    /// grant, which the owner drops when that member leaves or is removed.
    pub fn adopt_room(
        &self,
        handover: &RoomHandover,
        sender: &str,
    ) -> Result<ReadKey<'key>, Error> {
        self.0.scope(&handover.context)?;
        if handover.context.owner != sender || sender == self.0.member {
            return Err(Error::Context);
        }
        self.reader(
            handover.context.clone(),
            Zeroizing::new(handover.secret.to_vec()),
        )
    }

    /// Restore a room-scoped grant under this custody, the original context and
    /// the same room (group). A personal wrap never opens here, nor the reverse.
    pub fn restore_room(
        &self,
        context: Context,
        group: &[u8; 32],
        wrapped: &WrappedReadKey,
    ) -> Result<ReadKey<'key>, Error> {
        self.0.scope(&context)?;
        let aad = self.0.room_wrap_aad(&context, group)?;
        let plain = open_wrapped(self.0.wrapping, &aad, &wrapped.0[1..])?;
        self.reader(context, plain)
    }

    /// Migrate the exact former StoreCipher wire format (24-byte nonce + AEAD of
    /// 32 bytes). Keys supplies its private legacy wrapping key internally. Only
    /// an opaque ReadKey bound to NEW custody is returned; no plaintext import.
    /// The caller must commit its new wrapped form in the original Store CAS.
    pub fn restore_legacy_store(
        &self,
        context: Context,
        old_wrapped: &[u8],
        legacy_wrapping_key: &[u8; 32],
    ) -> Result<ReadKey<'key>, Error> {
        self.0.scope(&context)?;
        let mut aad = b"ckmg.storage.wrap.v1\0".to_vec();
        aad.extend_from_slice(&context.aad()?);
        self.reader(
            context,
            open_wrapped(legacy_wrapping_key, &aad, old_wrapped)?,
        )
    }

    /// Open a maintained Auth-mode transfer only from the current verified sender
    /// into this actual recipient custody. Exchange rechecks current authority and
    /// adopts nonce/key/output atomically before making the received key usable.
    pub fn receive(
        &self,
        transfer: &KeyTransfer,
        expected: &Context,
        sender: &cgrd::VerifiedRecipient<'_>,
        recipient: &cgrd::VerifiedRecipient<'_>,
        binding: &TransferContext<'_>,
    ) -> Result<ReadKey<'key>, Error> {
        self.0.scope(expected)?;
        self.0.is_peer(recipient)?;
        transfer.validate()?;
        if &transfer.0.context != expected {
            return Err(Error::Context);
        }
        let aad = binding.aad(expected, sender, recipient)?;
        let sender = <Kem as hpke::Kem>::PublicKey::from_bytes(sender.hpke_key())
            .map_err(|_| Error::Authentication)?;
        let private = <Kem as hpke::Kem>::PrivateKey::from_bytes(self.0.hpke)
            .map_err(|_| Error::Authentication)?;
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&transfer.0.enc)
            .map_err(|_| Error::Authentication)?;
        let plain = hpke::single_shot_open::<AeadSuite, Kdf, Kem>(
            &OpModeR::Auth(sender),
            &private,
            &enc,
            INFO,
            &transfer.0.ciphertext,
            &aad,
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)?;
        self.reader(expected.clone(), plain)
    }

    fn reader(&self, context: Context, plain: Zeroizing<Vec<u8>>) -> Result<ReadKey<'key>, Error> {
        let secret = Zeroizing::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::Authentication)?,
        );
        Ok(ReadKey {
            secret,
            context,
            custody: self.0.clone(),
        })
    }
}
impl Binding<'_> {
    fn scope(&self, context: &Context) -> Result<(), Error> {
        context.aad()?;
        if context.community != self.community {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn is_peer(&self, peer: &cgrd::VerifiedRecipient<'_>) -> Result<(), Error> {
        if peer.community() != self.community
            || peer.member() != self.member
            || peer.device() != &self.device
            || peer.hpke_key() != &self.public
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn room_wrap_aad(&self, context: &Context, group: &[u8; 32]) -> Result<Vec<u8>, Error> {
        self.scope(context)?;
        serde_json::to_vec(&(
            "cnvl.read-key.room-wrap.v1",
            &self.community,
            &self.member,
            group,
            context,
        ))
        .map_err(|_| Error::Context)
    }
    fn wrap_aad(&self, context: &Context) -> Result<Vec<u8>, Error> {
        self.scope(context)?;
        serde_json::to_vec(&(
            "cnvl.read-key.wrap.v2",
            &self.community,
            &self.member,
            context,
        ))
        .map_err(|_| Error::Context)
    }
}

impl ReadKey<'_> {
    /// Persist under the immutable creating/opening custody. NO cipher/key input
    /// can redirect this wrapping to an attacker-selected storage key.
    pub fn wrap(&self) -> Result<WrappedReadKey, Error> {
        let aad = self.custody.wrap_aad(&self.context)?;
        self.wrap_bound(&aad)
    }

    /// Persist a key adopted from a room, bound to that room (group): it opens
    /// only through [`Custodian::restore_room`] for the same group, so removing
    /// the record when the member leaves is the whole of dropping the grant.
    pub fn wrap_room(&self, group: &[u8; 32]) -> Result<WrappedReadKey, Error> {
        let aad = self.custody.room_wrap_aad(&self.context, group)?;
        self.wrap_bound(&aad)
    }

    /// The profile owner's own key as a room hand-over, to be sent as an MLS
    /// application message in the epoch of admission. Only the owner's custody
    /// can make it, and only for a key of its own profile.
    pub fn room_handover(&self) -> Result<RoomHandover, Error> {
        if self.context.owner != self.custody.member {
            return Err(Error::Context);
        }
        Ok(RoomHandover {
            context: self.context.clone(),
            secret: self.secret.clone(),
        })
    }

    fn wrap_bound(&self, aad: &[u8]) -> Result<WrappedReadKey, Error> {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
        let ciphertext = XChaCha20Poly1305::new(self.custody.wrapping.into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: self.secret.as_slice(),
                    aad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        let mut bytes = vec![2];
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        Ok(WrappedReadKey(bytes))
    }

    /// Seal directly to the original Guard-verified recipient. Only the original
    /// profile owner may release, using the sender key already bound to this key.
    /// Exchange owns consent, current G3/Contacts, and durable one-use adoption.
    pub fn release(
        &self,
        sender: &cgrd::VerifiedRecipient<'_>,
        recipient: &cgrd::VerifiedRecipient<'_>,
        binding: &TransferContext<'_>,
    ) -> Result<KeyTransfer, Error> {
        self.custody.is_peer(sender)?;
        if self.context.owner != self.custody.member {
            return Err(Error::Context);
        }
        let aad = binding.aad(&self.context, sender, recipient)?;
        let private = <Kem as hpke::Kem>::PrivateKey::from_bytes(self.custody.hpke)
            .map_err(|_| Error::Authentication)?;
        let public = Kem::sk_to_pk(&private);
        let recipient = <Kem as hpke::Kem>::PublicKey::from_bytes(recipient.hpke_key())
            .map_err(|_| Error::Authentication)?;
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Randomness)?;
        let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<AeadSuite, Kdf, Kem>(
            &OpModeS::Auth((private, public)),
            &recipient,
            INFO,
            self.secret.as_slice(),
            &aad,
            &mut rand_chacha::ChaCha20Rng::from_seed(*seed),
        )
        .map_err(|_| Error::Authentication)?;
        let enc = enc
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| Error::Authentication)?;
        Ok(KeyTransfer(TransferWire {
            version: 1,
            context: self.context.clone(),
            enc,
            ciphertext,
        }))
    }
}

/// Bounded encrypted local key persistence. It contains no raw key, accepting
/// constructor or authority; restore authenticates its exact custody and context.
pub struct WrappedReadKey(Vec<u8>);
impl WrappedReadKey {
    /// Retain the exact encrypted bytes for the original Store transaction.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Reject unknown version/length before retaining untrusted bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 73 {
            return Err(Error::Limit);
        }
        if bytes[0] != 2 {
            return Err(Error::Context);
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// Exact original Exchange transcript inputs. These bytes/revisions must come
/// from Profile's verified publications, never a peer's accepting claim. This
/// bounded framing is NOT authority; Guard capabilities are required separately.
pub struct TransferContext<'a> {
    sender_publication: &'a [u8],
    recipient_publication: &'a [u8],
    sender_revision: u64,
    recipient_revision: u64,
    offer_nonce: [u8; 32],
}
impl<'a> TransferContext<'a> {
    /// Bind both ORIGINAL signed publications/revisions and the existing offer
    /// nonce. Exchange validates their complete signatures/currentness first.
    pub fn new(
        sender_publication: &'a [u8],
        recipient_publication: &'a [u8],
        sender_revision: u64,
        recipient_revision: u64,
        offer_nonce: [u8; 32],
    ) -> Result<Self, Error> {
        if sender_revision == 0 || recipient_revision == 0 || offer_nonce == [0; 32] {
            return Err(Error::Context);
        }
        if [sender_publication, recipient_publication]
            .iter()
            .any(|p| p.is_empty() || p.len() > MAX_PUBLICATION_BYTES)
        {
            return Err(Error::Limit);
        }
        Ok(Self {
            sender_publication,
            recipient_publication,
            sender_revision,
            recipient_revision,
            offer_nonce,
        })
    }
    fn aad(
        &self,
        context: &Context,
        sender: &cgrd::VerifiedRecipient<'_>,
        recipient: &cgrd::VerifiedRecipient<'_>,
    ) -> Result<Vec<u8>, Error> {
        context.aad()?;
        if sender.community() != context.community
            || recipient.community() != context.community
            || sender.member() != context.owner
            || sender.member() == recipient.member()
            || self.sender_revision != context.profile_revision
        {
            return Err(Error::Context);
        }
        serde_json::to_vec(&(
            "cnvl.profile-key.exchange.v1",
            context,
            (
                sender.member(),
                sender.device(),
                sender.hpke_key(),
                sender.bundle(),
            ),
            (
                recipient.member(),
                recipient.device(),
                recipient.hpke_key(),
                recipient.bundle(),
            ),
            self.sender_publication,
            self.recipient_publication,
            self.sender_revision,
            self.recipient_revision,
            self.offer_nonce,
        ))
        .map_err(|_| Error::Context)
    }
}

/// Authenticated-mode ciphertext, not consent or durable replay evidence.
pub struct KeyTransfer(TransferWire);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferWire {
    version: u8,
    context: Context,
    enc: [u8; 32],
    ciphertext: Vec<u8>,
}
impl KeyTransfer {
    fn validate(&self) -> Result<(), Error> {
        if self.0.version != 1 {
            return Err(Error::Context);
        }
        self.0.context.aad()?;
        if self.0.ciphertext.len() != 48 {
            return Err(Error::Limit);
        }
        Ok(())
    }
    /// Bounded encrypted wire output; Exchange withholds it until actual receipt.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        serde_json::to_vec(&self.0).map_err(|_| Error::Context)
    }
    /// Parse only bounded original wire; receive performs authentication.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 8192 {
            return Err(Error::Limit);
        }
        let value = Self(serde_json::from_slice(bytes).map_err(|_| Error::Context)?);
        value.validate()?;
        Ok(value)
    }
}
fn open_wrapped(key: &[u8; 32], aad: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if bytes.len() != 72 {
        return Err(Error::Limit);
    }
    let nonce: [u8; 24] = bytes[..24].try_into().map_err(|_| Error::Authentication)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &bytes[24..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

/// A profile key on its way into a room's MLS application message: the key and
/// the exact context it opens. It is secret material; it has no Clone, no
/// Debug output and zeroizes on drop. The MLS group, not this type, protects it.
pub struct RoomHandover {
    context: Context,
    secret: Zeroizing<[u8; 32]>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoomHandoverWire {
    version: u8,
    context: Context,
    secret: Vec<u8>,
}
impl RoomHandover {
    /// The context (owner, revision, key generation) this key opens.
    pub fn context(&self) -> &Context {
        &self.context
    }
    /// Bounded bytes for the application message.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.context.aad()?;
        serde_json::to_vec(&RoomHandoverWire {
            version: 1,
            context: self.context.clone(),
            secret: self.secret.to_vec(),
        })
        .map(Zeroizing::new)
        .map_err(|_| Error::Context)
    }
    /// Reject unknown version, shape or size before retaining untrusted bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4096 {
            return Err(Error::Limit);
        }
        let wire: RoomHandoverWire = serde_json::from_slice(bytes).map_err(|_| Error::Context)?;
        if wire.version != 1 {
            return Err(Error::Context);
        }
        wire.context.aad()?;
        Ok(Self {
            context: wire.context,
            secret: Zeroizing::new(wire.secret.try_into().map_err(|_| Error::Context)?),
        })
    }
}
impl std::fmt::Debug for RoomHandover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomHandover([redacted])")
    }
}

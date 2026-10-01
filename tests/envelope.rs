//! Real encryption, exact-byte and custody vectors on native and Wasm.
use ckmg::{
    Entropy, SystemEntropy,
    passkey::{PrfOutput, store_cipher},
};
use cnvl::{Context, Envelope, Error, ReadKey, SealKey, open, seal};
use zeroize::Zeroizing;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
fn context() -> Context {
    Context {
        community: "test-community".into(),
        owner: "test-pseudonym".into(),
        profile_revision: 1,
        schema_revision: 1,
        key_generation: 1,
    }
}
fn key() -> SealKey {
    SealKey::generate(&mut SystemEntropy).unwrap()
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn round_trip_exact_bytes_and_vault_custody() {
    let signed = b" { \"payload\": \"exact original signed bytes\" } ";
    let (envelope, reader) = seal(key(), context(), signed, &mut SystemEntropy).unwrap();
    let wire = envelope.to_bytes().unwrap();
    let envelope = Envelope::from_bytes(&wire).unwrap();
    assert_eq!(
        open(&envelope, &reader, &context()).unwrap().as_slice(),
        signed
    );
    let other = seal(key(), context(), signed, &mut SystemEntropy)
        .unwrap()
        .0
        .to_bytes()
        .unwrap();
    assert_ne!(wire, other);
    let cipher = store_cipher(&PrfOutput::from_bytes(&[1; 32]).unwrap(), "test-community").unwrap();
    let wrapped = reader.wrap(&cipher, &mut SystemEntropy).unwrap();
    let restored = ReadKey::unwrap(&cipher, context(), &wrapped).unwrap();
    assert_eq!(
        open(&envelope, &restored, &context()).unwrap().as_slice(),
        signed
    );
    assert_eq!(format!("{restored:?}"), "ReadKey([redacted])");
    assert_eq!(format!("{envelope:?}"), "Envelope([redacted])");
    assert_eq!(format!("{:?}", context()), "Context([redacted])");
    assert_eq!(Error::Context.to_string(), "envelope: Context");
    let mut changed = context();
    changed.profile_revision = 2;
    assert!(matches!(
        open(&envelope, &reader, &changed),
        Err(Error::Context)
    ));
    assert!(matches!(
        ReadKey::unwrap(&cipher, changed, &wrapped),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        ReadKey::unwrap(&cipher, context(), b"short"),
        Err(Error::Limit)
    ));
    let wrong = ReadKey::receive(Zeroizing::new([9; 32]), context()).unwrap();
    assert!(matches!(
        open(&envelope, &wrong, &context()),
        Err(Error::Authentication)
    ));
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_context_component_and_format_is_bound() {
    let (envelope, reader) = seal(key(), context(), b"signed", &mut SystemEntropy).unwrap();
    let wire = envelope.to_bytes().unwrap();
    for field in [
        "community",
        "owner",
        "profile_revision",
        "schema_revision",
        "key_generation",
    ] {
        let mut changed: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        let value = &mut changed["context"][field];
        *value = if value.is_string() {
            serde_json::json!("other")
        } else {
            serde_json::json!(2)
        };
        let substituted = Envelope::from_bytes(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(matches!(
            open(&substituted, &reader, &context()),
            Err(Error::Context)
        ));
    }
    for field in ["nonce", "ciphertext"] {
        let mut changed: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        changed[field][0] = serde_json::json!(changed[field][0].as_u64().unwrap() ^ 1);
        let tampered = Envelope::from_bytes(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(matches!(
            open(&tampered, &reader, &context()),
            Err(Error::Authentication)
        ));
    }
    for bad in [b"{".as_slice(), b"{}", b"{\"version\":1,\"version\":1}"] {
        assert!(Envelope::from_bytes(bad).is_err());
    }
    let mut changed: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    changed["version"] = 2.into();
    assert!(matches!(
        Envelope::from_bytes(&serde_json::to_vec(&changed).unwrap()),
        Err(Error::Context)
    ));
    changed["version"] = 1.into();
    changed["ciphertext"] = serde_json::json!([]);
    assert!(matches!(
        Envelope::from_bytes(&serde_json::to_vec(&changed).unwrap()),
        Err(Error::Limit)
    ));
    assert!(matches!(
        Envelope::from_bytes(&vec![0; cnvl::MAX_ENVELOPE_BYTES + 1]),
        Err(Error::Limit)
    ));
}
struct FailedEntropy;
impl Entropy for FailedEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Randomness)
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bounds_and_entropy_fail_closed() {
    assert!(matches!(
        SealKey::generate(&mut FailedEntropy),
        Err(Error::Randomness)
    ));
    assert!(matches!(
        seal(key(), context(), b"x", &mut FailedEntropy),
        Err(Error::Randomness)
    ));
    assert!(matches!(
        seal(
            key(),
            context(),
            &vec![0; cnvl::MAX_PLAINTEXT_BYTES + 1],
            &mut SystemEntropy
        ),
        Err(Error::Limit)
    ));
    for n in 0..7 {
        let mut c = context();
        match n {
            0 => c.community.clear(),
            1 => c.owner.clear(),
            2 => c.community = "c".repeat(257),
            3 => c.owner = "m".repeat(257),
            4 => c.profile_revision = 0,
            5 => c.schema_revision = 0,
            _ => c.key_generation = 0,
        }
        assert!(matches!(
            seal(key(), c, b"x", &mut SystemEntropy),
            Err(Error::Context)
        ));
    }
}

// This transport uses the real opaque wrapping capability; no plaintext key is returned.
struct EncryptedRecipient(ckmg::passkey::StoreCipher);
impl cnvl::KeyRecipient for EncryptedRecipient {
    type Output = Vec<u8>;
    fn seal_key(&mut self, context: &Context, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let aad = serde_json::to_vec(context).unwrap();
        self.0
            .seal(&mut SystemEntropy, &aad, key)
            .map_err(|_| Error::Authentication)
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn encrypted_delivery_and_remaining_bounds() {
    let (envelope, reader) = seal(key(), context(), b"signed", &mut SystemEntropy).unwrap();
    let cipher = store_cipher(&PrfOutput::from_bytes(&[7; 32]).unwrap(), "test-community").unwrap();
    let mut recipient = EncryptedRecipient(cipher);
    let delivered = reader.deliver(&mut recipient).unwrap();
    let bytes = recipient
        .0
        .open(&serde_json::to_vec(&context()).unwrap(), &delivered)
        .unwrap();
    let received = ReadKey::receive(
        Zeroizing::new(bytes.as_slice().try_into().unwrap()),
        context(),
    )
    .unwrap();
    assert_eq!(
        open(&envelope, &received, &context()).unwrap().as_slice(),
        b"signed"
    );
    assert!(matches!(
        reader.wrap(&recipient.0, &mut FailedEntropy),
        Err(Error::Authentication)
    ));
    let mut changed = context();
    changed.profile_revision = 2;
    let different_context = ReadKey::receive(Zeroizing::new([7; 32]), changed).unwrap();
    assert!(matches!(
        open(&envelope, &different_context, &context()),
        Err(Error::Context)
    ));
    let mut invalid = context();
    invalid.owner.clear();
    assert!(matches!(
        ReadKey::receive(Zeroizing::new([7; 32]), invalid.clone()),
        Err(Error::Context)
    ));
    assert!(matches!(
        ReadKey::unwrap(&recipient.0, invalid, &[0; 72]),
        Err(Error::Context)
    ));
    let mut value: serde_json::Value =
        serde_json::from_slice(&envelope.to_bytes().unwrap()).unwrap();
    value["ciphertext"] = serde_json::json!(vec![0; cnvl::MAX_PLAINTEXT_BYTES + 17]);
    assert!(matches!(
        Envelope::from_bytes(&serde_json::to_vec(&value).unwrap()),
        Err(Error::Limit)
    ));
    let (maximum, reader) = seal(
        key(),
        context(),
        &vec![5; cnvl::MAX_PLAINTEXT_BYTES],
        &mut SystemEntropy,
    )
    .unwrap();
    assert_eq!(
        open(&maximum, &reader, &context()).unwrap().len(),
        cnvl::MAX_PLAINTEXT_BYTES
    );
}

//! Real encryption, exact-byte and custody vectors on native and Wasm.
use cnvl::{Context, Custodian, Envelope, Error, WrappedReadKey, open};
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
fn custody() -> Custodian<'static> {
    Custodian::from_keys(
        &[1; 32],
        &[2; 32],
        "test-community",
        "test-pseudonym",
        [3; 32],
    )
    .unwrap()
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn round_trip_exact_bytes_and_vault_custody() {
    #[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
    let _ = browser_coverage_runtime::__owned_test_module_signature();
    let signed = b" { \"payload\": \"exact original signed bytes\" } ";
    let (envelope, reader) = custody().seal(context(), signed).unwrap();
    assert!(envelope.matches_context(&context()));
    let mut other_context = context();
    other_context.profile_revision += 1;
    assert!(!envelope.matches_context(&other_context));
    let wire = envelope.to_bytes().unwrap();
    let envelope = Envelope::from_bytes(&wire).unwrap();
    assert_eq!(
        open(&envelope, &reader, &context()).unwrap().as_slice(),
        signed
    );
    let other = custody()
        .seal(context(), signed)
        .unwrap()
        .0
        .to_bytes()
        .unwrap();
    assert_ne!(wire, other);
    let wrapped = reader.wrap().unwrap();
    let restored = custody().restore(context(), &wrapped).unwrap();
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
        custody().restore(changed, &wrapped),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        WrappedReadKey::from_bytes(b"short"),
        Err(Error::Limit)
    ));
    let (_, wrong) = custody().seal(context(), b"unrelated").unwrap();
    assert!(matches!(
        open(&envelope, &wrong, &context()),
        Err(Error::Authentication)
    ));
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_context_component_and_format_is_bound() {
    let (envelope, reader) = custody().seal(context(), b"signed").unwrap();
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bounds_and_wrong_custody_fail_closed() {
    assert!(matches!(
        custody().seal(context(), &vec![0; cnvl::MAX_PLAINTEXT_BYTES + 1]),
        Err(Error::Limit)
    ));
    let (_, key) = custody().seal(context(), b"x").unwrap();
    let wrapped = key.wrap().unwrap();
    let wrong = Custodian::from_keys(
        &[1; 32],
        &[99; 32],
        "test-community",
        "test-pseudonym",
        [3; 32],
    )
    .unwrap();
    assert!(matches!(
        wrong.restore(context(), &wrapped),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        WrappedReadKey::from_bytes(&[0; 73]),
        Err(Error::Context)
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
        assert!(matches!(custody().seal(c, b"x"), Err(Error::Context)));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn encrypted_local_custody_and_remaining_bounds() {
    let (envelope, reader) = custody().seal(context(), b"signed").unwrap();
    let wrapped = reader.wrap().unwrap();
    let received = custody().restore(context(), &wrapped).unwrap();
    assert_eq!(
        open(&envelope, &received, &context()).unwrap().as_slice(),
        b"signed"
    );
    let mut changed = context();
    changed.profile_revision = 2;
    let (_, different_context) = custody().seal(changed, b"other").unwrap();
    assert!(matches!(
        open(&envelope, &different_context, &context()),
        Err(Error::Context)
    ));
    let mut invalid = context();
    invalid.owner.clear();
    assert!(matches!(
        custody().restore(invalid, &wrapped),
        Err(Error::Context)
    ));
    let mut value: serde_json::Value =
        serde_json::from_slice(&envelope.to_bytes().unwrap()).unwrap();
    value["ciphertext"] = serde_json::json!(vec![0; cnvl::MAX_PLAINTEXT_BYTES + 17]);
    assert!(matches!(
        Envelope::from_bytes(&serde_json::to_vec(&value).unwrap()),
        Err(Error::Limit)
    ));
    let (maximum, reader) = custody()
        .seal(context(), &vec![5; cnvl::MAX_PLAINTEXT_BYTES])
        .unwrap();
    assert_eq!(
        open(&maximum, &reader, &context()).unwrap().len(),
        cnvl::MAX_PLAINTEXT_BYTES
    );
}

fn member(name: &str, byte: u8) -> Custodian<'static> {
    let (hpke, wrapping): (&'static [u8; 32], &'static [u8; 32]) = if byte == 7 {
        (&[7; 32], &[8; 32])
    } else {
        (&[9; 32], &[10; 32])
    };
    Custodian::from_keys(hpke, wrapping, "test-community", name, [byte; 32]).unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_room_grant_is_adopted_only_from_its_owner_and_is_scoped_to_the_room() {
    use cnvl::RoomHandover;
    let (envelope, owner_key) = custody().seal(context(), b"profile").unwrap();
    let handover = owner_key.room_handover().unwrap();
    let bytes = handover.to_bytes().unwrap();
    let received = RoomHandover::from_bytes(&bytes).unwrap();
    assert_eq!(format!("{received:?}"), "RoomHandover([redacted])");
    assert!(received.context() == &context());
    let reader = member("other-pseudonym", 7);
    // Only the MLS sender that owns the key may hand it over; never your own.
    assert!(reader.adopt_room(&received, "someone-else").is_err());
    assert!(
        member("test-pseudonym", 9)
            .adopt_room(&received, "test-pseudonym")
            .is_err()
    );
    let adopted = reader.adopt_room(&received, "test-pseudonym").unwrap();
    assert_eq!(
        open(&envelope, &adopted, &context()).unwrap().as_slice(),
        b"profile"
    );
    // Only the owner can make a hand-over, and only of its own key.
    assert!(adopted.room_handover().is_err());
    // Stored room-scoped: it restores for that room only, never as a personal key.
    let room = [5; 32];
    let wrapped = adopted.wrap_room(&room).unwrap();
    let restored = reader.restore_room(context(), &room, &wrapped).unwrap();
    assert_eq!(
        open(&envelope, &restored, &context()).unwrap().as_slice(),
        b"profile"
    );
    assert!(reader.restore_room(context(), &[6; 32], &wrapped).is_err());
    assert!(reader.restore(context(), &wrapped).is_err());
    assert!(
        reader
            .restore_room(context(), &room, &adopted.wrap().unwrap())
            .is_err()
    );
    // Malformed or oversized hand-overs are refused before use.
    assert!(RoomHandover::from_bytes(b"{}").is_err());
    assert!(RoomHandover::from_bytes(&[b' '; 5000]).is_err());
}

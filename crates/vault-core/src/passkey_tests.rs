//! Passkeys: the RP ID rule, the requests read, what is made and signed,
//! checked against frozen values, and how a login keeps them.

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::{
    ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey},
    PublicKey, SecretKey,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::{tempdir, TempDir};

use crate::{
    fixture_tests::hex,
    passkey::{
        client_data, client_data_hash, rp_id_allowed, rp_id_valid, Ceremony, Created, Refusal,
        Registering, Signing, UserVerification, ES256, MAX_PASSKEYS,
    },
    preview_import,
    storage::version_plaintext,
    vector_tests::{counting, frozen, unhex},
    Error, ImportFormat, Item, ItemKind, Origin, Passkey, Vault,
};

const NOW: u64 = 1_767_225_600;

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn page(serialized: &str) -> Origin {
    Origin::parse(serialized).unwrap()
}

#[test]
fn a_passkey_is_for_a_domain_that_is_no_public_suffix() {
    for valid in [
        "example.test",
        "login.example.test",
        "example.com",
        "example.co.uk",
        "user.github.io",
        "xn--bcher-kva.example",
        "a-b.example",
        "1password.com",
    ] {
        assert!(rp_id_valid(valid), "{valid}");
    }
    let too_long = format!("{}com", "a.".repeat(127));
    for invalid in [
        "",
        "com",
        "co.uk",
        // The list's private section counts: under github.io is everyone's.
        "github.io",
        "localhost",
        "test",
        "example.com.",
        ".example.com",
        "a..example.com",
        "Example.com",
        "bücher.example",
        "-a.example",
        "a-.example",
        "under_score.example",
        "192.0.2.7",
        "example.1",
        "example.0x7f",
        "[2001:db8::1]",
        "example.com:443",
        &too_long,
    ] {
        assert!(!rp_id_valid(invalid), "{invalid}");
    }
}

#[test]
fn a_page_uses_passkeys_of_its_own_host_or_a_domain_it_is_under() {
    let www = page("https://www.example.test");
    assert!(rp_id_allowed("example.test", &www));
    assert!(rp_id_allowed("www.example.test", &www));
    for other in [
        "other.example.test",
        "ww.example.test",
        "w.example.test",
        "xample.test",
        "sub.www.example.test",
        "example.com",
        "test",
    ] {
        assert!(!rp_id_allowed(other, &www), "{other}");
    }
    // Whatever its port.
    assert!(rp_id_allowed(
        "example.test",
        &page("https://example.test:8443")
    ));
    // An address is no domain, a public suffix is no site, and a host with
    // a dot at the end is another host.
    assert!(!rp_id_allowed("192.0.2.7", &page("https://192.0.2.7")));
    assert!(!rp_id_allowed("github.io", &page("https://github.io")));
    assert!(!rp_id_allowed(
        "example.test.",
        &page("https://example.test.")
    ));
    assert!(!rp_id_allowed(
        "example.test",
        &page("https://example.test.")
    ));
}

/// A request to make a passkey, as a site's `toJSON` writes one, changed by
/// `change`.
fn creation(change: impl FnOnce(&mut Value)) -> String {
    let mut options = json!({
        "rp": { "id": "example.test", "name": "Example" },
        "user": { "id": b64(&[1, 2, 3, 4]), "name": "owner@example.test", "displayName": "Owner" },
        "challenge": b64(&counting::<32>(0x50)),
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -8 },
            { "type": "public-key", "alg": -7 },
        ],
        "timeout": 60000,
        "excludeCredentials": [
            { "type": "public-key", "id": b64(&counting::<16>(0xa0)), "transports": ["internal"] },
            { "type": "a later type", "id": "not read" },
        ],
        "authenticatorSelection": { "residentKey": "required", "userVerification": "required" },
        "attestation": "direct",
        "extensions": { "credProps": true },
        "hints": ["client-device"],
    });
    change(&mut options);
    options.to_string()
}

fn request(change: impl FnOnce(&mut Value)) -> String {
    let mut options = json!({
        "challenge": b64(&counting::<32>(0x70)),
        "rpId": "example.test",
        "allowCredentials": [
            { "type": "public-key", "id": b64(&counting::<16>(0xa0)) },
            { "type": "a later type", "id": "not read" },
        ],
        "userVerification": "discouraged",
        "timeout": 60000,
    });
    change(&mut options);
    options.to_string()
}

#[test]
fn a_request_to_make_a_passkey_is_read_and_checked() {
    let www = page("https://www.example.test");
    let read = Registering::from_options(&creation(|_| {}), Some(&www)).unwrap();
    assert_eq!(read.rp_id, "example.test");
    assert_eq!(read.rp_name, "Example");
    assert_eq!(read.user_handle, [1, 2, 3, 4]);
    assert_eq!(
        (read.user_name.as_str(), read.user_display_name.as_str()),
        ("owner@example.test", "Owner")
    );
    assert_eq!(read.challenge, counting::<32>(0x50));
    assert_eq!(read.exclude, [counting::<16>(0xa0).to_vec()]);
    assert_eq!(read.user_verification, UserVerification::Required);

    let refusal = |options: String, origin: Option<&Origin>| {
        Registering::from_options(&options, origin).err()
    };
    // No RP ID is the page's host; an app has to name one.
    let without_id = creation(|options| {
        options["rp"].as_object_mut().unwrap().remove("id");
    });
    assert_eq!(
        Registering::from_options(&without_id, Some(&www))
            .unwrap()
            .rp_id,
        "www.example.test"
    );
    assert_eq!(
        refusal(without_id, None),
        Some(Refusal::Malformed("an app's request names no site"))
    );
    assert_eq!(
        Registering::from_options(&creation(|_| {}), None)
            .unwrap()
            .rp_id,
        "example.test"
    );
    for (rp_id, origin) in [
        ("example.com", Some(&www)),
        ("other.example.test", Some(&www)),
        ("github.io", None),
        ("Example.test", None),
    ] {
        assert_eq!(
            refusal(
                creation(|options| options["rp"]["id"] = json!(rp_id)),
                origin
            ),
            Some(Refusal::RelyingParty),
            "{rp_id}"
        );
    }

    // ES256 among those the site takes, or no list at all, which stands for
    // the defaults.
    for params in [
        json!([{ "type": "public-key", "alg": -257 }]),
        json!([{ "type": "other", "alg": -7 }]),
    ] {
        assert_eq!(
            refusal(
                creation(|options| options["pubKeyCredParams"] = params),
                Some(&www)
            ),
            Some(Refusal::Algorithm)
        );
    }
    for params in [json!([]), Value::Null] {
        assert!(Registering::from_options(
            &creation(|options| options["pubKeyCredParams"] = params),
            Some(&www)
        )
        .is_ok());
    }

    // Null where a value may be left out, and padding, are read.
    let lenient = creation(|options| {
        options["excludeCredentials"] = Value::Null;
        options["authenticatorSelection"] = Value::Null;
        options["rp"]["name"] = Value::Null;
        options["user"]["id"] = json!("AQIDBA==");
        options["user"]
            .as_object_mut()
            .unwrap()
            .remove("displayName");
    });
    let read = Registering::from_options(&lenient, Some(&www)).unwrap();
    assert_eq!(
        (
            read.user_handle.as_slice(),
            read.user_verification,
            read.exclude.len()
        ),
        (&[1, 2, 3, 4][..], UserVerification::Preferred, 0)
    );
    let named = |name: Value| {
        Registering::from_options(
            &creation(|options| options["authenticatorSelection"]["userVerification"] = name),
            Some(&www),
        )
        .unwrap()
        .user_verification
    };
    assert_eq!(named(json!("discouraged")), UserVerification::Discouraged);
    assert_eq!(named(json!("preferred")), UserVerification::Preferred);
    assert_eq!(named(json!("a later value")), UserVerification::Preferred);
    // A site's long name for the account is cut.
    let long = Registering::from_options(
        &creation(|options| options["user"]["name"] = json!("n".repeat(1000))),
        Some(&www),
    )
    .unwrap();
    assert_eq!(long.user_name.chars().count(), 256);

    for (malformed, why) in [
        (
            creation(|options| options["user"]["id"] = json!("")),
            "the user handle",
        ),
        (
            creation(|options| options["user"]["id"] = json!(b64(&[7; 65]))),
            "the user handle",
        ),
        (
            creation(|options| options["user"]["id"] = json!("not base64!")),
            "the user handle",
        ),
        (
            creation(|options| options["challenge"] = json!("")),
            "the challenge",
        ),
        (
            creation(|options| options["challenge"] = json!(b64(&[0; 1025]))),
            "the challenge",
        ),
        (
            creation(|options| options["excludeCredentials"][0]["id"] = json!("")),
            "a credential ID",
        ),
        (
            creation(|options| options["user"] = Value::Null),
            "the request does not read",
        ),
        ("not json".to_owned(), "the request does not read"),
        (
            creation(|options| options["padding"] = json!("x".repeat(64 * 1024))),
            "the request is too large",
        ),
    ] {
        assert_eq!(
            refusal(malformed, Some(&www)),
            Some(Refusal::Malformed(why)),
            "{why}"
        );
    }
}

#[test]
fn a_request_to_sign_in_is_read_and_checked() {
    let www = page("https://www.example.test");
    let read = Signing::from_options(&request(|_| {}), Some(&www)).unwrap();
    assert_eq!(
        read,
        Signing {
            rp_id: "example.test".into(),
            challenge: counting::<32>(0x70).to_vec(),
            allowed: vec![counting::<16>(0xa0).to_vec()],
            user_verification: UserVerification::Discouraged,
        }
    );
    let without_id = request(|options| {
        options.as_object_mut().unwrap().remove("rpId");
        options.as_object_mut().unwrap().remove("allowCredentials");
        options.as_object_mut().unwrap().remove("userVerification");
    });
    let read = Signing::from_options(&without_id, Some(&www)).unwrap();
    assert_eq!(
        (
            read.rp_id.as_str(),
            read.allowed.len(),
            read.user_verification
        ),
        ("www.example.test", 0, UserVerification::Preferred)
    );
    assert_eq!(
        Signing::from_options(&without_id, None),
        Err(Refusal::Malformed("an app's request names no site"))
    );
    assert_eq!(
        Signing::from_options(
            &request(|options| options["rpId"] = json!("example.com")),
            Some(&www)
        ),
        Err(Refusal::RelyingParty)
    );
    let many = (0..257)
        .map(|_| json!({ "type": "public-key", "id": "AQ" }))
        .collect::<Vec<_>>();
    assert_eq!(
        Signing::from_options(
            &request(|options| options["allowCredentials"] = json!(many)),
            Some(&www)
        ),
        Err(Refusal::Malformed("the request names too many credentials"))
    );
}

/// The request the frozen values were made from.
fn vector_request() -> Registering {
    Registering {
        rp_id: "example.test".into(),
        rp_name: "Example".into(),
        user_handle: counting::<16>(0x30).to_vec(),
        user_name: "owner@example.test".into(),
        user_display_name: "Owner".into(),
        challenge: counting::<32>(0x50).to_vec(),
        exclude: Vec::new(),
        user_verification: UserVerification::Required,
    }
}

fn vector_key() -> SigningKey {
    SigningKey::from_slice(&counting::<32>(0x20)).unwrap()
}

const VECTOR_PAGE: &str = "https://www.example.test";

fn vector_passkey() -> Created {
    vector_request()
        .create_with(&vector_key(), &counting::<16>(0xa0), true, NOW)
        .unwrap()
}

fn passkey_vectors() -> Value {
    let request = vector_request();
    let created = vector_passkey();
    let made = client_data(Ceremony::Create, &request.challenge, VECTOR_PAGE);
    let challenge = counting::<32>(0x70);
    let signed = client_data(Ceremony::Get, &challenge, VECTOR_PAGE);
    let hash = client_data_hash(&signed);
    let verified = created.passkey.assert(&hash, true, NOW).unwrap();
    let unverified = created.passkey.assert(&hash, false, NOW).unwrap();
    let mut imported = created.passkey.clone();
    imported.sign_count = 7;
    let imported = imported.assert(&hash, true, NOW).unwrap();
    let mut item = Item::new("Example");
    item.id = "vector-passkey".into();
    item.username = "owner@example.test".into();
    item.url = "https://example.test".into();
    item.passkeys.push(created.passkey.clone());
    let plaintext = version_plaintext(Some(&item), Some(NOW)).unwrap();
    let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).unwrap();
    json!({
        "about": "Passkeys, from inputs anyone can write down. Bytes are lowercase hexadecimal. The private key is the P-256 scalar given; the credential ID, user handle and challenges count up. Signatures are ECDSA with SHA-256 and RFC 6979 nonces, so they are fixed, DER encoded. The responses are what a site is sent, as WebAuthn's JSON writes them, and are checked by an independent verifier (apps/browser-extension/src/passkey-vectors.test.ts).",
        "inputs": {
            "private_key": hex(&counting::<32>(0x20)),
            "credential_id": hex(&counting::<16>(0xa0)),
            "rp_id": request.rp_id,
            "origin": VECTOR_PAGE,
            "user_handle": hex(&request.user_handle),
            "user_name": request.user_name,
            "user_display_name": request.user_display_name,
            "created_at": NOW,
            "registration_challenge": hex(&request.challenge),
            "sign_in_challenge": hex(&challenge),
            "now": NOW,
            "imported_sign_count": 7,
        },
        "passkey": serde_json::to_value(&created.passkey).unwrap(),
        "item_plaintext": text(&plaintext),
        "registration": {
            "client_data": text(&made),
            "authenticator_data": hex(&created.registration.authenticator_data),
            "attestation_object": hex(&created.registration.attestation_object),
            "public_key": hex(&created.registration.public_key),
            "response_json": created.registration.response_json(&made),
        },
        "sign_in": {
            "client_data": text(&signed),
            "client_data_hash": hex(&hash),
            "authenticator_data": hex(&verified.authenticator_data),
            "signature": hex(&verified.signature),
            "response_json": verified.response_json(&signed),
            "authenticator_data_unverified": hex(&unverified.authenticator_data),
            "imported_authenticator_data": hex(&imported.authenticator_data),
        },
    })
}

#[test]
fn the_passkey_encodings_are_the_frozen_ones() {
    let frozen = frozen("vectors-passkeys.json", &passkey_vectors());
    let bytes = |section: &str, name: &str| unhex(frozen[section][name].as_str().unwrap());

    // Read back from the frozen values alone, byte by byte.
    let public_key = PublicKey::from_public_key_der(&bytes("registration", "public_key")).unwrap();
    assert_eq!(
        public_key,
        PublicKey::from(vector_key().verifying_key()),
        "the public key is the private key's"
    );
    let point = p256::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&public_key, false);
    let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    cose.extend_from_slice(point.x().unwrap());
    cose.extend_from_slice(&[0x22, 0x58, 0x20]);
    cose.extend_from_slice(point.y().unwrap());

    let rp_id_hash = Sha256::digest(b"example.test").to_vec();
    let mut made = rp_id_hash.clone();
    // Present, verified, backup eligible, backed up, and attested.
    made.push(0x5d);
    made.extend_from_slice(&[0; 4]);
    made.extend_from_slice(&[0; 16]);
    made.extend_from_slice(&[0, 16]);
    made.extend_from_slice(&counting::<16>(0xa0));
    made.extend_from_slice(&cose);
    assert_eq!(bytes("registration", "authenticator_data"), made);

    let mut attestation = vec![0xa3, 0x63];
    attestation.extend_from_slice(b"fmt");
    attestation.push(0x64);
    attestation.extend_from_slice(b"none");
    attestation.push(0x67);
    attestation.extend_from_slice(b"attStmt");
    attestation.extend_from_slice(&[0xa0, 0x68]);
    attestation.extend_from_slice(b"authData");
    attestation.extend_from_slice(&[0x58, made.len() as u8]);
    attestation.extend_from_slice(&made);
    assert_eq!(bytes("registration", "attestation_object"), attestation);

    let challenge = Base64UrlUnpadded::encode_string(&counting::<32>(0x70));
    let signed = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://www.example.test","crossOrigin":false}}"#
    );
    assert_eq!(frozen["sign_in"]["client_data"], signed.as_str());
    let hash = Sha256::digest(signed.as_bytes()).to_vec();
    assert_eq!(bytes("sign_in", "client_data_hash"), hash);
    let authenticator_data = |flags: u8, counter: u32| {
        let mut data = rp_id_hash.clone();
        data.push(flags);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    };
    assert_eq!(
        bytes("sign_in", "authenticator_data"),
        authenticator_data(0x1d, 0)
    );
    assert_eq!(
        bytes("sign_in", "authenticator_data_unverified"),
        authenticator_data(0x19, 0)
    );
    assert_eq!(
        bytes("sign_in", "imported_authenticator_data"),
        authenticator_data(0x1d, NOW as u32)
    );
    let mut message = authenticator_data(0x1d, 0);
    message.extend_from_slice(&hash);
    VerifyingKey::from(&public_key)
        .verify(
            &message,
            &Signature::from_der(&bytes("sign_in", "signature")).unwrap(),
        )
        .unwrap();

    // The login as a version holds it, and its key as PKCS #8.
    let item: Item = serde_json::from_str(frozen["item_plaintext"].as_str().unwrap()).unwrap();
    assert_eq!(item.passkeys.len(), 1);
    assert_eq!(
        serde_json::to_value(&item.passkeys[0]).unwrap(),
        frozen["passkey"]
    );
    let key = Base64UrlUnpadded::decode_vec(&item.passkeys[0].key).unwrap();
    assert_eq!(
        SecretKey::from_pkcs8_der(&key)
            .unwrap()
            .to_bytes()
            .as_slice(),
        counting::<32>(0x20)
    );
    assert_eq!(item.passkeys[0].algorithm, ES256);
}

#[test]
fn a_passkey_made_signs_in_and_each_has_its_own_key_and_id() {
    let request = vector_request();
    let one = request.create(false, NOW).unwrap();
    let other = request.create(false, NOW).unwrap();
    assert_ne!(
        one.registration.credential_id,
        other.registration.credential_id
    );
    assert_ne!(one.passkey.key, other.passkey.key);
    assert_eq!(one.registration.credential_id.len(), 16);
    // Not verified, and so not flagged.
    assert_eq!(one.registration.authenticator_data[32], 0x59);

    let hash = client_data_hash(b"any client data");
    let assertion = one.passkey.assert(&hash, false, NOW).unwrap();
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&hash);
    let key = VerifyingKey::from_public_key_der(&one.registration.public_key).unwrap();
    key.verify(
        &message,
        &Signature::from_der(&assertion.signature).unwrap(),
    )
    .unwrap();
    assert_eq!(assertion.user_handle, request.user_handle);
    assert_eq!(assertion.credential_id, one.registration.credential_id);

    let response: Value = serde_json::from_str(&assertion.response_json(b"{}")).unwrap();
    assert_eq!(response["id"], b64(&assertion.credential_id));
    assert_eq!(response["response"]["clientDataJSON"], b64(b"{}"));
    assert_eq!(response["authenticatorAttachment"], "platform");
    assert_eq!(
        crate::passkey::android_app_origin(&[0xfa; 32]),
        format!("android:apk-key-hash:{}", b64(&[0xfa; 32]))
    );
    let response: Value = serde_json::from_str(&one.registration.response_json(b"{}")).unwrap();
    assert_eq!(response["response"]["publicKeyAlgorithm"], ES256);
    assert_eq!(response["clientExtensionResults"]["credProps"]["rk"], true);
}

fn vault() -> (TempDir, Vault) {
    let dir = tempdir().unwrap();
    let (vault, _) = Vault::create(dir.path().join("vault.db"), "password").unwrap();
    (dir, vault)
}

fn made_for(rp_id: &str, user: &str) -> Created {
    let mut request = vector_request();
    rp_id.clone_into(&mut request.rp_id);
    user.clone_into(&mut request.user_name);
    request.create(true, NOW).unwrap()
}

fn verifies(created: &Created, assertion: &crate::passkey::Assertion, hash: &[u8; 32]) -> bool {
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(hash);
    VerifyingKey::from_public_key_der(&created.registration.public_key)
        .unwrap()
        .verify(
            &message,
            &Signature::from_der(&assertion.signature).unwrap(),
        )
        .is_ok()
}

#[test]
fn a_passkey_saved_as_a_login_is_found_signs_in_and_is_removed() {
    let (_dir, mut vault) = vault();
    let created = made_for("example.test", "owner");
    let id = created.registration.credential_id.clone();
    let credential = created.passkey.credential_id.clone();
    let saved = vault
        .save_passkey_as_login(created.passkey.clone(), "Example")
        .unwrap();
    let listed = vault.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (
            listed[0].title.as_str(),
            listed[0].kind,
            listed[0].username.as_str(),
            listed[0].url.as_str(),
            listed[0].passkeys
        ),
        (
            "Example",
            ItemKind::Login,
            "owner",
            "https://example.test",
            1
        )
    );

    let found = vault.passkeys_for("example.test", &[]).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(
        (
            found[0].item_id.as_str(),
            found[0].title.as_str(),
            &found[0].passkey
        ),
        (
            saved.item_id.as_str(),
            "Example",
            &created.passkey.summary()
        )
    );
    assert!(vault.passkeys_for("other.test", &[]).unwrap().is_empty());
    assert_eq!(
        vault
            .passkeys_for("example.test", std::slice::from_ref(&id))
            .unwrap()
            .len(),
        1
    );
    assert!(vault
        .passkeys_for("example.test", &[vec![1, 2, 3]])
        .unwrap()
        .is_empty());
    assert!(vault
        .holds_passkey("example.test", &[vec![1], id.clone()])
        .unwrap());
    assert!(!vault.holds_passkey("example.test", &[vec![1]]).unwrap());
    assert!(!vault
        .holds_passkey("other.test", std::slice::from_ref(&id))
        .unwrap());
    assert!(!vault.holds_passkey("example.test", &[]).unwrap());

    let hash = client_data_hash(b"client data");
    let assertion = vault
        .sign_with_passkey(
            &saved.item_id,
            &credential,
            "example.test",
            &hash,
            true,
            NOW,
        )
        .unwrap();
    assert!(verifies(&created, &assertion, &hash));
    assert!(matches!(
        vault.sign_with_passkey(&saved.item_id, &credential, "other.test", &hash, true, NOW),
        Err(Error::OriginMismatch)
    ));
    assert!(matches!(
        vault.sign_with_passkey(&saved.item_id, "AQ", "example.test", &hash, true, NOW),
        Err(Error::NotFound)
    ));

    // A second passkey on the same login, then an ordinary edit, which
    // keeps both.
    let second = made_for("example.test", "owner+work");
    let added = vault
        .add_passkey(&saved.item_id, &saved.revision, second.passkey.clone())
        .unwrap();
    assert_eq!(
        vault.history(&saved.item_id).unwrap()[0].changed,
        ["passkeys"]
    );
    let mut edited = vault.get(&saved.item_id).unwrap().item;
    edited.title = "Example, renamed".into();
    let edited = vault.update(edited, &added.revision).unwrap();
    let found = vault.passkeys_for("example.test", &[]).unwrap();
    assert_eq!(
        found
            .iter()
            .map(|found| found.passkey.user_name.as_str())
            .collect::<Vec<_>>(),
        ["owner", "owner+work"]
    );

    let removed = vault
        .remove_passkey(&saved.item_id, &edited.revision, &credential)
        .unwrap();
    let item = vault.get(&saved.item_id).unwrap().item;
    assert_eq!(item.passkeys, std::slice::from_ref(&second.passkey));
    assert!(matches!(
        vault.remove_passkey(&saved.item_id, &removed.revision, &credential),
        Err(Error::NotFound)
    ));
    // Its key stays in the login's earlier versions.
    assert!(vault.history(&saved.item_id).unwrap()[1]
        .item
        .as_ref()
        .unwrap()
        .passkeys
        .contains(&created.passkey));

    // The logins a new passkey may go on: those of the site, or under it.
    let mut other = Item::new("Other site");
    other.url = "https://example.com/sign-in".into();
    vault.put(other).unwrap();
    let mut under = Item::new("Under it");
    under.url = "https://login.example.test/".into();
    let under = vault.put(under).unwrap().item_id;
    let mut on_site = vault
        .logins_for_site("example.test")
        .unwrap()
        .into_iter()
        .map(|item| item.id)
        .collect::<Vec<_>>();
    on_site.sort();
    let mut expected = vec![saved.item_id.clone(), under];
    expected.sort();
    assert_eq!(on_site, expected);

    // Without a title, a login is named for its site.
    let unnamed = vault
        .save_passkey_as_login(made_for("login.example.test", "me").passkey, " ")
        .unwrap();
    assert_eq!(
        vault.get(&unnamed.item_id).unwrap().item.title,
        "login.example.test"
    );
}

/// A passkey as a later build might write one: another algorithm, a key
/// this build cannot read, and a field it does not know.
const LATER_PASSKEY: &str = r#"{"credential_id":"AQID","rp_id":"example.test","user_handle":"BAUG","user_name":"later","user_display_name":"Later","algorithm":-8,"key":"an opaque key","created_at":5,"sign_count":0,"prf":{"salt":"secret"}}"#;

#[test]
fn a_passkey_written_here_is_checked_and_one_a_later_build_wrote_is_kept_as_it_is() {
    let (_dir, mut vault) = vault();
    let refused =
        |vault: &mut Vault, item: Item| matches!(vault.put(item), Err(Error::InvalidItem(_)));
    let with = |passkeys: Vec<Passkey>| {
        let mut item = Item::new("Example");
        item.passkeys = passkeys;
        item
    };
    let good = made_for("example.test", "owner").passkey;
    let mut broken = good.clone();
    broken.key = "AAAA".into();
    let mut public_suffix = made_for("example.test", "owner").passkey;
    public_suffix.rp_id = "com".into();
    let mut padded = made_for("example.test", "owner").passkey;
    padded.credential_id.push('=');
    let mut named_twice = made_for("example.test", "owner").passkey;
    named_twice
        .unknown_fields
        .insert("rp_id".into(), json!("other.test"));
    for passkey in [broken, public_suffix, padded, named_twice] {
        assert!(refused(&mut vault, with(vec![passkey])));
    }
    assert!(refused(&mut vault, with(vec![good.clone(), good.clone()])));
    let mut card = with(vec![good.clone()]);
    card.kind = ItemKind::Card;
    assert!(refused(&mut vault, card));
    let many = |count| {
        (0..count)
            .map(|_| made_for("example.test", "owner").passkey)
            .collect::<Vec<_>>()
    };
    assert!(refused(&mut vault, with(many(MAX_PASSKEYS + 1))));
    vault.put(with(many(MAX_PASSKEYS))).unwrap();

    // A login's type does not change while it has a passkey.
    let login = vault.put(with(vec![good.clone()])).unwrap();
    let mut changed = vault.get(&login.item_id).unwrap().item;
    changed.kind = ItemKind::Card;
    assert!(matches!(
        vault.update(changed, &login.revision),
        Err(Error::InvalidItem(_))
    ));

    // A later build's passkey reads, is kept through an edit here, and is
    // neither listed nor used, since this build cannot sign with it.
    let later: Passkey = serde_json::from_str(LATER_PASSKEY).unwrap();
    assert_eq!(later.unknown_fields["prf"]["salt"], "secret");
    assert_eq!(serde_json::to_string(&later).unwrap(), LATER_PASSKEY);
    let mut item = with(vec![later.clone()]);
    item.id = "later".into();
    let first = vault.put_as_later_build(item).unwrap();
    let mut edited = vault.get("later").unwrap().item;
    edited.title = "Renamed".into();
    let edited = vault.update(edited, &first.revision).unwrap();
    // And a passkey added beside it is checked alone.
    let added = vault
        .add_passkey("later", &edited.revision, good.clone())
        .unwrap();
    assert_eq!(
        vault.get("later").unwrap().item.passkeys,
        [later, good.clone()]
    );
    assert!(vault
        .passkeys_for("example.test", &[vec![1, 2, 3]])
        .unwrap()
        .is_empty());
    assert!(matches!(
        vault.sign_with_passkey("later", "AQID", "example.test", &[0; 32], true, NOW),
        Err(Error::InvalidItem(_))
    ));
    vault
        .remove_passkey("later", &added.revision, "AQID")
        .unwrap();

    // Each of a passkey's fields has to be there, once.
    let missing = LATER_PASSKEY.replace(r#""sign_count":0,"#, "");
    assert!(serde_json::from_str::<Passkey>(&missing).is_err());
    let twice = LATER_PASSKEY.replace(r#""prf""#, r#""rp_id":"again","prf""#);
    assert!(serde_json::from_str::<Passkey>(&twice).is_err());
    let unknown_twice = LATER_PASSKEY.replace(r#""prf""#, r#""prf":1,"prf""#);
    assert!(serde_json::from_str::<Passkey>(&unknown_twice).is_err());
}

#[test]
fn an_item_without_passkeys_is_written_as_before_and_one_with_them_after_its_fields() {
    let mut item = Item::new("t");
    item.id = "i".into();
    let before = serde_json::to_string(&item).unwrap();
    assert!(!before.contains("passkeys"));
    let with_none = format!(r#"{},"passkeys":[]}}"#, &before[..before.len() - 1]);
    let read: Item = serde_json::from_str(&with_none).unwrap();
    assert!(read.passkeys.is_empty());
    item.passkeys
        .push(serde_json::from_str(LATER_PASSKEY).unwrap());
    item.unknown_fields.insert("added_later".into(), json!("x"));
    let written = serde_json::to_string(&item).unwrap();
    assert!(written.starts_with(&before[..before.len() - 1]));
    assert!(written.ends_with(&format!(
        r#","passkeys":[{LATER_PASSKEY}],"added_later":"x"}}"#
    )));
    // A field of that name from a build that did not know it is no
    // unknown field of this one.
    let mut taken = Item::new("t");
    taken.unknown_fields.insert("passkeys".into(), json!([]));
    let (_dir, mut vault) = vault();
    assert!(matches!(vault.put(taken), Err(Error::InvalidItem(_))));
}

/// Two devices of one vault with one login, which each has edited from
/// the same version.
fn two_devices(dir: &std::path::Path) -> (Vault, Vault, Item, String) {
    let (mut first, recovery) = Vault::create(dir.join("a.db"), "password").unwrap();
    let mut item = Item::new("Example");
    item.url = "https://example.test".into();
    let base = first.put(item.clone()).unwrap().revision;
    first.export_backup(dir.join("a.osmbak")).unwrap();
    let second = Vault::restore_backup(
        dir.join("a.osmbak"),
        dir.join("b.db"),
        &recovery,
        "password",
    )
    .unwrap();
    first
        .authorize_device(
            second.device_id().unwrap(),
            second.device_public_key().unwrap(),
        )
        .unwrap();
    (first, second, item, base)
}

fn sent(vault: &Vault, revision: &str) -> crate::EncryptedRevision {
    vault
        .encrypted_revisions()
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.revision_id() == revision)
        .unwrap()
}

#[test]
fn settling_a_conflict_or_restoring_a_version_keeps_every_passkey() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_devices(dir.path());
    let on_a = made_for("example.test", "on a");
    let on_b = made_for("example.test", "on b");
    a.add_passkey(&item.id, &base, on_a.passkey.clone())
        .unwrap();
    let from_b = b
        .add_passkey(&item.id, &base, on_b.passkey.clone())
        .unwrap();
    a.apply_encrypted_revision(sent(&b, &from_b.revision))
        .unwrap();
    assert!(a.get(&item.id).unwrap().conflict);

    // In conflict, a passkey of either version is found and signs in.
    assert_eq!(a.passkeys_for("example.test", &[]).unwrap().len(), 2);
    let hash = client_data_hash(b"client data");
    let assertion = a
        .sign_with_passkey(
            &item.id,
            &on_b.passkey.credential_id,
            "example.test",
            &hash,
            false,
            NOW,
        )
        .unwrap();
    assert!(verifies(&on_b, &assertion, &hash));

    // Keeping A's version whole keeps B's passkey too.
    let versions = a.versions(&item.id).unwrap();
    let heads = versions
        .iter()
        .map(|version| version.revision.clone())
        .collect::<Vec<_>>();
    let kept = versions
        .into_iter()
        .filter_map(|version| version.item)
        .find(|item| item.passkeys.contains(&on_a.passkey))
        .unwrap();
    let resolved = a.resolve(&item.id, Some(kept), &heads).unwrap();
    let mut passkeys = a.get(&item.id).unwrap().item.passkeys.clone();
    passkeys.sort_by(|one, other| one.user_name.cmp(&other.user_name));
    assert_eq!(passkeys, [on_a.passkey.clone(), on_b.passkey.clone()]);

    // So does restoring the version from before either was made.
    a.restore(&item.id, &base, &[resolved.revision]).unwrap();
    let restored = a.get(&item.id).unwrap().item;
    assert_eq!(restored.passkeys.len(), 2);
    assert_eq!(a.history(&item.id).unwrap()[0].changed, Vec::<&str>::new());

    // A version that is no login cannot be kept over one with passkeys.
    let mut b_card = b.get(&item.id).unwrap();
    b_card.item.passkeys.clear();
    b_card.item.kind = ItemKind::Card;
    let card = b.update(b_card.item, &b_card.revision).unwrap();
    let current = a.get(&item.id).unwrap();
    let mut on_a_again = current.item.clone();
    on_a_again.title = "Example, again".into();
    a.update(on_a_again, &current.revision).unwrap();
    // B's chain is missing its parent on A: send it in order.
    for revision in [from_b.revision, card.revision.clone()] {
        let _ = a.apply_encrypted_revision(sent(&b, &revision));
    }
    let versions = a.versions(&item.id).unwrap();
    let heads = versions
        .iter()
        .map(|version| version.revision.clone())
        .collect::<Vec<_>>();
    let card_version = versions
        .into_iter()
        .find(|version| version.revision == card.revision)
        .unwrap();
    assert!(matches!(
        a.resolve(&item.id, card_version.item, &heads),
        Err(Error::InvalidItem(_))
    ));
}

#[test]
fn a_bitwarden_logins_passkeys_come_in_and_one_this_app_cannot_use_is_named() {
    let key = SigningKey::from_slice(&counting::<32>(0x21)).unwrap();
    let pkcs8 = b64(SecretKey::from(&key).to_pkcs8_der().unwrap().as_bytes());
    let credential = |id: &str, rp_id: &str, curve: &str| {
        json!({
            "credentialId": id,
            "keyType": "public-key",
            "keyAlgorithm": "ECDSA",
            "keyCurve": curve,
            "keyValue": pkcs8,
            "rpId": rp_id,
            "userHandle": b64(&[9; 16]),
            "userName": "owner",
            "counter": "5",
            "rpName": "Example",
            "userDisplayName": "Owner",
            "discoverable": "true",
            "creationDate": "2024-01-31T10:05:33.123Z",
        })
    };
    let export = json!({
        "items": [
            {
                "type": 1,
                "name": "Example",
                "login": {
                    "username": "owner",
                    "password": "password",
                    "uris": [{ "uri": "https://example.test" }],
                    "fido2Credentials": [
                        credential("1ea5bb16-0f4e-4a35-a7d3-7f8e0c3b1d2a", "example.test", "P-256"),
                        credential("b64.AAECAw", "login.example.test", "P-256"),
                        credential("b64.BAUG", "example.test", "P-384"),
                        credential("b64.BwgJ", "com", "P-256"),
                        credential("not a guid", "example.test", "P-256"),
                    ],
                },
            },
            {
                "type": 1,
                "name": "No passkeys",
                "login": { "username": "u", "password": "p", "fido2Credentials": null },
            },
        ],
    });
    let preview =
        preview_import(ImportFormat::BitwardenJson, export.to_string().as_bytes()).unwrap();
    assert_eq!(preview.valid_count(), 2);
    let passkeys = &preview.items()[0].passkeys;
    assert_eq!(passkeys.len(), 2);
    assert_eq!(
        passkeys[0].credential_id,
        b64(&[
            0x1e, 0xa5, 0xbb, 0x16, 0x0f, 0x4e, 0x4a, 0x35, 0xa7, 0xd3, 0x7f, 0x8e, 0x0c, 0x3b,
            0x1d, 0x2a
        ])
    );
    assert_eq!(passkeys[1].credential_id, "AAECAw");
    assert_eq!(
        (
            passkeys[0].created_at,
            passkeys[0].sign_count,
            passkeys[0].user_display_name.as_str()
        ),
        (1_706_695_533, 5, "Owner")
    );
    assert_eq!(passkeys[0].user_handle, b64(&[9; 16]));
    assert!(preview.items()[1].passkeys.is_empty());
    assert_eq!(
        preview
            .warnings()
            .iter()
            .map(|warning| (warning.row, warning.message.as_str()))
            .collect::<Vec<_>>(),
        [(
            1,
            "3 passkeys were not imported: this app takes P-256 keys for a site's domain, at most 32 on a login"
        )]
    );

    let (_dir, mut vault) = vault();
    let stored = vault.confirm_import(preview).unwrap();
    let credential = vault.get(&stored[0].item_id).unwrap().item.passkeys[0]
        .credential_id
        .clone();
    let hash = client_data_hash(b"client data");
    let assertion = vault
        .sign_with_passkey(
            &stored[0].item_id,
            &credential,
            "example.test",
            &hash,
            true,
            NOW,
        )
        .unwrap();
    // It was imported with a counter, so it answers with the time.
    assert_eq!(
        assertion.authenticator_data[33..37],
        (NOW as u32).to_be_bytes()
    );
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&hash);
    key.verifying_key()
        .verify(
            &message,
            &Signature::from_der(&assertion.signature).unwrap(),
        )
        .unwrap();
}

#[test]
fn a_passkeys_key_and_account_are_never_printed() {
    let created = made_for("example.test", "owner-do-not-print");
    let secrets = [created.passkey.key.clone(), "owner-do-not-print".to_owned()];
    let mut item = Item::new("Example");
    item.passkeys.push(created.passkey.clone());
    let (_dir, mut vault) = vault();
    let saved = vault.put(item.clone()).unwrap();
    let found = vault.passkeys_for("example.test", &[]).unwrap();
    for printed in [
        format!("{:?}", created.passkey),
        format!("{created:?}"),
        format!("{item:?}"),
        format!("{:?}", vault.get(&saved.item_id).unwrap()),
        format!("{:?}", created.passkey.summary()),
        format!("{found:?}"),
        format!("{:?}", vector_request()),
    ] {
        for secret in &secrets {
            assert!(
                !printed.contains(secret.as_str()),
                "printed a secret: {printed}"
            );
        }
    }
}

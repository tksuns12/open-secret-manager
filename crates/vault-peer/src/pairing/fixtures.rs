//! The frozen pairing formats: the invitation's text, the join request, the
//! transcript both sides hash, the short code, and the enrollment grant.

use ed25519_dalek::{Signer, SigningKey};
use osm_vault_core::{verify_pairing_signature, PAIRING_SIGNATURE_DOMAIN};
use osm_vault_sync::HpkeKeyPair;
use serde_json::json;

use super::*;
use crate::fixture::{counting, frozen, hex, sent, unhex};

/// A pairing signature by `key`, as a device makes one.
fn signed(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let mut covered = PAIRING_SIGNATURE_DOMAIN.to_vec();
    covered.extend_from_slice(message);
    key.sign(&covered).to_bytes().to_vec()
}

#[test]
fn pairing_messages_are_the_frozen_ones() {
    let vault_id: [u8; 32] = counting(0x10);
    let inviter_id: [u8; 16] = counting(0x40);
    let inviter_key = SigningKey::from_bytes(&counting(0x60));
    let inviter_public = inviter_key.verifying_key().to_bytes();
    let inviter_pin: [u8; 32] = counting(0x20);
    let token: [u8; 32] = counting(0x70);
    let joiner_id: [u8; 16] = counting(0x90);
    let joiner_key = SigningKey::from_bytes(&counting(0xb0));
    let joiner_public = joiner_key.verifying_key().to_bytes();
    let joiner_hpke = HpkeKeyPair::from_secret(&counting(0x30))
        .public()
        .as_bytes();
    let joiner_pin: [u8; 32] = counting(0xd0);
    let addresses = vec![
        "192.0.2.10:47820".to_owned(),
        "[2001:db8::1]:47820".to_owned(),
    ];

    let invitation = Invitation {
        body: InvitationBody {
            version: PAIRING_VERSION,
            vault_id,
            inviter_device_id: inviter_id,
            inviter_public_key: inviter_public,
            inviter_transport_pin: inviter_pin,
            addresses: addresses.clone(),
            token,
            expires_at: 1_800_000_000,
        },
    };
    let text = invitation.encode().unwrap();

    let mut request = JoinRequest {
        version: PAIRING_VERSION,
        vault_id,
        token,
        joiner_device_id: joiner_id,
        joiner_public_key: joiner_public,
        joiner_hpke_key: joiner_hpke,
        joiner_transport_pin: joiner_pin,
        signature: Vec::new(),
    };
    let transcript = transcript(
        &Inviter {
            vault_id: &vault_id,
            device_id: &inviter_id,
            public_key: &inviter_public,
            transport_pin: &inviter_pin,
            token: &token,
        },
        &request,
    );
    request.signature = signed(&joiner_key, &request_message(&transcript));
    verify_pairing_signature(
        &joiner_public,
        &request_message(&transcript),
        &request.signature,
    )
    .unwrap();

    let grant = |recovery_check, members: Vec<MemberContact>, inviter_port| {
        let mut grant = EnrollmentGrant {
            version: PAIRING_VERSION,
            vault_id,
            request_id: counting(0xe0),
            recovery_check,
            members,
            inviter_port,
            signature: Vec::new(),
        };
        grant.signature = signed(&inviter_key, &grant.signed_message(&transcript));
        verify_pairing_signature(
            &inviter_public,
            &grant.signed_message(&transcript),
            &grant.signature,
        )
        .unwrap();
        json!({
            "signed_message": hex(&grant.signed_message(&transcript)),
            "signature": hex(&grant.signature),
            "sent": sent(&grant),
        })
    };
    let members = vec![
        MemberContact {
            device_id: inviter_id,
            transport_pin: inviter_pin,
            address: Some("192.0.2.10:47821".into()),
        },
        MemberContact {
            device_id: counting(0xa0),
            transport_pin: counting(0x01),
            address: None,
        },
    ];

    let made = json!({
        "about": "Pairing messages as this code made them when the formats were frozen. Bytes are lowercase hexadecimal; messages are postcard, sent in a frame of a 4-byte big-endian length and the body. A pairing signature is Ed25519 over osm-pairing-signature-v1, a zero byte, and the signed message. The keys are counting patterns and protect nothing.",
        "inputs": {
            "vault_id": hex(&vault_id),
            "inviter_device_id": hex(&inviter_id),
            "inviter_signing_seed": hex(&counting::<32>(0x60)),
            "inviter_public_key": hex(&inviter_public),
            "inviter_transport_pin": hex(&inviter_pin),
            "addresses": addresses,
            "token": hex(&token),
            "expires_at": 1_800_000_000_u64,
            "joiner_device_id": hex(&joiner_id),
            "joiner_signing_seed": hex(&counting::<32>(0xb0)),
            "joiner_public_key": hex(&joiner_public),
            "joiner_hpke_key": hex(&joiner_hpke),
            "joiner_transport_pin": hex(&joiner_pin),
            "grant_request_id": hex(&counting::<16>(0xe0)),
        },
        "invitation_text": text.as_str(),
        "transcript": hex(&transcript),
        "short_code": short_code(&transcript),
        "join_request": {
            "signed_message": hex(&request_message(&transcript)),
            "signature": hex(&request.signature),
            "sent": sent(&request),
        },
        "enrollment_grant": grant(Some(counting(0x01)), members, Some(47821)),
        "enrollment_grant_with_nothing_optional": grant(None, Vec::new(), None),
    });
    let frozen = frozen("pairing.json", &made);

    // And back: the frozen text and bytes read as what they were.
    let read = Invitation::decode(frozen["invitation_text"].as_str().unwrap()).unwrap();
    assert_eq!(read.encode().unwrap().as_str(), frozen["invitation_text"]);
    assert_eq!(read.vault_id(), vault_id);
    assert_eq!(read.body.inviter_device_id, inviter_id);
    assert_eq!(read.body.token, token);
    assert_eq!(read.addresses(), addresses);
    assert_eq!(read.expires_at(), 1_800_000_000);
    let body = |section: &str| unhex(frozen[section]["sent"]["body"].as_str().unwrap());
    let read: JoinRequest = crate::wire::decode_body(&body("join_request")).unwrap();
    assert_eq!(read.joiner_device_id, joiner_id);
    assert_eq!(read.signature, request.signature);
    let read: EnrollmentGrant = crate::wire::decode_body(&body("enrollment_grant")).unwrap();
    assert_eq!(read.members.len(), 2);
    assert_eq!(read.inviter_port, Some(47821));
    verify_pairing_signature(
        &inviter_public,
        &read.signed_message(&transcript),
        &read.signature,
    )
    .unwrap();

    // An invitation of a later version, with a byte too many, or of the
    // wrong kind is refused.
    let mut later = invitation.body_bytes();
    later[0] = PAIRING_VERSION + 1;
    assert!(matches!(
        Invitation::decode(&format!(
            "{INVITATION_PREFIX}{}",
            Base64UrlUnpadded::encode_string(&later)
        )),
        Err(Error::UnsupportedVersion)
    ));
    let mut longer = invitation.body_bytes();
    longer.push(0);
    assert!(matches!(
        Invitation::decode(&format!(
            "{INVITATION_PREFIX}{}",
            Base64UrlUnpadded::encode_string(&longer)
        )),
        Err(Error::InvalidInvitation)
    ));
    assert!(Invitation::decode(&text.replace("OSM-PAIR1-", "OSM-PAIR2-")).is_err());
}

impl Invitation {
    fn body_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&self.body).unwrap()
    }
}

/// An invitation and a join request carry a bearer token, which their
/// printed forms leave out.
#[test]
fn an_invitation_and_a_join_request_print_no_token() {
    let token: [u8; 32] = counting(0x70);
    let invitation = Invitation {
        body: InvitationBody {
            version: PAIRING_VERSION,
            vault_id: counting(0x10),
            inviter_device_id: counting(0x40),
            inviter_public_key: counting(0x60),
            inviter_transport_pin: counting(0x20),
            addresses: vec!["192.0.2.10:47820".into()],
            token,
            expires_at: 1_800_000_000,
        },
    };
    let request = JoinRequest {
        version: PAIRING_VERSION,
        vault_id: counting(0x10),
        token,
        joiner_device_id: counting(0x90),
        joiner_public_key: counting(0xb0),
        joiner_hpke_key: counting(0x30),
        joiner_transport_pin: counting(0xd0),
        signature: vec![0; 64],
    };
    let text = invitation.encode().unwrap();
    for printed in [format!("{invitation:?}"), format!("{request:?}")] {
        for secret in [
            hex(&token),
            format!("{token:?}"),
            text.to_string(),
            text[10..30].to_owned(),
        ] {
            assert!(!printed.contains(&secret), "{printed}");
        }
    }
}

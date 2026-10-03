//! Envelopes and invitation tokens from outside are refused unless they are
//! exactly right. The cases are new on every run; a failing one is kept in
//! `proptest-regressions/`.

use proptest::prelude::*;

use crate::{
    open_epoch_key, seal_epoch_key, DeviceId, EpochKeyEnvelope, HpkeKeyPair, InvitationPolicy,
    InvitationStore, InvitationToken, VaultId,
};

proptest! {
    /// Any bytes are an envelope only if they have its exact length and
    /// magic, and then they read back as themselves.
    #[test]
    fn any_bytes_are_an_envelope_only_in_its_exact_form(
        bytes in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..240),
            prop::collection::vec(any::<u8>(), 184).prop_map(|rest| [b"OSK1".to_vec(), rest].concat()),
        ],
    ) {
        if let Ok(envelope) = EpochKeyEnvelope::from_bytes(&bytes) {
            prop_assert_eq!(bytes.len(), 188);
            prop_assert_eq!(&bytes[..4], b"OSK1");
            let written = envelope.to_bytes();
            prop_assert_eq!(written.as_slice(), bytes.as_slice());
        }
    }

    /// An envelope sealed to one recipient opens for it alone, and a changed
    /// bit anywhere stops it from opening.
    #[test]
    fn an_envelope_opens_only_unchanged_and_only_for_its_recipient(
        secret in any::<[u8; 32]>(),
        other in any::<[u8; 32]>(),
        key in any::<[u8; 32]>(),
        epoch in 1_u64..1 << 32,
        flip in prop::option::of((0_usize..188, 0_u8..8)),
    ) {
        prop_assume!(secret != other);
        let pair = HpkeKeyPair::from_secret(&secret);
        let (vault, recipient) = (VaultId([7; 32]), DeviceId([9; 32]));
        let mut bytes = seal_epoch_key(vault, epoch, recipient, pair.public(), &key).unwrap().to_bytes().to_vec();
        if let Some((at, bit)) = flip {
            bytes[at] ^= 1 << bit;
        }
        let opened = EpochKeyEnvelope::from_bytes(&bytes)
            .and_then(|envelope| open_epoch_key(&envelope, vault, epoch, recipient, pair.private()));
        match flip {
            None => prop_assert_eq!(*opened.unwrap(), key),
            Some(_) => prop_assert!(opened.is_err()),
        }
        let envelope = EpochKeyEnvelope::from_bytes(&seal_epoch_key(vault, epoch, recipient, pair.public(), &key).unwrap().to_bytes()).unwrap();
        prop_assert!(open_epoch_key(&envelope, vault, epoch, recipient, HpkeKeyPair::from_secret(&other).private()).is_err());
    }

    /// A token that was not issued opens no invitation.
    #[test]
    fn a_token_that_was_not_issued_is_refused(guesses in prop::collection::vec(any::<[u8; 32]>(), 1..20)) {
        let mut store = InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap();
        let issued = store.issue_pairing(VaultId([1; 32]), 100, 200).unwrap();
        for guess in guesses {
            prop_assume!(&guess != issued.expose_secret());
            prop_assert!(store.check(&InvitationToken::from_bytes(guess), 150).is_err());
        }
        prop_assert!(store.check(&issued, 150).is_ok());
    }
}

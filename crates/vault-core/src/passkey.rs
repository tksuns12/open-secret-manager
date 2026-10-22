//! Passkeys: the WebAuthn credentials a login keeps, and the authenticator
//! that makes and uses them.
//!
//! A passkey is a key pair for one site, the relying party, which names
//! itself by a domain: its RP ID. One made here is ES256, ECDSA over P-256
//! with SHA-256. Its private key is kept with the login, so it goes to the
//! owner's devices and into backups as a password does.
//!
//! What a site is sent follows WebAuthn Level 3. Registering sends the
//! authenticator data with the public key in COSE form, in an attestation
//! object of format "none". Signing in sends the authenticator data and a
//! DER signature over it followed by the hash of the client data. The flags
//! say that the owner was present, that the passkey may be and is backed
//! up, since it syncs, and that the owner was verified only when the owner
//! was verified in that same request.
//!
//! What happens here is pure. The apps decide who is asking, verify the
//! owner when the site wants it, and save what was made with
//! [`Vault::save_passkey_as_login`] or [`Vault::add_passkey`].

use std::{collections::BTreeMap, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    PublicKey, SecretKey,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    model::{other_fields, zeroize_value},
    Error, Item, ItemKind, Origin, Result, RevisionInfo, Vault,
};

/// ES256 as COSE numbers it: the one algorithm of passkeys made here.
pub const ES256: i64 = -7;
/// The most passkeys a login keeps.
pub const MAX_PASSKEYS: usize = 32;
/// The length of a credential ID made here.
const CREDENTIAL_ID_LEN: usize = 16;
/// The longest credential ID WebAuthn allows.
const MAX_CREDENTIAL_ID: usize = 1023;
/// The longest user handle WebAuthn allows.
const MAX_USER_HANDLE: usize = 64;
/// How much of a site's name for an account is kept, in characters.
const MAX_NAME: usize = 256;
/// The longest challenge read.
const MAX_CHALLENGE: usize = 1024;
/// The largest request read, in bytes of JSON.
const MAX_OPTIONS: usize = 64 * 1024;
/// The most credentials a request may name.
const MAX_DESCRIPTORS: usize = 256;

// The authenticator data's flags.
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const ATTESTED: u8 = 0x40;

/// A passkey made here attests no make or model: its AAGUID is zeros.
const AAGUID: [u8; 16] = [0; 16];

/// A passkey, as a login keeps it in the `passkeys` field.
///
/// Reading takes what a later build wrote as it is: its values are checked
/// only when this device writes a passkey it did not read (see
/// [`check_written`]), so that a later build's passkey, of another
/// algorithm perhaps, is kept rather than refused.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passkey {
    /// The credential's ID, in base64url without padding.
    pub credential_id: String,
    /// The site it is for.
    pub rp_id: String,
    /// The site's ID for the account, in base64url without padding.
    pub user_handle: String,
    /// The site's name for the account, and the name it shows for it.
    pub user_name: String,
    pub user_display_name: String,
    /// The key's algorithm as COSE numbers it: [`ES256`].
    pub algorithm: i64,
    /// The private key: PKCS #8 in base64url without padding.
    pub key: String,
    /// When it was made, in seconds since 1970, by the clock of the device
    /// that made it; 0 when not known.
    pub created_at: u64,
    /// The signature counter it was imported with; 0 for one made here,
    /// which counts nothing (see [`Passkey::assert`]).
    pub sign_count: u32,
    /// The fields of a later build, kept as for an item.
    #[serde(flatten, deserialize_with = "other_fields")]
    pub unknown_fields: BTreeMap<String, Value>,
}

/// This build's names for a passkey's fields, which an unknown field may
/// not take.
const PASSKEY_FIELDS: [&str; 9] = [
    "credential_id",
    "rp_id",
    "user_handle",
    "user_name",
    "user_display_name",
    "algorithm",
    "key",
    "created_at",
    "sign_count",
];

impl Drop for Passkey {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        self.rp_id.zeroize();
        self.user_handle.zeroize();
        self.user_name.zeroize();
        self.user_display_name.zeroize();
        self.key.zeroize();
        for (mut name, mut value) in std::mem::take(&mut self.unknown_fields) {
            name.zeroize();
            zeroize_value(&mut value);
        }
    }
}

impl fmt::Debug for Passkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passkey([REDACTED])")
    }
}

/// What may be shown of a passkey. Never its key.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeySummary {
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub created_at: u64,
}

impl fmt::Debug for PasskeySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeySummary([REDACTED])")
    }
}

impl Passkey {
    pub fn summary(&self) -> PasskeySummary {
        PasskeySummary {
            credential_id: self.credential_id.clone(),
            rp_id: self.rp_id.clone(),
            user_name: self.user_name.clone(),
            user_display_name: self.user_display_name.clone(),
            created_at: self.created_at,
        }
    }

    /// Checks a passkey this device is about to write and did not read:
    /// IDs WebAuthn allows, a site a passkey may be for, and an ES256 key
    /// that parses.
    fn check(&self) -> Result<()> {
        let invalid = |what: &str| Err(Error::InvalidItem(format!("a passkey's {what}")));
        if stored_bytes(&self.credential_id, MAX_CREDENTIAL_ID).is_none() {
            return invalid("credential ID is not one WebAuthn allows");
        }
        if !rp_id_valid(&self.rp_id) {
            return invalid("site is not one a passkey may be for");
        }
        if stored_bytes(&self.user_handle, MAX_USER_HANDLE).is_none() {
            return invalid("user handle is not one WebAuthn allows");
        }
        if self.user_name.chars().count() > MAX_NAME
            || self.user_display_name.chars().count() > MAX_NAME
        {
            return invalid("account name is too long");
        }
        if self.algorithm != ES256 || self.signing_key().is_err() {
            return invalid("key is not an ES256 key");
        }
        if self
            .unknown_fields
            .keys()
            .any(|name| PASSKEY_FIELDS.contains(&name.as_str()))
        {
            return invalid("unknown field has the name of a known one");
        }
        Ok(())
    }

    fn signing_key(&self) -> Result<SigningKey> {
        let der = zeroize::Zeroizing::new(
            Base64UrlUnpadded::decode_vec(&self.key).map_err(|_| Error::Crypto)?,
        );
        SigningKey::from_pkcs8_der(&der).map_err(|_| Error::Crypto)
    }

    /// Signs in to the site: the authenticator data, and the signature over
    /// it followed by `client_data_hash`.
    ///
    /// Devices that share a passkey cannot agree on a counter, so one made
    /// here counts nothing: its counter is always 0, which tells the site
    /// so. One imported with a counter above 0, which the site may hold,
    /// answers with the time in seconds instead, which only grows.
    pub fn assert(
        &self,
        client_data_hash: &[u8; 32],
        verified: bool,
        now: u64,
    ) -> Result<Assertion> {
        if self.algorithm != ES256 {
            return Err(Error::InvalidItem(
                "this app cannot sign with that passkey's key".into(),
            ));
        }
        let key = self.signing_key()?;
        let credential_id = stored_bytes(&self.credential_id, MAX_CREDENTIAL_ID)
            .ok_or_else(|| Error::InvalidItem("a passkey's credential ID is not valid".into()))?;
        let user_handle = stored_bytes(&self.user_handle, MAX_USER_HANDLE)
            .ok_or_else(|| Error::InvalidItem("a passkey's user handle is not valid".into()))?;
        let counter = match self.sign_count {
            0 => 0,
            imported => u32::try_from(now).unwrap_or(u32::MAX).max(imported),
        };
        let authenticator_data = authenticator_data(&self.rp_id, flags(verified), counter, None);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(client_data_hash);
        let signature: Signature = key.sign(&signed);
        Ok(Assertion {
            credential_id,
            authenticator_data,
            signature: signature.to_der().as_bytes().to_vec(),
            user_handle,
        })
    }
}

/// What a site is sent to sign in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// ECDSA, DER encoded.
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

impl Assertion {
    /// The `AuthenticationResponseJSON` a site reads, with `client_data`
    /// as its client data.
    pub fn response_json(&self, client_data: &[u8]) -> String {
        json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": b64(client_data),
                "authenticatorData": b64(&self.authenticator_data),
                "signature": b64(&self.signature),
                "userHandle": b64(&self.user_handle),
            },
            "clientExtensionResults": {},
        })
        .to_string()
    }
}

/// What a site is sent when a passkey is made for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    /// The public key as SubjectPublicKeyInfo in DER.
    pub public_key: Vec<u8>,
}

impl Registration {
    /// The `RegistrationResponseJSON` a site reads, with `client_data` as
    /// its client data.
    pub fn response_json(&self, client_data: &[u8]) -> String {
        json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": b64(client_data),
                "attestationObject": b64(&self.attestation_object),
                "authenticatorData": b64(&self.authenticator_data),
                "transports": ["hybrid", "internal"],
                "publicKey": b64(&self.public_key),
                "publicKeyAlgorithm": ES256,
            },
            "clientExtensionResults": { "credProps": { "rk": true } },
        })
        .to_string()
    }
}

/// A passkey just made, to be saved, and what the site is sent.
pub struct Created {
    pub passkey: Passkey,
    pub registration: Registration,
}

impl fmt::Debug for Created {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Created")
            .field("passkey", &self.passkey)
            .field("registration", &self.registration)
            .finish()
    }
}

/// Whether the owner is to be verified, as the site asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserVerification {
    /// The site refuses an answer without it.
    Required,
    /// The site wants it: the owner is verified when the device can.
    Preferred,
    /// The site does not want it: the owner is not.
    Discouraged,
}

impl UserVerification {
    /// As a request names it. A name this build does not know is the
    /// default, as WebAuthn has a client read one.
    fn named(name: Option<&str>) -> Self {
        match name {
            Some("required") => Self::Required,
            Some("discouraged") => Self::Discouraged,
            _ => Self::Preferred,
        }
    }
}

/// Why a request for a passkey is not answered here. The browser's own
/// passkeys, or another provider's, may still answer it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the request is not one this app reads: {0}")]
    Malformed(&'static str),
    /// The site named a domain it may not use passkeys of, or one no
    /// passkey may be for.
    #[error("the site may not use passkeys of the domain it named")]
    RelyingParty,
    /// The site takes no ES256 key.
    #[error("the site takes no key of the kind this app makes")]
    Algorithm,
}

/// Which request a client data is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

/// The client data a browser makes for a request, which the site checks
/// and the signature covers: its type, challenge and origin, in that order,
/// and never from another origin's frame. `origin` is a page's origin or,
/// for an app, the `android:apk-key-hash:` name of its certificate.
pub fn client_data(ceremony: Ceremony, challenge: &[u8], origin: &str) -> Vec<u8> {
    let kind = match ceremony {
        Ceremony::Create => "webauthn.create",
        Ceremony::Get => "webauthn.get",
    };
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":{},"crossOrigin":false}}"#,
        b64(challenge),
        Value::from(origin)
    )
    .into_bytes()
}

/// The origin an Android app has in a client data: `android:apk-key-hash:`
/// and the SHA-256 of the app's signing certificate in base64url. A site
/// that takes passkeys from the app checks it against the app's.
pub fn android_app_origin(certificate_sha256: &[u8; 32]) -> String {
    format!("android:apk-key-hash:{}", b64(certificate_sha256))
}

/// The SHA-256 hash of a client data, which an authenticator signs.
pub fn client_data_hash(client_data: &[u8]) -> [u8; 32] {
    Sha256::digest(client_data).into()
}

/// Whether a passkey may be for `rp_id` at all. It must be a domain in
/// lower case ASCII, as the URL standard writes one, with no dot at the
/// end. It may not be an address, and it may not be a public suffix by the
/// public suffix list, its private section included: a passkey for
/// `github.io` would be one for every site under it.
pub fn rp_id_valid(rp_id: &str) -> bool {
    let labels = || rp_id.split('.');
    let label_valid = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    // The URL standard reads a host whose last label is a number as an
    // IPv4 address.
    let last = labels().next_back().unwrap_or_default();
    let numeric = last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    rp_id.len() <= 253 && labels().all(label_valid) && !numeric && psl::domain_str(rp_id).is_some()
}

/// Whether a page of `origin` may use passkeys for `rp_id`: the origin's
/// host is the RP ID itself, or a name under it.
pub fn rp_id_allowed(rp_id: &str, origin: &Origin) -> bool {
    let host = origin.host();
    rp_id_valid(rp_id)
        && (host == rp_id
            || host
                .strip_suffix(rp_id)
                .is_some_and(|rest| rest.ends_with('.')))
}

/// A request to make a passkey, as checked: what the owner is asked, and
/// what is made.
#[derive(Clone, PartialEq, Eq)]
pub struct Registering {
    pub rp_id: String,
    /// The site's name for itself, as it gave it: for showing only.
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub challenge: Vec<u8>,
    /// The credentials the site already has for the account. When the
    /// vault holds one of them, the request is refused, but only once the
    /// owner has chosen to save, so a site learns nothing from it before.
    pub exclude: Vec<Vec<u8>>,
    pub user_verification: UserVerification,
}

impl fmt::Debug for Registering {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registering")
            .field("rp_id", &self.rp_id)
            .field("user_verification", &self.user_verification)
            .finish_non_exhaustive()
    }
}

/// A request to sign in, as checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signing {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    /// The credentials the site takes, when it names any; otherwise any of
    /// the site's.
    pub allowed: Vec<Vec<u8>>,
    pub user_verification: UserVerification,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreationJson {
    rp: RelyingPartyJson,
    user: UserJson,
    challenge: String,
    #[serde(default, deserialize_with = "or_default")]
    pub_key_cred_params: Vec<ParameterJson>,
    #[serde(default, deserialize_with = "or_default")]
    exclude_credentials: Vec<DescriptorJson>,
    #[serde(default, deserialize_with = "or_default")]
    authenticator_selection: SelectionJson,
}

#[derive(Deserialize)]
struct RelyingPartyJson {
    #[serde(default, deserialize_with = "or_default")]
    id: Option<String>,
    #[serde(default, deserialize_with = "or_default")]
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserJson {
    id: String,
    #[serde(default, deserialize_with = "or_default")]
    name: String,
    #[serde(default, deserialize_with = "or_default")]
    display_name: String,
}

#[derive(Deserialize)]
struct ParameterJson {
    #[serde(rename = "type")]
    kind: String,
    alg: i64,
}

#[derive(Deserialize)]
struct DescriptorJson {
    #[serde(rename = "type")]
    kind: String,
    id: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SelectionJson {
    #[serde(default, deserialize_with = "or_default")]
    user_verification: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestJson {
    challenge: String,
    #[serde(default, deserialize_with = "or_default")]
    rp_id: Option<String>,
    #[serde(default, deserialize_with = "or_default")]
    allow_credentials: Vec<DescriptorJson>,
    #[serde(default, deserialize_with = "or_default")]
    user_verification: Option<String>,
}

/// A value a request may give as null, read as if left out.
fn or_default<'de, D: Deserializer<'de>, T: Default + Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<T, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Reads a request's JSON, as WebAuthn's `toJSON` writes it, binary values
/// in base64url. What it has besides is not read.
fn read<T: for<'de> Deserialize<'de>>(options: &str) -> std::result::Result<T, Refusal> {
    if options.len() > MAX_OPTIONS {
        return Err(Refusal::Malformed("the request is too large"));
    }
    serde_json::from_str(options).map_err(|_| Refusal::Malformed("the request does not read"))
}

/// The RP ID of a request: as named, or else the page's host. `origin` is
/// the page's, or `None` for an app, which must name the site; its RP ID
/// is then only checked to be one a passkey may be for.
fn rp_id_of(
    named: Option<String>,
    origin: Option<&Origin>,
) -> std::result::Result<String, Refusal> {
    let rp_id = match (named, origin) {
        (Some(rp_id), _) => rp_id,
        (None, Some(origin)) => origin.host().to_owned(),
        (None, None) => return Err(Refusal::Malformed("an app's request names no site")),
    };
    let allowed = match origin {
        Some(origin) => rp_id_allowed(&rp_id, origin),
        None => rp_id_valid(&rp_id),
    };
    if allowed {
        Ok(rp_id)
    } else {
        Err(Refusal::RelyingParty)
    }
}

/// The credential IDs a request names, of the one type there is.
fn descriptors(listed: &[DescriptorJson]) -> std::result::Result<Vec<Vec<u8>>, Refusal> {
    if listed.len() > MAX_DESCRIPTORS {
        return Err(Refusal::Malformed("the request names too many credentials"));
    }
    listed
        .iter()
        .filter(|descriptor| descriptor.kind == "public-key")
        .map(|descriptor| {
            requested_bytes(&descriptor.id, MAX_CREDENTIAL_ID)
                .filter(|id| !id.is_empty())
                .ok_or(Refusal::Malformed("a credential ID"))
        })
        .collect()
}

fn challenge_of(text: &str) -> std::result::Result<Vec<u8>, Refusal> {
    requested_bytes(text, MAX_CHALLENGE)
        .filter(|challenge| !challenge.is_empty())
        .ok_or(Refusal::Malformed("the challenge"))
}

/// A site's name for an account, cut to what is kept.
fn name_of(name: &str) -> String {
    name.chars().take(MAX_NAME).collect()
}

impl Registering {
    /// Reads and checks a request to make a passkey:
    /// `PublicKeyCredentialCreationOptionsJSON`. `origin` is the page's, or
    /// `None` for an app.
    pub fn from_options(
        options: &str,
        origin: Option<&Origin>,
    ) -> std::result::Result<Self, Refusal> {
        let options: CreationJson = read(options)?;
        let rp_id = rp_id_of(options.rp.id, origin)?;
        // No parameters stands for the defaults, of which ES256 is one.
        if !options.pub_key_cred_params.is_empty()
            && !options
                .pub_key_cred_params
                .iter()
                .any(|parameter| parameter.kind == "public-key" && parameter.alg == ES256)
        {
            return Err(Refusal::Algorithm);
        }
        let user_handle = requested_bytes(&options.user.id, MAX_USER_HANDLE)
            .filter(|handle| !handle.is_empty())
            .ok_or(Refusal::Malformed("the user handle"))?;
        Ok(Self {
            rp_id,
            rp_name: name_of(&options.rp.name),
            user_handle,
            user_name: name_of(&options.user.name),
            user_display_name: name_of(&options.user.display_name),
            challenge: challenge_of(&options.challenge)?,
            exclude: descriptors(&options.exclude_credentials)?,
            user_verification: UserVerification::named(
                options.authenticator_selection.user_verification.as_deref(),
            ),
        })
    }

    /// Makes a passkey for this request, with a new key and credential ID.
    /// `verified` says the owner was verified in this request.
    pub fn create(&self, verified: bool, now: u64) -> Result<Created> {
        let mut credential_id = [0_u8; CREDENTIAL_ID_LEN];
        OsRng.fill_bytes(&mut credential_id);
        self.create_with(
            &SigningKey::random(&mut OsRng),
            &credential_id,
            verified,
            now,
        )
    }

    pub(crate) fn create_with(
        &self,
        key: &SigningKey,
        credential_id: &[u8],
        verified: bool,
        now: u64,
    ) -> Result<Created> {
        let point = key.verifying_key().to_encoded_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            return Err(Error::Crypto);
        };
        let cose_key = {
            let mut cbor = Cbor::default();
            cbor.map(5);
            cbor.int(1); // kty: EC2
            cbor.int(2);
            cbor.int(3); // alg
            cbor.int(ES256);
            cbor.int(-1); // crv: P-256
            cbor.int(1);
            cbor.int(-2); // x
            cbor.bytes(x);
            cbor.int(-3); // y
            cbor.bytes(y);
            cbor.0
        };
        let authenticator_data = authenticator_data(
            &self.rp_id,
            flags(verified) | ATTESTED,
            0,
            Some((credential_id, &cose_key)),
        );
        let attestation_object = {
            let mut cbor = Cbor::default();
            cbor.map(3);
            cbor.text("fmt");
            cbor.text("none");
            cbor.text("attStmt");
            cbor.map(0);
            cbor.text("authData");
            cbor.bytes(&authenticator_data);
            cbor.0
        };
        let public_key = PublicKey::from(key.verifying_key())
            .to_public_key_der()
            .map_err(|_| Error::Crypto)?
            .into_vec();
        let private_key = SecretKey::from(key)
            .to_pkcs8_der()
            .map_err(|_| Error::Crypto)?;
        Ok(Created {
            passkey: Passkey {
                credential_id: b64(credential_id),
                rp_id: self.rp_id.clone(),
                user_handle: b64(&self.user_handle),
                user_name: self.user_name.clone(),
                user_display_name: self.user_display_name.clone(),
                algorithm: ES256,
                key: b64(private_key.as_bytes()),
                created_at: now,
                sign_count: 0,
                unknown_fields: BTreeMap::new(),
            },
            registration: Registration {
                credential_id: credential_id.to_vec(),
                authenticator_data,
                attestation_object,
                public_key,
            },
        })
    }
}

impl Signing {
    /// Reads and checks a request to sign in:
    /// `PublicKeyCredentialRequestOptionsJSON`. `origin` is the page's, or
    /// `None` for an app.
    pub fn from_options(
        options: &str,
        origin: Option<&Origin>,
    ) -> std::result::Result<Self, Refusal> {
        let options: RequestJson = read(options)?;
        Ok(Self {
            rp_id: rp_id_of(options.rp_id, origin)?,
            challenge: challenge_of(&options.challenge)?,
            allowed: descriptors(&options.allow_credentials)?,
            user_verification: UserVerification::named(options.user_verification.as_deref()),
        })
    }
}

/// The flags of every answer: the owner was present, and the passkey may
/// be and is backed up; verified, when the owner was in this request.
fn flags(verified: bool) -> u8 {
    let verified = if verified { USER_VERIFIED } else { 0 };
    USER_PRESENT | BACKUP_ELIGIBLE | BACKED_UP | verified
}

/// Authenticator data: the hash of the RP ID, the flags, the counter, and
/// for a passkey just made its credential ID and public key.
fn authenticator_data(
    rp_id: &str,
    flags: u8,
    counter: u32,
    attested: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    if let Some((credential_id, cose_key)) = attested {
        data.extend_from_slice(&AAGUID);
        // At most MAX_CREDENTIAL_ID, which fits.
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(cose_key);
    }
    data
}

/// Just the CBOR the answers need, each map's keys given in CTAP2's
/// canonical order.
#[derive(Default)]
struct Cbor(Vec<u8>);

impl Cbor {
    fn head(&mut self, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..=23 => self.0.push(major | value as u8),
            24..=0xff => self.0.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                self.0.push(major | 25);
                self.0.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(major | 26);
                self.0.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(major | 27);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
    }

    fn int(&mut self, value: i64) {
        match u64::try_from(value) {
            Ok(value) => self.head(0, value),
            Err(_) => self.head(1, !value as u64),
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.head(2, bytes.len() as u64);
        self.0.extend_from_slice(bytes);
    }

    fn text(&mut self, text: &str) {
        self.head(3, text.len() as u64);
        self.0.extend_from_slice(text.as_bytes());
    }

    fn map(&mut self, entries: u64) {
        self.head(5, entries);
    }
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Bytes a passkey keeps in base64url, written as this code writes them:
/// without padding, and between 1 and `max` long.
fn stored_bytes(text: &str, max: usize) -> Option<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(text)
        .ok()
        .filter(|bytes| (1..=max).contains(&bytes.len()))
}

/// Bytes a request names in base64url, padded or not, at most `max` long.
fn requested_bytes(text: &str, max: usize) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    if text.len() > max.div_ceil(3) * 4 {
        return None;
    }
    Base64UrlUnpadded::decode_vec(text)
        .ok()
        .filter(|bytes| bytes.len() <= max)
}

/// A passkey from another app's export, if it is one this app can use and
/// keep (see [`Passkey::check`]): its key is written again as this app
/// writes one.
#[allow(clippy::too_many_arguments)]
pub(crate) fn imported(
    credential_id: &[u8],
    rp_id: &str,
    user_handle: &[u8],
    user_name: &str,
    user_display_name: &str,
    key: &[u8],
    created_at: u64,
    sign_count: u32,
) -> Option<Passkey> {
    let key = SigningKey::from_pkcs8_der(key).ok()?;
    let key = SecretKey::from(&key).to_pkcs8_der().ok()?;
    let passkey = Passkey {
        credential_id: b64(credential_id),
        rp_id: rp_id.to_owned(),
        user_handle: b64(user_handle),
        user_name: name_of(user_name),
        user_display_name: name_of(user_display_name),
        algorithm: ES256,
        key: b64(key.as_bytes()),
        created_at,
        sign_count,
        unknown_fields: BTreeMap::new(),
    };
    passkey.check().is_ok().then_some(passkey)
}

/// The same passkey: a site's credential ID names one.
fn same_credential(one: &Passkey, other: &Passkey) -> bool {
    one.rp_id == other.rp_id && one.credential_id == other.credential_id
}

/// Checks the passkeys of an item this device writes, following the
/// versions in `followed`, which it read. What it read is taken as it is.
/// Of the rest: only a login keeps passkeys, and so the type of a login
/// that has one cannot change; a login keeps at most [`MAX_PASSKEYS`]; a
/// passkey is there once; and each must pass [`Passkey::check`].
pub(crate) fn check_written(item: &Item, followed: &[Item]) -> Result<()> {
    if item.passkeys.is_empty() {
        return Ok(());
    }
    if item.kind != ItemKind::Login
        && !followed
            .iter()
            .any(|before| before.kind == item.kind && !before.passkeys.is_empty())
    {
        return Err(Error::InvalidItem(
            "only a login keeps passkeys: remove them first".into(),
        ));
    }
    let added = item
        .passkeys
        .iter()
        .filter(|passkey| {
            !followed
                .iter()
                .any(|before| before.passkeys.contains(passkey))
        })
        .collect::<Vec<_>>();
    if !added.is_empty() && item.passkeys.len() > MAX_PASSKEYS {
        return Err(Error::InvalidItem(format!(
            "a login keeps at most {MAX_PASSKEYS} passkeys"
        )));
    }
    for passkey in added {
        passkey.check()?;
        if item
            .passkeys
            .iter()
            .filter(|other| same_credential(passkey, other))
            .count()
            > 1
        {
            return Err(Error::InvalidItem(
                "the login has that passkey already".into(),
            ));
        }
    }
    Ok(())
}

/// Adds to a version that settles others the passkeys of theirs it lacks:
/// keeping one version whole, in a conflict or a restore, then loses no
/// passkey of another. The owner removes one afterwards if that was meant.
pub(crate) fn keep_all(item: &mut Item, followed: &[Item]) {
    for before in followed {
        for passkey in &before.passkeys {
            if !item
                .passkeys
                .iter()
                .any(|kept| same_credential(kept, passkey))
            {
                item.passkeys.push(passkey.clone());
            }
        }
    }
}

/// A passkey the vault holds for a site, and the login it is on.
#[derive(Clone, PartialEq, Eq)]
pub struct FoundPasskey {
    pub item_id: String,
    pub title: String,
    pub passkey: PasskeySummary,
}

impl fmt::Debug for FoundPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FoundPasskey")
            .field("item_id", &self.item_id)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// The items whose current versions hold a passkey: every version of
    /// an item in conflict, so that a passkey on either is found.
    fn items_with_passkeys(&self) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        for summary in self.list()? {
            if summary.conflict {
                items.extend(
                    self.versions(&summary.id)?
                        .into_iter()
                        .filter_map(|version| version.item)
                        .filter(|item| !item.passkeys.is_empty()),
                );
            } else if summary.passkeys > 0 {
                items.push(self.get(&summary.id)?.item);
            }
        }
        Ok(items)
    }

    /// The passkeys this app can sign with for `rp_id`: of those IDs only,
    /// when `allowed` names any.
    pub fn passkeys_for(&self, rp_id: &str, allowed: &[Vec<u8>]) -> Result<Vec<FoundPasskey>> {
        let mut found: Vec<FoundPasskey> = Vec::new();
        for item in self.items_with_passkeys()? {
            for passkey in &item.passkeys {
                let named = || {
                    stored_bytes(&passkey.credential_id, MAX_CREDENTIAL_ID)
                        .is_some_and(|id| allowed.contains(&id))
                };
                let listed = found.iter().any(|other| {
                    other.item_id == item.id && other.passkey.credential_id == passkey.credential_id
                });
                if passkey.rp_id == rp_id
                    && passkey.algorithm == ES256
                    && (allowed.is_empty() || named())
                    && !listed
                {
                    found.push(FoundPasskey {
                        item_id: item.id.clone(),
                        title: item.title.clone(),
                        passkey: passkey.summary(),
                    });
                }
            }
        }
        found.sort_by(|one, other| {
            (&one.title, &one.passkey.user_name).cmp(&(&other.title, &other.passkey.user_name))
        });
        Ok(found)
    }

    /// Whether the vault holds a passkey for `rp_id` of one of these
    /// credential IDs: one a request to make a passkey excludes.
    pub fn holds_passkey(&self, rp_id: &str, credential_ids: &[Vec<u8>]) -> Result<bool> {
        if credential_ids.is_empty() {
            return Ok(false);
        }
        Ok(self.items_with_passkeys()?.iter().any(|item| {
            item.passkeys.iter().any(|passkey| {
                passkey.rp_id == rp_id
                    && stored_bytes(&passkey.credential_id, MAX_CREDENTIAL_ID)
                        .is_some_and(|id| credential_ids.contains(&id))
            })
        }))
    }

    /// Saves a passkey just made as a new login, named `title`, for the
    /// site and account it is for.
    pub fn save_passkey_as_login(&mut self, passkey: Passkey, title: &str) -> Result<RevisionInfo> {
        let mut item = Item::new(if title.trim().is_empty() {
            passkey.rp_id.as_str()
        } else {
            title.trim()
        });
        item.username = passkey.user_name.clone();
        item.url = format!("https://{}", passkey.rp_id);
        item.passkeys.push(passkey);
        self.put(item)
    }

    /// Adds a passkey just made to a login, as read at `expected_revision`.
    pub fn add_passkey(
        &mut self,
        item_id: &str,
        expected_revision: &str,
        passkey: Passkey,
    ) -> Result<RevisionInfo> {
        let mut item = self.get(item_id)?.item;
        if item.kind != ItemKind::Login {
            return Err(Error::InvalidItem("only a login keeps passkeys".into()));
        }
        item.passkeys.push(passkey);
        self.update(item, expected_revision)
    }

    /// Removes a login's passkey, as read at `expected_revision`. Its key
    /// stays in the login's earlier versions, and in backups.
    pub fn remove_passkey(
        &mut self,
        item_id: &str,
        expected_revision: &str,
        credential_id: &str,
    ) -> Result<RevisionInfo> {
        let mut item = self.get(item_id)?.item;
        let before = item.passkeys.len();
        item.passkeys
            .retain(|passkey| passkey.credential_id != credential_id);
        if item.passkeys.len() == before {
            return Err(Error::NotFound);
        }
        self.update(item, expected_revision)
    }

    /// Signs in to `rp_id` with a passkey of the item, of any of its
    /// current versions (see [`Passkey::assert`]).
    pub fn sign_with_passkey(
        &self,
        item_id: &str,
        credential_id: &str,
        rp_id: &str,
        client_data_hash: &[u8; 32],
        verified: bool,
        now: u64,
    ) -> Result<Assertion> {
        let items = self.items_with_passkeys()?;
        let passkey = items
            .iter()
            .filter(|item| item.id == item_id)
            .flat_map(|item| &item.passkeys)
            .find(|passkey| passkey.credential_id == credential_id)
            .ok_or(Error::NotFound)?;
        if passkey.rp_id != rp_id {
            return Err(Error::OriginMismatch);
        }
        passkey.assert(client_data_hash, verified, now)
    }
}

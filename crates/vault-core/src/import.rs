use std::collections::{BTreeMap, HashMap};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    card, crypto::random_array, passkey, Error, ImportFormat, ImportPreview, ImportWarning, Item,
    ItemKind, Passkey, Result,
};

const MAX_IMPORT_BYTES: usize = 128 * 1024 * 1024;
/// More entries than any export of a person's logins has; a file with more
/// is some other file.
const MAX_IMPORT_ITEMS: usize = 100_000;

pub fn preview_import(format: ImportFormat, bytes: &[u8]) -> Result<ImportPreview> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(Error::InvalidImport("input is too large".into()));
    }
    let (items, warnings) = match format {
        ImportFormat::BitwardenJson => parse_bitwarden(bytes)?,
        ImportFormat::ChromeCsv => parse_csv(bytes, CsvFlavor::Chrome)?,
        ImportFormat::FirefoxCsv => parse_csv(bytes, CsvFlavor::Firefox)?,
    };
    if items.is_empty() {
        return Err(Error::InvalidImport("no valid entries found".into()));
    }
    if items.len() > MAX_IMPORT_ITEMS {
        return Err(too_many());
    }
    Ok(ImportPreview {
        items,
        warnings,
        confirmation_id: random_array(),
    })
}

#[derive(Deserialize)]
struct BitwardenExport {
    #[serde(default)]
    items: Vec<BitwardenItem>,
}

#[derive(Deserialize)]
struct BitwardenItem {
    #[serde(rename = "type")]
    item_type: u8,
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    favorite: bool,
    login: Option<BitwardenLogin>,
    #[serde(default)]
    fields: Vec<BitwardenField>,
    card: Option<BTreeMap<String, Value>>,
    identity: Option<BTreeMap<String, Value>>,
}

#[derive(Deserialize)]
struct BitwardenLogin {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<BitwardenUri>,
    #[serde(default, rename = "fido2Credentials")]
    passkeys: Option<Vec<BitwardenPasskey>>,
}

/// A passkey as Bitwarden exports one: every value text.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenPasskey {
    /// A GUID, for its 16 bytes, or `b64.` and the bytes in base64url.
    credential_id: Option<String>,
    key_type: Option<String>,
    key_algorithm: Option<String>,
    key_curve: Option<String>,
    /// PKCS #8, in base64url.
    key_value: Option<String>,
    rp_id: Option<String>,
    user_handle: Option<String>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    counter: Option<String>,
    creation_date: Option<String>,
}

impl BitwardenPasskey {
    /// The passkey, if it is one this app can use and keep.
    fn passkey(&self) -> Option<Passkey> {
        if self.key_type.as_deref().unwrap_or("public-key") != "public-key"
            || self.key_algorithm.as_deref() != Some("ECDSA")
            || self.key_curve.as_deref() != Some("P-256")
        {
            return None;
        }
        let id = self.credential_id.as_deref()?;
        let credential_id = match id.strip_prefix("b64.") {
            Some(encoded) => decoded(encoded)?,
            None => guid_bytes(id)?,
        };
        let key = Zeroizing::new(decoded(self.key_value.as_deref()?)?);
        passkey::imported(
            &credential_id,
            self.rp_id.as_deref()?,
            &decoded(self.user_handle.as_deref()?)?,
            self.user_name.as_deref().unwrap_or_default(),
            self.user_display_name.as_deref().unwrap_or_default(),
            &key,
            self.creation_date
                .as_deref()
                .and_then(seconds_of)
                .unwrap_or_default(),
            self.counter
                .as_deref()
                .and_then(|counter| counter.trim().parse().ok())
                .unwrap_or_default(),
        )
    }
}

impl Drop for BitwardenPasskey {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        self.key_value.zeroize();
        self.rp_id.zeroize();
        self.user_handle.zeroize();
        self.user_name.zeroize();
        self.user_display_name.zeroize();
    }
}

/// Bytes in base64url, or in base64, padded or not.
fn decoded(text: &str) -> Option<Vec<u8>> {
    let text: Zeroizing<String> = Zeroizing::new(
        text.trim_end_matches('=')
            .chars()
            .map(|char| match char {
                '+' => '-',
                '/' => '_',
                other => other,
            })
            .collect(),
    );
    Base64UrlUnpadded::decode_vec(&text).ok()
}

/// The 16 bytes of a GUID, in the order it is written.
fn guid_bytes(guid: &str) -> Option<Vec<u8>> {
    let hyphens = [8, 13, 18, 23];
    if guid.len() != 36
        || !guid.char_indices().all(|(at, char)| {
            if hyphens.contains(&at) {
                char == '-'
            } else {
                char.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    let digits = guid.replace('-', "");
    (0..32)
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).ok())
        .collect()
}

/// Seconds since 1970 of a time as an export writes it,
/// `2024-01-31T10:05:33.123Z`; `None` for any other form.
fn seconds_of(time: &str) -> Option<u64> {
    let (date, clock) = time.strip_suffix('Z')?.split_once('T')?;
    let numbers = |text: &str, separator| {
        let parts = text
            .split(separator)
            .map(|part| {
                (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                    .then(|| part.parse::<i64>().ok())
                    .flatten()
            })
            .collect::<Option<Vec<_>>>()?;
        <[i64; 3]>::try_from(parts).ok()
    };
    let [year, month, day] = numbers(date, '-')?;
    let [hour, minute, second] = numbers(clock.split('.').next()?, ':')?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Days since 1970 of a date in the Gregorian calendar.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + of_era * 365 + of_era / 4 - of_era / 100 + of_year - 719_468;
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

#[derive(Deserialize)]
struct BitwardenUri {
    #[serde(default)]
    uri: String,
}

#[derive(Deserialize)]
struct BitwardenField {
    name: Option<String>,
    value: Option<String>,
}

// What an export holds is wiped once it has been read: values moved into
// items leave empty strings behind, and anything skipped is not left in
// freed memory. The file's own bytes belong to the caller.
impl Drop for BitwardenItem {
    fn drop(&mut self) {
        self.name.zeroize();
        self.notes.zeroize();
        for values in [&mut self.card, &mut self.identity].into_iter().flatten() {
            values.values_mut().for_each(wipe);
        }
    }
}

impl Drop for BitwardenLogin {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.totp.zeroize();
        for uri in &mut self.uris {
            uri.uri.zeroize();
        }
    }
}

impl Drop for BitwardenField {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

/// Wipes the strings inside a JSON value.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(fields) => fields.values_mut().for_each(wipe),
        _ => {}
    }
}

fn too_many() -> Error {
    Error::InvalidImport(format!("more than {MAX_IMPORT_ITEMS} entries"))
}

fn parse_bitwarden(bytes: &[u8]) -> Result<(Vec<Item>, Vec<ImportWarning>)> {
    // Where the file stops being a Bitwarden export, and nothing of what it
    // says there: the parser's own message quotes the value it met, which
    // can be a password.
    let export: BitwardenExport = serde_json::from_slice(bytes).map_err(|error| {
        Error::InvalidImport(format!(
            "not a Bitwarden JSON export (line {}, column {})",
            error.line(),
            error.column()
        ))
    })?;
    if export.items.len() > MAX_IMPORT_ITEMS {
        return Err(too_many());
    }
    let mut items = Vec::with_capacity(export.items.len());
    let mut warnings = Vec::new();
    let mut export = export;
    for (index, mut source) in std::mem::take(&mut export.items).into_iter().enumerate() {
        let row = index + 1;
        let kind = match source.item_type {
            1 => ItemKind::Login,
            2 => ItemKind::SecureNote,
            3 => ItemKind::Card,
            4 => ItemKind::Identity,
            other => {
                warnings.push(ImportWarning {
                    row,
                    message: format!("unsupported Bitwarden item type {other}; skipped"),
                });
                continue;
            }
        };
        if source.name.trim().is_empty() {
            warnings.push(ImportWarning {
                row,
                message: "empty title; skipped".into(),
            });
            continue;
        }
        // Values are taken out, not copied, so that what is wiped when the
        // parsed export is dropped is what was not used.
        let mut custom_fields = BTreeMap::new();
        for field in &mut source.fields {
            if let (Some(name), Some(value)) = (field.name.take(), field.value.take()) {
                if !name.is_empty() {
                    custom_fields.insert(name, value);
                }
            }
        }
        flatten_values(&mut custom_fields, source.card.as_mut());
        flatten_values(&mut custom_fields, source.identity.as_mut());
        let (username, password, url, totp_secret) = source
            .login
            .as_mut()
            .map(|login| {
                (
                    std::mem::take(&mut login.username),
                    std::mem::take(&mut login.password),
                    login
                        .uris
                        .iter_mut()
                        .find(|uri| !uri.uri.is_empty())
                        .map(|uri| std::mem::take(&mut uri.uri))
                        .unwrap_or_default(),
                    login.totp.take().filter(|value| !value.trim().is_empty()),
                )
            })
            .unwrap_or_default();
        if !url.is_empty() && url::Url::parse(&url).is_err() {
            warnings.push(ImportWarning {
                row,
                message: "URL is not absolute; imported unchanged".into(),
            });
        }
        let mut passkeys = Vec::new();
        let mut left = 0;
        let exported = source
            .login
            .as_ref()
            .and_then(|login| login.passkeys.as_ref());
        for exported in exported.into_iter().flatten() {
            match exported.passkey() {
                Some(passkey)
                    if kind == ItemKind::Login
                        && passkeys.len() < passkey::MAX_PASSKEYS
                        && !passkeys.iter().any(|kept: &Passkey| {
                            kept.rp_id == passkey.rp_id
                                && kept.credential_id == passkey.credential_id
                        }) =>
                {
                    passkeys.push(passkey)
                }
                _ => left += 1,
            }
        }
        if left > 0 {
            warnings.push(ImportWarning {
                row,
                message: format!(
                    "{left} passkey{} not imported: this app takes P-256 keys for a site's domain, \
                     at most {} on a login",
                    if left == 1 { " was" } else { "s were" },
                    passkey::MAX_PASSKEYS
                ),
            });
        }
        items.push(Item {
            id: Uuid::new_v4().to_string(),
            title: std::mem::take(&mut source.name),
            kind,
            username,
            password,
            url,
            notes: std::mem::take(&mut source.notes),
            totp_secret,
            custom_fields,
            tags: Vec::new(),
            favorite: source.favorite,
            passkeys,
            unknown_fields: BTreeMap::new(),
        });
    }
    Ok((items, warnings))
}

/// A Bitwarden card or identity field's name as the owner reads it; one
/// this build does not know keeps the export's own.
fn readable(name: &str) -> String {
    match name {
        "cardholderName" => card::CARDHOLDER,
        "brand" => card::BRAND,
        "number" => card::NUMBER,
        "expMonth" => card::EXPIRY_MONTH,
        "expYear" => card::EXPIRY_YEAR,
        "code" => card::SECURITY_CODE,
        "title" => "Title",
        "firstName" => "First name",
        "middleName" => "Middle name",
        "lastName" => "Last name",
        "address1" => "Address line 1",
        "address2" => "Address line 2",
        "address3" => "Address line 3",
        "city" => "City",
        "state" => "State or province",
        "postalCode" => "Postal code",
        "country" => "Country",
        "company" => "Company",
        "email" => "Email",
        "phone" => "Phone",
        "ssn" => "Social security number",
        "username" => "Username",
        "passportNumber" => "Passport number",
        "licenseNumber" => "License number",
        other => other,
    }
    .to_owned()
}

fn flatten_values(
    target: &mut BTreeMap<String, String>,
    values: Option<&mut BTreeMap<String, Value>>,
) {
    for (name, value) in values.into_iter().flatten() {
        let string = match value {
            Value::String(value) => std::mem::take(value),
            Value::Number(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            _ => continue,
        };
        match target.entry(readable(name)) {
            std::collections::btree_map::Entry::Vacant(slot) if !string.is_empty() => {
                slot.insert(string);
            }
            // Not used: a field of that name is there already.
            _ => {
                let mut string = string;
                string.zeroize();
            }
        }
    }
}

#[derive(Clone, Copy)]
enum CsvFlavor {
    Chrome,
    Firefox,
}

fn parse_csv(bytes: &[u8], flavor: CsvFlavor) -> Result<(Vec<Item>, Vec<ImportWarning>)> {
    // Header names are normalized below; field values, especially passwords,
    // must retain leading/trailing whitespace exactly as exported.
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::None)
        .from_reader(bytes);
    let headers = reader.headers()?.clone();
    let indices: HashMap<String, usize> = headers
        .iter()
        .enumerate()
        .map(|(index, name)| (name.trim().to_ascii_lowercase(), index))
        .collect();
    let url_key = match flavor {
        CsvFlavor::Chrome => "url",
        CsvFlavor::Firefox => "url",
    };
    require_header(&indices, url_key)?;
    require_header(&indices, "username")?;
    require_header(&indices, "password")?;
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for (offset, record) in reader.records().enumerate() {
        let row = offset + 2;
        let record = record?;
        if items.len() >= MAX_IMPORT_ITEMS {
            return Err(too_many());
        }
        let url = field(&record, &indices, "url");
        let username = field(&record, &indices, "username");
        let password = field(&record, &indices, "password");
        let mut title = field(&record, &indices, "name");
        // An item needs a title that is more than blanks.
        if title.trim().is_empty() {
            title = if !url.trim().is_empty() {
                url.clone()
            } else if !username.trim().is_empty() {
                username.clone()
            } else {
                format!("Imported login {row}")
            };
            warnings.push(ImportWarning {
                row,
                message: "missing title; generated one".into(),
            });
        }
        if !url.is_empty() && url::Url::parse(&url).is_err() {
            warnings.push(ImportWarning {
                row,
                message: "URL is not absolute; imported unchanged".into(),
            });
        }
        let notes = match flavor {
            CsvFlavor::Chrome => field(&record, &indices, "note"),
            CsvFlavor::Firefox => {
                let realm = field(&record, &indices, "httprealm");
                let origin = field(&record, &indices, "formactionorigin");
                [
                    (!realm.is_empty()).then(|| format!("HTTP realm: {realm}")),
                    (!origin.is_empty()).then(|| format!("Form action: {origin}")),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("\n")
            }
        };
        items.push(Item {
            id: Uuid::new_v4().to_string(),
            title,
            kind: ItemKind::Login,
            username,
            password,
            url,
            notes,
            totp_secret: None,
            custom_fields: BTreeMap::new(),
            tags: Vec::new(),
            favorite: false,
            passkeys: Vec::new(),
            unknown_fields: BTreeMap::new(),
        });
    }
    Ok((items, warnings))
}

fn require_header(indices: &HashMap<String, usize>, name: &str) -> Result<()> {
    if indices.contains_key(name) {
        Ok(())
    } else {
        Err(Error::InvalidImport(format!(
            "missing required column {name}"
        )))
    }
}

fn field(record: &csv::StringRecord, indices: &HashMap<String, usize>, name: &str) -> String {
    indices
        .get(name)
        .and_then(|index| record.get(*index))
        .unwrap_or_default()
        .to_owned()
}

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, seq::SliceRandom};
use sha1::Sha1;
use url::Url;
use zeroize::Zeroizing;

use crate::{Error, PasswordPolicy, Result};

/// The characters of each kind a generated password takes, before the
/// look-alikes are left out. The desktop window's preview mirrors them
/// (`apps/desktop/src/bridge.ts`), which a test of the desktop app checks.
pub const PASSWORD_LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub const PASSWORD_UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const PASSWORD_DIGITS: &str = "0123456789";
pub const PASSWORD_SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:,.?";
/// What [`PasswordPolicy::avoid_look_alike`] leaves out: `l`, `I`, and `1`,
/// taken for one another, and `O` and `0`.
pub const PASSWORD_LOOK_ALIKES: &str = "lIO01";

/// The characters of each kind `policy` chose, in the order above.
fn character_sets(policy: &PasswordPolicy) -> Vec<Vec<u8>> {
    let letters = policy.lowercase || policy.uppercase;
    [
        (policy.lowercase, PASSWORD_LOWERCASE, true),
        (policy.uppercase, PASSWORD_UPPERCASE, true),
        // Digits alone, as for a PIN, have no letter to be taken for.
        (policy.digits, PASSWORD_DIGITS, letters),
        (policy.symbols, PASSWORD_SYMBOLS, true),
    ]
    .into_iter()
    .filter(|(chosen, _, _)| *chosen)
    .map(|(_, set, look_alikes_matter)| {
        set.bytes()
            .filter(|byte| {
                !(policy.avoid_look_alike
                    && look_alikes_matter
                    && PASSWORD_LOOK_ALIKES.as_bytes().contains(byte))
            })
            .collect()
    })
    .collect()
}

/// A new password as `policy` asks, from the system's random source.
/// Refused when no kind of character is chosen, or the length is below the
/// number of kinds chosen or above 1024.
pub fn generate_password(policy: &PasswordPolicy) -> Result<String> {
    let groups = character_sets(policy);
    if groups.is_empty() {
        return Err(Error::InvalidItem(
            "password policy has no character sets".into(),
        ));
    }
    if !(groups.len()..=1024).contains(&policy.length) {
        return Err(Error::InvalidItem(
            "password length is outside the allowed range".into(),
        ));
    }
    let alphabet = groups
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect::<Vec<_>>();
    let mut bytes = Zeroizing::new(Vec::with_capacity(policy.length));
    for group in &groups {
        bytes.push(*group.choose(&mut OsRng).ok_or(Error::Crypto)?);
    }
    while bytes.len() < policy.length {
        bytes.push(*alphabet.choose(&mut OsRng).ok_or(Error::Crypto)?);
    }
    bytes.shuffle(&mut OsRng);
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::Crypto)
}

pub fn totp_code(secret_or_uri: &str, unix_time: u64) -> Result<String> {
    let config = parse_totp(secret_or_uri)?;
    if config.digits != 6 && config.digits != 8 {
        return Err(Error::InvalidItem("TOTP digits must be 6 or 8".into()));
    }
    if config.period == 0 {
        return Err(Error::InvalidItem("TOTP period must be positive".into()));
    }
    let secret = Zeroizing::new(decode_base32(&config.secret)?);
    if secret.len() < 10 {
        return Err(Error::InvalidItem("TOTP secret is too short".into()));
    }
    let counter = (unix_time / config.period).to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(&secret).map_err(|_| Error::Crypto)?;
    mac.update(&counter);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.pow(config.digits);
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = config.digits as usize
    ))
}

struct TotpConfig {
    secret: String,
    digits: u32,
    period: u64,
}

fn parse_totp(value: &str) -> Result<TotpConfig> {
    if !value.starts_with("otpauth://") {
        return Ok(TotpConfig {
            secret: value.to_owned(),
            digits: 6,
            period: 30,
        });
    }
    let url = Url::parse(value).map_err(|_| Error::InvalidItem("invalid otpauth URI".into()))?;
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return Err(Error::InvalidItem(
            "only TOTP otpauth URIs are supported".into(),
        ));
    }
    let mut secret = None;
    let mut digits = 6;
    let mut period = 30;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "secret" => secret = Some(value.into_owned()),
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| Error::InvalidItem("invalid TOTP digits".into()))?
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| Error::InvalidItem("invalid TOTP period".into()))?
            }
            "algorithm" if !value.eq_ignore_ascii_case("SHA1") => {
                return Err(Error::InvalidItem("only SHA1 TOTP is supported".into()))
            }
            _ => {}
        }
    }
    Ok(TotpConfig {
        secret: secret.ok_or_else(|| Error::InvalidItem("missing TOTP secret".into()))?,
        digits,
        period,
    })
}

fn decode_base32(value: &str) -> Result<Vec<u8>> {
    let mut bits = 0_u32;
    let mut bit_count = 0_u8;
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    for byte in value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'-' && *byte != b'=')
    {
        let value = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(Error::InvalidItem("invalid base32 TOTP secret".into())),
        };
        bits = (bits << 5) | u32::from(value);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1_u32 << bit_count) - 1;
        }
    }
    if output.is_empty() {
        return Err(Error::InvalidItem("empty TOTP secret".into()));
    }
    Ok(output)
}

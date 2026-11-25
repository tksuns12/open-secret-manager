//! Which logins hold a password worth changing: one that is weak for a
//! reason that can be shown, or one that several logins share.
//!
//! This is a judgement made here, on this device, from what the unlocked
//! vault holds. Nothing is looked up, nothing leaves, and the result names
//! items and reasons, never a password. Which logins share a password is
//! itself worth keeping private, so the result is made when asked for and
//! kept by no one.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::model::{Item, ItemKind};

/// Passwords shorter than this are weak.
pub const MIN_LENGTH: usize = 8;
/// A password of one kind of character (only lowercase, only digits, ...)
/// is weak below this length.
pub const MIN_LENGTH_OF_ONE_KIND: usize = 12;
/// A word of the item's own (its username, title or site) is only looked
/// for in a password when it is this long: a shorter one is found by chance.
const MIN_OWN_WORD: usize = 4;
/// Bound on the prefix of an item's title or username checked by
/// [`holds_own_name`], and on the number of title words checked, so an
/// oversized metadata field cannot be used as a substring-matching oracle.
const MAX_OWN_NAME_CHARS: usize = 128;
const MAX_TITLE_WORDS: usize = 8;

/// Why a password is called weak.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Weakness {
    /// Fewer than [`MIN_LENGTH`] characters.
    TooShort,
    /// Only one kind of character (lowercase, uppercase, digits or
    /// symbols) and fewer than [`MIN_LENGTH_OF_ONE_KIND`] characters. A
    /// letter of a script with no case (Hangul, kana, Han) counts as two
    /// kinds: its alphabet is thousands of characters, not 26.
    OneKind,
    /// A password on the list of the commonest, however it is capitalised
    /// or followed by digits and symbols, or a run of one character or of
    /// neighbouring keys or characters (`aaaaaaaa`, `12345678`, `qwertyui`),
    /// with digits and symbols after it.
    Common,
    /// Holds the item's own username, title or site name.
    HoldsOwnName,
}

/// A login whose password is weak, and why.
#[derive(Clone, PartialEq, Eq)]
pub struct WeakPassword {
    pub id: String,
    pub reasons: Vec<Weakness>,
}

/// What the vault's logins say of their passwords.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PasswordHealth {
    /// Logins with a weak password, in id order.
    pub weak: Vec<WeakPassword>,
    /// Sets of logins, each of at least two, that share one password: the
    /// ids of a set in id order, and the sets in the order of their first
    /// id, which tells nothing of the passwords. Two logins for one username
    /// at one site do not make a set: that is a duplicate, not a reuse.
    pub reused: Vec<Vec<String>>,
}

// A debug form that listed which items share a password would be as much as
// a log can know, so these print only how many.
impl std::fmt::Debug for PasswordHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordHealth")
            .field("weak", &self.weak.len())
            .field("reused", &self.reused.len())
            .finish()
    }
}

impl std::fmt::Debug for WeakPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeakPassword")
            .field("reasons", &self.reasons)
            .finish_non_exhaustive()
    }
}

/// A login as reuse needs it: a keyed digest of its password under the
/// check's ephemeral key, and where it is for. Plaintext passwords are not
/// retained across items.
struct Held {
    id: String,
    password_digest: [u8; 32],
    place: (String, String),
}

/// Judges the logins it is given one at a time, so that of an item only
/// what the check needs is held at once, and the ephemeral key is wiped when
/// it is done.
pub struct Check {
    key: Zeroizing<[u8; 32]>,
    weak: Vec<WeakPassword>,
    held: Vec<Held>,
}

impl Default for Check {
    fn default() -> Self {
        Self {
            key: Zeroizing::new(crate::crypto::random_array()),
            weak: Vec::new(),
            held: Vec::new(),
        }
    }
}

impl Check {
    /// Takes `item` in: only a login with a password is judged, as a card's
    /// number or a note's text is not one.
    pub fn add(&mut self, item: &Item) {
        if item.kind != ItemKind::Login || item.password.is_empty() {
            return;
        }
        let reasons = weaknesses(item);
        if !reasons.is_empty() {
            self.weak.push(WeakPassword {
                id: item.id.clone(),
                reasons,
            });
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.key.as_ref())
            .expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(item.password.as_bytes());
        let password_digest: [u8; 32] = mac.finalize().into_bytes().into();
        self.held.push(Held {
            id: item.id.clone(),
            password_digest,
            place: (
                item.username.trim().to_lowercase(),
                site(&item.url).unwrap_or_default(),
            ),
        });
    }

    pub fn finish(mut self) -> PasswordHealth {
        self.weak.sort_by(|a, b| a.id.cmp(&b.id));
        // By keyed password digest; the places of each.
        let mut by_password: BTreeMap<&[u8; 32], Vec<&Held>> = BTreeMap::new();
        for held in &self.held {
            by_password
                .entry(&held.password_digest)
                .or_default()
                .push(held);
        }
        let mut reused: Vec<Vec<String>> = by_password
            .into_values()
            .filter(|sharing| {
                let mut places: Vec<&(String, String)> =
                    sharing.iter().map(|held| &held.place).collect();
                places.sort();
                places.dedup();
                // A login with no site is a place of its own.
                places.len() >= 2
                    || (places.len() == 1 && places[0].1.is_empty() && sharing.len() >= 2)
            })
            .map(|sharing| {
                let mut ids: Vec<String> = sharing.iter().map(|held| held.id.clone()).collect();
                ids.sort();
                ids
            })
            .collect();
        reused.sort();
        PasswordHealth {
            weak: std::mem::take(&mut self.weak),
            reused,
        }
    }
}

/// The health of the passwords of `items`.
pub fn password_health<'a>(items: impl IntoIterator<Item = &'a Item>) -> PasswordHealth {
    let mut check = Check::default();
    for item in items {
        check.add(item);
    }
    check.finish()
}

/// Schemes whose host is a name in the domain system, so that its
/// registrable domain is the site. Of another scheme (`android://`,
/// `androidapp://`) the host is something else, a reversed package name,
/// and is the site as it is.
const NAMED_HOSTS: [&str; 14] = [
    "http", "https", "ftp", "ftps", "sftp", "ssh", "smb", "ws", "wss", "imap", "imaps", "pop3",
    "pop3s", "smtp",
];

/// Whether `address` starts with a scheme: letters, digits, `+`, `-` or `.`
/// from a letter, then `:/`. (`localhost:3000` has none.)
fn scheme_of(address: &str) -> Option<&str> {
    let (scheme, rest) = address.split_once(':')?;
    let mut characters = scheme.chars();
    let first = characters.next()?;
    (first.is_ascii_alphabetic()
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && rest.starts_with('/'))
    .then_some(scheme)
}

/// The site an address is for: the registrable domain of its host, such as
/// `example.co.uk` for `https://login.example.co.uk/in`; an IP address as it
/// is; of a scheme whose host is no domain name, the host as it is; and for
/// an address that is not one, what it says, lowercased. An address with no
/// scheme is read as an https one. Whatever the scheme, `http://example.com`
/// and `https://example.com` are one site. The second is whether it is a
/// domain, which may hold a name.
fn site_of(address: &str) -> Option<(String, bool)> {
    let address = address.trim();
    if address.is_empty() {
        return None;
    }
    let scheme = scheme_of(address).map(str::to_ascii_lowercase);
    let parsed = if scheme.is_some() {
        Url::parse(address)
    } else {
        Url::parse(&format!("https://{address}"))
    };
    let Ok(parsed) = parsed else {
        return Some((address.to_lowercase(), false));
    };
    let named = scheme
        .as_deref()
        .is_none_or(|scheme| NAMED_HOSTS.contains(&scheme));
    Some(match parsed.host() {
        Some(Host::Domain(host)) => {
            let host = host.to_ascii_lowercase();
            // Other schemes hand an address back as text, as a domain, and
            // the list would take its last two numbers for one.
            if host.parse::<std::net::IpAddr>().is_ok() || !named {
                return Some((host, false));
            }
            (
                psl::domain_str(&host).map(str::to_owned).unwrap_or(host),
                true,
            )
        }
        Some(host) => (host.to_string(), false),
        None => (address.to_lowercase(), false),
    })
}

fn site(address: &str) -> Option<String> {
    site_of(address).map(|(site, _)| site)
}

fn weaknesses(item: &Item) -> Vec<Weakness> {
    let password = item.password.as_str();
    let length = password.chars().count();
    let mut reasons = Vec::new();
    if length < MIN_LENGTH {
        reasons.push(Weakness::TooShort);
    }
    if length < MIN_LENGTH_OF_ONE_KIND && kinds(password) == 1 {
        reasons.push(Weakness::OneKind);
    }
    if is_common(password) {
        reasons.push(Weakness::Common);
    }
    if holds_own_name(item) {
        reasons.push(Weakness::HoldsOwnName);
    }
    reasons
}

/// How many of lowercase, uppercase, digits and the rest it holds, a letter
/// of a script with no case counting as a lowercase and an uppercase one.
fn kinds(password: &str) -> usize {
    let mut seen = [false; 4];
    for character in password.chars() {
        if character.is_lowercase() {
            seen[0] = true;
        } else if character.is_uppercase() {
            seen[1] = true;
        } else if character.is_alphabetic() {
            seen[0] = true;
            seen[1] = true;
        } else if character.is_numeric() {
            seen[2] = true;
        } else {
            seen[3] = true;
        }
    }
    seen.iter().filter(|seen| **seen).count()
}

/// Whether the password holds a word that names its item: the username (and
/// what is before an `@` in it), the title, each word of the title and the
/// title run together (`Acme Shop` as `acmeshop`), or the first label of the
/// site's registrable domain (`example` for `https://www.example.com`).
fn holds_own_name(item: &Item) -> bool {
    let password = Zeroizing::new(item.password.to_lowercase());
    let title_prefix: String = item.title.chars().take(MAX_OWN_NAME_CHARS).collect();
    let username_prefix: String = item
        .username
        .trim()
        .chars()
        .take(MAX_OWN_NAME_CHARS)
        .collect();
    let title = title_prefix.to_lowercase();
    let username = username_prefix.to_lowercase();
    let mut words = vec![username.clone(), title.clone()];
    words.extend(
        title
            .split(|c: char| !c.is_alphanumeric())
            .filter(|word| word.chars().count() >= MIN_OWN_WORD)
            .take(MAX_TITLE_WORDS)
            .map(str::to_owned),
    );
    words.push(title.chars().filter(|c| c.is_alphanumeric()).collect());
    if let Some((name, _)) = username.split_once('@') {
        words.push(name.trim().to_owned());
    }
    if let Some((site, true)) = site_of(&item.url) {
        if let Some(label) = site.split('.').next() {
            words.push(label.chars().take(MAX_OWN_NAME_CHARS).collect());
        }
    }
    words
        .iter()
        .filter(|word| word.chars().count() >= MIN_OWN_WORD)
        .any(|word| password.contains(word.as_str()))
}

/// Whether the password is on the list or is a run, as it is, or without the
/// symbols after it, or without the digits and symbols after it: `Password1!`
/// is `password`, `Trustno1!` is `trustno1`, `12345678!` is `12345678`.
fn is_common(password: &str) -> bool {
    let lowered = Zeroizing::new(password.to_lowercase());
    let without_symbols = lowered.trim_end_matches(|c: char| !c.is_alphanumeric());
    let without_digits = lowered.trim_end_matches(|c: char| !c.is_alphabetic());
    let found = [lowered.as_str(), without_symbols, without_digits]
        .into_iter()
        .filter(|candidate| !candidate.is_empty())
        .any(|candidate| COMMON.contains(&candidate) || is_run(candidate));
    found
}

/// All one character, or a stretch of one row of a keyboard, or of the
/// digits (round from 9 to 0) or the alphabet, going up or down, of at least
/// four characters; or a shorter piece repeated (`123123123123`,
/// `passwordpassword`).
fn is_run(password: &str) -> bool {
    // Room for every character at once, so that no copy is left behind by a
    // buffer that grew.
    let mut characters: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(password.len()));
    characters.extend(password.chars());
    if characters.len() < 4 {
        return false;
    }
    if (1..=characters.len() / 2)
        .filter(|unit| characters.len().is_multiple_of(*unit))
        .any(|unit| {
            characters
                .chunks(unit)
                .all(|chunk| chunk == &characters[..unit])
        })
    {
        return true;
    }
    let mut forward: Zeroizing<String> = Zeroizing::new(String::with_capacity(password.len()));
    forward.extend(characters.iter());
    let mut backward: Zeroizing<String> = Zeroizing::new(String::with_capacity(password.len()));
    backward.extend(characters.iter().rev());
    ROWS.iter()
        .any(|row| row.contains(forward.as_str()) || row.contains(backward.as_str()))
}

/// Strings whose stretches are runs.
const ROWS: [&str; 6] = [
    "0123456789012345678901234567890123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1qaz2wsx3edc",
];

/// Common passwords, lowercase, from the lists of passwords most often
/// found in leaks that have been published for years. A short list of the
/// commonest, not a measure of strength: a password not on it is not
/// thereby strong.
const COMMON: &[&str] = &[
    "password",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "pa$$word",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwertyuiop",
    "qwerty123",
    "abc123",
    "111111",
    "000000",
    "123123",
    "654321",
    "iloveyou",
    "admin",
    "administrator",
    "welcome",
    "login",
    "letmein",
    "monkey",
    "dragon",
    "master",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "shadow",
    "superman",
    "batman",
    "trustno1",
    "starwars",
    "hello",
    "freedom",
    "whatever",
    "secret",
    "changeme",
    "default",
    "guest",
    "test",
    "testing",
    "root",
    "toor",
    "access",
    "michael",
    "jordan",
    "jennifer",
    "hunter",
    "ranger",
    "buster",
    "soccer",
    "hockey",
    "killer",
    "george",
    "charlie",
    "andrew",
    "ashley",
    "mustang",
    "summer",
    "love",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn login(id: &str, title: &str, username: &str, url: &str, password: &str) -> Item {
        let mut item = Item::new(title);
        item.id = id.into();
        item.username = username.into();
        item.url = url.into();
        item.password = password.into();
        item
    }

    fn reasons(password: &str) -> Vec<Weakness> {
        let item = login("a", "Shop", "someone", "https://shop.test", password);
        password_health([&item])
            .weak
            .into_iter()
            .next()
            .map(|weak| weak.reasons)
            .unwrap_or_default()
    }

    /// An item with no name, so that only the password is judged.
    fn reasons_of_the_password_alone(password: &str) -> Vec<Weakness> {
        let item = login("a", "", "", "", password);
        password_health([&item])
            .weak
            .into_iter()
            .next()
            .map(|weak| weak.reasons)
            .unwrap_or_default()
    }

    fn shared(a: &str, b: &str) -> bool {
        let one = login("a", "A", "me", a, "rT9#vLm2qXa");
        let two = login("b", "B", "me", b, "rT9#vLm2qXa");
        !password_health([&one, &two]).reused.is_empty()
    }

    #[test]
    fn what_is_weak_says_why() {
        assert_eq!(reasons("aB3$"), [Weakness::TooShort]);
        assert_eq!(reasons("kjhdsfpq"), [Weakness::OneKind]);
        assert_eq!(reasons("31415926"), [Weakness::OneKind]);
        assert_eq!(reasons("Password1!"), [Weakness::Common]);
        assert_eq!(reasons("PASSWORD"), [Weakness::OneKind, Weakness::Common]);
        assert_eq!(reasons("Zq7!shop-x9"), [Weakness::HoldsOwnName]);
        assert!(reasons("rT9#vLm2qXa").is_empty());
    }

    #[test]
    fn a_word_of_the_list_with_digits_and_symbols_after_it_is_common() {
        for common in [
            "Trustno1!",
            "12345678!",
            "Abc123!!",
            "asdfghjkl1",
            "Welcome2024!",
        ] {
            assert!(
                reasons_of_the_password_alone(common).contains(&Weakness::Common),
                "{common}"
            );
        }
        assert!(!reasons_of_the_password_alone("Zq7!welcome-x9Lm").contains(&Weakness::Common));
    }

    #[test]
    fn runs_are_common_and_the_rest_of_a_row_is_not() {
        for run in [
            "12345678", "87654321", "abcdefgh", "qwertyui", "aaaaaaaa", "ZXCVBNM",
        ] {
            assert!(reasons(run).contains(&Weakness::Common), "{run}");
        }
        assert!(!reasons("qwXrtyui9#Zk").contains(&Weakness::Common));
    }

    #[test]
    fn a_long_one_kind_password_is_not_called_weak() {
        assert!(reasons("sdkfjhqwlekjhrqwlekj").is_empty());
    }

    #[test]
    fn a_password_of_a_script_with_no_case_is_not_of_one_kind() {
        assert!(reasons_of_the_password_alone("햇살구름바람노을별빛").is_empty());
        assert!(reasons_of_the_password_alone("ソラニワケイトモ").is_empty());
    }

    #[test]
    fn only_a_login_with_a_password_is_judged() {
        let mut card = login("c", "Card", "", "", "1234");
        card.kind = ItemKind::Card;
        let mut note = login("n", "Note", "", "", "abc");
        note.kind = ItemKind::SecureNote;
        let empty = login("e", "Empty", "", "", "");
        let health = password_health([&card, &note, &empty]);
        assert!(health.weak.is_empty() && health.reused.is_empty());
    }

    #[test]
    fn logins_sharing_a_password_at_different_sites_are_reused() {
        let a = login("a", "A", "me", "https://one.test", "rT9#vLm2qXa");
        let b = login("b", "B", "me", "https://two.test", "rT9#vLm2qXa");
        let c = login("c", "C", "me", "https://three.test", "another-Strong#4");
        let health = password_health([&c, &b, &a]);
        assert_eq!(health.reused, vec![vec!["a".to_owned(), "b".to_owned()]]);
    }

    #[test]
    fn one_username_at_one_site_is_a_duplicate_not_a_reuse() {
        let a = login("a", "A", "Me", "https://www.one.test/in", "rT9#vLm2qXa");
        let b = login("b", "B", "me", "https://app.one.test", "rT9#vLm2qXa");
        assert!(password_health([&a, &b]).reused.is_empty());
        // The same site with another username is a reuse.
        let c = login("c", "C", "you", "https://one.test", "rT9#vLm2qXa");
        assert_eq!(password_health([&a, &b, &c]).reused.len(), 1);
        // Whether it was saved as http or https, with or without a scheme.
        assert!(!shared("http://example.com", "https://example.com"));
        assert!(!shared("example.com", "https://www.example.com/in"));
    }

    #[test]
    fn what_is_not_an_https_address_is_still_a_site() {
        // Other schemes are not read as a host called `http` or `android`.
        assert!(shared("http://forum-a.org", "http://forum-b.org"));
        assert!(shared("https://u@a.org", "https://u@b.org"));
        assert!(shared("ftp://a.org", "ftp://b.org"));
        assert!(shared(
            "android://AAAA@com.alpha.app/",
            "android://BBBB@com.beta.app/"
        ));
        // Addresses of machines are as they are, not their last two numbers.
        assert!(shared("https://192.168.1.1", "https://10.0.1.1"));
        assert!(shared("ssh://192.168.1.1", "ssh://10.0.1.1"));
        assert!(shared("smb://192.168.1.1", "smb://10.0.1.1"));
        assert!(shared("https://[2001:db8::1]", "https://[2001:db8::2]"));
        assert!(!shared("https://192.168.1.1", "http://192.168.1.1/admin"));
        // Whatever is not an address stays what it says.
        assert!(shared("my router", "my nas"));
        assert!(!shared("My Router", "my router"));
    }

    #[test]
    fn an_address_is_read_by_its_own_scheme_and_not_by_what_it_mentions() {
        // A `://` inside the address is not its scheme.
        assert!(!shared("example.com/r?to=http://x", "example.com"));
        assert!(!shared(
            "example.com/in?next=http://x",
            "https://example.com/other"
        ));
        // The secure and mail forms of a host are the same account as the plain one.
        assert!(!shared("wss://www.example.com", "https://www.example.com"));
        assert!(!shared(
            "imap://mail.example.com",
            "https://mail.example.com"
        ));
        assert!(!shared("ftps://ftp.example.com", "ftp://ftp.example.com"));
        // One slash, a typo, is still http.
        assert!(!shared("http:/example.com", "https://example.com"));
        // Apps are told apart by their whole package name, and are not
        // taken for a domain of the public suffix list.
        assert!(shared(
            "android://H@com.alpha.mail.android/",
            "android://H@org.beta.mail.android/"
        ));
        assert!(shared(
            "androidapp://com.facebook.katana",
            "androidapp://com.facebook.orca"
        ));
        assert!(!shared(
            "androidapp://com.facebook.katana",
            "androidapp://com.facebook.katana"
        ));
        // A package's word `android` is not the item's own name.
        let app = login(
            "a",
            "Mail",
            "me",
            "androidapp://com.google.android.gm",
            "Zq7!android9Lm#2",
        );
        assert!(password_health([&app]).weak.is_empty());
    }

    #[test]
    fn a_long_run_and_a_repeated_piece_are_common() {
        for common in [
            "123456789012",
            "1234567890123",
            "0987654321098",
            "123123123123",
            "passwordpassword",
        ] {
            assert!(
                reasons_of_the_password_alone(common).contains(&Weakness::Common),
                "{common}"
            );
        }
        assert!(
            !reasons_of_the_password_alone("rT9#vLm2qXarT9#vLm2qXb").contains(&Weakness::Common)
        );
    }

    #[test]
    fn each_word_of_a_title_is_a_name_of_the_item() {
        let item = |title: &str, password: &str| {
            let item = login("a", title, "someone", "", password);
            password_health([&item])
                .weak
                .into_iter()
                .next()
                .map(|weak| weak.reasons)
        };
        assert_eq!(
            item("Acme Shop", "AcmeShop2024!xQ"),
            Some(vec![Weakness::HoldsOwnName])
        );
        assert_eq!(
            item("My Bank", "MyBank#2024xQz"),
            Some(vec![Weakness::HoldsOwnName])
        );
        assert_eq!(
            item("Acme Shop", "Zq7!Shop-x9Lm#"),
            Some(vec![Weakness::HoldsOwnName])
        );
        assert_eq!(item("Acme Shop", "rT9#vLm2qXa!"), None);
    }

    #[test]
    fn a_username_is_taken_as_it_is_without_the_spaces_around_it() {
        let a = login("a", "A", " me ", "https://one.test", "rT9#vLm2qXa");
        let b = login("b", "B", "me", "https://one.test", "rT9#vLm2qXa");
        assert!(password_health([&a, &b]).reused.is_empty());
    }

    #[test]
    fn logins_with_no_site_that_share_a_password_are_reused() {
        let a = login("a", "A", "me", "", "rT9#vLm2qXa");
        let b = login("b", "B", "me", "", "rT9#vLm2qXa");
        assert_eq!(password_health([&a, &b]).reused.len(), 1);
    }

    #[test]
    fn passwords_that_differ_by_case_are_not_shared() {
        let a = login("a", "A", "me", "https://one.test", "rT9#vLm2qXa");
        let b = login("b", "B", "me", "https://two.test", "Rt9#vLm2qXa");
        assert!(password_health([&a, &b]).reused.is_empty());
    }

    #[test]
    fn the_sets_are_in_the_order_of_their_ids_not_of_their_passwords() {
        let make = |first: &str, second: &str| {
            let a = login("a", "A", "me", "https://one.test", first);
            let b = login("b", "B", "me", "https://two.test", first);
            let c = login("c", "C", "me", "https://three.test", second);
            let d = login("d", "D", "me", "https://four.test", second);
            password_health([&d, &c, &b, &a]).reused
        };
        let expected = vec![
            vec!["a".to_owned(), "b".to_owned()],
            vec!["c".to_owned(), "d".to_owned()],
        ];
        assert_eq!(make("aaa-Zq7!1", "zzz-Zq7!1"), expected);
        assert_eq!(make("zzz-Zq7!1", "aaa-Zq7!1"), expected);
    }

    #[test]
    fn what_is_printed_holds_no_password_and_no_id() {
        let a = login(
            "id-a",
            "A",
            "me",
            "https://one.test",
            "hunter2-do-not-print",
        );
        let b = login(
            "id-b",
            "B",
            "me",
            "https://two.test",
            "hunter2-do-not-print",
        );
        let weak = login("id-w", "W", "me", "https://w.test", "hunter2");
        let health = password_health([&a, &b, &weak]);
        assert_eq!(health.weak.len(), 1);
        let printed = format!("{health:?} {:?}", health.weak[0]);
        for secret in ["hunter2", "id-a", "id-b", "id-w"] {
            assert!(!printed.contains(secret), "{printed}");
        }
    }

    #[test]
    fn the_generators_choices_are_judged_as_meant() {
        use crate::{generate_password, PasswordPolicy};
        // Every length it offers, with all kinds, is never weak by length or
        // kind. The item has no name, so none can be found by chance.
        for length in 8..=64 {
            for _ in 0..20 {
                let password = generate_password(&PasswordPolicy {
                    length,
                    ..PasswordPolicy::default()
                })
                .unwrap();
                let found = reasons_of_the_password_alone(&password);
                // A word of the list can be made by chance, so not `Common`.
                assert!(
                    !found.contains(&Weakness::TooShort) && !found.contains(&Weakness::OneKind),
                    "{length}: {found:?}"
                );
            }
        }
        // Digits alone, or one other kind alone, are one kind: weak when
        // short, which the generator's shortest lengths are.
        for kinds in [(false, false, true, false), (true, false, false, false)] {
            let password = generate_password(&PasswordPolicy {
                length: 8,
                lowercase: kinds.0,
                uppercase: kinds.1,
                digits: kinds.2,
                symbols: kinds.3,
                ..PasswordPolicy::default()
            })
            .unwrap();
            assert!(reasons_of_the_password_alone(&password).contains(&Weakness::OneKind));
        }
    }

    #[test]
    fn holds_own_name_bounds_title_words_and_length() {
        // More than MAX_TITLE_WORDS words: the 9th word is ignored so a huge
        // title cannot batch-probe candidate substrings of the password.
        let many_words = "alpha bravo charlie delta echo foxtrot golf hotel targetword";
        let item = login("a", many_words, "user", "", "Zq7!targetword-x9");
        assert!(password_health([&item]).weak.is_empty());

        // Characters past MAX_OWN_NAME_CHARS in title or username are ignored.
        let long_title = format!("{} targetword", "a".repeat(MAX_OWN_NAME_CHARS));
        let item_long_title = login("b", &long_title, "user", "", "Zq7!targetword-x9");
        assert!(password_health([&item_long_title]).weak.is_empty());

        let long_username = format!("{}@example.test", "b".repeat(MAX_OWN_NAME_CHARS));
        let item_long_user = login("c", "Shop", &long_username, "", "Zq7!example-x9");
        assert!(password_health([&item_long_user]).weak.is_empty());
    }
}

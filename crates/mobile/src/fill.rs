//! Filling another app's form, or a page, from a phone, and saving what it
//! submitted: the one place that decides what a requester is offered, what
//! it is filled, and which login a save may go into. Each phone works out
//! who asks from what its system says (a [`Requester`]); everything after
//! that is decided here, so that a fill path in the app cannot hand a login
//! to someone it was not meant for by leaving out a check.
//!
//! A page is offered and filled only the logins saved for exactly its
//! origin. An app is filled only a login the owner chose for it, which this
//! phone remembers ([`AppChoices`]); the logins of the sites that the system
//! verified name the app as their own are suggested to it, and become its
//! own once the owner chooses one. A requester that names no one is filled
//! only what the owner chooses each time, and nothing is remembered for it.
//! Cards belong to no site: any requester may be filled the card the owner
//! chose.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use osm_vault_core::{Item, ItemKind, Origin, Vault};
use zeroize::Zeroizing;

use crate::{CardFill, FillCredentials, ItemDraft, ItemSummary, MobileError, SaveCandidate};

/// Who asks for a fill or a save, as the phone's system names it: the app
/// works it out from what the system vouches for, never from what the
/// asking app says of itself.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Requester {
    /// Pages of these origins, each as a browser serializes it
    /// (`https://host` or `https://host:port`): on Android, the page a
    /// trusted browser shows over https; on iOS, each domain and https
    /// address the system names, an app's verified associated domains among
    /// them.
    Page { origins: Vec<String> },
    /// An app, by a key the phone makes from what the system says of it,
    /// the same each time the same app asks: on Android its package, its
    /// original signing certificate, and the domain it says it shows, if
    /// any; on iOS its App ID. `linked_domains` are the domains whose sites
    /// the system verified name the app as theirs (Android's verified app
    /// links); none on iOS, which names those as origins.
    App {
        key: String,
        linked_domains: Vec<String>,
    },
    /// A request that names no one.
    Unnamed,
}

/// What a form asks to be filled with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Asks {
    /// A username and a password.
    Login,
    /// Only a one-time code: only logins with one are offered.
    OneTimeCode,
    /// A username, a password, and a one-time code, which a login without
    /// one is filled without.
    LoginAndOneTimeCode,
}

impl Asks {
    fn login(self) -> bool {
        matches!(self, Self::Login | Self::LoginAndOneTimeCode)
    }

    fn code(self) -> bool {
        matches!(self, Self::OneTimeCode | Self::LoginAndOneTimeCode)
    }
}

/// The logins a requester is offered. No secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Offer {
    /// For a page, the logins saved for its origins; for an app, those the
    /// owner chose for it. They fill at once.
    pub logins: Vec<ItemSummary>,
    /// For an app, the logins saved for a site its links were verified for,
    /// that the owner has not chosen for it yet: filled only once the owner
    /// chooses one, which is then the app's.
    pub suggested: Vec<ItemSummary>,
}

/// What fills a form, of what it asked for: given only for a login the
/// requester may be filled.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct Filled {
    pub credentials: Option<FillCredentials>,
    pub one_time_code: Option<String>,
}

impl std::fmt::Debug for Filled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Filled { .. }")
    }
}

/// A requester, read and checked.
enum Asker {
    Page(Vec<Origin>),
    App { key: String, domains: Vec<String> },
    Unnamed,
}

impl Asker {
    fn of(requester: &Requester) -> Result<Self, MobileError> {
        match requester {
            Requester::Page { origins } => {
                if origins.is_empty() {
                    return Err(MobileError::InvalidRequester);
                }
                let origins = origins
                    .iter()
                    .map(|origin| Origin::parse(origin).ok_or(MobileError::InvalidOrigin))
                    .collect::<Result<_, _>>()?;
                Ok(Self::Page(origins))
            }
            Requester::App {
                key,
                linked_domains,
            } => {
                if key.is_empty() {
                    return Err(MobileError::InvalidRequester);
                }
                Ok(Self::App {
                    key: key.clone(),
                    domains: linked_domains
                        .iter()
                        .map(String::as_str)
                        .filter_map(domain)
                        .collect(),
                })
            }
            Requester::Unnamed => Ok(Self::Unnamed),
        }
    }

    /// Whether a login saved at `url` is for one of a page's origins: the
    /// vault's one rule, by the one origin type.
    fn page_has(origins: &[Origin], url: &str) -> bool {
        Origin::of_url(url).is_some_and(|origin| origins.contains(&origin))
    }
}

/// A verified domain of an app's links, as the system lists it: lower case,
/// without `*.` or a trailing dot, and a valid registrable domain (not a
/// public suffix). Preserves `www.` so a `www.` link never widens to apex.
fn domain(listed: &str) -> Option<String> {
    let listed = listed.trim().to_ascii_lowercase();
    let listed = listed.strip_prefix("*.").unwrap_or(&listed);
    let listed = listed.trim_end_matches('.');
    (listed.contains('.') && osm_vault_core::passkey::rp_id_valid(listed))
        .then(|| listed.to_owned())
}

/// Whether a login saved at `url` is for a site on one of an app's verified
/// `domains`, or a host under one: over https on its usual port, as an
/// app's links are.
fn covered(domains: &[String], url: &str) -> bool {
    if domains.is_empty() {
        return false;
    }
    let Some(origin) = Origin::of_url(url) else {
        return false;
    };
    if origin.port() != 443 {
        return false;
    }
    let host = origin.host().trim_end_matches('.');
    domains
        .iter()
        .any(|domain| host == domain || host.ends_with(&format!(".{domain}")))
}

/// The logins among `listed` that a form asking for `asks` could be filled
/// with: every login, or for a code alone, those with a one-time code.
fn fit(
    vault: &Vault,
    listed: Vec<osm_vault_core::ItemSummary>,
    asks: Asks,
) -> Result<Vec<ItemSummary>, MobileError> {
    let mut found = Vec::new();
    for item in listed {
        if item.kind != ItemKind::Login {
            continue;
        }
        if asks == Asks::OneTimeCode && vault.get(&item.id)?.item.totp_secret.is_none() {
            continue;
        }
        found.push(item.into());
    }
    Ok(found)
}

pub(crate) fn offer(
    vault: &Vault,
    choices: &AppChoices,
    requester: &Requester,
    asks: Asks,
) -> Result<Offer, MobileError> {
    let asker = Asker::of(requester)?;
    let listed = vault.list()?;
    let (logins, suggested) = match asker {
        Asker::Page(origins) => (
            listed
                .into_iter()
                .filter(|item| Asker::page_has(&origins, &item.url))
                .collect(),
            Vec::new(),
        ),
        Asker::App { key, domains } => {
            let chosen = choices.chosen(&key);
            listed
                .into_iter()
                .filter(|item| chosen.contains(&item.id) || covered(&domains, &item.url))
                .partition(|item| chosen.contains(&item.id))
        }
        Asker::Unnamed => (Vec::new(), Vec::new()),
    };
    Ok(Offer {
        logins: fit(vault, logins, asks)?,
        suggested: fit(vault, suggested, asks)?,
    })
}

/// Every login a form that `asks` could be filled with, for the owner to
/// choose one from on the phone's screen for an app or a requester that
/// names no one.
pub(crate) fn logins_to_choose(vault: &Vault, asks: Asks) -> Result<Vec<ItemSummary>, MobileError> {
    fit(vault, vault.list()?, asks)
}

/// Fills the login `id` for `requester`, with what `asks` names. Unless
/// `owner_chose` it on the phone's screen just now, only a login the
/// requester is offered: one for a page's origin, or one chosen for an app
/// before. A login the owner chose for an app is remembered for it; a page
/// is filled only its own logins whoever chose.
pub(crate) fn fill(
    vault: &Vault,
    choices: &AppChoices,
    requester: &Requester,
    id: &str,
    asks: Asks,
    owner_chose: bool,
    now: u64,
) -> Result<Filled, MobileError> {
    let asker = Asker::of(requester)?;
    let found = vault.get(id)?;
    let item = &found.item;
    if item.kind != ItemKind::Login {
        return Err(MobileError::NotALogin);
    }
    let remember = match &asker {
        Asker::Page(origins) => {
            if !Asker::page_has(origins, &item.url) {
                return Err(MobileError::NotForThisPage);
            }
            None
        }
        Asker::App { key, .. } => {
            if owner_chose {
                Some(key.as_str())
            } else if choices.chosen(key).contains(id) {
                None
            } else {
                return Err(MobileError::NotChosen);
            }
        }
        Asker::Unnamed => {
            if !owner_chose {
                return Err(MobileError::NotChosen);
            }
            None
        }
    };
    let credentials = asks.login().then(|| FillCredentials {
        username: item.username.clone(),
        password: item.password.clone(),
    });
    let one_time_code = match (asks.code(), item.totp_secret.is_some()) {
        (false, _) => None,
        (true, true) => Some(vault.item_totp_code(id, now)?),
        (true, false) if asks.login() => None,
        (true, false) => return Err(MobileError::NoOneTimeCode),
    };
    if let Some(key) = remember {
        choices.remember(key, id)?;
    }
    Ok(Filled {
        credentials,
        one_time_code,
    })
}

/// Every card not in conflict: any requester may be offered them.
pub(crate) fn offer_cards(vault: &Vault) -> Result<Vec<ItemSummary>, MobileError> {
    Ok(vault
        .list()?
        .into_iter()
        .filter(|item| item.kind == ItemKind::Card && !item.conflict)
        .map(Into::into)
        .collect())
}

/// The fields of the card `id`, as it is kept; refused for an item that is
/// not a card, and for a card two devices changed at once.
pub(crate) fn fill_card(vault: &Vault, id: &str) -> Result<CardFill, MobileError> {
    use osm_vault_core::card;
    let found = vault.get(id)?;
    if found.item.kind != ItemKind::Card {
        return Err(MobileError::NotACard);
    }
    if found.conflict {
        return Err(MobileError::InConflict);
    }
    let field = |name: &str| {
        found
            .item
            .custom_fields
            .get(name)
            .cloned()
            .unwrap_or_default()
    };
    Ok(CardFill {
        cardholder: field(card::CARDHOLDER),
        number: field(card::NUMBER),
        expiry_month: field(card::EXPIRY_MONTH),
        expiry_year: field(card::EXPIRY_YEAR),
        security_code: field(card::SECURITY_CODE),
    })
}

/// Whether what a form of `requester` sent under `username` could go into
/// `item`: a login it could be filled with, not in conflict, under that
/// username (any, if the form sent none).
fn takes_save(
    asker: &Asker,
    choices: &AppChoices,
    item: &Item,
    conflict: bool,
    username: &str,
) -> bool {
    let for_requester = match asker {
        Asker::Page(origins) => Asker::page_has(origins, &item.url),
        Asker::App { key, .. } => choices.chosen(key).contains(&item.id),
        Asker::Unnamed => false,
    };
    let username = username.trim();
    for_requester
        && !conflict
        && item.kind == ItemKind::Login
        && (username.is_empty() || item.username.trim() == username)
}

/// The logins what a form of `requester` submitted could be saved into,
/// and whether each has its password already.
pub(crate) fn save_candidates(
    vault: &Vault,
    choices: &AppChoices,
    requester: &Requester,
    username: &str,
    password: &str,
) -> Result<Vec<SaveCandidate>, MobileError> {
    let asker = Asker::of(requester)?;
    let ids: Vec<String> = match &asker {
        Asker::Page(origins) => vault
            .list()?
            .into_iter()
            .filter(|item| Asker::page_has(origins, &item.url))
            .map(|item| item.id)
            .collect(),
        Asker::App { key, .. } => choices.chosen(key).into_iter().collect(),
        Asker::Unnamed => Vec::new(),
    };
    let mut candidates = Vec::new();
    for id in ids {
        let found = match vault.get(&id) {
            Ok(found) => found,
            Err(osm_vault_core::Error::NotFound) => continue,
            Err(error) => return Err(error.into()),
        };
        if !takes_save(&asker, choices, &found.item, found.conflict, username) {
            continue;
        }
        candidates.push(SaveCandidate {
            id: found.item.id.clone(),
            title: found.item.title.clone(),
            username: found.item.username.clone(),
            revision: found.revision.clone(),
            has_this_password: found.item.password == password,
        });
    }
    Ok(candidates)
}

/// Changes only the password of the login `id`, as read at `revision`, to
/// what a form of `requester` sent under `username`; refused unless it is
/// one of [`save_candidates`].
pub(crate) fn update_saved(
    vault: &mut Vault,
    choices: &AppChoices,
    requester: &Requester,
    id: &str,
    revision: &str,
    username: &str,
    password: String,
) -> Result<(), MobileError> {
    let mut password = Zeroizing::new(password);
    let asker = Asker::of(requester)?;
    if password.is_empty() {
        return Err(MobileError::InvalidItem {
            reason: "there is no password to save".into(),
        });
    }
    let found = vault.get(id)?;
    if found.conflict {
        return Err(MobileError::InConflict);
    }
    if found.item.kind != ItemKind::Login {
        return Err(MobileError::NotALogin);
    }
    if !takes_save(&asker, choices, &found.item, found.conflict, username) {
        return Err(MobileError::NotForThisForm);
    }
    let mut item = found.item;
    // Into the item, which wipes it when it goes.
    item.password = std::mem::take(&mut *password);
    vault.update(item, revision)?;
    Ok(())
}

/// Saves what a form of `requester` sent as a new login, and returns its
/// ID: for a page, saved for its (first) origin; for an app, with no
/// address, and remembered for it; for no one named, with no address.
pub(crate) fn save_new(
    vault: &mut Vault,
    choices: &AppChoices,
    requester: &Requester,
    title: String,
    username: String,
    password: String,
) -> Result<String, MobileError> {
    let mut password = Zeroizing::new(password);
    let asker = Asker::of(requester)?;
    let url = match &asker {
        Asker::Page(origins) => origins[0].to_string(),
        Asker::App { .. } | Asker::Unnamed => String::new(),
    };
    let draft = ItemDraft {
        title,
        kind: crate::ItemKind::Login,
        username,
        url,
        notes: String::new(),
        favorite: false,
        password: Some(std::mem::take(&mut *password)),
        one_time_code_secret: None,
        card: None,
    };
    let mut item = Item::default();
    draft.apply_to(&mut item);
    let id = item.id.clone();
    vault.put(item)?;
    if let Asker::App { key, .. } = &asker {
        choices.remember(key, &id)?;
    }
    Ok(id)
}

/// Which logins the owner chose for which app, on this phone only: kept in
/// `app-logins.json` in the device's folder, a JSON object from each app's
/// key to the IDs of its logins. Not synced, and holding no secret. A file
/// that is missing, or not of that form, is taken for none and replaced at
/// the next choice; an ID no longer in the vault is passed over.
pub(crate) struct AppChoices {
    path: PathBuf,
    /// Held while the file is read, changed, and written again.
    writing: Mutex<()>,
}

type Chosen = BTreeMap<String, BTreeSet<String>>;

impl AppChoices {
    const FILE: &'static str = "app-logins.json";

    pub(crate) fn in_folder(folder: &Path) -> Self {
        Self {
            path: folder.join(Self::FILE),
            writing: Mutex::new(()),
        }
    }

    /// The whole file. A file that cannot be read now is an error, so that
    /// a change does not write over it; one not of the expected form is
    /// none.
    fn read(&self) -> std::io::Result<Chosen> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Chosen::new()),
            Err(error) => Err(error),
        }
    }

    /// The logins chosen for the app `key`. None if the file cannot be read:
    /// nothing is filled rather than something wrong.
    pub(crate) fn chosen(&self, key: &str) -> BTreeSet<String> {
        self.read()
            .ok()
            .and_then(|mut all| all.remove(key))
            .unwrap_or_default()
    }

    fn change(&self, change: impl FnOnce(&mut Chosen) -> bool) -> std::io::Result<()> {
        let _writing = self
            .writing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut all = self.read()?;
        if !change(&mut all) {
            return Ok(());
        }
        // Written whole to a unique sibling with owner-only permissions, then
        // put in place: a stop part-way leaves the file as it was.
        static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let partial = self.path.with_file_name(format!(
            "{}.{}-{seq}.partial",
            Self::FILE,
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let write_result = (|| -> std::io::Result<()> {
            let mut file = options.open(&partial)?;
            file.write_all(&serde_json::to_vec(&all).map_err(std::io::Error::other)?)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&partial, &self.path)
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&partial);
        }
        write_result
    }

    pub(crate) fn remember(&self, key: &str, id: &str) -> std::io::Result<()> {
        self.change(|all| all.entry(key.to_owned()).or_default().insert(id.to_owned()))
    }

    /// Adds the choices an earlier build kept elsewhere to those here.
    pub(crate) fn import(&self, earlier: HashMap<String, Vec<String>>) -> std::io::Result<()> {
        self.change(|all| {
            let mut changed = false;
            for (key, ids) in earlier {
                if key.is_empty() {
                    continue;
                }
                let chosen = all.entry(key).or_default();
                for id in ids {
                    changed |= chosen.insert(id);
                }
            }
            changed
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_apps_listed_domains_are_read_as_android_lists_them() {
        assert_eq!(domain("*.Example.com").as_deref(), Some("example.com"));
        assert_eq!(
            domain("www.example.com.").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            domain(" shop.example.com ").as_deref(),
            Some("shop.example.com")
        );
        for invalid in [
            "localhost",
            "www.",
            "*.",
            "",
            ".com",
            "com",
            "co.uk",
            "github.io",
        ] {
            assert_eq!(domain(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn a_verified_domain_covers_its_hosts_over_https_on_the_usual_port() {
        let domains = vec!["example.com".to_owned()];
        for covered_url in [
            "https://example.com",
            "https://example.com/login",
            "https://shop.example.com/",
            "https://example.com:443/",
            "https://EXAMPLE.com",
        ] {
            assert!(covered(&domains, covered_url), "{covered_url}");
        }
        for other in [
            "http://example.com/",
            "https://example.com:8443/",
            "https://notexample.com/",
            "https://example.com.evil.test/",
            "https://evil.test/example.com",
            "example.com",
            "",
        ] {
            assert!(!covered(&domains, other), "{other}");
        }
        assert!(!covered(&[], "https://example.com"));
    }
}

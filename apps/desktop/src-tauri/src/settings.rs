//! What the owner sets on this device, kept beside the vault in
//! `settings.json`: how many minutes the window waits without activity
//! before it locks the vault, and the password generator's choice. Each
//! device keeps its own; nothing here is synced, and a reset of the device
//! leaves it.

use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use osm_vault_core::PasswordPolicy;
use serde::{Deserialize, Serialize};

use crate::{AppState, CommandError};

/// The waits the owner can choose, in minutes.
pub const AUTO_LOCK_CHOICES: [u32; 5] = [1, 5, 15, 60, 240];
const DEFAULT_AUTO_LOCK: u32 = 5;

/// The lengths the generator offers.
pub const GENERATOR_LENGTHS: RangeInclusive<u32> = 8..=64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub auto_lock_minutes: u32,
    /// Written only once it is not the default, so that the file of a
    /// device that never changed it is as an earlier build wrote it.
    #[serde(skip_serializing_if = "GeneratorChoice::is_default")]
    pub generator: GeneratorChoice,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK,
            generator: GeneratorChoice::default(),
        }
    }
}

/// What the generator makes: a length in [`GENERATOR_LENGTHS`], and at
/// least one kind of character.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorChoice {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_look_alike: bool,
}

impl Default for GeneratorChoice {
    fn default() -> Self {
        let policy = PasswordPolicy::default();
        Self {
            length: policy.length as u32,
            lowercase: policy.lowercase,
            uppercase: policy.uppercase,
            digits: policy.digits,
            symbols: policy.symbols,
            avoid_look_alike: policy.avoid_look_alike,
        }
    }
}

impl GeneratorChoice {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }

    fn allowed(&self) -> bool {
        GENERATOR_LENGTHS.contains(&self.length)
            && (self.lowercase || self.uppercase || self.digits || self.symbols)
    }

    pub fn policy(&self) -> PasswordPolicy {
        PasswordPolicy {
            length: self.length as usize,
            lowercase: self.lowercase,
            uppercase: self.uppercase,
            digits: self.digits,
            symbols: self.symbols,
            avoid_look_alike: self.avoid_look_alike,
        }
    }
}

fn file(vault: &Path) -> PathBuf {
    vault.with_file_name("settings.json")
}

/// The settings kept beside the vault at `vault`. Each is read on its own:
/// one missing, or not as this app writes it, is the default, and leaves
/// the other as it is.
pub fn read(vault: &Path) -> Settings {
    let kept = std::fs::read(file(vault))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let part = |name: &str| kept.as_ref().and_then(|kept| kept.get(name)).cloned();
    Settings {
        auto_lock_minutes: part("autoLockMinutes")
            .and_then(|minutes| serde_json::from_value::<u32>(minutes).ok())
            .filter(|minutes| AUTO_LOCK_CHOICES.contains(minutes))
            .unwrap_or(DEFAULT_AUTO_LOCK),
        generator: part("generator")
            .and_then(|choice| serde_json::from_value::<GeneratorChoice>(choice).ok())
            .filter(GeneratorChoice::allowed)
            .unwrap_or_default(),
    }
}

fn write(vault: &Path, settings: &Settings) -> Result<(), CommandError> {
    let path = file(vault);
    let partial = path.with_extension("json.partial");
    serde_json::to_vec_pretty(settings)
        .map_err(std::io::Error::from)
        .and_then(|bytes| std::fs::write(&partial, bytes))
        .and_then(|()| std::fs::rename(&partial, &path))
        .map_err(|error| CommandError {
            code: "storage",
            message: format!("the settings could not be saved: {error}"),
        })
}

#[tauri::command]
pub fn settings(state: tauri::State<'_, AppState>) -> Settings {
    read(&state.path)
}

/// Sets how many minutes without activity lock the vault: one of
/// [`AUTO_LOCK_CHOICES`].
#[tauri::command]
pub fn set_auto_lock(
    minutes: u32,
    state: tauri::State<'_, AppState>,
) -> Result<Settings, CommandError> {
    set_auto_lock_at(&state.path, minutes)
}

pub(crate) fn set_auto_lock_at(vault: &Path, minutes: u32) -> Result<Settings, CommandError> {
    if !AUTO_LOCK_CHOICES.contains(&minutes) {
        return Err(CommandError {
            code: "invalid_setting",
            message: format!("lock after 1, 5, 15, 60, or 240 minutes, not {minutes}"),
        });
    }
    let settings = Settings {
        auto_lock_minutes: minutes,
        ..read(vault)
    };
    write(vault, &settings)?;
    Ok(settings)
}

/// Sets what the generator makes, from now on in this window.
#[tauri::command]
pub fn set_generator(
    choice: GeneratorChoice,
    state: tauri::State<'_, AppState>,
) -> Result<Settings, CommandError> {
    set_generator_at(&state.path, choice)
}

pub(crate) fn set_generator_at(
    vault: &Path,
    choice: GeneratorChoice,
) -> Result<Settings, CommandError> {
    if !choice.allowed() {
        return Err(CommandError {
            code: "invalid_setting",
            message: format!(
                "a password of {} to {} characters, of at least one kind",
                GENERATOR_LENGTHS.start(),
                GENERATOR_LENGTHS.end()
            ),
        });
    }
    let settings = Settings {
        generator: choice,
        ..read(vault)
    };
    write(vault, &settings)?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_auto_lock_time_is_one_of_five_and_kept_beside_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.sqlite3");
        assert_eq!(read(&vault).auto_lock_minutes, 5);
        assert_eq!(
            set_auto_lock_at(&vault, 240).unwrap().auto_lock_minutes,
            240
        );
        assert_eq!(read(&vault).auto_lock_minutes, 240);
        assert_eq!(set_auto_lock_at(&vault, 15).unwrap().auto_lock_minutes, 15);
        assert_eq!(read(&vault).auto_lock_minutes, 15);
        assert_eq!(
            set_auto_lock_at(&vault, 7).unwrap_err().code,
            "invalid_setting"
        );
        assert_eq!(read(&vault).auto_lock_minutes, 15);
        // What another program left there is not taken for a setting.
        std::fs::write(
            dir.path().join("settings.json"),
            br#"{"autoLockMinutes": 0}"#,
        )
        .unwrap();
        assert_eq!(read(&vault).auto_lock_minutes, 5);
        std::fs::write(dir.path().join("settings.json"), b"not json").unwrap();
        assert_eq!(read(&vault).auto_lock_minutes, 5);
    }

    #[test]
    fn the_generator_choice_is_kept_beside_the_vault_with_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.sqlite3");
        assert_eq!(read(&vault).generator, GeneratorChoice::default());
        assert_eq!(read(&vault).generator.policy(), PasswordPolicy::default());
        set_auto_lock_at(&vault, 15).unwrap();
        let digits = GeneratorChoice {
            length: 8,
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..GeneratorChoice::default()
        };
        assert_eq!(
            set_generator_at(&vault, digits.clone()).unwrap(),
            Settings {
                auto_lock_minutes: 15,
                generator: digits.clone()
            }
        );
        // Each setter keeps what the other set.
        set_auto_lock_at(&vault, 60).unwrap();
        assert_eq!(read(&vault).generator, digits);
        assert_eq!(read(&vault).auto_lock_minutes, 60);

        // Neither a length out of range nor no kind at all is kept.
        for refused in [
            GeneratorChoice {
                length: 7,
                ..GeneratorChoice::default()
            },
            GeneratorChoice {
                length: 65,
                ..GeneratorChoice::default()
            },
            GeneratorChoice {
                digits: false,
                ..digits.clone()
            },
        ] {
            assert_eq!(
                set_generator_at(&vault, refused).unwrap_err().code,
                "invalid_setting"
            );
        }
        assert_eq!(read(&vault).generator, digits);

        // A generator choice not as this app writes it is the default, and
        // leaves the wait as it is.
        std::fs::write(
            dir.path().join("settings.json"),
            br#"{"autoLockMinutes": 15, "generator": {"length": 2}}"#,
        )
        .unwrap();
        assert_eq!(
            read(&vault),
            Settings {
                auto_lock_minutes: 15,
                generator: GeneratorChoice::default()
            }
        );
    }
}

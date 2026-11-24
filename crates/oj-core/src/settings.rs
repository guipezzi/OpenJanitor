//! The user's settings (PLANNING.md §7.4 and D31), saved as
//! `settings.json` in OpenJanitor's data folder.
//!
//! Every choice can only make cleaning more careful than the defaults: the
//! minimum age is a floor on each rule's own, and quarantine retention
//! starts at the default number of days. A file that can't be read, or
//! holds a value outside the choices, is an error. Callers must refuse to
//! scan or clean rather than fall back to defaults, which could be less
//! careful than what the user chose.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use oj_safety::persist::write_atomic;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::clean::{Action, Policy};

/// The `settings.json` format written by this version.
pub const FORMAT_VERSION: u32 = 1;

/// The minimum ages offered, in days. 1 day is the shortest any rule uses.
pub const MIN_AGE_DAYS: [u32; 4] = [1, 3, 7, 30];
/// How long medium-risk files can stay in quarantine, in days.
pub const MEDIUM_DAYS: [u32; 3] = [7, 14, 30];
/// How long files marked "Review" can stay in quarantine, in days.
pub const REVIEW_DAYS: [u32; 3] = [30, 60, 90];

const DAY: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    /// Follow the Windows setting.
    #[default]
    System,
    Light,
    Dark,
}

/// What the user chose. Every field is required in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Files changed more recently than this are left out of scans,
    /// unless a rule waits longer (one of [`MIN_AGE_DAYS`]).
    pub min_age_days: u32,
    /// Low-risk files go to quarantine too, for `medium_days`, instead of
    /// being deleted.
    pub always_quarantine: bool,
    /// One of [`MEDIUM_DAYS`].
    pub medium_days: u32,
    /// One of [`REVIEW_DAYS`].
    pub review_days: u32,
    pub theme: Theme,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            min_age_days: MIN_AGE_DAYS[0],
            always_quarantine: false,
            medium_days: MEDIUM_DAYS[0],
            review_days: REVIEW_DAYS[0],
            theme: Theme::System,
        }
    }
}

/// The values each setting can take, for the Settings screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SettingsChoices {
    pub min_age_days: &'static [u32],
    pub medium_days: &'static [u32],
    pub review_days: &'static [u32],
}

pub const CHOICES: SettingsChoices = SettingsChoices {
    min_age_days: &MIN_AGE_DAYS,
    medium_days: &MEDIUM_DAYS,
    review_days: &REVIEW_DAYS,
};

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("couldn't read the file: {0}")]
    Io(#[from] io::Error),
    #[error("the file isn't valid: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("the file has no format version")]
    NoVersion,
    #[error("the file was written by a newer version of OpenJanitor (format {0})")]
    NewerVersion(u64),
    #[error("{0}")]
    Invalid(String),
}

impl Settings {
    /// Reads `settings.json`. A missing file means the defaults; a damaged
    /// one is an error, never the defaults.
    pub fn load(path: &Path) -> Result<Self, SettingsError> {
        match fs::read(path) {
            Ok(bytes) => Self::from_json(&bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Checks the settings, then saves them atomically.
    pub fn save(&self, path: &Path) -> Result<(), SettingsError> {
        self.validate()?;
        Ok(write_atomic(path, &self.to_json())?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, SettingsError> {
        let mut fields: Map<String, Value> = serde_json::from_slice(bytes)?;
        let version = fields
            .remove("version")
            .and_then(|version| version.as_u64())
            .ok_or(SettingsError::NoVersion)?;
        if version > u64::from(FORMAT_VERSION) {
            return Err(SettingsError::NewerVersion(version));
        }
        let settings: Self = serde_json::from_value(Value::Object(fields))?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn to_json(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct File<'a> {
            version: u32,
            #[serde(flatten)]
            settings: &'a Settings,
        }
        serde_json::to_vec_pretty(&File {
            version: FORMAT_VERSION,
            settings: self,
        })
        .expect("settings always serialize")
    }

    /// Every value must be one of the choices offered.
    pub fn validate(&self) -> Result<(), SettingsError> {
        check("minimum age", self.min_age_days, &MIN_AGE_DAYS)?;
        check("medium-risk retention", self.medium_days, &MEDIUM_DAYS)?;
        check("review retention", self.review_days, &REVIEW_DAYS)
    }

    /// The floor on every rule's minimum age.
    pub fn min_age(&self) -> Duration {
        Duration::from_secs(u64::from(self.min_age_days) * DAY)
    }

    /// What a cleanup does with each risk level.
    pub fn policy(&self) -> Policy {
        let medium = Action::Quarantine {
            days: self.medium_days,
        };
        Policy {
            low: if self.always_quarantine {
                medium
            } else {
                Action::Delete
            },
            medium,
            review: Action::Quarantine {
                days: self.review_days,
            },
        }
    }
}

fn check(name: &str, days: u32, choices: &[u32]) -> Result<(), SettingsError> {
    if choices.contains(&days) {
        return Ok(());
    }
    let listed: Vec<String> = choices.iter().map(u32::to_string).collect();
    Err(SettingsError::Invalid(format!(
        "the {name} must be {} days, not {days}",
        listed.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::age::DEFAULT_MIN_AGE;

    #[test]
    fn defaults_match_the_built_in_behavior() {
        let settings = Settings::default();
        assert_eq!(settings.min_age(), DEFAULT_MIN_AGE);
        assert_eq!(settings.policy(), Policy::default());
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn always_quarantine_keeps_low_risk_files_for_the_medium_retention() {
        let settings = Settings {
            always_quarantine: true,
            medium_days: 14,
            review_days: 90,
            ..Settings::default()
        };
        let policy = settings.policy();
        assert_eq!(policy.low, Action::Quarantine { days: 14 });
        assert_eq!(policy.medium, Action::Quarantine { days: 14 });
        assert_eq!(policy.review, Action::Quarantine { days: 90 });
    }

    #[test]
    fn saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        assert_eq!(Settings::load(&path).unwrap(), Settings::default());

        let settings = Settings {
            min_age_days: 7,
            always_quarantine: true,
            medium_days: 30,
            review_days: 60,
            theme: Theme::Dark,
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path).unwrap(), settings);

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\": 1"), "{text}");
        assert!(text.contains("\"theme\": \"dark\""), "{text}");
    }

    #[test]
    fn refuses_values_outside_the_choices() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let shorter = Settings {
            medium_days: 1,
            ..Settings::default()
        };
        let error = shorter.save(&path).unwrap_err().to_string();
        assert_eq!(
            error,
            "the medium-risk retention must be 7, 14, 30 days, not 1"
        );
        assert!(!path.exists());
    }

    #[test]
    fn a_damaged_file_is_an_error_never_the_defaults() {
        let valid = r#""min_age_days": 3, "always_quarantine": true, "medium_days": 7, "review_days": 30, "theme": "light""#;
        let damaged = [
            String::new(),
            "not json".to_string(),
            "[]".to_string(),
            format!("{{{valid}}}"),
            format!(r#"{{"version": "1", {valid}}}"#),
            format!(r#"{{"version": 2, {valid}}}"#),
            r#"{"version": 1, "min_age_days": 3}"#.to_string(),
            format!(r#"{{"version": 1, {valid}, "extra": true}}"#),
            format!(r#"{{"version": 1, {}}}"#, valid.replace("3,", "0,")),
            format!(r#"{{"version": 1, {}}}"#, valid.replace("light", "blue")),
            format!(r#"{{"version": 1, {}}}"#, valid.replace("true", "1")),
        ];
        for text in damaged {
            assert!(Settings::from_json(text.as_bytes()).is_err(), "{text}");
        }

        let ok = Settings::from_json(format!(r#"{{"version": 1, {valid}}}"#).as_bytes()).unwrap();
        assert_eq!(ok.min_age_days, 3);
        assert!(ok.always_quarantine);
        assert_eq!(ok.theme, Theme::Light);
    }

    #[test]
    fn a_newer_format_says_so() {
        let error = Settings::from_json(br#"{"version": 9}"#).unwrap_err();
        assert!(matches!(error, SettingsError::NewerVersion(9)), "{error}");
    }
}

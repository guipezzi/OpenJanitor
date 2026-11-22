//! Cleaning rules: loading, validation, and matching (PLANNING.md §5.3).
//!
//! Rules are data only. A rule can't run commands or scripts, can't use
//! arbitrary environment variables, and can't weaken the deny list.

use std::collections::HashSet;
use std::time::Duration;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use crate::age::parse_age;
use crate::vars::check_template;

/// Rule files shipped with OpenJanitor.
const BUNDLED: &[(&str, &str)] = &[
    (
        "windows-temp.toml",
        include_str!("../../../rules/windows-temp.toml"),
    ),
    (
        "windows-caches.toml",
        include_str!("../../../rules/windows-caches.toml"),
    ),
    (
        "windows-reports.toml",
        include_str!("../../../rules/windows-reports.toml"),
    ),
    (
        "windows-logs.toml",
        include_str!("../../../rules/windows-logs.toml"),
    ),
    (
        "graphics.toml",
        include_str!("../../../rules/graphics.toml"),
    ),
    (
        "browsers.toml",
        include_str!("../../../rules/browsers.toml"),
    ),
    ("apps.toml", include_str!("../../../rules/apps.toml")),
];

/// Built-in actions rules may reference (DISM cleanup, emptying the Recycle
/// Bin, …). None exist yet; they arrive with the cleanups that need them.
pub const KNOWN_BUILTINS: &[&str] = &[];

/// Which cleanup a rule belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Simple,
    Advanced,
}

impl Level {
    /// An advanced scan also runs the simple rules.
    pub fn includes(self, other: Level) -> bool {
        self == Level::Advanced || other == Level::Simple
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    Review,
}

/// A rule as written in a TOML file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub level: Level,
    pub risk: Risk,
    #[serde(default)]
    pub needs_admin: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_include")]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub min_age: Option<String>,
    /// Only run the rule if this path exists (for example, an app's folder).
    #[serde(default)]
    pub detect: Option<String>,
    #[serde(default)]
    pub builtin: Option<String>,
    pub name: String,
    pub description: String,
}

fn default_include() -> Vec<String> {
    vec!["**/*".to_string()]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(rename = "rule", default)]
    rules: Vec<Rule>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("{file}: {source}")]
    Parse {
        file: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("{file}: rule {id:?}: {message}")]
    Invalid {
        file: String,
        id: String,
        message: String,
    },
    #[error("rule id {0:?} is defined more than once")]
    Duplicate(String),
}

/// A validated rule, ready to match paths.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub min_age: Option<Duration>,
    include: GlobSet,
    exclude: GlobSet,
}

impl CompiledRule {
    /// Whether a path relative to the rule's root (with `/` separators) is a
    /// match.
    pub fn matches(&self, relative: &str) -> bool {
        self.include.is_match(relative) && !self.exclude.is_match(relative)
    }
}

/// A set of validated rules with unique ids.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    /// The rules shipped with OpenJanitor.
    pub fn bundled() -> Result<Self, RuleError> {
        Self::from_sources(BUNDLED)
    }

    /// Parses and validates `(file name, TOML contents)` pairs.
    pub fn from_sources(sources: &[(&str, &str)]) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
        let mut ids = HashSet::new();
        for (file, contents) in sources {
            let parsed: RuleFile = toml::from_str(contents).map_err(|source| RuleError::Parse {
                file: file.to_string(),
                source,
            })?;
            for rule in parsed.rules {
                if !ids.insert(rule.id.clone()) {
                    return Err(RuleError::Duplicate(rule.id));
                }
                rules.push(compile(file, rule)?);
            }
        }
        Ok(Self { rules })
    }

    pub fn iter(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules.iter()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

fn compile(file: &str, rule: Rule) -> Result<CompiledRule, RuleError> {
    let invalid = |message: String| RuleError::Invalid {
        file: file.to_string(),
        id: rule.id.clone(),
        message,
    };

    if !is_valid_id(&rule.id) {
        return Err(invalid(
            "ids are lowercase words separated by dots, like \"windows.temp.user\"".into(),
        ));
    }
    if rule.name.trim().is_empty() || rule.description.trim().is_empty() {
        return Err(invalid("name and description are required".into()));
    }
    if let Some(builtin) = &rule.builtin
        && !KNOWN_BUILTINS.contains(&builtin.as_str())
    {
        return Err(invalid(format!("unknown builtin action {builtin:?}")));
    }
    if rule.paths.is_empty() && rule.builtin.is_none() {
        return Err(invalid(
            "a rule needs at least one path or a builtin".into(),
        ));
    }
    for template in rule.paths.iter().chain(&rule.detect) {
        check_template(template).map_err(|e| invalid(e.to_string()))?;
        if !template.starts_with('%') {
            return Err(invalid(format!(
                "path {template:?} must start with a variable such as %LOCALAPPDATA%"
            )));
        }
        if template.split(['\\', '/']).any(|part| part == "..") {
            return Err(invalid(format!("path {template:?} must not contain '..'")));
        }
    }
    let min_age = rule
        .min_age
        .as_deref()
        .map(parse_age)
        .transpose()
        .map_err(|e| invalid(e.to_string()))?;
    let include = glob_set(&rule.include).map_err(&invalid)?;
    let exclude = glob_set(&rule.exclude).map_err(&invalid)?;

    Ok(CompiledRule {
        rule,
        min_age,
        include,
        exclude,
    })
}

fn is_valid_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn glob_set(patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
            .map_err(|e| format!("invalid pattern {pattern:?}: {e}"))?;
        builder.add(glob);
    }
    builder.build().map_err(|e| e.to_string())
}

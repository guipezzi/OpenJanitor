//! Expanding `%VARIABLES%` in rule paths.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The only variables rules may use. Anything else is rejected, so a rule
/// can't be pointed somewhere unexpected through an arbitrary environment
/// variable.
pub const ALLOWED_VARS: &[&str] = &[
    "TEMP",
    "TMP",
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "PROGRAMDATA",
    "WINDIR",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PUBLIC",
];

/// A source of variable values. Production uses [`EnvVars`]; tests use a
/// `HashMap` pointing at a fake layout.
pub trait Vars {
    /// The value of an uppercase variable name, or `None` if it isn't set.
    fn get(&self, name: &str) -> Option<PathBuf>;
}

/// Reads variables from the environment and expands 8.3 short names, so
/// paths like `C:\Users\GUILHE~1\AppData\Local\Temp` become long paths the
/// safety layer accepts.
pub struct EnvVars;

impl Vars for EnvVars {
    fn get(&self, name: &str) -> Option<PathBuf> {
        let value = std::env::var_os(name)?;
        Some(oj_windows::long_path(Path::new(&value)))
    }
}

impl Vars for HashMap<String, PathBuf> {
    fn get(&self, name: &str) -> Option<PathBuf> {
        HashMap::get(self, &name.to_ascii_uppercase()).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpandError {
    #[error("unclosed '%' in {0:?}")]
    Unclosed(String),
    #[error("%{0}% is not an allowed variable")]
    NotAllowed(String),
    #[error("%{0}% is not set on this machine")]
    Unset(String),
    #[error("the value of %{0}% is not valid Unicode")]
    NotUnicode(String),
}

/// Checks that a template only uses allowed variables, without resolving
/// them. Used when loading rules.
pub fn check_template(template: &str) -> Result<(), ExpandError> {
    for name in variable_names(template)? {
        if !ALLOWED_VARS.contains(&name.as_str()) {
            return Err(ExpandError::NotAllowed(name));
        }
    }
    Ok(())
}

/// Replaces every `%NAME%` in `template` with its value.
pub fn expand(template: &str, vars: &dyn Vars) -> Result<PathBuf, ExpandError> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after
            .find('%')
            .ok_or_else(|| ExpandError::Unclosed(template.to_string()))?;
        let name = after[..end].to_ascii_uppercase();
        if !ALLOWED_VARS.contains(&name.as_str()) {
            return Err(ExpandError::NotAllowed(name));
        }
        let value = vars
            .get(&name)
            .ok_or_else(|| ExpandError::Unset(name.clone()))?;
        let value = value
            .to_str()
            .ok_or_else(|| ExpandError::NotUnicode(name.clone()))?;
        out.push_str(value.trim_end_matches(['\\', '/']));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(PathBuf::from(out))
}

fn variable_names(template: &str) -> Result<Vec<String>, ExpandError> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('%') {
        let after = &rest[start + 1..];
        let end = after
            .find('%')
            .ok_or_else(|| ExpandError::Unclosed(template.to_string()))?;
        names.push(after[..end].to_ascii_uppercase());
        rest = &after[end + 1..];
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> HashMap<String, PathBuf> {
        HashMap::from([
            ("WINDIR".to_string(), PathBuf::from(r"C:\Windows")),
            (
                "TEMP".to_string(),
                PathBuf::from(r"C:\Users\me\AppData\Local\Temp\"),
            ),
        ])
    }

    #[test]
    fn expands_variables_case_insensitively() {
        assert_eq!(
            expand(r"%windir%\Temp", &vars()).unwrap(),
            PathBuf::from(r"C:\Windows\Temp")
        );
        assert_eq!(
            expand("%TEMP%", &vars()).unwrap(),
            PathBuf::from(r"C:\Users\me\AppData\Local\Temp")
        );
    }

    #[test]
    fn rejects_unknown_unset_and_malformed_variables() {
        assert_eq!(
            expand(r"%PATH%\x", &vars()),
            Err(ExpandError::NotAllowed("PATH".into()))
        );
        assert_eq!(
            expand(r"%APPDATA%\x", &vars()),
            Err(ExpandError::Unset("APPDATA".into()))
        );
        assert!(matches!(
            expand(r"%WINDIR\x", &vars()),
            Err(ExpandError::Unclosed(_))
        ));
        assert!(check_template(r"%HOMEDRIVE%\x").is_err());
        assert!(check_template(r"%LOCALAPPDATA%\x").is_ok());
    }
}

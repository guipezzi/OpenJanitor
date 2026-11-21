//! Rule loading and validation.

use oj_core::{Level, RuleError, RuleSet};

fn load(toml: &str) -> Result<RuleSet, RuleError> {
    RuleSet::from_sources(&[("test.toml", toml)])
}

const VALID: &str = r#"
[[rule]]
id = "test.example"
category = "temporary-files"
level = "simple"
risk = "low"
paths = ['%TEMP%\Example']
name = "Example"
description = "An example rule."
"#;

fn with(extra_line: &str) -> String {
    VALID.replace("name = ", &format!("{extra_line}\nname = "))
}

fn assert_invalid(toml: &str, expected: &str) {
    match load(toml) {
        Ok(_) => panic!("rule should be rejected:\n{toml}"),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains(expected),
                "expected {expected:?} in error, got: {message}"
            );
        }
    }
}

#[test]
fn bundled_rules_load() {
    let rules = RuleSet::bundled().expect("bundled rules must be valid");
    assert!(rules.len() >= 4);
    for compiled in rules.iter() {
        assert!(
            compiled.min_age.is_some(),
            "{} should set min_age explicitly",
            compiled.rule.id
        );
        if compiled.rule.level == Level::Simple {
            assert_ne!(
                compiled.rule.risk,
                oj_core::Risk::Review,
                "{}: simple-clean rules can't need review",
                compiled.rule.id
            );
        }
    }
}

#[test]
fn accepts_a_valid_rule() {
    let rules = load(VALID).unwrap();
    assert_eq!(rules.len(), 1);
}

#[test]
fn rejects_unknown_fields() {
    assert_invalid(&with("command = 'del /s'"), "unknown field");
}

#[test]
fn rejects_bad_ids() {
    for id in ["Test.Example", "example", "test..example", "test.ex ample"] {
        assert_invalid(
            &VALID.replace("test.example", id),
            "ids are lowercase words",
        );
    }
}

#[test]
fn rejects_duplicate_ids() {
    let twice = format!("{VALID}\n{VALID}");
    assert!(matches!(load(&twice), Err(RuleError::Duplicate(_))));
}

#[test]
fn rejects_variables_outside_the_allowlist() {
    assert_invalid(
        &VALID.replace("%TEMP%", "%HOMEPATH%"),
        "not an allowed variable",
    );
}

#[test]
fn rejects_paths_without_a_variable_or_with_traversal() {
    assert_invalid(
        &VALID.replace(r"'%TEMP%\Example'", r"'C:\Windows'"),
        "must start with a variable",
    );
    assert_invalid(
        &VALID.replace(r"%TEMP%\Example", r"%TEMP%\..\..\Documents"),
        "must not contain '..'",
    );
}

#[test]
fn rejects_unknown_builtins() {
    assert_invalid(&with("builtin = 'format-c'"), "unknown builtin");
}

#[test]
fn rejects_bad_min_age_and_globs() {
    assert_invalid(&with("min_age = 'soon'"), "invalid age");
    assert_invalid(&with("include = ['[unclosed']"), "invalid pattern");
}

#[test]
fn rejects_rules_without_paths() {
    assert_invalid(
        &VALID.replace(r"paths = ['%TEMP%\Example']", ""),
        "at least one path",
    );
}

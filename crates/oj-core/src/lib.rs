//! OpenJanitor's scan engine and cleaning rules (PLANNING.md §5).
//!
//! Scanning is read-only: this crate finds candidates and explains them. All
//! file operations go through `oj-safety`.

#![forbid(unsafe_code)]

pub mod age;
pub mod rule;
pub mod scan;
pub mod vars;

pub use rule::{CompiledRule, Level, Risk, Rule, RuleError, RuleSet};
pub use scan::{Finding, RuleReport, RuleStatus, ScanOptions, ScanReport, Scanner};
pub use vars::{EnvVars, Vars};

//! OpenJanitor's scan engine and cleaning rules (PLANNING.md §5).
//!
//! Scanning is read-only: this crate finds candidates and explains them.
//! Cleaning runs a plan the user confirmed, and every file operation in it
//! goes through `oj-safety`.

#![forbid(unsafe_code)]

pub mod age;
pub mod clean;
pub mod history;
pub mod results;
pub mod rule;
pub mod scan;
pub mod vars;

pub use clean::{
    Action, CleanProgress, CleanReport, Cleaner, Plan, PlanSummary, Policy, QuarantineGroup,
    QuarantinedGroup, SkipCount, Tally,
};
pub use history::History;
pub use oj_safety::CancelToken;
pub use results::{ChildPage, NodeId, NodeKind, NodeView, ScanResults};
pub use rule::{CompiledRule, Level, Risk, Rule, RuleError, RuleSet};
pub use scan::{Finding, RuleReport, RuleStatus, ScanOptions, ScanProgress, ScanReport, Scanner};
pub use vars::{EnvVars, Vars};

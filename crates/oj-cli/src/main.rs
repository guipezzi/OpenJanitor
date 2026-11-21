//! OpenJanitor command line tool (development).
//!
//! It only scans and reports. It never deletes or moves anything.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use oj_core::age::parse_age;
use oj_core::{EnvVars, Finding, Level, RuleReport, RuleSet, ScanOptions, Scanner};
use oj_safety::{DenyList, SystemPaths};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "oj-cli",
    version,
    about = "OpenJanitor command line tool (development). Scanning is read-only."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List what OpenJanitor would clean, as JSON. Never deletes anything.
    Scan {
        /// Which cleanup to run. Advanced also runs the simple rules.
        #[arg(long, value_enum, default_value_t = LevelArg::Simple)]
        level: LevelArg,
        /// Override every rule's minimum file age (for example 0, 12h, 7d).
        #[arg(long, value_name = "AGE")]
        min_age: Option<String>,
        /// Include every finding, not just the per-rule summary.
        #[arg(long)]
        details: bool,
    },
    /// List the bundled rules.
    Rules,
}

#[derive(Clone, Copy, ValueEnum)]
enum LevelArg {
    Simple,
    Advanced,
}

impl From<LevelArg> for Level {
    fn from(level: LevelArg) -> Self {
        match level {
            LevelArg::Simple => Level::Simple,
            LevelArg::Advanced => Level::Advanced,
        }
    }
}

#[derive(Serialize)]
struct ScanOutput<'a> {
    mode: &'static str,
    level: Level,
    findings_total: u64,
    size_on_disk_total: u64,
    size_on_disk_human: String,
    rules: &'a [RuleReport],
    #[serde(skip_serializing_if = "Option::is_none")]
    findings: Option<&'a [Finding]>,
}

#[derive(Serialize)]
struct RuleOutput<'a> {
    id: &'a str,
    name: &'a str,
    level: Level,
    risk: oj_core::Risk,
    needs_admin: bool,
    paths: &'a [String],
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let rules = RuleSet::bundled().map_err(|e| e.to_string())?;
    match cli.command {
        Command::Rules => {
            let list: Vec<RuleOutput> = rules
                .iter()
                .map(|c| RuleOutput {
                    id: &c.rule.id,
                    name: &c.rule.name,
                    level: c.rule.level,
                    risk: c.rule.risk,
                    needs_admin: c.rule.needs_admin,
                    paths: &c.rule.paths,
                })
                .collect();
            print_json(&list)
        }
        Command::Scan {
            level,
            min_age,
            details,
        } => {
            let system = SystemPaths::discover().map_err(|e| e.to_string())?;
            let deny = DenyList::new(&system).map_err(|e| e.to_string())?;
            let mut options = ScanOptions::new(level.into());
            options.min_age_override = min_age
                .as_deref()
                .map(parse_age)
                .transpose()
                .map_err(|e| e.to_string())?;

            let scanner = Scanner {
                rules: &rules,
                vars: &EnvVars,
                deny: &deny,
            };
            let report = scanner.scan(&options);
            print_json(&ScanOutput {
                mode: "read-only scan (nothing was deleted)",
                level: report.level,
                findings_total: report.findings_total,
                size_on_disk_total: report.size_on_disk_total,
                size_on_disk_human: human_size(report.size_on_disk_total),
                rules: &report.rules,
                findings: details.then_some(report.findings.as_slice()),
            })
        }
    }
}

fn print_json(value: &impl Serialize) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    println!("{json}");
    Ok(())
}

/// Sizes the way File Explorer shows them (1 KB = 1024 bytes).
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

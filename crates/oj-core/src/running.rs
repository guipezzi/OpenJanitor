//! Which programs are running, so cleanups can leave an open app's files
//! alone (PLANNING.md §6.1).

use std::collections::HashSet;
use std::io;

use crate::rule::App;

/// The programs running for this user, by file name ("chrome.exe"),
/// compared without regard to case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunningPrograms {
    names: HashSet<String>,
}

impl RunningPrograms {
    /// A set made of these program file names.
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            names: names
                .into_iter()
                .map(|name| name.as_ref().to_lowercase())
                .collect(),
        }
    }

    /// What's running right now in this user's Windows session.
    pub fn now() -> io::Result<Self> {
        Ok(Self::new(oj_windows::running_programs()?))
    }

    /// Whether any of the app's programs is running.
    pub fn is_running(&self, app: &App) -> bool {
        app.processes
            .iter()
            .any(|process| self.names.contains(&process.to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_app_runs_while_any_of_its_programs_runs() {
        let discord = App {
            name: "Discord".into(),
            processes: vec!["Discord.exe".into(), "DiscordPTB.exe".into()],
        };
        assert!(RunningPrograms::new(["explorer.exe", "discordptb.EXE"]).is_running(&discord));
        assert!(!RunningPrograms::new(["explorer.exe"]).is_running(&discord));
        assert!(!RunningPrograms::default().is_running(&discord));
    }
}

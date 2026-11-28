//! Running the elevated helper (PLANNING.md §4.6): for a cleanup's
//! admin-only files (D34), and for "Check with admin rights" (D35).
//!
//! The helper is `openjanitor-helper.exe` next to the app. Starting it
//! shows Windows' UAC prompt; the user's "no" changes nothing. The
//! helper then opens a private pipe, and the app checks that the process
//! answering is the one it just started before sending anything.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use oj_core::{
    AppMessage, CancelToken, ElevatedError, ElevatedItem, ElevatedRequest, Elevator, HelperMessage,
    HelperRequest, Level, PROTOCOL_VERSION, ScanRequest, Settings,
};
use oj_safety::{Entry, Mode, ProtectedList};
use oj_windows::elevation::{ElevatedProcess, is_declined, run_as_admin};
use oj_windows::pipe;

/// How long to wait for the helper to open its pipe after the prompt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Helper {
    exe: PathBuf,
    mode: Mode,
    min_age_floor_secs: u64,
    protected: Vec<Entry>,
}

impl Helper {
    /// The helper next to the app, with what every request carries: the
    /// mode, the user's minimum age, and their Protected list.
    pub fn new(mode: Mode, settings: &Settings, protected: &ProtectedList) -> Result<Self, String> {
        let app = std::env::current_exe().map_err(|e| format!("Couldn't find the app: {e}"))?;
        Ok(Self {
            exe: app.with_file_name("openjanitor-helper.exe"),
            mode,
            min_age_floor_secs: settings.min_age().as_secs(),
            protected: protected.entries().to_vec(),
        })
    }

    /// Scans the admin rules on `drives` with administrator rights, passing
    /// on the helper's progress and what it found (D35). Only reads.
    pub fn scan(
        &self,
        level: Level,
        drives: Vec<char>,
        cancel: &CancelToken,
        on_message: &mut dyn FnMut(HelperMessage),
    ) -> Result<(), ElevatedError> {
        let request = HelperRequest::Scan(ScanRequest {
            version: PROTOCOL_VERSION,
            level,
            drives,
            min_age_floor_secs: self.min_age_floor_secs,
            protected: self.protected.clone(),
        });
        self.exchange(&request, cancel, on_message)
    }

    /// Starts the helper (the UAC prompt), sends `request`, and passes each
    /// message on until the helper is done.
    fn exchange(
        &self,
        request: &HelperRequest,
        cancel: &CancelToken,
        on_message: &mut dyn FnMut(HelperMessage),
    ) -> Result<(), ElevatedError> {
        if !self.exe.is_file() {
            return Err(failed(
                "The administrator helper (openjanitor-helper.exe) isn't next to the app.",
            ));
        }
        let name = pipe::random_name("openjanitor-helper");
        let arguments = format!("--pipe {name} --client {}", std::process::id());
        let process = run_as_admin(&self.exe, &arguments).map_err(|e| {
            if is_declined(&e) {
                ElevatedError::Declined
            } else {
                failed(format!("Couldn't start the administrator helper: {e}"))
            }
        })?;
        let connection = connect(&name, &process)?;

        let mut line = serde_json::to_vec(request).map_err(|e| failed(e.to_string()))?;
        line.push(b'\n');
        (&connection)
            .write_all(&line)
            .map_err(|e| failed(format!("Couldn't reach the administrator helper: {e}")))?;

        let mut asked_to_stop = false;
        let mut finished = false;
        for line in BufReader::new(&connection).lines() {
            let Ok(line) = line else { break };
            let message: HelperMessage = serde_json::from_str(&line).map_err(|e| {
                failed(format!(
                    "The administrator helper said something unreadable: {e}"
                ))
            })?;
            let last = matches!(message, HelperMessage::Done | HelperMessage::Refused { .. });
            on_message(message);
            if last {
                finished = true;
                break;
            }
            if cancel.is_cancelled() && !asked_to_stop {
                asked_to_stop = true;
                let mut stop = serde_json::to_vec(&AppMessage::Cancel).unwrap_or_default();
                stop.push(b'\n');
                let _ = (&connection).write_all(&stop);
            }
        }
        drop(connection);
        let _ = process.wait(Duration::from_secs(10));
        if finished {
            Ok(())
        } else {
            Err(failed(
                "The administrator helper stopped before it finished.",
            ))
        }
    }
}

fn failed(message: impl Into<String>) -> ElevatedError {
    ElevatedError::Failed(message.into())
}

impl Elevator for Helper {
    fn run(
        &mut self,
        items: &[ElevatedItem],
        cancel: &CancelToken,
        on_message: &mut dyn FnMut(HelperMessage),
    ) -> Result<(), ElevatedError> {
        let request = HelperRequest::Clean(ElevatedRequest {
            version: PROTOCOL_VERSION,
            mode: self.mode,
            min_age_floor_secs: self.min_age_floor_secs,
            protected: self.protected.clone(),
            items: items.to_vec(),
        });
        self.exchange(&request, cancel, on_message)
    }
}

/// Connects to the helper's pipe, and makes sure the helper we started is
/// what answers: another program could have opened a pipe of that name.
fn connect(name: &str, process: &ElevatedProcess) -> Result<std::fs::File, ElevatedError> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match pipe::connect(name) {
            Ok((connection, server)) if server == process.id() => return Ok(connection),
            Ok(_) => {
                return Err(failed(
                    "Another program answered in place of the administrator helper, so nothing was sent.",
                ));
            }
            Err(_) => {
                if let Ok(Some(code)) = process.wait(Duration::ZERO) {
                    return Err(failed(format!(
                        "The administrator helper stopped right away (code {code})."
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(failed("The administrator helper didn't answer."));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

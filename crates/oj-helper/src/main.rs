//! OpenJanitor's elevated helper (PLANNING.md §4.6 and D34).
//!
//! The app starts it with a UAC prompt when a cleanup includes files that
//! need administrator rights. It then:
//!
//! 1. refuses to run unless it really is elevated;
//! 2. creates the private pipe the app named, and waits up to a minute for
//!    the app to connect (it exits if nobody does);
//! 3. checks that the process that connected is the one that started it,
//!    and is OpenJanitor from the helper's own folder;
//! 4. reads one request, checks every file in it against OpenJanitor's own
//!    rules (`oj_core::Checker`), deletes the ones that pass through
//!    `oj-safety`, and reports each outcome;
//! 5. exits.
//!
//! It never trusts a path it's sent, and it writes nothing of its own: the
//! app records the history.

// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use oj_core::elevated::serve;
use oj_core::{CancelToken, Checker, ElevatedRequest, EnvVars, HelperMessage, RuleSet};
use oj_safety::{DenyList, Executor, Mode, ProtectedList, SystemPaths};
use oj_windows::elevation::{is_elevated, process_image};
use oj_windows::pipe::{PipeServer, available};

/// How long to wait for the app to connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// A request bigger than this isn't a cleanup anyone reviewed.
const MAX_REQUEST: u64 = 256 * 1024 * 1024;

/// The app's program file name; Windows doesn't care about case.
const APP: &str = "openjanitor.exe";

#[derive(Debug, PartialEq, Eq)]
struct Args {
    pipe: String,
    /// The app's process ID.
    client: u32,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let args: Vec<String> = args.into_iter().collect();
    match &args[..] {
        [flag_pipe, pipe, flag_client, client]
            if flag_pipe == "--pipe" && flag_client == "--client" =>
        {
            Ok(Args {
                pipe: pipe.clone(),
                client: client
                    .parse()
                    .map_err(|_| format!("{client:?} isn't a process ID"))?,
            })
        }
        _ => Err("usage: openjanitor-helper --pipe <name> --client <process id>".into()),
    }
}

/// Whether `client` (the program that connected) is OpenJanitor from the
/// same folder as `helper`.
fn trusted_client(client: &Path, helper: &Path) -> bool {
    let normalize = |path: &Path| oj_windows::long_path(path).to_string_lossy().to_lowercase();
    let same_folder = match (client.parent(), helper.parent()) {
        (Some(a), Some(b)) => normalize(a) == normalize(b),
        _ => false,
    };
    let named = client
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(APP));
    same_folder && named
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("openjanitor-helper: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args(std::env::args().skip(1))?;
    if !is_elevated().map_err(|e| format!("couldn't check its own rights: {e}"))? {
        return Err("it only runs with administrator rights".into());
    }
    let server =
        PipeServer::create(&args.pipe).map_err(|e| format!("couldn't open its pipe: {e}"))?;

    // If the app never connects, don't wait forever with admin rights.
    let connected = Arc::new(AtomicBool::new(false));
    let watchdog = Arc::clone(&connected);
    std::thread::spawn(move || {
        std::thread::sleep(CONNECT_TIMEOUT);
        if !watchdog.load(Ordering::SeqCst) {
            std::process::exit(2);
        }
    });
    let (pipe, client) = server.accept().map_err(|e| format!("no connection: {e}"))?;
    connected.store(true, Ordering::SeqCst);

    if client != args.client {
        return Err(format!(
            "process {client} connected, not the app ({})",
            args.client
        ));
    }
    let image = process_image(client).map_err(|e| format!("couldn't check the app: {e}"))?;
    let helper = std::env::current_exe().map_err(|e| e.to_string())?;
    if !trusted_client(&image, &helper) {
        return Err(format!(
            "{} isn't OpenJanitor from this folder",
            image.display()
        ));
    }

    let mut line = String::new();
    BufReader::new((&pipe).take(MAX_REQUEST))
        .read_line(&mut line)
        .map_err(|e| format!("couldn't read the request: {e}"))?;
    let mut send = sender(&pipe);
    let request: ElevatedRequest = match serde_json::from_str(&line) {
        Ok(request) => request,
        Err(e) => {
            send(HelperMessage::Refused {
                message: format!("the request couldn't be read: {e}"),
            });
            return Err("unreadable request".into());
        }
    };
    let protected = match ProtectedList::from_entries(request.protected.clone()) {
        Ok(protected) => protected,
        Err(e) => {
            send(HelperMessage::Refused {
                message: format!("the Protected list couldn't be read: {e}"),
            });
            return Err("unreadable Protected list".into());
        }
    };

    let rules = RuleSet::bundled().map_err(|e| e.to_string())?;
    let system = SystemPaths::discover().map_err(|e| e.to_string())?;
    let deny = DenyList::new(&system).map_err(|e| e.to_string())?;
    // A dry run if either side says so.
    let mode = if request.mode == Mode::DryRun || Mode::from_env() == Mode::DryRun {
        Mode::DryRun
    } else {
        Mode::Live
    };
    let executor = Executor::new(mode, &deny).with_protected_list(protected.clone());
    let checker = Checker::new(
        &rules,
        &EnvVars,
        &protected,
        Duration::from_secs(request.min_age_floor_secs),
        SystemTime::now(),
    );

    let cancel = CancelToken::new();
    let mut send_and_listen = |message: HelperMessage| {
        send(message);
        // The only thing the app sends after the request is "stop".
        if available(&pipe).unwrap_or(1) > 0 {
            cancel.cancel();
        }
    };
    serve(&request, &checker, &executor, &cancel, &mut send_and_listen);
    Ok(())
}

/// Writes messages to the app, one JSON line each. Once a write fails (the
/// app is gone), the rest are dropped.
fn sender(pipe: &File) -> impl FnMut(HelperMessage) + '_ {
    let mut broken = false;
    move |message| {
        if broken {
            return;
        }
        let Ok(mut line) = serde_json::to_vec(&message) else {
            return;
        };
        line.push(b'\n');
        let mut pipe = pipe;
        broken = pipe.write_all(&line).and_then(|()| pipe.flush()).is_err();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        parse_args(list.iter().map(|s| s.to_string()))
    }

    #[test]
    fn takes_exactly_a_pipe_and_a_client() {
        assert_eq!(
            args(&["--pipe", "openjanitor-helper-1a2b", "--client", "4242"]),
            Ok(Args {
                pipe: "openjanitor-helper-1a2b".into(),
                client: 4242
            })
        );
        assert!(args(&[]).is_err());
        assert!(args(&["--client", "1", "--pipe", "x"]).is_err());
        assert!(args(&["--pipe", "x", "--client", "me"]).is_err());
        assert!(args(&["--pipe", "x", "--client", "1", "--extra"]).is_err());
    }

    #[test]
    fn only_openjanitor_from_the_same_folder_is_trusted() {
        let helper = Path::new(r"C:\Program Files\OpenJanitor\openjanitor-helper.exe");
        assert!(trusted_client(
            Path::new(r"C:\Program Files\OpenJanitor\OpenJanitor.exe"),
            helper
        ));
        assert!(trusted_client(
            Path::new(r"c:\program files\openjanitor\openjanitor.exe"),
            helper
        ));
        assert!(!trusted_client(
            Path::new(r"C:\Users\me\Downloads\openjanitor.exe"),
            helper
        ));
        assert!(!trusted_client(
            Path::new(r"C:\Program Files\OpenJanitor\other.exe"),
            helper
        ));
    }
}

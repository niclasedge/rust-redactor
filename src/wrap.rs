//! `redactor wrap -- <cmd> [args...]` — execute a subprocess, redact its
//! stdout+stderr line-by-line, and forward the original exit code.
//!
//! This is the cross-platform, shell-independent alternative to piping
//! (`cmd | redactor`). It works identically in bash, zsh, fish, cmd.exe,
//! and PowerShell, and avoids the PIPESTATUS / `$LASTEXITCODE` dance.

use crate::logger;
use crate::patterns::Rule;
use crate::redactor::{redact_pattern, LogEntry};
use anyhow::Result;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

/// Run `cmd args...`, filter both streams through pattern-mode redaction, write
/// the redacted lines to *our* stdout/stderr, and return the child exit code.
pub fn run(
    cmd: &str,
    args: &[String],
    rules: Arc<Vec<Rule>>,
    log_dir: Option<&Path>,
    source_label: &str,
    command_label: &str,
) -> Result<i32> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::inherit()) // pass user's stdin straight through
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn {cmd}: {e}"))?;

    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");

    let log_buf: Arc<Mutex<Vec<LogEntry>>> = Arc::new(Mutex::new(Vec::new()));

    let rules_o = rules.clone();
    let log_o = log_buf.clone();
    let h_out = thread::spawn(move || {
        let _ = filter_stream(stdout, &rules_o, StreamKind::Stdout, log_o);
    });

    let rules_e = rules.clone();
    let log_e = log_buf.clone();
    let h_err = thread::spawn(move || {
        let _ = filter_stream(stderr, &rules_e, StreamKind::Stderr, log_e);
    });

    let _ = h_out.join();
    let _ = h_err.join();

    let status = child.wait()?;
    let exit_code = status.code().unwrap_or({
        // killed by signal on unix → conventional 128 + signal
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map(|s| 128 + s).unwrap_or(1)
        }
        #[cfg(not(unix))]
        {
            1
        }
    });

    if let Some(dir) = log_dir {
        let entries = log_buf.lock().expect("log mutex").clone();
        for ev in &entries {
            let event = logger::Event {
                source: source_label,
                mode: "wrap",
                command: command_label,
                rule: &ev.rule,
                count: ev.count,
                sample: &ev.sample,
            };
            logger::log_event(dir, &event);
        }
    }

    Ok(exit_code)
}

#[derive(Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

fn filter_stream<R: std::io::Read + Send + 'static>(
    stream: R,
    rules: &[Rule],
    kind: StreamKind,
    log_buf: Arc<Mutex<Vec<LogEntry>>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::<u8>::new();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        // Lossy UTF-8: don't crash on binary chunks; replace invalid bytes.
        let as_str = String::from_utf8_lossy(&line);
        let (red, logs) = redact_pattern(&as_str, rules);
        if !logs.is_empty() {
            log_buf
                .lock()
                .expect("log buffer mutex poisoned")
                .extend(logs);
        }
        let bytes = red.as_bytes();
        match kind {
            StreamKind::Stdout => {
                let mut h = stdout.lock();
                h.write_all(bytes)?;
                h.flush()?;
            }
            StreamKind::Stderr => {
                let mut h = stderr.lock();
                h.write_all(bytes)?;
                h.flush()?;
            }
        }
    }
    Ok(())
}

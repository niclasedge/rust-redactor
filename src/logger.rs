//! Append-only redaction log.
//!
//! Logs to `<log-dir>/YYYY-MM-DD-redacted.jsonl` (one JSON object per line).
//! Field order is stable: `ts`, `source`, `command`, `mode`, `rule`, `count`,
//! `sample`. Compatible with `jq`, Splunk, Substrate.
//!
//! The log directory is auto-created. Failure to write the log is non-fatal —
//! redaction itself must always succeed (we'd rather lose telemetry than leak
//! data because of a logging error).

use chrono::Local;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Resolve the log directory.
///
/// Priority:
///   1. `REDACTOR_LOG_DIR` env var
///   2. `<cwd>/logs/`     (when invoked inside a repo with logs/ already)
///   3. `<exe-parent>/logs/` fallback
pub fn resolve_log_dir() -> PathBuf {
    if let Ok(p) = std::env::var("REDACTOR_LOG_DIR") {
        return PathBuf::from(p);
    }
    if let Ok(cwd) = std::env::current_dir() {
        return cwd.join("logs");
    }
    PathBuf::from("logs")
}

fn log_file_path(dir: &Path) -> PathBuf {
    let date = Local::now().format("%Y-%m-%d").to_string();
    dir.join(format!("{date}-redacted.jsonl"))
}

/// One redaction event — one JSON line in the log.
#[derive(Debug)]
pub struct Event<'a> {
    pub source: &'a str,
    pub mode: &'a str,
    pub command: &'a str,
    pub rule: &'a str,
    pub count: usize,
    pub sample: &'a str,
}

const SAMPLE_MAX: usize = 60;
const COMMAND_MAX: usize = 100;

pub fn log_event(dir: &Path, ev: &Event) {
    if let Err(e) = log_event_inner(dir, ev) {
        eprintln!("redactor: log write failed: {e}");
    }
}

fn log_event_inner(dir: &Path, ev: &Event) -> std::io::Result<()> {
    create_dir_all(dir)?;
    let path = log_file_path(dir);
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    let ts = Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let sample = truncate_sample(ev.sample);
    let command = truncate_field(ev.command, COMMAND_MAX);
    let line = serde_json::json!({
        "ts": ts,
        "source": ev.source,
        "command": command,
        "mode": ev.mode,
        "rule": ev.rule,
        "count": ev.count,
        "sample": sample,
    });
    writeln!(f, "{}", serde_json::to_string(&line).unwrap_or_default())?;
    Ok(())
}

fn truncate_field(s: &str, max: usize) -> String {
    let single = s.replace(['\n', '\r', '\t'], " ");
    if single.chars().count() > max {
        single.chars().take(max).collect::<String>() + "..."
    } else {
        single
    }
}

fn truncate_sample(s: &str) -> String {
    let mut single = s.replace(['\n', '\r', '\t'], " ");
    if single.chars().count() > SAMPLE_MAX {
        single = single.chars().take(SAMPLE_MAX).collect::<String>() + "...";
    }
    single
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn read_first_line(dir: &Path) -> serde_json::Value {
        let entries: Vec<_> = std::fs::read_dir(dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let path = entries[0].as_ref().unwrap().path();
        assert!(
            path.to_string_lossy().ends_with(".jsonl"),
            "expected jsonl extension"
        );
        let content = std::fs::read_to_string(&path).unwrap();
        let line = content.lines().next().unwrap();
        serde_json::from_str(line).expect("valid JSON line")
    }

    #[test]
    fn writes_jsonl_line() {
        let dir = tempdir().unwrap();
        let ev = Event {
            source: "stdin",
            mode: "pattern",
            command: "Read test.csv",
            rule: "openai_key",
            count: 1,
            sample: "sk-proj-abcdef",
        };
        log_event(dir.path(), &ev);
        let v = read_first_line(dir.path());
        assert_eq!(v["rule"], "openai_key");
        assert_eq!(v["count"], 1);
        assert_eq!(v["sample"], "sk-proj-abcdef");
        assert_eq!(v["source"], "stdin");
        assert_eq!(v["mode"], "pattern");
        assert!(v["ts"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn truncates_long_samples() {
        let s = "x".repeat(200);
        let t = truncate_sample(&s);
        assert!(t.ends_with("..."));
        assert!(t.chars().count() <= SAMPLE_MAX + 3);
    }

    #[test]
    fn sample_with_newlines_stays_single_line() {
        let dir = tempdir().unwrap();
        let ev = Event {
            source: "stdin",
            mode: "pattern",
            command: "Bash",
            rule: "jwt",
            count: 1,
            sample: "line1\nline2\tline3",
        };
        log_event(dir.path(), &ev);
        let v = read_first_line(dir.path());
        let s = v["sample"].as_str().unwrap();
        assert!(!s.contains('\n'));
        assert!(!s.contains('\t'));
    }

    #[test]
    fn command_truncated_to_max() {
        let dir = tempdir().unwrap();
        let long = "a".repeat(500);
        let ev = Event {
            source: "stdin",
            mode: "wrap",
            command: &long,
            rule: "openai_key",
            count: 1,
            sample: "sk-proj-abc",
        };
        log_event(dir.path(), &ev);
        let v = read_first_line(dir.path());
        let cmd = v["command"].as_str().unwrap();
        assert!(cmd.chars().count() <= COMMAND_MAX + 3);
        assert!(cmd.ends_with("..."));
    }
}

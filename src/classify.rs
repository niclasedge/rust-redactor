// Phase 3: the public surface here (`FileEntry`, `run_classifier`, error
// variants) is the contract the Phase-4 `classify-files` subcommand wires
// up. Until then nothing in this crate calls it, so silence the dead-code
// lint for the whole module — the tests below still exercise the path.
#![allow(dead_code)]

//! Rust ↔ Python sidecar IPC for the ML file classifier.
//!
//! Phase 3: just the transport — spawn the venv'd python, write a JSON
//! request to its stdin, read a JSON response from stdout, hand it back.
//! No walkdir, no threshold filtering, no `.suggested` writing yet
//! (those land in Phase 4 with `redactor classify-files`).
//!
//! The Python side returns a stub response in Phase 3; this module's
//! contract holds across the Phase-4 upgrade because the JSON schema
//! (request + response) does not change.
//!
//! Design notes:
//! - We rely on the venv at `<config>/classifier/venv/bin/python`. The
//!   installer (`redactor classifier-install`) is responsible for putting
//!   it there; we surface a typed [`ClassifierError::NotInstalled`] error
//!   when it is missing so callers can print an actionable hint.
//! - A configurable timeout (`REDACTOR_CLASSIFIER_TIMEOUT_SECS`, default
//!   300) protects against a stuck sidecar.
//! - Standard error is captured and surfaced verbatim on
//!   [`ClassifierError::Crashed`]; the Python side prints a one-liner on
//!   schema failures, so the user sees a useful message.

use crate::config;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use thiserror::Error;

/// Wire-protocol version. Bumped only when the JSON request/response shape
/// changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default timeout for the sidecar process (5 minutes per spec §5).
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

const TIMEOUT_ENV: &str = "REDACTOR_CLASSIFIER_TIMEOUT_SECS";
const PYTHON_PATH_ENV: &str = "REDACTOR_CLASSIFIER_PYTHON";

/// One file entry sent to the classifier — see spec §5.5 request schema.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub filename: String,
    pub size_bytes: u64,
    pub content_preview: String,
}

/// Top-level request body written to the sidecar's stdin.
#[derive(Serialize, Debug)]
struct ClassifierRequest<'a> {
    version: u32,
    labels: &'a [String],
    files: &'a [FileEntry],
}

/// One result entry returned from the classifier.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClassifierResult {
    pub path: String,
    pub confidence: f64,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub evidence: String,
    /// Phase 6b: detailed entity hits from the sidecar. Sidecar may omit this
    /// field for backwards compatibility — defaults to empty.
    #[serde(default)]
    pub entities: Vec<EntityHit>,
}

/// One named-entity hit returned by GLiNER (Phase 6b). `entity_type` is the
/// Rust-side category — `"PERSON"`, `"ORGANIZATION"`, `"LOCATION"`, `"URL"`,
/// `"EMAIL"`, `"HOSTNAME"`, `"PASSWORD"`, `"SECRET"`, `"API_KEY"` or
/// `"DOCUMENT_TYPE"`. Anything else maps to `"OTHER"` and is dropped at
/// aggregation time.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntityHit {
    pub text: String,
    pub label: String,
    pub score: f64,
    #[serde(default)]
    pub entity_type: String,
}

/// Top-level response body parsed from the sidecar's stdout.
#[derive(Deserialize, Debug, Clone)]
pub struct ClassifierResponse {
    pub version: u32,
    #[serde(default)]
    pub results: Vec<ClassifierResult>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Typed error variants from a single classifier run. Callers turn these
/// into user-facing hints via `Display` or pattern-match for special-case
/// handling (e.g. exit code 2 on `NotInstalled`).
#[derive(Debug, Error)]
pub enum ClassifierError {
    /// The venv'd python is not on disk yet — user hasn't run
    /// `redactor classifier-install`.
    #[error(
        "classifier sidecar not installed (missing {0}). Run `redactor classifier-install` first."
    )]
    NotInstalled(PathBuf),

    /// Python exited non-zero. `stderr` is the captured error stream
    /// (typically a one-line schema error).
    #[error("classifier sidecar crashed (exit {exit}): {stderr}")]
    Crashed { exit: i32, stderr: String },

    /// Sidecar did not produce output within the configured timeout.
    #[error("classifier sidecar timed out after {0:?}")]
    Timeout(Duration),

    /// Python printed something, but it wasn't valid JSON against our schema.
    #[error("classifier sidecar produced an unparseable response: {parse_error}")]
    BadResponse { parse_error: String },
}

/// Resolve the venv'd python the installer wrote at
/// `<config>/classifier/venv/bin/python` (or `Scripts\python.exe` on Windows).
///
/// `REDACTOR_CLASSIFIER_PYTHON` overrides everything — used by tests to point
/// at a mock script and by power users who manage their own venv.
pub fn resolve_python_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var(PYTHON_PATH_ENV) {
        return Ok(PathBuf::from(p));
    }
    let dir = classifier_dir().context("could not determine classifier directory")?;
    Ok(venv_python(&dir))
}

/// `<config>/classifier/` — the directory the installer manages.
pub fn classifier_dir() -> Option<PathBuf> {
    config::config_dir().map(|d| d.join("classifier"))
}

/// Path to the python interpreter inside the classifier venv. The directory
/// layout matches `uv venv`'s default (`bin/` on Unix, `Scripts/` on Windows).
pub fn venv_python(classifier_dir: &Path) -> PathBuf {
    if cfg!(windows) {
        classifier_dir
            .join("venv")
            .join("Scripts")
            .join("python.exe")
    } else {
        classifier_dir.join("venv").join("bin").join("python")
    }
}

/// Local directory the installer writes GLiNER weights to. Passed to the
/// sidecar via `REDACTOR_GLINER_PATH` so the analyzer can load from disk
/// instead of re-resolving through the HuggingFace Hub. Symlink-free flat
/// layout (`snapshot_download(local_dir=…)`), required on Windows without
/// Developer Mode where the default HF cache layout fails to create the
/// `blobs/`→`snapshots/` symlinks.
pub fn gliner_model_dir() -> Option<PathBuf> {
    classifier_dir().map(|d| d.join("models").join("gliner"))
}

/// Resolve the timeout for a sidecar run. When `$REDACTOR_CLASSIFIER_TIMEOUT_SECS`
/// is set, it wins. Otherwise scale by the number of files: GLiNER on CPU
/// processes roughly 3-5 files/second, so a 300s default is fine for tiny
/// runs but starves anything over ~1000 files. Auto-scale at 1s/file,
/// clamped to [300s, 14400s] (4h max — past that point the user should
/// chunk manually).
fn resolve_timeout(files_count: usize) -> Duration {
    if let Some(secs) = std::env::var(TIMEOUT_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        return Duration::from_secs(secs);
    }
    // ~1 second per file is a generous over-estimate for CPU GLiNER; faster
    // is fine, the timeout is just the *upper* bound.
    let scaled = (files_count as u64).clamp(DEFAULT_TIMEOUT_SECS, 14_400);
    Duration::from_secs(scaled)
}

/// Send a classification request to the sidecar and parse its response.
///
/// `files` and `labels` are forwarded verbatim under the v1 request schema
/// (see spec §5.5). Phase 3 sidecar returns a stub response with empty
/// `results`; this function does not interpret the contents — it just
/// performs the IPC.
pub fn run_classifier(
    files: Vec<FileEntry>,
    labels: Vec<String>,
) -> std::result::Result<ClassifierResponse, ClassifierError> {
    let python = resolve_python_path().map_err(|e| ClassifierError::BadResponse {
        parse_error: format!("could not resolve python path: {e}"),
    })?;

    if !python.exists() {
        return Err(ClassifierError::NotInstalled(python));
    }

    let request = ClassifierRequest {
        version: PROTOCOL_VERSION,
        labels: &labels,
        files: &files,
    };
    let request_json =
        serde_json::to_string(&request).map_err(|e| ClassifierError::BadResponse {
            parse_error: format!("serialize request: {e}"),
        })?;

    let mut cmd = Command::new(&python);
    cmd.args(["-m", "classify"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Point the analyzer at the local GLiNER weights the installer wrote.
    // Only set when the directory actually exists — on a fresh install
    // without the model the analyzer's HF-default fallback is the right
    // error path (it will surface "weights load failed" with a clear hint).
    if let Some(gliner_dir) = gliner_model_dir() {
        if gliner_dir.exists() {
            cmd.env("REDACTOR_GLINER_PATH", &gliner_dir);
        }
    }

    let mut child = cmd.spawn().map_err(|e| ClassifierError::BadResponse {
        parse_error: format!("spawn {}: {e}", python.display()),
    })?;

    // Write stdin from the calling thread, then wait for the child with a
    // timeout. A short helper thread polls `wait()` so the caller can drop
    // the process if it hangs.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(request_json.as_bytes())
            .map_err(|e| ClassifierError::BadResponse {
                parse_error: format!("write stdin: {e}"),
            })?;
        // dropping stdin closes the pipe → EOF for the child
    }

    let timeout = resolve_timeout(files.len());
    eprintln!(
        "redactor: classifier timeout set to {}s ({} files)",
        timeout.as_secs(),
        files.len()
    );
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let out = child.wait_with_output();
        let _ = tx.send(out);
    });

    let output = match rx.recv_timeout(timeout) {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            let _ = handle.join();
            return Err(ClassifierError::BadResponse {
                parse_error: format!("wait child: {e}"),
            });
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Best-effort: we cannot kill via the moved child handle, so
            // leak the thread (it will exit when the child eventually does)
            // and surface the timeout. In practice the sidecar is python
            // and respects SIGPIPE on its closed stdout.
            return Err(ClassifierError::Timeout(timeout));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(ClassifierError::BadResponse {
                parse_error: "child wait channel disconnected".to_string(),
            });
        }
    };
    let _ = handle.join();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(ClassifierError::Crashed {
            exit: output.status.code().unwrap_or(-1),
            stderr,
        });
    }

    let stdout = std::str::from_utf8(&output.stdout).map_err(|e| ClassifierError::BadResponse {
        parse_error: format!("stdout is not UTF-8: {e}"),
    })?;
    let response: ClassifierResponse =
        serde_json::from_str(stdout.trim()).map_err(|e| ClassifierError::BadResponse {
            parse_error: format!("parse response JSON: {e}"),
        })?;

    if response.version != PROTOCOL_VERSION {
        return Err(ClassifierError::BadResponse {
            parse_error: format!(
                "unsupported response version {} (expected {})",
                response.version, PROTOCOL_VERSION
            ),
        });
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::sync::Mutex;
    #[cfg(unix)]
    use tempfile::tempdir;

    // The tests in this module mutate `REDACTOR_CLASSIFIER_PYTHON` — a global.
    // cargo runs tests in parallel by default, so we serialize on a single
    // mutex. Each test takes the lock for its whole body.
    #[cfg(unix)]
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Write a fake "python" shell script that prints the canned response on
    /// stdout, then returns the requested exit code. Returns the path so a
    /// test can point `REDACTOR_CLASSIFIER_PYTHON` at it.
    #[cfg(unix)]
    fn write_mock_python(dir: &Path, stdout_body: &str, exit_code: i32) -> PathBuf {
        let script = dir.join("mock_python.sh");
        let body = format!(
            "#!/bin/sh\n\
             # mock sidecar: drain stdin so the producer doesn't SIGPIPE,\n\
             # then emit a canned response and exit.\n\
             cat > /dev/null\n\
             cat <<'EOF'\n{stdout_body}\nEOF\n\
             exit {exit_code}\n"
        );
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[cfg(unix)]
    #[test]
    fn run_classifier_roundtrips_stub_response() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let td = tempdir().unwrap();
        let canned = r#"{"version":1,"results":[],"warnings":["phase-3 stub"]}"#;
        let script = write_mock_python(td.path(), canned, 0);
        std::env::set_var(PYTHON_PATH_ENV, &script);

        let resp = run_classifier(vec![], vec!["TAX_DOC".to_string()]).unwrap();
        assert_eq!(resp.version, 1);
        assert!(resp.results.is_empty());
        assert_eq!(resp.warnings, vec!["phase-3 stub"]);

        std::env::remove_var(PYTHON_PATH_ENV);
    }

    #[cfg(unix)]
    #[test]
    fn run_classifier_returns_not_installed_when_missing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let td = tempdir().unwrap();
        let missing = td.path().join("no-such-python");
        std::env::set_var(PYTHON_PATH_ENV, &missing);

        let err = run_classifier(vec![], vec![]).unwrap_err();
        assert!(matches!(err, ClassifierError::NotInstalled(_)));

        std::env::remove_var(PYTHON_PATH_ENV);
    }

    #[cfg(unix)]
    #[test]
    fn run_classifier_surfaces_crashed_with_stderr() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let td = tempdir().unwrap();
        let script = td.path().join("crashing.sh");
        let body = "#!/bin/sh\ncat > /dev/null\necho 'boom from sidecar' >&2\nexit 2\n";
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var(PYTHON_PATH_ENV, &script);

        let err = run_classifier(vec![], vec![]).unwrap_err();
        match err {
            ClassifierError::Crashed { exit, stderr } => {
                assert_eq!(exit, 2);
                assert!(stderr.contains("boom from sidecar"), "stderr={stderr}");
            }
            other => panic!("expected Crashed, got {other:?}"),
        }

        std::env::remove_var(PYTHON_PATH_ENV);
    }

    #[cfg(unix)]
    #[test]
    fn run_classifier_returns_bad_response_on_garbage_stdout() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let td = tempdir().unwrap();
        let script = write_mock_python(td.path(), "not a json doc", 0);
        std::env::set_var(PYTHON_PATH_ENV, &script);

        let err = run_classifier(vec![], vec![]).unwrap_err();
        assert!(
            matches!(err, ClassifierError::BadResponse { .. }),
            "got {err:?}"
        );

        std::env::remove_var(PYTHON_PATH_ENV);
    }

    #[cfg(unix)]
    #[test]
    fn run_classifier_rejects_version_mismatch() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let td = tempdir().unwrap();
        let canned = r#"{"version":99,"results":[],"warnings":[]}"#;
        let script = write_mock_python(td.path(), canned, 0);
        std::env::set_var(PYTHON_PATH_ENV, &script);

        let err = run_classifier(vec![], vec![]).unwrap_err();
        match err {
            ClassifierError::BadResponse { parse_error } => {
                assert!(parse_error.contains("version"), "msg={parse_error}");
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }

        std::env::remove_var(PYTHON_PATH_ENV);
    }

    #[test]
    fn venv_python_layout_is_platform_aware() {
        let dir = PathBuf::from("/x");
        let p = venv_python(&dir);
        if cfg!(windows) {
            assert!(
                p.ends_with("venv/Scripts/python.exe") || p.ends_with("venv\\Scripts\\python.exe")
            );
        } else {
            assert_eq!(p, PathBuf::from("/x/venv/bin/python"));
        }
    }
}

//! Lifecycle subcommands for the Python classifier sidecar:
//! `classifier-install`, `classifier-status`, `classifier-uninstall`,
//! `classifier-update`.
//!
//! The sidecar source lives in-repo at `classifier-py/`. The installed
//! tree at runtime is `<config>/classifier/`:
//!
//! ```text
//! <config>/classifier/
//!   venv/                 — uv-managed virtualenv (~50 MB)
//!   models/               — downloaded GLiNER + spaCy models (~450 MB)
//!   config.toml           — model overrides, device choice
//!   labels.txt            — user-editable label set (default-prefilled)
//!   version.json          — { classifier_version, installed_at }
//! ```
//!
//! Phase 3 wires the lifecycle; Phase 4 fills in real classification.
//! `classifier-update` is a Phase-5 deliverable per spec §P — this module
//! ships a placeholder that prints an informative message.

use crate::classify::{self, classifier_dir, gliner_model_dir, venv_python};
use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_CONFIG_TOML: &str = include_str!("../classifier-py/defaults/config.toml");
const DEFAULT_LABELS_TXT: &str = include_str!("../classifier-py/defaults/labels.txt");

/// Default GLiNER model identifier (spec §5.4 default). Overridable in
/// `config.toml` by the user post-install.
pub const DEFAULT_GLINER_MODEL: &str = "urchade/gliner_multi_pii-v1";
/// Default spaCy models. Multilingual coverage = German + English at minimum.
pub const DEFAULT_SPACY_MODELS: &[&str] = &["de_core_news_sm", "en_core_web_sm"];

/// Approximate post-install disk usage in MB (spec §1.3, §5.3). Used for
/// the interactive confirmation prompt.
pub const APPROX_DISK_USAGE_MB: u64 = 550;

#[derive(Debug, Clone, Copy)]
pub enum StatusFormat {
    Human,
    Json,
}

#[derive(Serialize, Debug)]
struct StatusReport {
    installed: bool,
    classifier_dir: String,
    python: Option<String>,
    python_version: Option<String>,
    torch_version: Option<String>,
    gliner_model_present: bool,
    spacy_models_present: Vec<SpacyStatus>,
    disk_usage_bytes: u64,
}

#[derive(Serialize, Debug)]
struct SpacyStatus {
    name: String,
    present: bool,
}

// ---------------------------------------------------------------------------
// classifier-install
// ---------------------------------------------------------------------------

/// Run `redactor classifier-install`. `quiet=true` skips the interactive
/// disk-space confirmation (for CI/scripted installs).
pub fn run_install(quiet: bool) -> Result<i32> {
    ensure_uv_available()?;
    let dir = classifier_dir().context("could not determine classifier directory")?;

    if !quiet && !confirm_disk_usage(&dir)? {
        eprintln!("redactor: classifier-install aborted by user");
        return Ok(1);
    }

    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;

    let repo_classifier_py = repo_classifier_py_dir()?;
    if !repo_classifier_py.exists() {
        bail!(
            "classifier-py source not found at {}. The redactor binary was \
             built without bundling the sidecar source; install from source.",
            repo_classifier_py.display()
        );
    }

    let venv_dir = dir.join("venv");
    eprintln!("redactor: creating venv at {}", venv_dir.display());
    run_uv(&["venv", venv_dir.to_str().unwrap()]).context("uv venv (create classifier venv)")?;

    eprintln!("redactor: installing classifier-py package (editable)");
    run_uv_in_venv(
        &venv_dir,
        &["pip", "install", "-e", repo_classifier_py.to_str().unwrap()],
    )
    .context("uv pip install -e classifier-py")?;

    // Defaults: write before model download so a Ctrl-C mid-download still
    // leaves a usable config (the user can re-run with the same shape).
    write_default_config_files(&dir)?;

    let gliner_dir = gliner_model_dir().context("could not determine GLiNER model directory")?;
    std::fs::create_dir_all(&gliner_dir)
        .with_context(|| format!("create {}", gliner_dir.display()))?;

    let mut failures: Vec<String> = Vec::new();

    eprintln!("redactor: downloading GLiNER model '{DEFAULT_GLINER_MODEL}' (~350 MB)");
    if let Err(e) = download_gliner_model(&venv_dir, &gliner_dir, DEFAULT_GLINER_MODEL) {
        eprintln!("redactor: ERROR — GLiNER download failed ({e})");
        failures.push(format!("GLiNER model '{DEFAULT_GLINER_MODEL}': {e}"));
    }

    for model in DEFAULT_SPACY_MODELS {
        eprintln!("redactor: downloading spaCy model '{model}'");
        if let Err(e) = download_spacy_model(&venv_dir, model) {
            eprintln!("redactor: ERROR — spaCy '{model}' download failed: {e}");
            failures.push(format!("spaCy model '{model}': {e}"));
        } else if !spacy_model_installed(&venv_python(&dir), model) {
            // Defence in depth: even when `python -m spacy download` exits 0,
            // verify the model is actually importable from the sidecar venv.
            // On Windows we have seen uv's environment discovery silently
            // install the wheel into an unrelated `.venv`, leaving the spaCy
            // command exit code at 0 but the sidecar empty. Treat that case
            // as a hard failure so users see the install actually broke.
            let msg = format!(
                "spaCy '{model}' reports success but is not importable from \
                 sidecar venv {} (possibly installed into the wrong env)",
                venv_dir.display()
            );
            eprintln!("redactor: ERROR — {msg}");
            failures.push(msg);
        }
    }

    write_version_json(&dir)?;

    if failures.is_empty() {
        eprintln!("redactor: classifier-install complete ({})", dir.display());
        Ok(0)
    } else {
        eprintln!(
            "\nredactor: classifier-install INCOMPLETE — {} component(s) failed:",
            failures.len()
        );
        for f in &failures {
            eprintln!("  - {f}");
        }
        eprintln!(
            "redactor: run `redactor classifier-status` for current state, then \
             re-run `redactor classifier-install` once the underlying issue is fixed."
        );
        Ok(3)
    }
}

// ---------------------------------------------------------------------------
// classifier-status
// ---------------------------------------------------------------------------

/// Print a status report. `format` controls human-table vs. JSON output.
pub fn run_status(format: StatusFormat) -> Result<i32> {
    let dir = classifier_dir().context("could not determine classifier directory")?;
    let report = collect_status(&dir);

    match format {
        StatusFormat::Human => print_status_human(&report),
        StatusFormat::Json => {
            let s =
                serde_json::to_string_pretty(&report).context("serialize status report as JSON")?;
            println!("{s}");
        }
    }
    Ok(0)
}

fn collect_status(dir: &Path) -> StatusReport {
    let python = venv_python(dir);
    let installed = python.exists();
    let python_version = if installed {
        capture_stdout(&python, &["--version"]).ok()
    } else {
        None
    };
    let torch_version = if installed {
        capture_stdout(&python, &["-c", "import torch;print(torch.__version__)"]).ok()
    } else {
        None
    };

    let gliner_dir = gliner_model_dir().unwrap_or_else(|| dir.join("models").join("gliner"));
    let gliner_present = gliner_dir.exists()
        && std::fs::read_dir(&gliner_dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);

    let spacy_models_present = DEFAULT_SPACY_MODELS
        .iter()
        .map(|name| SpacyStatus {
            name: name.to_string(),
            present: spacy_model_installed(&python, name),
        })
        .collect();

    let disk_usage_bytes = dir_size_bytes(dir).unwrap_or(0);

    StatusReport {
        installed,
        classifier_dir: dir.display().to_string(),
        python: Some(python.display().to_string()),
        python_version,
        torch_version,
        gliner_model_present: gliner_present,
        spacy_models_present,
        disk_usage_bytes,
    }
}

fn print_status_human(r: &StatusReport) {
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    println!("classifier status:");
    println!("  installed         {}", yes_no(r.installed));
    println!("  classifier_dir    {}", r.classifier_dir);
    if let Some(p) = &r.python {
        println!("  python_path       {p}");
    }
    if let Some(v) = &r.python_version {
        println!("  python_version    {}", v.trim());
    }
    if let Some(v) = &r.torch_version {
        println!("  torch_version     {}", v.trim());
    }
    println!("  gliner_model      {}", yes_no(r.gliner_model_present));
    for s in &r.spacy_models_present {
        println!("  spacy[{}]   {}", s.name, yes_no(s.present));
    }
    println!(
        "  disk_usage        {:.1} MB",
        (r.disk_usage_bytes as f64) / (1024.0 * 1024.0)
    );
}

// ---------------------------------------------------------------------------
// classifier-uninstall
// ---------------------------------------------------------------------------

/// Remove `<config>/classifier/` recursively. `yes=true` skips the prompt.
pub fn run_uninstall(yes: bool) -> Result<i32> {
    let dir = classifier_dir().context("could not determine classifier directory")?;
    if !dir.exists() {
        eprintln!(
            "redactor: nothing to uninstall (no {} on disk)",
            dir.display()
        );
        return Ok(0);
    }

    if !yes {
        eprintln!("redactor: this will recursively delete {}", dir.display());
        if !prompt_yes_no("Continue? [y/N] ", false)? {
            eprintln!("redactor: aborted");
            return Ok(1);
        }
    }

    std::fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
    eprintln!("redactor: removed {}", dir.display());
    Ok(0)
}

// ---------------------------------------------------------------------------
// classifier-update (Phase 5 placeholder per spec)
// ---------------------------------------------------------------------------

/// Phase 3 placeholder. Real `--upgrade` flow lands in Phase 5 — for now
/// we surface a clear "not yet" message rather than half-running.
pub fn run_update() -> Result<i32> {
    ensure_uv_available()?;
    let dir = classifier_dir().context("could not determine classifier directory")?;
    let venv_dir = dir.join("venv");
    if !venv_dir.exists() {
        bail!(
            "classifier not installed (no {}). Run `redactor classifier-install` first.",
            venv_dir.display()
        );
    }
    eprintln!(
        "redactor: classifier-update is a Phase-5 deliverable. \
         For now, run `redactor classifier-uninstall --yes && redactor classifier-install` \
         to refresh deps and models."
    );
    Ok(2)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn ensure_uv_available() -> Result<()> {
    let status = Command::new("uv").arg("--version").output();
    match status {
        Ok(o) if o.status.success() => Ok(()),
        _ => Err(anyhow!(
            "uv is not installed (or not on PATH). Install it first:\n  \
             macOS:    brew install uv\n  \
             Linux:    curl -LsSf https://astral.sh/uv/install.sh | sh\n  \
             Windows:  winget install --id astral-sh.uv\n\
             redactor does not fall back to pip — uv is required."
        )),
    }
}

fn run_uv(args: &[&str]) -> Result<()> {
    let status = Command::new("uv")
        .args(args)
        .status()
        .with_context(|| format!("spawn `uv {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`uv {}` exited with status {}", args.join(" "), status);
    }
    Ok(())
}

fn run_uv_in_venv(venv_dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("uv")
        .args(args)
        .env("VIRTUAL_ENV", venv_dir)
        .env("UV_PROJECT_ENVIRONMENT", venv_dir)
        .status()
        .with_context(|| format!("spawn `uv {}` (in venv)", args.join(" ")))?;
    if !status.success() {
        bail!("`uv {}` exited with status {}", args.join(" "), status);
    }
    Ok(())
}

fn capture_stdout(bin: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("spawn `{} {}`", bin.display(), args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`{} {}` exited with status {}",
            bin.display(),
            args.join(" "),
            out.status
        );
    }
    let s = String::from_utf8(out.stdout).context("decode stdout as UTF-8")?;
    Ok(s)
}

fn spacy_model_installed(python: &Path, model: &str) -> bool {
    let script =
        format!("import spacy;import sys;sys.exit(0 if spacy.util.is_package('{model}') else 1)");
    Command::new(python)
        .args(["-c", &script])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn download_gliner_model(venv_dir: &Path, target: &Path, model: &str) -> Result<()> {
    let python = venv_dir.join(if cfg!(windows) {
        "Scripts/python.exe"
    } else {
        "bin/python"
    });
    std::fs::create_dir_all(target).with_context(|| format!("create {}", target.display()))?;
    let script = build_gliner_script(model, target);
    let status = Command::new(python)
        .args(["-c", &script])
        .status()
        .context("spawn python for GLiNER snapshot_download")?;
    if !status.success() {
        bail!("GLiNER snapshot_download exited with status {status}");
    }
    // HuggingFace's snapshot_download returns 0 even when the underlying
    // ThreadPool swallowed all worker exceptions (e.g. WinError 1314 on
    // Windows without Developer Mode). Verify at least one weight file
    // actually landed before declaring success.
    let has_files = std::fs::read_dir(target)
        .map(|mut d| d.any(|e| e.is_ok()))
        .unwrap_or(false);
    if !has_files {
        bail!(
            "GLiNER snapshot_download exited 0 but {} is empty — the underlying \
             HuggingFace call likely failed silently",
            target.display()
        );
    }
    Ok(())
}

/// Build the inline Python `-c` script that drives HuggingFace's
/// `snapshot_download` to fetch a GLiNER model into `target_dir`.
///
/// Uses `local_dir` (not `cache_dir`) so files land in a flat layout we can
/// hand to `GLiNER.from_pretrained(path)` at runtime. `local_dir_use_symlinks`
/// is forced to False because the default HF cache layout uses symlinks
/// between `blobs/` and `snapshots/`, and Windows non-admin users without
/// Developer Mode hit `OSError: [WinError 1314]` when those are created.
///
/// The target path is normalised to forward slashes so it can be embedded in
/// a single-quoted Python string literal without tripping Python's escape
/// parser. On Windows, `C:\Users\…` contains `\U` which Python reads as a
/// truncated unicode escape (`\UXXXXXXXX`) and refuses to compile. Forward
/// slashes are accepted by `pathlib.Path` and `os.path` on Windows.
fn build_gliner_script(model: &str, target_dir: &Path) -> String {
    let target = target_dir.to_string_lossy().replace('\\', "/");
    format!(
        "from huggingface_hub import snapshot_download\n\
         snapshot_download(repo_id='{model}', local_dir='{target}', local_dir_use_symlinks=False)\n"
    )
}

fn download_spacy_model(venv_dir: &Path, model: &str) -> Result<()> {
    let python = venv_dir.join(if cfg!(windows) {
        "Scripts/python.exe"
    } else {
        "bin/python"
    });
    // `python -m spacy download` shells out to install the model wheel.
    // Modern spaCy (3.8+) prefers `uv pip install` when uv is on PATH, and
    // uv's environment discovery walks up the cwd tree looking for a
    // `.venv` — which can find a stray top-level `~/.venv` instead of the
    // sidecar's venv. Pin both env vars so uv (and pip's PEP 668 check)
    // know exactly which interpreter to target.
    //
    // Subtle: a uv-created venv (`uv venv`) does NOT include pip by default,
    // because `uv` is self-contained. spaCy's downloader still shells out
    // to pip internally, so we need to seed it first. `uv pip install pip`
    // into the target venv is the canonical fix.
    ensure_pip_in_venv(venv_dir, &python)?;
    let status = Command::new(&python)
        .args(["-m", "spacy", "download", model])
        .env("VIRTUAL_ENV", venv_dir)
        .env("UV_PROJECT_ENVIRONMENT", venv_dir)
        .status()
        .with_context(|| format!("spawn `python -m spacy download {model}`"))?;
    if !status.success() {
        bail!("`python -m spacy download {model}` exited with status {status}");
    }
    Ok(())
}

/// Make sure `pip` is installed inside the target venv. `uv venv` produces a
/// pip-less environment by default, which breaks tools like `spacy download`
/// that shell out to pip internally. Idempotent — a no-op if pip is already
/// available.
fn ensure_pip_in_venv(venv_dir: &Path, python: &Path) -> Result<()> {
    // Cheap check: ask the venv-python whether it can import pip.
    let probe = Command::new(python).args(["-c", "import pip"]).status();
    if matches!(probe, Ok(s) if s.success()) {
        return Ok(());
    }
    // Install pip via uv. We prefer this over `python -m ensurepip` because
    // uv venvs ship without ensurepip data on some platforms.
    let status = Command::new("uv")
        .args(["pip", "install", "pip"])
        .env("VIRTUAL_ENV", venv_dir)
        .env("UV_PROJECT_ENVIRONMENT", venv_dir)
        .status()
        .with_context(|| "spawn `uv pip install pip` to seed the venv")?;
    if !status.success() {
        bail!("`uv pip install pip` exited with status {status}");
    }
    Ok(())
}

fn write_default_config_files(dir: &Path) -> Result<()> {
    let cfg = dir.join("config.toml");
    if !cfg.exists() {
        std::fs::write(&cfg, DEFAULT_CONFIG_TOML)
            .with_context(|| format!("write {}", cfg.display()))?;
    }
    let labels = dir.join("labels.txt");
    if !labels.exists() {
        std::fs::write(&labels, DEFAULT_LABELS_TXT)
            .with_context(|| format!("write {}", labels.display()))?;
    }
    Ok(())
}

fn write_version_json(dir: &Path) -> Result<()> {
    let body = serde_json::json!({
        "classifier_version": classify::PROTOCOL_VERSION,
        // Persist as a separate string for the human; the protocol version
        // is the integer above. The "0.1.0" tag mirrors `classifier-py`'s
        // `__init__.__version__` and is bumped together with it.
        "redactor_classify_version": "0.1.0",
        "installed_at": Utc::now().to_rfc3339(),
    });
    let path = dir.join("version.json");
    std::fs::write(&path, serde_json::to_string_pretty(&body)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn repo_classifier_py_dir() -> Result<PathBuf> {
    // Source ships next to Cargo.toml at the repo root. The binary embeds
    // the path at compile time via `CARGO_MANIFEST_DIR` so `cargo install`
    // and dev runs both resolve correctly.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir.join("classifier-py"))
}

fn dir_size_bytes(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0_u64;
    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            if let Ok(m) = entry.metadata() {
                total += m.len();
            }
        }
    }
    Ok(total)
}

fn confirm_disk_usage(dir: &Path) -> Result<bool> {
    eprintln!("redactor classifier-install will:");
    eprintln!("  - create a uv venv at {}/venv", dir.display());
    eprintln!("  - install pinned ML dependencies (Presidio + GLiNER + spaCy + torch)");
    eprintln!(
        "  - download '{DEFAULT_GLINER_MODEL}' and spaCy '{}' / '{}'",
        DEFAULT_SPACY_MODELS[0], DEFAULT_SPACY_MODELS[1]
    );
    eprintln!("  - expected disk usage: ~{APPROX_DISK_USAGE_MB} MB total");
    prompt_yes_no("Proceed? [y/N] ", false)
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line).context("read stdin")?;
    let trimmed = line.trim().to_ascii_lowercase();
    Ok(match trimmed.as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_config_toml_includes_model_section() {
        assert!(DEFAULT_CONFIG_TOML.contains("[model]"));
        assert!(DEFAULT_CONFIG_TOML.contains(DEFAULT_GLINER_MODEL));
    }

    #[test]
    fn default_labels_txt_includes_core_pii_labels() {
        for label in ["TAX_DOC", "PERSONAL_RECORD", "CREDENTIAL"] {
            assert!(
                DEFAULT_LABELS_TXT.contains(label),
                "default labels missing '{label}'"
            );
        }
    }

    #[test]
    fn write_default_config_files_creates_both() {
        let td = tempdir().unwrap();
        write_default_config_files(td.path()).unwrap();
        assert!(td.path().join("config.toml").exists());
        assert!(td.path().join("labels.txt").exists());
    }

    #[test]
    fn write_default_config_files_does_not_overwrite() {
        let td = tempdir().unwrap();
        let labels = td.path().join("labels.txt");
        std::fs::write(&labels, "USER_LABEL\n").unwrap();
        write_default_config_files(td.path()).unwrap();
        let after = std::fs::read_to_string(&labels).unwrap();
        assert_eq!(after, "USER_LABEL\n", "existing file must not be clobbered");
    }

    #[test]
    fn write_version_json_serializes_required_fields() {
        let td = tempdir().unwrap();
        write_version_json(td.path()).unwrap();
        let body = std::fs::read_to_string(td.path().join("version.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["classifier_version"], 1);
        assert!(v["installed_at"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn dir_size_walks_recursively() {
        let td = tempdir().unwrap();
        std::fs::create_dir_all(td.path().join("a/b")).unwrap();
        std::fs::write(td.path().join("a/x.txt"), b"hello").unwrap();
        std::fs::write(td.path().join("a/b/y.txt"), b"world!").unwrap();
        let size = dir_size_bytes(td.path()).unwrap();
        assert_eq!(size, 11);
    }

    #[test]
    fn dir_size_returns_zero_when_missing() {
        let td = tempdir().unwrap();
        let missing = td.path().join("nope");
        assert_eq!(dir_size_bytes(&missing).unwrap(), 0);
    }

    #[test]
    fn gliner_script_normalises_windows_backslashes() {
        // Regression: a Windows path like `C:\Users\X\redactor\models\gliner`
        // contains `\U` which Python parses as a truncated unicode escape and
        // refuses to compile. The build helper must emit forward slashes so
        // the embedded string literal is valid Python on every platform.
        let cache = Path::new(r"C:\Users\Foo\AppData\Roaming\redactor\models\gliner");
        let script = build_gliner_script("urchade/gliner_multi_pii-v1", cache);

        assert!(
            !script.contains('\\'),
            "script must not contain raw backslashes (would break Python parser): {script}"
        );
        assert!(
            script.contains("'C:/Users/Foo/AppData/Roaming/redactor/models/gliner'"),
            "expected forward-slashed target path, got: {script}"
        );
        assert!(
            script.contains("urchade/gliner_multi_pii-v1"),
            "expected model id present, got: {script}"
        );
        assert!(
            script.contains("snapshot_download"),
            "expected HuggingFace API call, got: {script}"
        );
    }

    #[test]
    fn gliner_script_preserves_unix_slashes() {
        let cache = Path::new("/home/user/.config/redactor/models/gliner");
        let script = build_gliner_script("foo/bar", cache);
        assert!(
            script.contains("'/home/user/.config/redactor/models/gliner'"),
            "got: {script}"
        );
    }

    #[test]
    fn gliner_script_uses_local_dir_mode_without_symlinks() {
        // Regression: cache_dir mode triggers HF's symlinked blobs/snapshots
        // layout, which `os.symlink` cannot create on Windows without
        // Developer Mode (WinError 1314). local_dir + local_dir_use_symlinks=False
        // forces a flat, copy-only layout that works everywhere.
        let cache = Path::new("/tmp/redactor/models/gliner");
        let script = build_gliner_script("foo/bar", cache);
        assert!(
            script.contains("local_dir="),
            "must use local_dir (not cache_dir) so Windows non-admin works: {script}"
        );
        assert!(
            script.contains("local_dir_use_symlinks=False"),
            "must disable symlinks so Windows non-admin works: {script}"
        );
        assert!(
            !script.contains("cache_dir="),
            "must not use cache_dir (triggers symlinks): {script}"
        );
    }
}

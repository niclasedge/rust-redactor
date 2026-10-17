//! redactor — strip sensitive values from text/structured files for use as a
//! pre-tool-use hook in Codex/OpenCode/Claude Code.
//!
//! Two invocation styles:
//!   - filter:  `redactor [FILE]`         (stdin or file → stdout)
//!   - wrap:    `redactor wrap -- <cmd>`  (run cmd, filter stdout+stderr)
//!
//! See README for hook-integration patterns.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

mod classifier_lifecycle;
mod classify;
mod classify_cmd;
mod classify_filter;
mod classify_llm;
mod classify_merge;
mod classify_state;
mod classify_suggest;
mod classify_walk;
mod clean;
mod config;
mod explain;
mod hook;
mod ignorefile;
mod install;
mod logger;
mod mock;
mod network_guard;
mod patterns;
mod redact_markdown;
mod redactor;
mod search;
mod search_tasks;
mod wrap;

use redactor::{detect_mode, Mode};

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum CliMode {
    Csv,
    Json,
    Env,
    Pattern,
    /// auto-detect from file basename/extension; falls back to `pattern` for stdin
    #[default]
    Auto,
}

impl CliMode {
    fn resolve(
        self,
        path: Option<&std::path::Path>,
        overrides: &std::collections::HashMap<String, Mode>,
    ) -> Mode {
        match self {
            CliMode::Csv => Mode::Csv,
            CliMode::Json => Mode::Json,
            CliMode::Env => Mode::Env,
            CliMode::Pattern => Mode::Pattern,
            CliMode::Auto => path
                .and_then(|p| detect_mode(p, overrides))
                .unwrap_or(Mode::Pattern),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "redactor",
    version,
    about = "Redact secrets/structure in stdin, files, or wrapped subprocess output.",
    long_about = "Modes:\n  csv      header verbatim, line 2 -> <redacted>, rest dropped with marker\n  json     structure preserved, leaves -> <redacted>, lists keep first item\n  env      KEY=<redacted>, comments/blank lines preserved\n  pattern  inline regex scrubbing for arbitrary text/log/code\n  auto     pick mode by file extension (default for FILE arg)\n\nLogging: every redaction is appended to <log-dir>/YYYY-MM-DD-redacted.log\n(default: $REDACTOR_LOG_DIR or ./logs/, override with --log-dir).\n\nUse `redactor wrap -- <cmd>` to execute a subprocess and filter both its\nstdout and stderr line-by-line. This is the recommended cross-platform\nalternative to piping (`cmd | redactor`)."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Sub>,

    /// (no-subcommand mode) Path to file. Use '-' or omit to read stdin.
    #[arg(default_value = "-", global = false)]
    file: String,

    #[command(flatten)]
    common: CommonOpts,
}

#[derive(Subcommand, Debug)]
enum Sub {
    /// Run a subprocess and redact its stdout+stderr line-by-line.
    /// Exit code of the wrapped process is forwarded.
    Wrap {
        #[command(flatten)]
        common: CommonOpts,

        /// Command + args to execute. Use `--` to separate from redactor flags.
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },

    /// Write starter `keywords.txt` + `patterns.json` into the config dir
    /// ($REDACTOR_CONFIG_DIR or platform-default like ~/.config/redactor/).
    InitConfig {
        /// Overwrite existing files
        #[arg(long)]
        force: bool,
    },

    /// Print the resolved config directory and whether files exist there
    ConfigPath,

    /// Run a Claude Code hook event. Reads JSON payload on stdin, writes
    /// decision JSON on stdout.
    Hook {
        #[arg(value_enum)]
        event: HookEvent,
    },

    /// Deploy strict-redaction hook config (settings + CLAUDE.md) to
    /// <target>/.claude/. Templates baked into the binary at compile time.
    ///
    /// Alias for `install-plugin local <target>`. Use `install-plugin` for
    /// the full CLI including `--dry-run`, `--merge`, and global install.
    InstallHooks {
        /// Target project directory (default: current directory).
        /// Ignored when --global is set.
        #[arg(default_value = ".")]
        target: PathBuf,
        /// Overwrite existing .claude/ without backup
        #[arg(long)]
        force: bool,
        /// Install/merge into ~/.claude/ instead of a local project
        #[arg(long, conflicts_with = "target")]
        global: bool,
        /// Show planned actions without writing any files
        #[arg(long)]
        dry_run: bool,
        /// Merge hook entries into an existing settings.json instead of
        /// replacing the whole .claude/ directory
        #[arg(long)]
        merge: bool,
    },

    /// Install the redactor Claude Code plugin locally or globally.
    ///
    /// Local: deploys `.claude/settings.json` + `CLAUDE.md` into <target>.
    /// Global: merges hook entries into `~/.claude/settings.json` and
    ///         appends/refreshes a managed block in `~/.claude/CLAUDE.md`.
    InstallPlugin {
        #[command(subcommand)]
        scope: InstallPluginScope,
    },

    /// Remove redactor plugin artifacts from a local project's .claude/.
    UninstallPlugin {
        /// Target project directory (default: current directory)
        #[arg(default_value = ".")]
        target: PathBuf,
        /// Show planned actions without removing anything
        #[arg(long)]
        dry_run: bool,
    },

    /// Report plugin installation state for a local project and/or globally.
    PluginStatus {
        /// Check the global (~/.claude/) installation
        #[arg(long)]
        global: bool,
        /// Local project directory to check (default: current directory)
        #[arg(long, value_name = "PATH")]
        target: Option<PathBuf>,
    },

    /// Scan a file and emit one JSONL line per match (audit pipeline format).
    /// Stdout is JSONL findings only — no sanitized output, no log entries.
    Scan {
        #[command(flatten)]
        common: CommonOpts,
        /// Path to file. Use - or omit for stdin.
        #[arg(default_value = "-")]
        file: String,
    },

    /// Anonymize a structured file. Output goes to <FILE>.clean. Supports
    /// CSV and JSON (extension-detected).
    Clean {
        /// Path to a CSV or JSON file.
        file: String,
    },

    /// Generate schema-inferred mock CSV. Output goes to <basename>mock.csv.
    /// Reads header + first data row to infer column types, then emits N rows.
    Mock {
        /// Path to a CSV file.
        file: String,
        /// Number of mock rows to generate (default 10).
        #[arg(long, default_value_t = 10)]
        rows: usize,
    },

    /// Update the redactor binary in place from the latest GitHub release.
    /// Currently a placeholder that points to the manual install path; the
    /// fully-automated flow lands together with the release pipeline.
    SelfUpdate {
        /// Print what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,
    },

    /// Ranked full-text search over markdown (and source files with --code)
    /// with sanitized snippets. Replaces the Python q tool for initial
    /// knowledge lookup.
    Search(search::SearchArgs),

    /// Install the Python classifier sidecar: creates a uv venv under
    /// `<config>/classifier/venv`, installs pinned ML deps, and downloads
    /// the default GLiNER + spaCy models (~550 MB). Requires `uv` on PATH.
    ClassifierInstall {
        /// Skip the interactive disk-space confirmation prompt.
        #[arg(long)]
        quiet: bool,
    },

    /// Show classifier install state: venv presence, python/torch versions,
    /// model availability, and on-disk size.
    ClassifierStatus {
        /// Output format. Default is a human-readable table.
        #[arg(long, value_enum, default_value_t = ClassifierStatusFormat::Human)]
        format: ClassifierStatusFormat,
    },

    /// Recursively remove `<config>/classifier/` (venv, models, configs).
    ClassifierUninstall {
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },

    /// Upgrade pinned classifier dependencies and re-pull models. Currently
    /// a Phase-5 placeholder — use `classifier-uninstall && classifier-install`
    /// for now.
    ClassifierUpdate,

    /// Walk a directory, ask the ML sidecar to classify each file, and
    /// write a `.redactorignore.suggested` review file. Requires the
    /// classifier sidecar — install it with `redactor classifier-install`.
    ClassifyFiles(classify_cmd::ClassifyFilesArgs),

    /// Review a `.redactorignore.suggested` file interactively and append
    /// accepted entries to `~/.redactorignore`. Each entry shows the
    /// suggested path + ML confidence/labels/evidence; you respond with
    /// y / n / s (skip-rest) / q (quit). Use `--yes` to append every
    /// suggestion without prompts, or `--dry-run` to preview.
    ClassifyMerge(classify_merge::ClassifyMergeArgs),

    /// One-shot migration helper: copies keyword entries from the legacy
    /// `<config>/keywords.txt` into `~/.redactorignore` and renames the
    /// legacy file to `keywords.txt.bak`. Idempotent — running twice is
    /// a no-op.
    MigrateKeywords,

    /// Phase 6d — explain why a path or text would be blocked / redacted.
    /// Reports each matching source (self-protect, crypto, sensitive-path,
    /// office-doc, ~/.redactorignore line, built-in pattern rule).
    Explain {
        /// Path or text to inspect.
        target: String,
    },

    /// Interactively redact keywords/patterns in Markdown files (Obsidian vault).
    /// Walks `*.md` in batches (default 10), shows each hit as
    /// original → placeholder, and writes only after confirmation.
    RedactMarkdown {
        #[command(flatten)]
        common: CommonOpts,

        #[command(flatten)]
        args: redact_markdown::RedactMarkdownArgs,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum ClassifierStatusFormat {
    #[default]
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HookEvent {
    Prompt,
    PreBash,
    PrePatch,
    PreRead,
    /// v0.7: PreToolUse matcher `Edit|MultiEdit|Write` — path-guard only,
    /// no content sanitisation. Primary purpose: block Write from creating
    /// new files at protected paths (Edit/MultiEdit are indirectly blocked
    /// via the pre-existing Read-block since Claude Code requires a Read
    /// before any in-place edit).
    PreEdit,
    PostTool,
    PostWrite,
    SessionStart,
    /// rred-36: fixed-deny for `mcp__*` tools (high-density PII, no per-server redaction)
    DenyMcp,
    /// rred-36: fixed-deny for `Grep` tool (bypasses path-guard via matching lines)
    DenyGrep,
    /// rred-36: fixed-deny for `NotebookEdit` tool (not used in this profile)
    DenyNotebook,
}

#[derive(Subcommand, Debug)]
enum InstallPluginScope {
    /// Install into <target>/.claude/ (default: current directory).
    Local {
        /// Target project directory
        #[arg(default_value = ".")]
        target: PathBuf,
        /// Show planned actions without writing any files
        #[arg(long)]
        dry_run: bool,
        /// Overwrite existing .claude/ without backup
        #[arg(long)]
        force: bool,
        /// Merge hook entries into an existing settings.json instead of
        /// replacing the whole .claude/ directory
        #[arg(long)]
        merge: bool,
    },
    /// Install/merge into ~/.claude/ (global, all Claude Code sessions).
    Global {
        /// Show planned actions without writing any files
        #[arg(long)]
        dry_run: bool,
        /// Skip creating a timestamped backup of settings.json
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args, Debug, Default)]
struct CommonOpts {
    /// Force mode (default: auto-detect from extension; pattern for stdin/wrap)
    #[arg(short = 't', long, value_enum, default_value_t = CliMode::Auto)]
    r#type: CliMode,

    /// (pattern) JSON file with extra rules: [{"name","re","sub"?}]
    #[arg(long)]
    patterns: Option<PathBuf>,

    /// (pattern) comma-separated literal terms to scrub case-insensitively
    #[arg(long, default_value = "")]
    keywords: String,

    /// (pattern) load keywords from file (.txt one-per-line or .json string array)
    #[arg(long, value_name = "FILE")]
    keywords_file: Option<PathBuf>,

    /// (pattern) skip built-in regex patterns
    #[arg(long)]
    no_defaults: bool,

    /// Skip auto-loading from the config dir (keywords.txt / patterns.json)
    #[arg(long)]
    no_config: bool,

    /// Override log directory (default: $REDACTOR_LOG_DIR or ./logs/)
    #[arg(long)]
    log_dir: Option<PathBuf>,

    /// Disable logging entirely
    #[arg(long)]
    no_log: bool,

    /// Free-form label that gets logged as `command=...`. Useful when invoked
    /// from an agent hook so logs show the originating tool call, e.g.
    /// `--source-label "Read test.csv"` or `--source-label "Bash"`.
    #[arg(long, default_value = "")]
    source_label: String,
}

fn read_input(arg: &str) -> Result<(String, Option<PathBuf>)> {
    if arg == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s).context("read stdin")?;
        Ok((s, None))
    } else {
        let p = PathBuf::from(arg);
        let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        Ok((s, Some(p)))
    }
}

fn build_pattern_rules(common: &CommonOpts) -> Result<Vec<patterns::Rule>> {
    let mut rules = if common.no_defaults {
        Vec::new()
    } else {
        patterns::defaults()
    };
    // Apply `[policy] mask_username` from cwd's `.redactor.toml`. Symmetric
    // with build_default_rules() in hook.rs — without this, the docs' claim
    // that mask_username=false disables home-dir rules holds only for the
    // hook entry point, not for direct CLI use (wrap/filter/scan).
    if !common.no_config && !common.no_defaults {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        if let Ok(policy) = config::autoload_project_policy(&cwd) {
            if !policy.mask_username {
                rules.retain(|r| r.name != "windows_home_dir" && r.name != "unix_home_dir");
            }
        }
    }
    // CLI --patterns FILE
    if let Some(p) = &common.patterns {
        rules.extend(patterns::load_custom(p)?);
    }
    // CLI --keywords inline
    if !common.keywords.is_empty() {
        rules.extend(patterns::from_keywords(&common.keywords));
    }
    // CLI --keywords-file
    if let Some(p) = &common.keywords_file {
        rules.extend(config::load_keywords_file(p)?);
    }
    // Auto-loaded config dir defaults (additive, opt-out via --no-config)
    if !common.no_config {
        rules.extend(config::autoload_rules()?);
    }
    // Per-project .redactor.toml [patterns.custom] (additive)
    if !common.no_config {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        rules.extend(config::autoload_project_rules(&cwd)?);
    }
    Ok(rules)
}

fn resolve_log_dir(common: &CommonOpts) -> Option<PathBuf> {
    if common.no_log {
        None
    } else {
        Some(
            common
                .log_dir
                .clone()
                .unwrap_or_else(logger::resolve_log_dir),
        )
    }
}

fn run_filter(file: &str, common: CommonOpts) -> Result<i32> {
    let (text, path) = read_input(file)?;
    let mode_overrides = if common.no_config {
        std::collections::HashMap::new()
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        config::autoload_project_modes(&cwd).unwrap_or_default()
    };
    let mode = common.r#type.resolve(path.as_deref(), &mode_overrides);
    let source_label = match path.as_ref() {
        Some(p) => p.display().to_string(),
        None => "stdin".to_string(),
    };

    let (output, log_entries) = match mode {
        Mode::Csv => redactor::redact_csv(&text)?,
        Mode::Json => redactor::redact_json(&text)?,
        Mode::Env => redactor::redact_env(&text)?,
        Mode::Pattern => {
            let rules = build_pattern_rules(&common)?;
            if rules.is_empty() {
                bail!("pattern mode: no rules (use built-ins or --patterns/--keywords)");
            }
            redactor::redact_pattern(&text, &rules)
        }
    };

    let stdout = io::stdout();
    let mut h = stdout.lock();
    h.write_all(output.as_bytes())?;
    if !output.ends_with('\n') {
        h.write_all(b"\n")?;
    }

    if let Some(dir) = resolve_log_dir(&common) {
        let cmd_label = if common.source_label.is_empty() {
            "-".to_string()
        } else {
            common.source_label.clone()
        };
        for ev in &log_entries {
            let event = logger::Event {
                source: &source_label,
                mode: mode.name(),
                command: &cmd_label,
                rule: &ev.rule,
                count: ev.count,
                sample: &ev.sample,
            };
            logger::log_event(&dir, &event);
        }
    }
    Ok(0)
}

fn run_wrap(common: CommonOpts, argv: Vec<String>) -> Result<i32> {
    if argv.is_empty() {
        bail!("wrap: missing command (usage: redactor wrap -- <cmd> [args...])");
    }
    let rules = build_pattern_rules(&common)?;
    if rules.is_empty() {
        bail!("wrap: no rules (use built-ins or --patterns/--keywords)");
    }
    let log_dir = resolve_log_dir(&common);
    let cmd = &argv[0];
    let args = &argv[1..];
    let source_label = format!("wrap:{cmd}");
    let command_label = if common.source_label.is_empty() {
        argv.join(" ")
    } else {
        common.source_label.clone()
    };
    wrap::run(
        cmd,
        args,
        Arc::new(rules),
        log_dir.as_deref(),
        &source_label,
        &command_label,
    )
}

fn run_scan(file: &str, common: CommonOpts) -> Result<i32> {
    let (text, _path) = read_input(file)?;
    let rules = build_pattern_rules(&common)?;
    let findings = redactor::scan_pattern(&text, &rules);
    let stdout = io::stdout();
    let mut h = stdout.lock();
    for f in &findings {
        let s = serde_json::to_string(f).context("serialize finding")?;
        h.write_all(s.as_bytes())?;
        h.write_all(b"\n")?;
    }
    Ok(0)
}

fn run_clean(file: &str) -> Result<i32> {
    let p = PathBuf::from(file);
    let text = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let cleaned = match ext.as_str() {
        "csv" => clean::clean_csv(&text)?,
        "json" => clean::clean_json(&text)?,
        other => bail!("clean: unsupported extension '{other}' (expected csv or json)"),
    };
    let mut out_path = p.clone().into_os_string();
    out_path.push(".clean");
    let out_path = PathBuf::from(out_path);
    std::fs::write(&out_path, cleaned).with_context(|| format!("write {}", out_path.display()))?;
    println!("redactor: wrote {}", out_path.display());
    Ok(0)
}

fn run_mock(file: &str, rows: usize) -> Result<i32> {
    let p = PathBuf::from(file);
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if ext != "csv" {
        bail!("mock: only CSV is supported (got '{ext}'); use a path with the csv extension");
    }
    let text = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    let mocked = mock::mock_csv(&text, rows)?;
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("data");
    let parent = p.parent().unwrap_or_else(|| std::path::Path::new(""));
    let out_path = parent.join(format!("{stem}.mock.csv"));
    std::fs::write(&out_path, mocked).with_context(|| format!("write {}", out_path.display()))?;
    println!("redactor: wrote {} ({rows} rows)", out_path.display());
    Ok(0)
}

fn run_self_update(dry_run: bool) -> Result<i32> {
    // Stub: full HTTP-based self-update lands with the release pipeline.
    // For now point users at the manual install path.
    let current = env!("CARGO_PKG_VERSION");
    if dry_run {
        println!("redactor: self-update dry-run (current version: {current})");
        println!(
            "redactor: would download the matching asset from \
            https://github.com/niclasedge/rust-redactor/releases/latest"
        );
        return Ok(0);
    }
    eprintln!(
        "redactor: self-update is not yet wired to the release pipeline.\n\
         For now, update via:\n\
         \n\
             cargo install --git https://github.com/niclasedge/rust-redactor --force\n\
         \n\
         Once rred-24 is shipped (release.yml CI workflow), this command will \n\
         download and replace the binary in place."
    );
    Ok(2)
}

fn run_init_config(force: bool) -> Result<i32> {
    let dir = config::init_config(force)?;
    println!(
        "redactor: wrote {} and {}",
        dir.join(config::KEYWORDS_FILE).display(),
        dir.join(config::PATTERNS_FILE).display()
    );
    Ok(0)
}

fn run_config_path() -> Result<i32> {
    let dir = config::config_dir().context("could not determine config directory")?;
    let kw = dir.join(config::KEYWORDS_FILE);
    let pat = dir.join(config::PATTERNS_FILE);
    println!("config_dir={}", dir.display());
    println!("keywords_file={} (exists={})", kw.display(), kw.exists());
    println!("patterns_file={} (exists={})", pat.display(), pat.exists());
    if let Some(ign) = ignorefile::ignorefile_path() {
        println!("redactorignore={} (exists={})", ign.display(), ign.exists());
    }
    Ok(0)
}

/// v0.7: one-shot migration from legacy `<config>/keywords.txt` to
/// `~/.redactorignore`. Behaviour:
///   1. If `~/.redactorignore` exists, refuse to overwrite — abort with a
///      hint to merge manually.
///   2. If legacy file missing → no-op (return Ok with exit 0 + info msg).
///   3. Otherwise: copy keyword lines (skipping comments/blanks) into a
///      new `~/.redactorignore`, then rename the legacy file to
///      `keywords.txt.bak`. Idempotent in the sense that subsequent runs
///      see no legacy file and bail out cleanly.
fn run_migrate_keywords() -> Result<i32> {
    let cfg = config::config_dir().context("could not determine config directory")?;
    let legacy = cfg.join(config::KEYWORDS_FILE);
    if !legacy.exists() {
        println!(
            "migrate-keywords: no legacy {} found — nothing to do.",
            legacy.display()
        );
        return Ok(0);
    }
    let target = ignorefile::ignorefile_path()
        .context("could not determine home dir for ~/.redactorignore")?;
    if target.exists() {
        eprintln!(
            "migrate-keywords: target {} already exists.\n\
             Refusing to overwrite. To merge, manually append entries from {} \
             and then delete or rename the legacy file.",
            target.display(),
            legacy.display()
        );
        return Ok(2);
    }

    let body =
        std::fs::read_to_string(&legacy).with_context(|| format!("read {}", legacy.display()))?;
    let header = format!(
        "# Migrated from {} on {}\n# (legacy file renamed to keywords.txt.bak)\n",
        legacy.display(),
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%z")
    );
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut out = String::with_capacity(header.len() + body.len());
    out.push_str(&header);
    out.push_str(&body);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    std::fs::write(&target, out).with_context(|| format!("write {}", target.display()))?;

    let backup = legacy.with_extension("txt.bak");
    std::fs::rename(&legacy, &backup)
        .with_context(|| format!("rename {} -> {}", legacy.display(), backup.display()))?;

    println!(
        "migrate-keywords: copied {} → {}, renamed legacy to {}",
        legacy.display(),
        target.display(),
        backup.display()
    );
    Ok(0)
}

fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.cmd {
        Some(Sub::Wrap { common, argv }) => match run_wrap(common, argv) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::InitConfig { force }) => match run_init_config(force) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::ConfigPath) => match run_config_path() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::Hook { event }) => match event {
            HookEvent::Prompt => hook::run_prompt(),
            HookEvent::PreBash => hook::run_pre_bash(),
            HookEvent::PrePatch => hook::run_pre_patch(),
            HookEvent::PreRead => hook::run_pre_read(),
            HookEvent::PreEdit => hook::run_pre_edit(),
            HookEvent::PostTool => hook::run_post_tool(),
            HookEvent::PostWrite => hook::run_post_write(),
            HookEvent::SessionStart => hook::run_session_start(),
            HookEvent::DenyMcp => hook::run_deny_mcp(),
            HookEvent::DenyGrep => hook::run_deny_grep(),
            HookEvent::DenyNotebook => hook::run_deny_notebook(),
        },
        Some(Sub::InstallHooks {
            target,
            force,
            global,
            dry_run,
            merge,
        }) => {
            let result = if global {
                install::run_install_plugin_global(dry_run, force)
            } else {
                install::run_install_plugin_local(&target, dry_run, force, merge)
            };
            match result {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("redactor: {e}");
                    1
                }
            }
        }
        Some(Sub::InstallPlugin { scope }) => {
            let result = match scope {
                InstallPluginScope::Local {
                    target,
                    dry_run,
                    force,
                    merge,
                } => install::run_install_plugin_local(&target, dry_run, force, merge),
                InstallPluginScope::Global { dry_run, force } => {
                    install::run_install_plugin_global(dry_run, force)
                }
            };
            match result {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("redactor: {e}");
                    1
                }
            }
        }
        Some(Sub::UninstallPlugin { target, dry_run }) => {
            match install::run_uninstall_plugin_local(&target, dry_run) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("redactor: {e}");
                    1
                }
            }
        }
        Some(Sub::PluginStatus { global, target }) => {
            match install::run_plugin_status(global, target.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("redactor: {e}");
                    1
                }
            }
        }
        Some(Sub::Scan { common, file }) => match run_scan(&file, common) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::Clean { file }) => match run_clean(&file) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::Mock { file, rows }) => match run_mock(&file, rows) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::SelfUpdate { dry_run }) => match run_self_update(dry_run) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::Search(args)) => match search::run(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::ClassifierInstall { quiet }) => match classifier_lifecycle::run_install(quiet) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::ClassifierStatus { format }) => {
            let fmt = match format {
                ClassifierStatusFormat::Human => classifier_lifecycle::StatusFormat::Human,
                ClassifierStatusFormat::Json => classifier_lifecycle::StatusFormat::Json,
            };
            match classifier_lifecycle::run_status(fmt) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("redactor: {e}");
                    1
                }
            }
        }
        Some(Sub::ClassifierUninstall { yes }) => match classifier_lifecycle::run_uninstall(yes) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::ClassifierUpdate) => match classifier_lifecycle::run_update() {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::ClassifyFiles(args)) => match classify_cmd::run_classify_files(args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::ClassifyMerge(args)) => match classify_merge::run(args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::MigrateKeywords) => match run_migrate_keywords() {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::Explain { target }) => match explain::run_explain(&target) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
        Some(Sub::RedactMarkdown { mut common, args }) => {
            if args.keyword_only {
                common.no_defaults = true;
            }
            match build_pattern_rules(&common) {
                Ok(rules) => match redact_markdown::run(args, &rules) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("redactor: {e}");
                        1
                    }
                },
                Err(e) => {
                    eprintln!("redactor: {e}");
                    1
                }
            }
        }
        None => match run_filter(&cli.file, cli.common) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("redactor: {e}");
                1
            }
        },
    };
    std::process::exit(exit_code);
}

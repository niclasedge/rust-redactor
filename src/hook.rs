//! Claude Code hook subcommands — replaces the previous Bash hook stack.
//!
//! Each subcommand reads a single JSON object from stdin (Claude Code's hook
//! payload), runs its logic, and writes a single JSON object to stdout that
//! Claude Code interprets as the hook decision:
//!
//!   - allow   → `{}`
//!   - block   → `{"decision":"block","reason":"…"}`
//!
//! The hook subcommands replace the following bash scripts:
//!   prompt-scan.sh          → `redactor hook prompt`
//!   path-guard.sh + bash-strict.sh → `redactor hook pre-bash`
//!   path-guard.sh + read-strict.sh (structured files only) → `redactor hook pre-read`
//!   post-tool-redact.sh     → `redactor hook post-tool`
//!
//! Wiring goes through `.claude/settings.json` — see the template in
//! examples/strict-redaction/claude/settings.json.

use crate::patterns::Rule;
use crate::redactor::{self, Mode};
use crate::{config, logger, network_guard, patterns};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

// ============================================================================
// Hook payload (subset of Claude Code's hook input that we care about)
// ============================================================================

#[derive(Deserialize, Debug, Default)]
#[serde(default)]
struct HookInput {
    #[serde(rename = "tool_name")]
    tool_name: String,
    #[serde(rename = "tool_input")]
    tool_input: ToolInput,
    #[serde(rename = "tool_response")]
    tool_response: ToolResponse,
    /// UserPromptSubmit
    prompt: String,
}

#[derive(Deserialize, Debug, Default)]
#[serde(default)]
struct ToolInput {
    command: String,
    file_path: String,
    path: String,
}

impl ToolInput {
    fn target(&self) -> &str {
        if !self.file_path.is_empty() {
            &self.file_path
        } else if !self.path.is_empty() {
            &self.path
        } else {
            &self.command
        }
    }
}

#[derive(Deserialize, Debug, Default)]
#[serde(default)]
struct ToolResponse {
    stdout: String,
    content: String,
    text: String,
}

impl ToolResponse {
    fn body(&self) -> &str {
        if !self.stdout.is_empty() {
            &self.stdout
        } else if !self.content.is_empty() {
            &self.content
        } else {
            &self.text
        }
    }
}

// ============================================================================
// Hook output
// ============================================================================

#[derive(Serialize)]
struct BlockResponse<'a> {
    decision: &'a str,
    reason: String,
}

fn allow() -> i32 {
    println!("{{}}");
    0
}

/// Desktop notification on every hook block. Implemented via `notify-rust`
/// so the same call covers macOS (osascript / NSUserNotification),
/// Windows (WinRT toast), and Linux (libnotify).
///
/// Sound default per OS — verified audible on each: macOS `Sosumi`,
/// Windows `Reminder`. Linux ignores unknown names and falls back to
/// the system default.
///
/// Suppress with `REDACTOR_NOTIFY=0` for tests / CI / batch runs that
/// would otherwise spam the user's notification center.
fn notify_blocked(reason: &str) {
    if std::env::var("REDACTOR_NOTIFY").as_deref() == Ok("0") {
        return;
    }

    #[cfg(target_os = "macos")]
    const SOUND: &str = "Sosumi";
    #[cfg(target_os = "windows")]
    const SOUND: &str = "Reminder";
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    const SOUND: &str = "";

    let body: String = reason
        .replace('\t', " ")
        .replace('\r', "")
        .chars()
        .take(1200)
        .collect();

    let _ = notify_rust::Notification::new()
        .summary("🚨 Redactor Block")
        .body(&body)
        .sound_name(SOUND)
        .show();
}

fn block(reason: impl Into<String>) -> i32 {
    let reason_str: String = reason.into();
    notify_blocked(&reason_str);
    let resp = BlockResponse {
        decision: "block",
        reason: reason_str,
    };
    let _ = serde_json::to_writer(io::stdout(), &resp);
    println!();
    0
}

// ============================================================================
// Sensitive-path regex (matches the old path-guard.sh logic)
// ============================================================================

/// Convert a simple glob (`*`, `?`, escaped rest) to an anchored regex.
fn glob_to_regex(glob: &str) -> Option<regex::Regex> {
    let mut re = String::from("^");
    for c in glob.chars() {
        match c {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            ch => re.push_str(&regex::escape(&ch.to_string())),
        }
    }
    re.push('$');
    regex::Regex::new(&re).ok()
}

/// Returns true if `target` matches any of the simple glob patterns.
fn path_matches_any(target: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        glob_to_regex(p)
            .map(|re| re.is_match(target))
            .unwrap_or(false)
    })
}

/// Load the per-project whitelist from cwd's `.redactor.toml`. Errors during
/// load are swallowed (fail-open) and produce an empty whitelist — we don't
/// want a malformed config to take the hook down.
fn load_project_whitelist() -> Vec<String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match config::autoload_project_whitelist(&cwd) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[redactor] warning: failed to load .redactor.toml whitelist: {e}");
            Vec::new()
        }
    }
}

/// Load the per-project policy from cwd's `.redactor.toml`. Falls back to
/// strict-by-default on missing file or parse error — strictness wins on
/// uncertainty, same rationale as `load_project_whitelist`.
fn load_project_policy() -> config::PolicySection {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match config::autoload_project_policy(&cwd) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[redactor] warning: failed to load .redactor.toml policy: {e}");
            config::PolicySection::default()
        }
    }
}

/// Load the per-project `[allow]` section from cwd's `.redactor.toml`.
/// Falls back to empty on missing file or parse error — fail-open here is
/// safe because `[allow]` is purely permissive (the worst case is that an
/// override fails to apply and the model gets a block it could have
/// proceeded through).
fn load_project_allow() -> config::AllowSection {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match config::autoload_project_allow(&cwd) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[redactor] warning: failed to load .redactor.toml [allow]: {e}");
            config::AllowSection::default()
        }
    }
}

/// True iff `target` is project-allowed via `[allow].paths` or
/// `[allow].filetypes`. Called AFTER unblockable checks (self-protect,
/// crypto, hardcoded .env/.ssh) and BEFORE `.redactorignore` /
/// office-doc / `read-strict` checks — so it overrides only the
/// override-able layers.
fn is_project_allowed(target: &str) -> bool {
    let a = load_project_allow();
    if a.paths.is_empty() && a.filetypes.is_empty() {
        return false;
    }
    config::allow_matches(&a, target)
}

// ============================================================================
// v0.7 path-guard extensions — self-protection, crypto containers, default
// office-doc blocks, and user-defined paths from ~/.redactorignore
// ============================================================================

/// Returns true iff `target` refers to the user's `.redactorignore` file
/// (resolved against `$HOME/.redactorignore` or the
/// `REDACTOR_IGNOREFILE_PATH` test override).
///
/// We compare both the canonical path AND the string form, so the check
/// catches non-existent paths (Write tool creating one for the first time)
/// as well as existing files via symlinks.
fn match_self_protect(target: &str) -> bool {
    let Some(home_ign) = crate::ignorefile::ignorefile_path() else {
        return false;
    };

    // Quick string equality on the unresolved form (covers `~/.redactorignore`
    // tilde-form before any expansion).
    if target == home_ign.display().to_string() || target == format!("\"{}\"", home_ign.display()) {
        return true;
    }

    // Substring match with end-boundary check — bash commands embed paths
    // inside argv. We must NOT match `.redactorignore.suggested` or
    // `.redactorignore.keywords.suggested` when the target is the
    // companion file, not the protected file itself. The boundary check
    // ensures the substring is followed by a non-pathname character
    // (whitespace, quote, end-of-string, shell metachar).
    let home_str = home_ign.display().to_string();
    if contains_with_end_boundary(target, &home_str) {
        return true;
    }

    // Tilde form fallback — only valid when `home_ign` IS the default home
    // path (no `REDACTOR_IGNOREFILE_PATH` override). Otherwise the tilde
    // form would mistakenly match in tests that point at a tempdir.
    let is_default_home = dirs::home_dir()
        .map(|h| h.join(crate::ignorefile::IGNOREFILE_NAME) == home_ign)
        .unwrap_or(false);
    if is_default_home && contains_with_end_boundary(target, "~/.redactorignore") {
        return true;
    }

    // Canonicalized form (covers symlinks). Only attempt if path exists.
    if let Ok(canon) = std::fs::canonicalize(&home_ign) {
        if contains_with_end_boundary(target, &canon.display().to_string()) {
            return true;
        }
    }
    false
}

/// True if `needle` appears in `haystack` AND the character immediately
/// after the match is not part of a pathname identifier. This prevents
/// `.redactorignore` from spuriously matching `.redactorignore.suggested`
/// or `.redactorignore.keywords.suggested` companion files.
fn contains_with_end_boundary(haystack: &str, needle: &str) -> bool {
    let mut search_from = 0;
    while let Some(rel) = haystack[search_from..].find(needle) {
        let abs = search_from + rel;
        let end = abs + needle.len();
        let next = haystack[end..].chars().next();
        let boundary_ok = match next {
            None => true,
            Some(c) => {
                // Non-pathname characters that end an argv-embedded path.
                c.is_whitespace()
                    || matches!(c, '"' | '\'' | ')' | ';' | '|' | '`' | '&' | '<' | '>')
            }
        };
        if boundary_ok {
            return true;
        }
        search_from = abs + 1;
    }
    false
}

/// Crypto containers — full block at both Read and Bash. These have no
/// legitimate read-use-case for an LLM (KeePass DB, GPG-encrypted blobs,
/// PKCS#12 cert bundles, macOS Keychain DB). The extension list is
/// hardcoded; users who genuinely need access must work outside the
/// agent session.
fn match_crypto_container(target: &str) -> Option<&'static str> {
    const CRYPTO_EXTS: &[(&str, &str)] = &[
        (".kdbx", "KeePass database"),
        (".kdb", "KeePass database (legacy)"),
        (".gpg", "GPG-encrypted file"),
        (".pgp", "PGP-encrypted file"),
        (".asc", "ASCII-armored PGP file"),
        (".age", "age-encrypted file"),
        (".p12", "PKCS#12 cert bundle"),
        (".pfx", "PKCS#12 cert bundle"),
        (".keychain-db", "macOS Keychain"),
    ];
    let lower = target.to_ascii_lowercase();
    for (ext, label) in CRYPTO_EXTS {
        if lower.contains(ext) {
            // Boundary check: ensure the extension is at the end of a
            // path-like token (followed by whitespace, end-of-string, or
            // a quote). Avoids accidental matches in arbitrary prose.
            let idx_iter = lower.match_indices(ext);
            for (idx, _) in idx_iter {
                let after = &lower[idx + ext.len()..];
                let next_char = after.chars().next();
                let ok = match next_char {
                    None => true,
                    Some(c) => {
                        c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ';' | '|' | '`' | '&')
                    }
                };
                if ok {
                    return Some(label);
                }
            }
        }
    }
    None
}

/// Phase 7e — same office-doc list as `match_office_doc`, but applied
/// token-by-token to a shell command. Returns `Some(label)` if any
/// non-pattern-literal token ends in an office-doc extension. Used by
/// `run_pre_bash` to enforce consistency: a Read-block must imply a
/// Bash-block, otherwise the model can simply `cat foo.docx` instead.
fn match_office_doc_in_bash(cmd: &str) -> Option<&'static str> {
    const OFFICE_EXTS: &[(&str, &str)] = &[
        (".xlsx", "Excel workbook"),
        (".xls", "Excel workbook (legacy)"),
        (".xlsm", "Excel workbook (macro)"),
        (".docx", "Word document"),
        (".doc", "Word document (legacy)"),
        (".pptx", "PowerPoint presentation"),
        (".ppt", "PowerPoint presentation (legacy)"),
        (".pdf", "PDF document"),
    ];
    for tok in tokenize_shell(cmd) {
        // Strip a trailing `;`, `,`, `)` or quote so `cat a.pdf;` still matches.
        let bare = tok.trim_end_matches([';', ',', ')', '"', '\'']);
        let lower = bare.to_ascii_lowercase();
        for (ext, label) in OFFICE_EXTS {
            if lower.ends_with(ext) {
                return Some(*label);
            }
        }
    }
    None
}

/// Office-document extensions blocked at Read only (Bash can still touch
/// them — skills like `xlsx` / `docx` / `pdf` parse them structurally).
fn match_office_doc(target: &str) -> Option<&'static str> {
    const OFFICE_EXTS: &[(&str, &str)] = &[
        (".xlsx", "Excel workbook"),
        (".xls", "Excel workbook (legacy)"),
        (".xlsm", "Excel workbook (macro)"),
        (".docx", "Word document"),
        (".doc", "Word document (legacy)"),
        (".pptx", "PowerPoint presentation"),
        (".ppt", "PowerPoint presentation (legacy)"),
        (".pdf", "PDF document"),
    ];
    let lower = target.to_ascii_lowercase();
    for (ext, label) in OFFICE_EXTS {
        if lower.ends_with(ext) {
            return Some(label);
        }
    }
    None
}

/// Returns Some(pattern) iff `target` matches a path entry in the user's
/// `~/.redactorignore`. Loads on every call — file is small and hook calls
/// are infrequent. Returns None if no ignorefile exists or no match.
fn match_redactorignore_path(target: &str) -> Option<String> {
    let f = crate::ignorefile::autoload().ok()?;
    if f.paths.is_empty() {
        return None;
    }
    let p = std::path::Path::new(target);
    if f.path_matches(p) {
        // Find the matching include pattern (the last include that fired).
        let mut last_include: Option<&str> = None;
        for entry in &f.paths {
            if entry.matcher.is_match(p) {
                last_include = if entry.negate { None } else { Some(&entry.raw) };
            }
        }
        last_include.map(|s| s.to_string())
    } else {
        None
    }
}

/// Phase 7d — Path-Guard-Smartness.
///
/// Tokenizes `cmd` (respecting `'...'` / `"..."` quotes) and returns a
/// re-joined command string with every "pattern-literal" argument removed.
/// Pattern-literal arguments are tokens that immediately follow a
/// pattern-only flag (`-E`, `-e`, `-P`, `-G`, `--regex`, `--regexp`,
/// `--grep`, `--include`, `--exclude`, `--include-glob`, `--exclude-glob`,
/// or ripgrep's `-g`/`--glob`), plus the `--flag=VALUE` glued form.
///
/// The point: `grep -E "\.pfx" file.txt` should NOT be blocked just because
/// the regex-literal contains a crypto-container extension. But
/// `cat /Users/x/vault.pfx` still must be — that token has no flag in front
/// of it.
fn strip_pattern_literal_args(cmd: &str) -> String {
    const PATTERN_FLAGS: &[&str] = &[
        "-e",
        "-E",
        "-P",
        "-G",
        "-g",
        "--regex",
        "--regexp",
        "--grep",
        "--include",
        "--exclude",
        "--include-glob",
        "--exclude-glob",
        "--glob",
    ];

    let tokens = tokenize_shell(cmd);
    let mut kept: Vec<String> = Vec::with_capacity(tokens.len());
    let mut skip_next = false;
    for tok in tokens.into_iter() {
        if skip_next {
            skip_next = false;
            continue;
        }
        // Glued form: `--regex=PATTERN`, `-E=PATTERN`.
        if PATTERN_FLAGS.iter().any(|f| {
            tok.starts_with(&format!("{f}="))
                || (f.len() == 2 && tok.starts_with(*f) && tok.len() > 2 && !tok.starts_with("--"))
        }) {
            // For short flags glued without `=` (e.g. `-Esecret`) we
            // conservatively keep only the flag and drop the rest.
            continue;
        }
        if PATTERN_FLAGS.contains(&tok.as_str()) {
            kept.push(tok);
            skip_next = true;
            continue;
        }
        kept.push(tok);
    }
    kept.join(" ")
}

/// Very small shell-style tokenizer for `strip_pattern_literal_args`. Honours
/// single and double quotes; everything else is whitespace-separated. The
/// returned tokens have their *outer* quotes stripped so the substring-match
/// inside `match_crypto_container` works on the bare path.
fn tokenize_shell(cmd: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for ch in cmd.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn match_sensitive_path(target: &str) -> Option<&'static str> {
    // Per-project whitelist wins first (rred-10).
    let wl = load_project_whitelist();
    if !wl.is_empty() && path_matches_any(target, &wl) {
        return None;
    }

    use regex::Regex;
    use std::sync::OnceLock;

    static RES: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let res = RES.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            (".env", r"(^|[\s/=:])\.env(\.|$|[\s])"),
            (".envrc", r"(^|[\s/=:])\.envrc($|\.|[\s])"),
            ("id_rsa", r"/id_rsa($|\.|/)"),
            ("AWS creds", r"/\.aws/(credentials|config)"),
            ("/secrets/ folder", r"/secrets/"),
            (".pem", r"[/~]\S*\.pem($|[^A-Za-z0-9_])"),
            (".key", r"[/~]\S*\.key($|[^A-Za-z0-9_])"),
            (".netrc", r"/\.netrc($|\.)"),
            (".ssh/", r"/\.ssh/[^\s]+"),
        ];
        raw.iter()
            .map(|(label, pat)| (*label, Regex::new(pat).expect("valid regex")))
            .collect()
    });
    for (label, re) in res {
        if !re.is_match(target) {
            continue;
        }
        // .ssh allowlist: known_hosts is intentionally readable
        if *label == ".ssh/" && target.contains(".ssh/known_hosts") {
            continue;
        }
        return Some(*label);
    }
    None
}

// ============================================================================
// Mode detection from a tool argument (file_path or command string)
// ============================================================================

/// Position-aware struct-file detection for shell commands (rred-35).
///
/// Returns `Some(Mode)` only when the command invokes a known file-reading
/// tool (`cat`, `head`, `tail`, `jq`, ...) AND the next non-flag token is a
/// structured-file argument (`.json` / `.csv` / `.tsv` / `.env` / `.envrc`).
///
/// Skips false positives where the extension appears as a string literal in
/// a heredoc, quoted argument, sed pattern, echo body, or comment — the
/// older `detect_struct_extension` substring scan flagged all of those.
///
/// Heuristic, not a bash parser. Out-of-scope cases (see rred-35 spec):
/// - `sed -i 's|.json|.jsonl|g' file.rs` (sed not in READ_TOOLS by design)
/// - Nested shells (`bash -c "cat data.json"`) — the inner cat IS detected
///   because we tokenize on whitespace; the outer quoting strips cleanly.
fn detect_struct_file_argument(cmd: &str) -> Option<Mode> {
    // Tools that READ a file (output its content). NOT exhaustive — extend
    // when new patterns surface. `sed`/`awk`/`grep` deliberately excluded:
    // they're more often used with patterns that look like extensions than
    // as file-readers (see rred-35 Out-of-Scope).
    const READ_TOOLS: &[&str] = &[
        "cat", "head", "tail", "less", "more", "view", "bat", "tac", "nl", "zcat", "gzcat", "jq",
        "yq", "csvkit", "csvlook", "csvgrep", "xsv", "mlr",
    ];

    let is_read_tool = |bare: &str| -> bool {
        READ_TOOLS.iter().any(|t| {
            bare == *t || bare.ends_with(&format!("/{t}")) || bare.ends_with(&format!("\\{t}"))
        })
    };

    // Once we see a read tool, scan EVERY subsequent positional argument for
    // a struct-file extension match — not just the immediate next token.
    // Tools like `jq '.k' data.json` or `jq -c . dump.ndjson` consume the
    // first positional as a filter program; the file comes later.
    //
    // The active scope ends at the next shell-control token (`|`, `;`,
    // `&&`, `||`, `>`, `<`, `>>`, `<<`, `&`) — those imply a new pipeline
    // segment where we re-evaluate from scratch.
    let mut active = false;
    for tok in cmd.split_whitespace() {
        let bare = tok.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
        if bare.is_empty() {
            continue;
        }
        if matches!(
            bare,
            "|" | "&" | "&&" | "||" | ";" | ">" | "<" | ">>" | "<<"
        ) {
            active = false;
            continue;
        }
        // Flag tokens belong to the previous tool — keep `active` sticky.
        if bare.starts_with('-') {
            continue;
        }
        if active {
            if let Some(m) = ext_to_mode(bare) {
                return Some(m);
            }
        } else if is_read_tool(bare) {
            active = true;
        }
    }
    None
}

/// Map a single argument (possibly a path) to its structural Mode.
///
/// Position-aware companion to `detect_struct_file_argument`. Recognises
/// `.json`/`.jsonl`/`.ndjson` as Json, `.csv`/`.tsv` as Csv, and
/// `.env`/`.envrc`/`.env.<x>`/`<name>.env` as Env.
fn ext_to_mode(arg: &str) -> Option<Mode> {
    let arg_lc = arg.to_ascii_lowercase();
    if arg_lc.ends_with(".json") || arg_lc.ends_with(".jsonl") || arg_lc.ends_with(".ndjson") {
        return Some(Mode::Json);
    }
    if arg_lc.ends_with(".csv") || arg_lc.ends_with(".tsv") {
        return Some(Mode::Csv);
    }
    let basename = std::path::Path::new(arg)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(arg);
    let bn_lc = basename.to_ascii_lowercase();
    if bn_lc == ".env" || bn_lc == ".envrc" || bn_lc.starts_with(".env.") || bn_lc.ends_with(".env")
    {
        return Some(Mode::Env);
    }
    None
}

fn detect_struct_extension(arg: &str) -> Option<Mode> {
    use regex::Regex;
    use std::sync::OnceLock;

    static JSON: OnceLock<Regex> = OnceLock::new();
    static CSV: OnceLock<Regex> = OnceLock::new();
    static ENV: OnceLock<Regex> = OnceLock::new();

    let arg_lc = arg.to_lowercase();
    if JSON
        .get_or_init(|| Regex::new(r"\.json($|[^a-z0-9_])").unwrap())
        .is_match(&arg_lc)
    {
        return Some(Mode::Json);
    }
    if CSV
        .get_or_init(|| Regex::new(r"\.(csv|tsv)($|[^a-z0-9_])").unwrap())
        .is_match(&arg_lc)
    {
        return Some(Mode::Csv);
    }
    if ENV
        .get_or_init(|| Regex::new(r"\.env(rc)?($|[^a-z0-9_])").unwrap())
        .is_match(&arg_lc)
    {
        return Some(Mode::Env);
    }
    None
}

fn extract_patch_paths(command: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in command.lines() {
        let trimmed = line.trim();
        for prefix in [
            "*** Add File: ",
            "*** Update File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let path = rest.trim();
                if !path.is_empty() {
                    paths.push(path.to_string());
                }
                break;
            }
        }
    }
    paths
}

fn first_sensitive_patch_path(command: &str) -> Option<(String, &'static str)> {
    extract_patch_paths(command)
        .into_iter()
        .find_map(|path| match_sensitive_path(&path).map(|label| (path, label)))
}

fn collect_post_write_paths(payload: &serde_json::Value) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = payload["tool_input"]["file_path"]
        .as_str()
        .or_else(|| payload["tool_input"]["path"].as_str())
    {
        if !path.is_empty() {
            paths.push(std::path::PathBuf::from(path));
        }
    }
    if paths.is_empty() {
        if let Some(command) = payload["tool_input"]["command"].as_str() {
            paths.extend(
                extract_patch_paths(command)
                    .into_iter()
                    .map(std::path::PathBuf::from),
            );
        }
    }
    paths
}

fn validate_written_file(path: &std::path::Path) -> Option<String> {
    if !path.exists() || !path.is_file() {
        return None;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let content = std::fs::read_to_string(path).ok()?;
    match ext.as_str() {
        "json" => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(_) => None,
            Err(e) => Some(format!("invalid JSON in {}: {e}", path.display())),
        },
        "toml" => match toml::from_str::<toml::Value>(&content) {
            Ok(_) => None,
            Err(e) => Some(format!("invalid TOML in {}: {e}", path.display())),
        },
        _ => None,
    }
}

// ============================================================================
// Accepted binary-name helpers (rred-52)
// ============================================================================

/// Names accepted as the bin prefix in bash-strict (rred-52).
/// `redactor` is canonical; `r` is a short-alias when symlinked at the
/// install location. ABSOLUTE paths to either are still rejected — only the
/// bare command form passes.
const REDACTOR_BIN_NAMES: &[&str] = &["redactor", "r"];

/// True if `cmd` (a bash command line) begins with one of the accepted
/// bin names followed by whitespace or end-of-string. Does NOT match
/// absolute paths like `/usr/bin/redactor` — those are intentionally
/// rejected to keep the strict-prefix check unambiguous.
fn starts_with_redactor_bin(cmd: &str) -> bool {
    let trimmed = cmd.trim_start();
    REDACTOR_BIN_NAMES.iter().any(|name| {
        if let Some(rest) = trimmed.strip_prefix(name) {
            rest.is_empty() || rest.starts_with(char::is_whitespace)
        } else {
            false
        }
    })
}

/// True if `cmd` is `<bin> wrap [...]` form (used by the post-tool-redact
/// skip and the wrap struct-file enforcement).
fn is_redactor_wrap(cmd: &str) -> bool {
    let trimmed = cmd.trim_start();
    REDACTOR_BIN_NAMES.iter().any(|name| {
        // `<bin>` then whitespace then `wrap` then whitespace/EOL
        let after_bin = match trimmed.strip_prefix(name) {
            Some(r) if r.starts_with(char::is_whitespace) => r.trim_start(),
            _ => return false,
        };
        if let Some(after_wrap) = after_bin.strip_prefix("wrap") {
            after_wrap.is_empty() || after_wrap.starts_with(char::is_whitespace)
        } else {
            false
        }
    })
}

// ============================================================================
// stdin → HookInput
// ============================================================================

fn read_input() -> Result<HookInput> {
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .context("read hook stdin")?;
    if raw.trim().is_empty() {
        // Fail-closed: empty stdin → block
        return Err(anyhow::anyhow!("empty hook stdin"));
    }
    let parsed: HookInput = serde_json::from_str(&raw).context("parse hook stdin as JSON")?;
    Ok(parsed)
}

// ============================================================================
// Hook: prompt — UserPromptSubmit
// ============================================================================

pub fn run_prompt() -> i32 {
    let input = match read_input() {
        Ok(i) => i,
        Err(_) => return block("redactor: invalid hook input — blocked (fail-closed)"),
    };
    if input.prompt.is_empty() {
        return allow();
    }

    let rules = match build_default_rules() {
        Ok(r) => r,
        Err(e) => return block(format!("redactor: {e}")),
    };
    // Match on `sanitized == input.prompt` only (not `events.is_empty()`):
    // some rules (e.g. `client_secret`, `auth_header`) re-match their own
    // `<redacted:LABEL>` placeholders with an idempotent replacement. That
    // grows the events list while leaving the text byte-identical — and an
    // already-redacted paste must pass through. Mirrors the post-write
    // hook's check at line ~763.
    let (sanitized, _events) = redactor::redact_pattern(&input.prompt, &rules);
    if sanitized == input.prompt {
        allow()
    } else {
        let copied = copy_to_clipboard(&sanitized);
        let dumped = dump_redacted_prompt(&sanitized);
        let hint = match (copied, dumped.as_ref()) {
            (true, Some(p)) => format!(
                "redacted version copied to clipboard (Ctrl+V / Cmd+V) — also saved to {}",
                p.display()
            ),
            (true, None) => {
                "redacted version copied to clipboard — paste with Ctrl+V / Cmd+V to resubmit"
                    .to_string()
            }
            (false, Some(p)) => format!(
                "redacted version saved to {} — copy it from there to resubmit",
                p.display()
            ),
            (false, None) => {
                "remove the offending value and resubmit, or pass it via a sealed env var"
                    .to_string()
            }
        };
        block(format!(
            "policy: your prompt appears to contain a secret or keyword.\n\
             redacted preview:\n{sanitized}\n\
             {hint}."
        ))
    }
}

/// Best-effort copy of the redacted prompt to the OS clipboard so the user
/// can repaste it with one keystroke. Silent on failure — clipboard access
/// must never affect block enforcement (headless CI, X11-less Linux,
/// locked-down sandboxes all need to keep working).
///
/// Suppress with `REDACTOR_CLIPBOARD=0` (e.g. for tests / batch runs).
/// Returns `true` iff the copy actually succeeded — the block-message uses
/// this to decide which next-step hint to print.
fn copy_to_clipboard(text: &str) -> bool {
    if std::env::var("REDACTOR_CLIPBOARD").as_deref() == Ok("0") {
        return false;
    }
    arboard::Clipboard::new()
        .and_then(|mut cb| cb.set_text(text.to_string()))
        .is_ok()
}

/// Best-effort dump of the redacted prompt to a file so the user can recover
/// it even where the clipboard is unavailable — headless boxes, SSH sessions
/// (where `arboard` would write to the *remote* clipboard anyway), X11-less
/// Linux. The block-message prints the returned path so the user knows where
/// to find it.
///
/// Defaults to `<tmpdir>/redactor-last-prompt.txt` (a fixed name, so the file
/// is overwritten each time rather than accumulating). Override the path with
/// `REDACTOR_PROMPT_FILE=/some/path`, or disable entirely with
/// `REDACTOR_PROMPT_DUMP=0`. The written content is already redacted, so it
/// contains no secret. Silent on failure — like the clipboard, file access
/// must never affect block enforcement. Returns the path iff the write
/// succeeded.
fn dump_redacted_prompt(text: &str) -> Option<std::path::PathBuf> {
    if std::env::var("REDACTOR_PROMPT_DUMP").as_deref() == Ok("0") {
        return None;
    }
    let path = match std::env::var_os("REDACTOR_PROMPT_FILE") {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::temp_dir().join("redactor-last-prompt.txt"),
    };
    std::fs::write(&path, text).ok()?;
    Some(path)
}

// ============================================================================
// Hook: pre-bash — PreToolUse Bash
// ============================================================================

pub fn run_pre_bash() -> i32 {
    let input = match read_input() {
        Ok(i) => i,
        Err(_) => return block("redactor: invalid hook input — blocked (fail-closed)"),
    };
    let cmd = input.tool_input.command.trim();
    if cmd.is_empty() {
        return allow();
    }

    // 0a. self-protect: ~/.redactorignore (unblockable)
    if match_self_protect(cmd) {
        return block(
            "redactor path-guard: refused — ~/.redactorignore is self-protected.\n\
             To edit, open directly with your editor in a terminal OUTSIDE this \
             agent session (e.g. `$EDITOR ~/.redactorignore`)."
                .to_string(),
        );
    }

    // Phase 7d: strip pattern-literal arguments before path-guard matching
    // so `grep -E "\.pfx" file.txt` isn't blocked by the substring-search
    // on `.pfx`. Self-protect runs against the original cmd above because
    // it needs to catch quoted home-paths verbatim.
    let cmd_for_pathguard = strip_pattern_literal_args(cmd);

    // 0b. crypto containers (.kdbx / .gpg / .age / .p12 / …) — unblockable
    if let Some(label) = match_crypto_container(&cmd_for_pathguard) {
        return block(format!(
            "redactor path-guard: refused — command touches a crypto container ({label}).\n\
             Encrypted containers have no LLM-readable use case. Open with the\n\
             dedicated tool (KeePass / gpg / age / …) outside the agent session."
        ));
    }

    // 1. path-guard — sensitive path substring (.env / .ssh / .aws / ...)
    if let Some(label) = match_sensitive_path(&cmd_for_pathguard) {
        return block(format!(
            "redactor path-guard: refused sensitive path in command (matches {label}).\n\
             If you genuinely need this file, ask the user to add an exception."
        ));
    }

    // 1a. project-level [allow] short-circuit — overrides .redactorignore +
    //     office-doc defaults (NOT the unblockable categories above).
    if is_project_allowed(cmd) {
        return allow();
    }

    // 1b. user-defined paths from ~/.redactorignore
    if let Some(pattern) = match_redactorignore_path(cmd) {
        return block(format!(
            "redactor path-guard: refused — command touches a path listed in \
             ~/.redactorignore (matches `{pattern}`).\n\
             To unblock for this project, add to .redactor.toml:\n\
                 [allow]\n\
                 paths = [\"<your-path-or-glob>\"]\n\
             To unblock globally, remove the entry from ~/.redactorignore."
        ));
    }

    // Phase 7e — Office-doc consistency: Read-block implies Bash-block.
    // If the command references an .xlsx / .docx / .pdf path as an actual
    // argument (not as a pattern-literal), refuse it. Skills like
    // `xlsx` / `docx` / `pdf` must opt in via project-level `[allow]`.
    if let Some(label) = match_office_doc_in_bash(&cmd_for_pathguard) {
        return block(format!(
            "redactor path-guard: refused — command touches an office document ({label}).\n\
             Office docs (.xlsx/.docx/.pptx/.pdf) are blocked at both Read and Bash to\n\
             keep the policy consistent. To enable a project-specific skill (xlsx/docx/pdf),\n\
             add the path or filetype to .redactor.toml [allow]."
        ));
    }

    // 1.5. network-guard (rred-18) — block unlisted URLs
    if let Some(reason) = network_guard::check_with_cwd(cmd) {
        return block(reason);
    }

    // 2. bash-strict: command must start with `redactor`
    if !starts_with_redactor_bin(cmd) {
        return block(format!(
            "redactor strict mode: every shell command (Bash / PowerShell) must go \
             through redactor.\nFor a subprocess, wrap it:\n    redactor wrap -- {cmd}\n\
             For reading a file, prefer direct file mode (in-line structural redaction):\n\
                 redactor --type json <file.json>\n\
                 redactor --type csv  <file.csv>\n\
                 redactor --type env  <file.env>\n\
                 redactor             <other-text-file>     # auto-detects mode\n\
             If a command must produce raw output, ask the user for an exception."
        ));
    }

    // 3. struct-file enforce on wrap+cmd (rred-35: position-aware — only
    //    triggers when a struct file is the actual argument to a read-tool,
    //    not when the extension appears in a heredoc/quoted/comment string).
    //    JSON is strict by default; opt out per project via
    //    `[policy] strict_json = false` in `.redactor.toml`.
    let policy = load_project_policy();
    if is_redactor_wrap(cmd) {
        if let Some(mode) = detect_struct_file_argument(cmd) {
            let json_exempt = matches!(mode, Mode::Json) && !policy.strict_json;
            if !json_exempt {
                return block(format!(
                    "redactor strict mode: structured file referenced inside `redactor wrap` — \
                     wrap is line-buffered pattern-mode only and does NOT apply structural \
                     redaction. Reformulate as:\n    redactor --type {} <file>\n\
                     This sanitizes structurally BEFORE writing to stdout, so both UI and model \
                     see the masked structure.",
                    mode.name()
                ));
            }
        }
    } else {
        // 4. flag-bypass guard — direct redactor call must NOT use -t pattern or
        //    --no-defaults / --no-config / --no-log when the file argument is a
        //    structured file. This closes the known bypass:
        //       redactor -t pattern foo.csv
        //       redactor --no-defaults --no-config foo.csv
        //    JSON is exempt iff the project opted out via [policy] strict_json = false.
        if let Some(struct_mode) = detect_struct_extension(cmd) {
            let json_exempt = matches!(struct_mode, Mode::Json) && !policy.strict_json;
            if !json_exempt {
                let forces_pattern = cmd.contains("-t pattern")
                    || cmd.contains("--type pattern")
                    || cmd.contains("-t=pattern")
                    || cmd.contains("--type=pattern");
                let disables_rules = cmd.contains("--no-defaults") || cmd.contains("--no-config");
                if forces_pattern || disables_rules {
                    return block(format!(
                        "redactor strict mode: structural redaction cannot be bypassed for \
                         {} files. Refusing flags that force pattern-mode or disable default \
                         rules on a structured file. Use:\n    redactor --type {} <file>\n\
                         If the file legitimately is unstructured despite the extension, ask \
                         the user to add an exception.",
                        struct_mode.name(),
                        struct_mode.name()
                    ));
                }
            }
        }
    }

    allow()
}

// ============================================================================
// Hook: pre-patch — PreToolUse apply_patch/Edit/Write (Codex)
// ============================================================================

pub fn run_pre_patch() -> i32 {
    let input = match read_input() {
        Ok(i) => i,
        Err(_) => return block("redactor: invalid hook input — blocked (fail-closed)"),
    };
    let command = input.tool_input.command.trim();
    if command.is_empty() {
        return allow();
    }
    if let Some((path, label)) = first_sensitive_patch_path(command) {
        return block(format!(
            "redactor path-guard: refused sensitive patch target: {path} (matches {label}).\n\
             If you genuinely need to edit this file, ask the user to add an exception."
        ));
    }
    allow()
}

// ============================================================================
// Hook: pre-read — PreToolUse Read
// ============================================================================

pub fn run_pre_read() -> i32 {
    let input = match read_input() {
        Ok(i) => i,
        Err(_) => return block("redactor: invalid hook input — blocked (fail-closed)"),
    };
    let target = input.tool_input.target();
    if target.is_empty() {
        return allow();
    }

    // 0a. self-protect: ~/.redactorignore (unblockable)
    if match_self_protect(target) {
        return block(
            "redactor path-guard: refused — ~/.redactorignore is self-protected.\n\
             To inspect, open with `$EDITOR ~/.redactorignore` in a terminal OUTSIDE \
             this agent session."
                .to_string(),
        );
    }

    // 0b. crypto containers — unblockable, no LLM-readable use case
    if let Some(label) = match_crypto_container(target) {
        return block(format!(
            "redactor path-guard: refused — {target} is a {label}.\n\
             Crypto containers cannot be sensibly parsed as text. Open with the\n\
             dedicated tool outside the agent session."
        ));
    }

    // 1. sensitive path (.env / .ssh / .aws / ...)
    if let Some(label) = match_sensitive_path(target) {
        return block(format!(
            "redactor path-guard: refused sensitive path: {target} (matches {label}).\n\
             If you genuinely need this file, ask the user to add an exception."
        ));
    }

    // 1a. project-level [allow] short-circuit — overrides .redactorignore +
    //     office-doc defaults (NOT the unblockable categories above).
    if is_project_allowed(target) {
        return allow();
    }

    // 1b. user-defined paths from ~/.redactorignore
    if let Some(pattern) = match_redactorignore_path(target) {
        return block(format!(
            "redactor path-guard: refused — {target} is listed in ~/.redactorignore \
             (matches `{pattern}`).\n\
             To unblock for this project, add to .redactor.toml:\n\
                 [allow]\n\
                 paths = [\"<your-path-or-glob>\"]\n\
             To unblock globally, remove the entry from ~/.redactorignore."
        ));
    }

    // 1c. office-doc default block (Read-only) — .xlsx / .docx / .pdf / .pptx
    //     Binary / ZIP-XML; Read would dump unparseable bytes. Use the
    //     `docx` / `xlsx` / `pdf` skills via Bash for structural access.
    if let Some(label) = match_office_doc(target) {
        return block(format!(
            "redactor path-guard: refused — {target} is a {label}. The Read tool\n\
             cannot parse this format; use the docx/xlsx/pdf skill via Bash instead,\n\
             or add this file to .redactor.toml [allow] for project-scoped opt-out."
        ));
    }

    // 2. read-strict: only structured files where pattern-mode could miss
    //    arbitrary values are blocked. CSV/TSV/ENV always strict — leaf
    //    values are completely opaque to pattern-mode. JSON is strict by
    //    default but a project can opt out via `.redactor.toml`:
    //
    //        [policy]
    //        strict_json = false
    //
    //    Source/markdown/text always pass through and are sanitised by
    //    post-tool-redact on the way out.
    let policy = load_project_policy();
    let suggested = match detect_struct_extension(target) {
        Some(Mode::Json) if policy.strict_json => {
            format!("redactor --type json \"{target}\"")
        }
        Some(Mode::Json) => return allow(),
        Some(Mode::Csv) => format!("redactor --type csv \"{target}\""),
        Some(Mode::Env) => format!("redactor --type env \"{target}\""),
        _ => return allow(),
    };
    block(format!(
        "redactor strict mode: structured files cannot be Read directly — \
         pattern-mode redaction can miss values that don't match a known \
         regex. Use:\n    {suggested}\n\
         instead. That sanitises the structure (leaves -> <redacted>) before the \
         output reaches the model. For JSON, set `[policy] strict_json = false` \
         in `.redactor.toml` to allow regular Read. For other types ask the user \
         for an exception."
    ))
}

// ============================================================================
// Hook: pre-edit — PreToolUse Edit|MultiEdit|Write (v0.7)
// ============================================================================
//
// Path-guard only — does NOT sanitise the `new_string` / file content that
// the tool is about to write. Primary purpose: block the Write tool from
// creating NEW files at protected paths (Edit + MultiEdit are indirectly
// blocked via the existing Read-block, since Claude Code requires a Read
// before any in-place edit). Defense-in-depth for the case where the
// Read-before-Edit invariant changes upstream.

pub fn run_pre_edit() -> i32 {
    let input = match read_input() {
        Ok(i) => i,
        Err(_) => return block("redactor: invalid hook input — blocked (fail-closed)"),
    };
    let target = input.tool_input.target();
    if target.is_empty() {
        return allow();
    }

    // 0a. self-protect: ~/.redactorignore (unblockable). The most important
    //     reason for pre-edit's existence — Write could otherwise overwrite
    //     this file at the user's home path.
    if match_self_protect(target) {
        return block(
            "redactor path-guard: refused — ~/.redactorignore is self-protected.\n\
             To edit, open with `$EDITOR ~/.redactorignore` in a terminal OUTSIDE \
             this agent session."
                .to_string(),
        );
    }

    // 0b. crypto containers — refuse to write/edit a path that LOOKS like an
    //     encrypted container. Defensive: a Write here would create a corrupt
    //     non-encrypted file at that name.
    if let Some(label) = match_crypto_container(target) {
        return block(format!(
            "redactor path-guard: refused — refusing to Write/Edit {target} ({label}).\n\
             Crypto containers must not be created or modified via agent tools."
        ));
    }

    // 1. hardcoded sensitive paths (.env / .ssh / .aws / id_rsa / .pem / .key)
    if let Some(label) = match_sensitive_path(target) {
        return block(format!(
            "redactor path-guard: refused — Write/Edit at sensitive path: {target} \
             (matches {label}).\n\
             If you genuinely need this file, ask the user to add an exception."
        ));
    }

    // 1a. project-level [allow] short-circuit — overrides .redactorignore
    if is_project_allowed(target) {
        return allow();
    }

    // 1b. user-defined paths from ~/.redactorignore
    if let Some(pattern) = match_redactorignore_path(target) {
        return block(format!(
            "redactor path-guard: refused — Write/Edit at {target} is listed in \
             ~/.redactorignore (matches `{pattern}`).\n\
             To unblock for this project, add to .redactor.toml:\n\
                 [allow]\n\
                 paths = [\"<your-path-or-glob>\"]\n\
             To unblock globally, remove the entry from ~/.redactorignore."
        ));
    }

    // Note: NO office-doc check here — those are only blocked at Read because
    // Read can't parse the binary format, not because we'd refuse to write
    // one. The user might legitimately Write a .docx via a markdown→docx
    // skill, and we don't want to interfere.

    allow()
}

// ============================================================================
// Hook: post-tool — PostToolUse Read|Bash
// ============================================================================

pub fn run_post_tool() -> i32 {
    let input = match read_input() {
        Ok(i) => i,
        // Fail-open on parse errors here (post-tool is the safety net,
        // not the gatekeeper — a bad payload shouldn't block tool output)
        Err(_) => return allow(),
    };
    let raw = input.tool_response.body();
    if raw.is_empty() {
        return allow();
    }

    let cmd = input.tool_input.command.trim();
    let target = input.tool_input.target();

    // Skip direct redactor calls — output is already sanitized by the binary
    // itself. Re-running structural mode here would cause double-pass artifacts
    // (CSV row-count drift, JSON list truncation collapse).
    let is_direct = starts_with_redactor_bin(cmd) && !is_redactor_wrap(cmd);
    if is_direct {
        return allow();
    }

    // Pick mode from the file extension in the command/target. Fall back to
    // pattern for unstructured streams (logs, free-form output).
    let mode = detect_struct_extension(target)
        .or_else(|| detect_struct_extension(cmd))
        .unwrap_or(Mode::Pattern);

    let (sanitized, _events) = match mode {
        Mode::Pattern => match build_default_rules() {
            Ok(rules) => redactor::redact_pattern(raw, &rules),
            Err(_) => return allow(), // no rules → can't sanitize, let it through
        },
        Mode::Json => redactor::redact_json(raw).unwrap_or_else(|_| (raw.to_string(), Vec::new())),
        Mode::Csv => redactor::redact_csv(raw).unwrap_or_else(|_| (raw.to_string(), Vec::new())),
        Mode::Env => redactor::redact_env(raw).unwrap_or_else(|_| (raw.to_string(), Vec::new())),
    };

    if sanitized == raw {
        allow()
    } else {
        let label = if !target.is_empty() {
            format!("{} {}", input.tool_name, target)
        } else {
            input.tool_name.clone()
        };
        block(format!(
            "redactor post-tool: tool output ({label}, mode={}) was sanitized — structure \
             preserved, sensitive values masked. Treat <redacted…> as opaque, do not attempt \
             to reconstruct.\n\n----- BEGIN SANITIZED OUTPUT -----\n{sanitized}\n----- END \
             SANITIZED OUTPUT -----",
            mode.name()
        ))
    }
}

// ============================================================================
// Helpers
// ============================================================================

// ============================================================================
// rred-36 — Fixed-deny hooks for tools that have no safe canonical form in
// this profile. Each consumes stdin best-effort and always blocks with a
// helpful reason that tells Claude what to do instead.
// ============================================================================

/// `redactor hook deny-mcp` — blocks every `mcp__*` tool call. MCP servers
/// (Gmail, Drive, Memory, etc.) return high-density PII directly into the
/// model context with no per-server redaction layer in this profile.
pub fn run_deny_mcp() -> i32 {
    // Consume stdin best-effort so Claude Code doesn't see a SIGPIPE.
    let mut buf = String::new();
    let _ = io::stdin().read_to_string(&mut buf);
    block(
        "redactor strict mode: MCP tools (mcp__*) are disabled in this profile. \
         MCP servers (Gmail, Drive, Memory, etc.) return high-density PII directly into \
         the agent context with no per-server redaction layer here. If you genuinely need \
         an MCP tool, ask the user to remove the deny-mcp matcher from the active hook \
         config for this session.",
    )
}

/// `redactor hook deny-grep` — blocks every `Grep` tool call. Grep can leak
/// content from blocked paths via matching lines without going through
/// `pre-read`'s path-guard. The user-facing replacement is `redactor wrap --
/// rg/grep ...` via Bash, which goes through pre-bash + wrap pattern-mode.
pub fn run_deny_grep() -> i32 {
    let mut buf = String::new();
    let _ = io::stdin().read_to_string(&mut buf);
    block(
        "redactor strict mode: the Grep tool is disabled — its matching lines bypass the \
         Read+path-guard chain and can leak content from sensitive paths (.env, secrets/, \
         *.pem, ...). Use Bash instead:\n\
             redactor wrap -- rg \"<pattern>\" <path>\n\
             redactor wrap -- grep -r \"<pattern>\" <path>\n\
         That goes through pre-bash (path-guard + strict-prefix + network-guard) and the \
         tool output flows through wrap's pattern-mode sanitization.",
    )
}

/// `redactor hook deny-notebook` — blocks every `NotebookEdit` tool call.
/// Jupyter notebooks are not used in this profile; enabling NotebookEdit
/// would add a code-and-output read/write path that has no sanitization
/// hook coverage today.
pub fn run_deny_notebook() -> i32 {
    let mut buf = String::new();
    let _ = io::stdin().read_to_string(&mut buf);
    block(
        "redactor strict mode: the NotebookEdit tool is disabled in this profile. Jupyter \
         notebooks are not used here, and enabling NotebookEdit would open a code-and-output \
         read/write path that no current hook sanitizes. If a notebook genuinely needs \
         editing, ask the user to remove the deny-notebook matcher from the active hook \
         config for the session.",
    )
}

// ============================================================================
// rred-20 — SessionStart hook (minimal)
// ============================================================================

/// `redactor hook session-start` — minimal slot. Reads payload from stdin
/// (best-effort), audit-logs the session start, allows. Never blocks.
pub fn run_session_start() -> i32 {
    // Best-effort: parse stdin and audit-log the cwd. Never block.
    let mut buf = String::new();
    let _ = io::stdin().read_to_string(&mut buf);
    if let Ok(cwd) = std::env::current_dir() {
        let dir = logger::resolve_log_dir();
        let cwd_str = cwd.display().to_string();
        let event = logger::Event {
            source: "session-start",
            mode: "session",
            command: &cwd_str,
            rule: "session_start",
            count: 1,
            sample: "",
        };
        logger::log_event(&dir, &event);
    }
    println!("{{}}");
    0
}

// ============================================================================
// rred-19 — PostWrite validators (per-extension lint/syntax check)
// ============================================================================

/// `redactor hook post-write` — runs after PostToolUse for Write|Edit.
/// Validates the written file's syntax based on extension. Block on failure
/// so Claude sees the lint output.
pub fn run_post_write() -> i32 {
    let mut buf = String::new();
    if io::stdin().read_to_string(&mut buf).is_err() {
        println!("{{}}");
        return 0;
    }
    let payload: serde_json::Value = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => {
            println!("{{}}");
            return 0;
        }
    };
    let paths = collect_post_write_paths(&payload);
    if paths.is_empty() {
        println!("{{}}");
        return 0;
    }
    for path in paths {
        if let Some(reason) = validate_written_file(&path) {
            let response = serde_json::json!({
                "decision": "block",
                "reason": reason,
            });
            println!("{response}");
            return 0;
        }
    }
    println!("{{}}");
    0
}

fn build_default_rules() -> Result<Vec<Rule>> {
    let policy = load_project_policy();
    let mut rules = patterns::defaults();

    // Phase 7c — username-masking is gated by [policy] mask_username.
    // When the project opts out, strip the static home-dir rules and skip
    // the dynamic-username injection. (Crypto-container / Azure / etc. are
    // unaffected — only the three username-related rules are stripped.)
    if !policy.mask_username {
        rules.retain(|r| r.name != "windows_home_dir" && r.name != "unix_home_dir");
    } else if let Some(dyn_rule) = patterns::dynamic_username_rule() {
        rules.push(dyn_rule);
    }

    // Auto-load user keywords from config dir (case-insensitive matching is
    // already handled by `(?i){escaped}` in load_keywords_file).
    rules.extend(config::autoload_rules()?);
    // Per-project .redactor.toml [patterns.custom] (rred-9).
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match config::autoload_project_rules(&cwd) {
        Ok(extra) => rules.extend(extra),
        Err(e) => eprintln!("[redactor] warning: failed to load .redactor.toml patterns: {e}"),
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_to_regex_star_matches_any_chars() {
        let re = glob_to_regex("docs/*.cfg").unwrap();
        assert!(re.is_match("docs/example.cfg"));
        assert!(re.is_match("docs/other.cfg"));
        assert!(!re.is_match("src/example.cfg"));
        assert!(!re.is_match("docs/example.txt"));
    }

    #[test]
    fn glob_to_regex_question_matches_one_char() {
        let re = glob_to_regex("file?.cfg").unwrap();
        assert!(re.is_match("file1.cfg"));
        assert!(re.is_match("fileA.cfg"));
        assert!(!re.is_match("file.cfg"));
        assert!(!re.is_match("file12.cfg"));
    }

    #[test]
    fn glob_to_regex_literal_chars_escaped() {
        // Regex specials in the glob must be escaped, not interpreted.
        let re = glob_to_regex("a.b+c").unwrap();
        assert!(re.is_match("a.b+c"));
        assert!(!re.is_match("aXbXc")); // dot is literal, not "any char"
    }

    #[test]
    fn path_matches_any_handles_empty_list() {
        assert!(!path_matches_any("anything", &[]));
    }

    #[test]
    fn path_matches_any_first_match_wins() {
        let patterns = vec!["docs/*.cfg".to_string(), "fixtures/*.crt".to_string()];
        assert!(path_matches_any("docs/x.cfg", &patterns));
        assert!(path_matches_any("fixtures/y.crt", &patterns));
        assert!(!path_matches_any("src/x.cfg", &patterns));
    }

    // ========================================================================
    // v0.7 path-guard extensions — self-protect, crypto, office-doc
    // ========================================================================

    #[test]
    fn self_protect_matches_tilde_form() {
        let _g = crate::ignorefile::test_env_lock();
        std::env::remove_var("REDACTOR_IGNOREFILE_PATH");
        assert!(match_self_protect("~/.redactorignore"));
        assert!(match_self_protect("cat ~/.redactorignore"));
        assert!(match_self_protect("redactor wrap -- cat ~/.redactorignore"));
    }

    #[test]
    fn self_protect_matches_absolute_form() {
        let _g = crate::ignorefile::test_env_lock();
        std::env::remove_var("REDACTOR_IGNOREFILE_PATH");
        let home = dirs::home_dir().unwrap();
        let absolute = home.join(".redactorignore");
        let s = absolute.display().to_string();
        assert!(match_self_protect(&s));
        assert!(match_self_protect(&format!("cat {s}")));
    }

    #[test]
    fn self_protect_does_not_match_other_dotfiles() {
        let _g = crate::ignorefile::test_env_lock();
        std::env::remove_var("REDACTOR_IGNOREFILE_PATH");
        assert!(!match_self_protect("~/.gitignore"));
        assert!(!match_self_protect("~/.bashrc"));
        assert!(!match_self_protect("/etc/redactor/config"));
    }

    #[test]
    fn self_protect_respects_test_override() {
        let _g = crate::ignorefile::test_env_lock();
        std::env::set_var("REDACTOR_IGNOREFILE_PATH", "/tmp/test-ign-99");
        // No longer matches default tilde form.
        assert!(!match_self_protect("~/.redactorignore"));
        // Matches the override path.
        assert!(match_self_protect("cat /tmp/test-ign-99"));
        std::env::remove_var("REDACTOR_IGNOREFILE_PATH");
    }

    #[test]
    fn crypto_container_detected_kdbx() {
        assert!(match_crypto_container("/Users/x/vault.kdbx").is_some());
        assert!(match_crypto_container("cat /Users/x/vault.kdbx").is_some());
        assert!(match_crypto_container("cat \"/Users/x/vault.kdbx\"").is_some());
    }

    #[test]
    fn crypto_container_detected_multiple_extensions() {
        assert!(match_crypto_container("foo.gpg").is_some());
        assert!(match_crypto_container("/path/secret.age").is_some());
        assert!(match_crypto_container("certs/client.p12").is_some());
        assert!(match_crypto_container("certs/client.pfx").is_some());
        assert!(match_crypto_container("login.keychain-db").is_some());
        assert!(match_crypto_container("message.asc").is_some());
    }

    #[test]
    fn crypto_container_boundary_avoids_false_positives() {
        // ".age" embedded in a longer word should NOT trigger.
        assert!(match_crypto_container("foo.agexyz").is_none());
        // ".kdbx" at start of unrelated identifier should NOT trigger.
        assert!(match_crypto_container("kdbxfoo").is_none());
    }

    #[test]
    fn crypto_container_case_insensitive() {
        assert!(match_crypto_container("vault.KDBX").is_some());
        assert!(match_crypto_container("FOO.Gpg").is_some());
    }

    #[test]
    fn office_doc_detected_xlsx_docx_pptx_pdf() {
        assert!(match_office_doc("/path/sheet.xlsx").is_some());
        assert!(match_office_doc("/path/letter.docx").is_some());
        assert!(match_office_doc("/path/deck.pptx").is_some());
        assert!(match_office_doc("/path/report.pdf").is_some());
        // Legacy
        assert!(match_office_doc("old.xls").is_some());
        assert!(match_office_doc("old.doc").is_some());
        assert!(match_office_doc("old.ppt").is_some());
        // Macro-enabled
        assert!(match_office_doc("macros.xlsm").is_some());
    }

    #[test]
    fn office_doc_case_insensitive() {
        assert!(match_office_doc("/path/REPORT.PDF").is_some());
        assert!(match_office_doc("Sheet.XLSX").is_some());
    }

    #[test]
    fn office_doc_does_not_match_plain_files() {
        assert!(match_office_doc("readme.md").is_none());
        assert!(match_office_doc("/path/config.toml").is_none());
        assert!(match_office_doc("data.csv").is_none()); // CSV intentionally excluded
        assert!(match_office_doc("/path/script.py").is_none());
    }

    #[test]
    fn office_doc_must_be_at_end_of_path() {
        // Substring at non-end position must NOT match.
        assert!(match_office_doc("/path/file.xlsx.bak").is_none());
        assert!(match_office_doc("/path/docx-converter.py").is_none());
    }

    #[test]
    fn redactorignore_path_match_via_test_override() {
        let _g = crate::ignorefile::test_env_lock();
        let td = tempfile::tempdir().unwrap();
        let ign = td.path().join(".redactorignore");
        std::fs::write(&ign, "/etc/private/*\n").unwrap();
        std::env::set_var("REDACTOR_IGNOREFILE_PATH", &ign);

        let pattern = match_redactorignore_path("/etc/private/secret.txt");
        assert!(pattern.is_some(), "expected match against /etc/private/*");
        assert_eq!(pattern.unwrap(), "/etc/private/*");

        let no_match = match_redactorignore_path("/etc/public/info.txt");
        assert!(no_match.is_none());

        std::env::remove_var("REDACTOR_IGNOREFILE_PATH");
    }

    #[test]
    fn redactorignore_path_negation_overrides() {
        let _g = crate::ignorefile::test_env_lock();
        let td = tempfile::tempdir().unwrap();
        let ign = td.path().join(".redactorignore");
        std::fs::write(&ign, "/etc/private/**\n!/etc/private/public.txt\n").unwrap();
        std::env::set_var("REDACTOR_IGNOREFILE_PATH", &ign);

        assert!(match_redactorignore_path("/etc/private/secret.txt").is_some());
        assert!(match_redactorignore_path("/etc/private/public.txt").is_none());

        std::env::remove_var("REDACTOR_IGNOREFILE_PATH");
    }

    #[test]
    fn redactorignore_path_empty_file_returns_none() {
        let _g = crate::ignorefile::test_env_lock();
        let td = tempfile::tempdir().unwrap();
        let ign = td.path().join(".redactorignore");
        std::fs::write(&ign, "# only comments\n# nothing here\n").unwrap();
        std::env::set_var("REDACTOR_IGNOREFILE_PATH", &ign);

        assert!(match_redactorignore_path("/anything/at/all").is_none());

        std::env::remove_var("REDACTOR_IGNOREFILE_PATH");
    }

    #[test]
    fn redactorignore_path_missing_file_returns_none() {
        let _g = crate::ignorefile::test_env_lock();
        std::env::set_var("REDACTOR_IGNOREFILE_PATH", "/nonexistent/__never__");
        assert!(match_redactorignore_path("/some/path").is_none());
        std::env::remove_var("REDACTOR_IGNOREFILE_PATH");
    }

    // ========================================================================
    // rred-35 — detect_struct_file_argument (position-aware struct-file check)
    // ========================================================================

    #[test]
    fn struct_file_blocked_when_real_read_cat_json() {
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- cat data.json"),
            Some(Mode::Json)
        );
    }

    #[test]
    fn struct_file_blocked_when_real_read_head_csv() {
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- head -50 cfg.csv"),
            Some(Mode::Csv)
        );
    }

    #[test]
    fn struct_file_blocked_when_real_read_tail_env() {
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- tail -F app.env"),
            Some(Mode::Env)
        );
    }

    #[test]
    fn struct_file_blocked_when_jq_reads_json() {
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- jq '.k' data.json"),
            Some(Mode::Json)
        );
    }

    #[test]
    fn struct_file_blocked_with_absolute_path_to_cat() {
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- /usr/bin/cat /etc/foo.json"),
            Some(Mode::Json)
        );
    }

    #[test]
    fn struct_file_blocked_jsonl_and_ndjson() {
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- cat events.jsonl"),
            Some(Mode::Json)
        );
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- jq -c . dump.ndjson"),
            Some(Mode::Json)
        );
    }

    #[test]
    fn struct_file_blocked_dot_env_basename() {
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- cat .env"),
            Some(Mode::Env)
        );
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- cat .envrc"),
            Some(Mode::Env)
        );
        assert_eq!(
            detect_struct_file_argument("redactor wrap -- cat .env.production"),
            Some(Mode::Env)
        );
    }

    #[test]
    fn struct_file_not_blocked_in_heredoc() {
        let cmd = r#"redactor wrap -- bash -c "cat > x.rs <<EOF\nlet p = \"data.json\";\nEOF""#;
        assert_eq!(detect_struct_file_argument(cmd), None);
    }

    #[test]
    fn struct_file_not_blocked_in_sed_pattern() {
        // sed is intentionally NOT in READ_TOOLS; substitution patterns that
        // mention `.json` should not block.
        let cmd = r"redactor wrap -- bash -c sed -i 's|\.json|.jsonl|g' file.rs";
        assert_eq!(detect_struct_file_argument(cmd), None);
    }

    #[test]
    fn struct_file_not_blocked_in_echo() {
        let cmd = r#"redactor wrap -- echo "see data.csv for details""#;
        assert_eq!(detect_struct_file_argument(cmd), None);
    }

    #[test]
    fn struct_file_not_blocked_in_doc_comment() {
        let cmd = r#"redactor wrap -- bash -c "echo '// e.g. data.csv'""#;
        assert_eq!(detect_struct_file_argument(cmd), None);
    }

    #[test]
    fn struct_file_not_blocked_in_task_body_arg() {
        let cmd = "redactor wrap -- task add 'fix .json parsing' --phase backlog";
        assert_eq!(detect_struct_file_argument(cmd), None);
    }

    #[test]
    fn struct_file_not_blocked_when_no_read_tool() {
        // No read-tool ever appears — the .csv is just a string in argv.
        let cmd = "redactor wrap -- python my_script.py --output data.csv";
        assert_eq!(detect_struct_file_argument(cmd), None);
    }

    #[test]
    fn ext_to_mode_handles_uppercase() {
        assert_eq!(ext_to_mode("Data.JSON"), Some(Mode::Json));
        assert_eq!(ext_to_mode("X.CSV"), Some(Mode::Csv));
        assert_eq!(ext_to_mode(".ENV"), Some(Mode::Env));
    }

    #[test]
    fn ext_to_mode_handles_paths() {
        assert_eq!(ext_to_mode("/etc/foo.json"), Some(Mode::Json));
        assert_eq!(ext_to_mode("./relative/x.csv"), Some(Mode::Csv));
        assert_eq!(ext_to_mode("/var/app/.env"), Some(Mode::Env));
        assert_eq!(ext_to_mode("home/.env.local"), Some(Mode::Env));
    }

    #[test]
    fn ext_to_mode_rejects_non_struct() {
        assert_eq!(ext_to_mode("data.txt"), None);
        assert_eq!(ext_to_mode("README.md"), None);
        assert_eq!(ext_to_mode("script.sh"), None);
        assert_eq!(ext_to_mode(""), None);
        assert_eq!(ext_to_mode(">"), None);
    }

    // ========================================================================
    // rred-36 — fixed-deny hooks: end-to-end binary coverage in
    // tests/hook_phase5.rs (run_hook helper). No unit tests here because the
    // functions return their result via stdout (println!), which is awkward
    // to capture in-process.
    // ========================================================================

    // ========================================================================
    // Phase 7d — Path-Guard-Smartness
    // ========================================================================

    #[test]
    fn strip_pattern_literal_args_drops_dash_e_arg() {
        let cmd = r#"grep -E "\.pfx" file.txt"#;
        let out = strip_pattern_literal_args(cmd);
        assert!(!out.contains(".pfx"));
        assert!(out.contains("file.txt"));
    }

    #[test]
    fn strip_pattern_literal_args_keeps_path_argument() {
        // The .pfx token is NOT after a pattern flag — it must survive.
        let cmd = "cat /Users/x/vault.pfx";
        let out = strip_pattern_literal_args(cmd);
        assert!(out.contains("vault.pfx"));
    }

    #[test]
    fn strip_pattern_literal_args_handles_double_dash_regex() {
        let cmd = r#"rg --regex "vault\.kdbx" /tmp"#;
        let out = strip_pattern_literal_args(cmd);
        assert!(!out.contains("kdbx"));
        assert!(out.contains("/tmp"));
    }

    #[test]
    fn strip_pattern_literal_args_handles_glued_form() {
        let cmd = r#"grep --regex=\.pfx file.txt"#;
        let out = strip_pattern_literal_args(cmd);
        assert!(!out.contains(".pfx"));
    }

    #[test]
    fn strip_pattern_literal_args_handles_include_exclude() {
        let cmd = "rg --include '*.pfx' secret /tmp";
        let out = strip_pattern_literal_args(cmd);
        assert!(!out.contains("*.pfx"));
        assert!(out.contains("/tmp"));
    }

    // ========================================================================
    // Phase 7e — Office-doc bash-block consistency
    // ========================================================================

    #[test]
    fn match_office_doc_in_bash_catches_cat_xlsx() {
        let cmd = "cat /Users/x/report.xlsx | head";
        assert!(match_office_doc_in_bash(cmd).is_some());
    }

    #[test]
    fn match_office_doc_in_bash_catches_pdf_path() {
        let cmd = "redactor wrap -- pdftotext /tmp/doc.pdf -";
        assert!(match_office_doc_in_bash(cmd).is_some());
    }

    #[test]
    fn match_office_doc_in_bash_ignores_pattern_literal() {
        // Caller should strip pattern args before calling; demonstrate that
        // a stripped command no longer matches.
        let cmd = r#"grep -E "\.pdf" notes.txt"#;
        let stripped = strip_pattern_literal_args(cmd);
        assert!(match_office_doc_in_bash(&stripped).is_none());
    }

    #[test]
    fn match_office_doc_in_bash_negative_no_office_path() {
        let cmd = "ls /tmp/foo.txt";
        assert!(match_office_doc_in_bash(cmd).is_none());
    }

    // ========================================================================
    // tokenize_shell — quick smoke
    // ========================================================================
    #[test]
    fn tokenize_shell_respects_single_quotes() {
        let toks = tokenize_shell("echo 'a b c' d");
        assert_eq!(toks, vec!["echo", "a b c", "d"]);
    }
    #[test]
    fn tokenize_shell_respects_double_quotes() {
        let toks = tokenize_shell(r#"cat "spaces inside" /tmp"#);
        assert_eq!(toks, vec!["cat", "spaces inside", "/tmp"]);
    }

    // ========================================================================
    // self-protect end-boundary fix — companion files (.suggested / .keywords.suggested)
    // must NOT trigger the self-protect block on the actual `.redactorignore` file.
    // ========================================================================

    #[test]
    fn contains_with_end_boundary_matches_exact_path_end() {
        let needle = "/home/u/.redactorignore";
        assert!(contains_with_end_boundary(needle, needle));
        assert!(contains_with_end_boundary(
            "cat /home/u/.redactorignore",
            needle
        ));
        assert!(contains_with_end_boundary(
            r#"cat "/home/u/.redactorignore""#,
            needle
        ));
        assert!(contains_with_end_boundary(
            "cat /home/u/.redactorignore | grep x",
            needle
        ));
    }

    #[test]
    fn contains_with_end_boundary_rejects_companion_suffix() {
        let needle = "/home/u/.redactorignore";
        // Companion files MUST NOT match.
        assert!(!contains_with_end_boundary(
            "/home/u/.redactorignore.suggested",
            needle
        ));
        assert!(!contains_with_end_boundary(
            "/home/u/.redactorignore.keywords.suggested",
            needle
        ));
        assert!(!contains_with_end_boundary(
            "cat /home/u/.redactorignore.bak",
            needle
        ));
    }
}

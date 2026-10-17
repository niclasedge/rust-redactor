//! `redactor install-plugin` / `install-hooks` subcommands.
//!
//! Deploys `.claude/settings.json` and `.claude/CLAUDE.md` into a target
//! project (local) or merges hook entries into `~/.claude/settings.json`
//! (global). Templates are baked into the binary at compile time.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// `settings.json` template, baked at compile time.
pub static SETTINGS_TEMPLATE: &str =
    include_str!("../examples/strict-redaction/claude/settings.json");

/// `CLAUDE.md` template, baked at compile time.
pub static CLAUDEMD_TEMPLATE: &str = include_str!("../examples/strict-redaction/claude/CLAUDE.md");

// ──────────────────────────────────────────────
// Global install hook definitions
// ──────────────────────────────────────────────

struct HookDef {
    event: &'static str,
    matcher: Option<&'static str>,
    command: &'static str,
}

static GLOBAL_HOOKS: &[HookDef] = &[
    HookDef {
        event: "PreToolUse",
        matcher: Some("Bash|PowerShell"),
        command: "redactor hook pre-bash",
    },
    HookDef {
        event: "PreToolUse",
        matcher: Some("Read"),
        command: "redactor hook pre-read",
    },
    HookDef {
        event: "PreToolUse",
        matcher: Some("Edit|MultiEdit|Write"),
        command: "redactor hook pre-edit",
    },
    HookDef {
        event: "PreToolUse",
        matcher: Some("Grep"),
        command: "redactor hook deny-grep",
    },
    HookDef {
        event: "PreToolUse",
        matcher: Some("NotebookEdit"),
        command: "redactor hook deny-notebook",
    },
    HookDef {
        event: "PreToolUse",
        matcher: Some("mcp__.*"),
        command: "redactor hook deny-mcp",
    },
    HookDef {
        event: "PostToolUse",
        matcher: Some("Write|Edit"),
        command: "redactor hook post-write",
    },
    HookDef {
        event: "UserPromptSubmit",
        matcher: None,
        command: "redactor hook prompt",
    },
    HookDef {
        event: "SessionStart",
        matcher: None,
        command: "redactor hook session-start",
    },
];

const GLOBAL_CLAUDEMD_START: &str =
    "<!-- BEGIN: redactor strict mode (managed block — do not edit between markers) -->";
const GLOBAL_CLAUDEMD_END: &str = "<!-- END: redactor strict mode -->";

static GLOBAL_CLAUDEMD_SECTION: &str = r#"<!-- BEGIN: redactor strict mode (managed block — do not edit between markers) -->

# Redactor Strict Mode (global)

`redactor` is globally wired into Claude Code hooks. Tool output and user input
are filtered; some tools are fully disabled.

## Placeholders you will see

`<redacted:LABEL>` replaces every value that matches a pattern or keyword:

| Placeholder | Meaning |
|---|---|
| `<redacted>` | structural redaction (CSV cell, JSON leaf, env value) |
| `<redacted:openai_key>` / `:anthropic_key` / `:aws_access_key` / `:github_token` / `:slack_token` / `:stripe_live` / `:jwt` / `:private_key` | known secret patterns |
| `<redacted:keyword>` | match from `~/.config/redactor/keywords.txt` |
| `<redacted:<custom>>` | user regex from `patterns.json` |

Treat placeholders as **sealed**. Do NOT try to reconstruct the original,
ask for the unredacted version, or suggest disabling the hook.

## Disabled tools

| Tool | Replacement |
|---|---|
| `Grep` | `redactor wrap -- rg "<pattern>" <path>` via Bash |
| `NotebookEdit` | ask the user for an exception |
| `mcp__*` | ask the user for an exception |

## Bash / PowerShell — required form

Every Bash / PowerShell call must start with `redactor wrap --` (or the alias `r wrap --`):

```bash
redactor wrap -- ./run.sh
redactor wrap -- bash -c "./step1 && ./step2"
redactor wrap --keywords "EXTRA-SECRET" -- kubectl logs deploy/api
```

## Reading files

```bash
redactor --type json <file.json>   # JSON: leaves redacted
redactor --type csv  <file.csv>    # CSV: header verbatim, row 2 redacted
redactor --type env  <file.env>    # ENV: KEY=<redacted>
redactor wrap -- cat <file>        # free-text / source files
```

## Sensitive paths (blocked)

`.env*`, `id_rsa*`, `.ssh/*` (except `known_hosts`), `.aws/credentials`,
`.aws/config`, `**/secrets/**`, `**/*.pem`, `**/*.key`.

## Keyword list

`redactor config-path` shows the path. Edit: `${EDITOR:-vi} <keywords.txt>`.
Per-call addition: `redactor wrap --keywords "TERM" -- <cmd>`.

<!-- END: redactor strict mode -->"#;

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn global_claude_dir() -> Result<PathBuf> {
    // Allow test (and advanced user) override without touching the real home.
    if let Ok(dir) = std::env::var("REDACTOR_CLAUDE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    dirs::home_dir()
        .map(|h| h.join(".claude"))
        .context("could not determine home directory")
}

/// Return true if the hook is already present in `entries` (idempotent check).
fn hook_already_present(entries: &[Value], matcher: Option<&str>, command: &str) -> bool {
    for entry in entries {
        if let Value::Object(obj) = entry {
            let m = obj.get("matcher").and_then(|v| v.as_str());
            if m != matcher {
                continue;
            }
            if let Some(Value::Array(hooks)) = obj.get("hooks") {
                for h in hooks {
                    if h.get("command").and_then(|v| v.as_str()) == Some(command) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ──────────────────────────────────────────────
// Local install
// ──────────────────────────────────────────────

/// Install into `<target>/.claude/`.
///
/// - `dry_run`: print actions without writing.
/// - `force`:   overwrite existing `.claude/` without backup.
/// - `merge`:   merge settings.json hooks instead of replacing the whole dir.
pub fn run_install_plugin_local(
    target: &Path,
    dry_run: bool,
    force: bool,
    merge: bool,
) -> Result<i32> {
    if !target.exists() {
        bail!(
            "install-plugin local: target directory does not exist: {}",
            target.display()
        );
    }
    if !target.is_dir() {
        bail!(
            "install-plugin local: target is not a directory: {}",
            target.display()
        );
    }

    let claude_dir = target.join(".claude");

    if merge && claude_dir.exists() {
        return merge_local_settings(&claude_dir, dry_run);
    }

    if claude_dir.exists() {
        if force {
            if dry_run {
                println!("[dry-run] would remove existing {}", claude_dir.display());
            } else {
                std::fs::remove_dir_all(&claude_dir)
                    .with_context(|| format!("remove {}", claude_dir.display()))?;
            }
        } else {
            let backup = target.join(format!(".claude.bak.{}", unix_ts()));
            if dry_run {
                println!(
                    "[dry-run] would backup {} → {}",
                    claude_dir.display(),
                    backup.display()
                );
            } else {
                std::fs::rename(&claude_dir, &backup).with_context(|| {
                    format!("backup {} → {}", claude_dir.display(), backup.display())
                })?;
                eprintln!(
                    "redactor: backed up existing .claude/ to {}",
                    backup.display()
                );
            }
        }
    }

    let settings_path = claude_dir.join("settings.json");
    let claudemd_path = claude_dir.join("CLAUDE.md");

    if dry_run {
        println!("[dry-run] would create {}", claude_dir.display());
        println!("[dry-run] would write  {}", settings_path.display());
        println!("[dry-run] would write  {}", claudemd_path.display());
        return Ok(0);
    }

    std::fs::create_dir_all(&claude_dir)
        .with_context(|| format!("create {}", claude_dir.display()))?;
    std::fs::write(&settings_path, SETTINGS_TEMPLATE)
        .with_context(|| format!("write {}", settings_path.display()))?;
    std::fs::write(&claudemd_path, CLAUDEMD_TEMPLATE)
        .with_context(|| format!("write {}", claudemd_path.display()))?;

    println!(
        "redactor: installed strict-redaction config at {}",
        claude_dir.display()
    );
    Ok(0)
}

/// Merge only the hook entries from the template into an existing settings.json.
/// CLAUDE.md is left untouched. On second run (idempotent) nothing changes.
fn merge_local_settings(claude_dir: &Path, dry_run: bool) -> Result<i32> {
    let settings_path = claude_dir.join("settings.json");
    let mut data: Value = if settings_path.exists() {
        let raw = std::fs::read_to_string(&settings_path)
            .with_context(|| format!("read {}", settings_path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", settings_path.display()))?
    } else {
        Value::Object(serde_json::Map::new())
    };

    let template: Value =
        serde_json::from_str(SETTINGS_TEMPLATE).context("parse built-in settings template")?;

    let template_hooks = template
        .get("hooks")
        .and_then(|h| h.as_object())
        .context("built-in template has no 'hooks' object")?;

    let hooks = data
        .as_object_mut()
        .context("settings.json root is not an object")?
        .entry("hooks")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .context("'hooks' is not an object")?;

    let mut added = 0usize;
    for (event, new_entries) in template_hooks {
        let Value::Array(new_arr) = new_entries else {
            continue;
        };
        let existing = hooks
            .entry(event.clone())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .context("hook event array is not an array")?;

        for entry in new_arr {
            let matcher = entry.get("matcher").and_then(|v| v.as_str());
            if let Some(Value::Array(cmds)) = entry.get("hooks") {
                for cmd in cmds {
                    let command = cmd.get("command").and_then(|v| v.as_str()).unwrap_or("");
                    if !hook_already_present(existing, matcher, command) {
                        if dry_run {
                            println!("[dry-run] would add hook: {event} [{matcher:?}] → {command}");
                        } else {
                            existing.push(entry.clone());
                        }
                        added += 1;
                        break; // one entry per matcher block
                    }
                }
            }
        }
    }

    if added == 0 {
        println!(
            "redactor: {} already up-to-date (0 hooks added)",
            settings_path.display()
        );
        return Ok(0);
    }
    if dry_run {
        println!("[dry-run] {added} hook(s) would be added");
        return Ok(0);
    }

    let out = serde_json::to_string_pretty(&data).context("serialize merged settings")?;
    std::fs::write(&settings_path, out + "\n")
        .with_context(|| format!("write {}", settings_path.display()))?;
    println!(
        "redactor: merged {} hook(s) into {}",
        added,
        settings_path.display()
    );
    Ok(0)
}

// ──────────────────────────────────────────────
// Global install
// ──────────────────────────────────────────────

/// Merge redactor hooks into `~/.claude/settings.json` and append/refresh a
/// managed block in `~/.claude/CLAUDE.md`.
///
/// Idempotent: hooks already present are skipped; CLAUDE.md block is
/// refreshed in-place.
pub fn run_install_plugin_global(dry_run: bool, force: bool) -> Result<i32> {
    let claude_dir = global_claude_dir()?;
    let settings_path = claude_dir.join("settings.json");
    let claudemd_path = claude_dir.join("CLAUDE.md");

    if dry_run {
        println!("[dry-run] global Claude dir: {}", claude_dir.display());
    }

    // ── settings.json ───────────────────────────────────────────────────────
    let mut data: Value = if settings_path.exists() {
        let raw = std::fs::read_to_string(&settings_path)
            .with_context(|| format!("read {}", settings_path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", settings_path.display()))?
    } else {
        if dry_run {
            println!(
                "[dry-run] {} does not exist — would create fresh",
                settings_path.display()
            );
        }
        Value::Object(serde_json::Map::new())
    };

    // Backup (unless force or dry-run)
    if settings_path.exists() {
        let backup = settings_path.with_file_name(format!("settings.json.bak.{}", unix_ts()));
        if dry_run {
            println!(
                "[dry-run] would backup {} → {}",
                settings_path.display(),
                backup.display()
            );
        } else if !force {
            std::fs::copy(&settings_path, &backup)
                .with_context(|| format!("backup {}", settings_path.display()))?;
            eprintln!("redactor: backup → {}", backup.display());
        }
    }

    // Merge hooks
    let hooks_map = data
        .as_object_mut()
        .context("settings.json root is not an object")?
        .entry("hooks")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .context("'hooks' is not an object")?;

    let mut added: Vec<String> = Vec::new();
    for hd in GLOBAL_HOOKS {
        let entries = hooks_map
            .entry(hd.event)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .context("hook event array is not an array")?;

        if hook_already_present(entries, hd.matcher, hd.command) {
            continue;
        }

        let mut entry = serde_json::Map::new();
        entry.insert(
            "hooks".into(),
            Value::Array(vec![serde_json::json!({
                "type": "command",
                "command": hd.command,
            })]),
        );
        if let Some(m) = hd.matcher {
            entry.insert("matcher".into(), Value::String(m.into()));
        }
        added.push(format!("{} [{:?}] → {}", hd.event, hd.matcher, hd.command));
        if !dry_run {
            entries.push(Value::Object(entry));
        }
    }

    if dry_run {
        if added.is_empty() {
            println!("[dry-run] settings.json already up-to-date (0 hooks to add)");
        } else {
            println!("[dry-run] {} hook(s) would be added:", added.len());
            for a in &added {
                println!("  + {a}");
            }
        }
    } else {
        if !settings_path.exists() {
            std::fs::create_dir_all(&claude_dir)
                .with_context(|| format!("create {}", claude_dir.display()))?;
        }
        let out = serde_json::to_string_pretty(&data).context("serialize settings")?;
        std::fs::write(&settings_path, out + "\n")
            .with_context(|| format!("write {}", settings_path.display()))?;
        println!(
            "redactor: settings.json — {} new hook(s) added",
            added.len()
        );
        for a in &added {
            println!("  + {a}");
        }
    }

    // ── CLAUDE.md ────────────────────────────────────────────────────────────
    let current_md = if claudemd_path.exists() {
        std::fs::read_to_string(&claudemd_path)
            .with_context(|| format!("read {}", claudemd_path.display()))?
    } else {
        String::new()
    };

    let new_md = upsert_managed_block(&current_md, GLOBAL_CLAUDEMD_SECTION);

    if new_md == current_md {
        if dry_run {
            println!("[dry-run] CLAUDE.md managed block already up-to-date");
        } else {
            println!("redactor: CLAUDE.md managed block already up-to-date");
        }
    } else if dry_run {
        println!(
            "[dry-run] would write {} ({} chars)",
            claudemd_path.display(),
            new_md.len()
        );
    } else {
        if !claudemd_path.parent().map(|p| p.exists()).unwrap_or(false) {
            if let Some(parent) = claudemd_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
        }
        std::fs::write(&claudemd_path, &new_md)
            .with_context(|| format!("write {}", claudemd_path.display()))?;
        println!("redactor: CLAUDE.md updated ({} chars)", new_md.len());
    }

    Ok(0)
}

/// Insert or replace the managed block in `text`. Returns the updated string.
fn upsert_managed_block(text: &str, section: &str) -> String {
    if let Some(start) = text.find(GLOBAL_CLAUDEMD_START) {
        if let Some(end_offset) = text[start..].find(GLOBAL_CLAUDEMD_END) {
            let end = start + end_offset + GLOBAL_CLAUDEMD_END.len();
            let mut out = text[..start].to_string();
            out.push_str(section);
            out.push_str(&text[end..]);
            return out;
        }
    }
    // No existing block — append
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(section);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

// ──────────────────────────────────────────────
// Uninstall
// ──────────────────────────────────────────────

/// Remove installed plugin artifacts from `<target>/.claude/`.
pub fn run_uninstall_plugin_local(target: &Path, dry_run: bool) -> Result<i32> {
    if !target.exists() {
        bail!(
            "uninstall-plugin: target directory does not exist: {}",
            target.display()
        );
    }
    let claude_dir = target.join(".claude");
    if !claude_dir.exists() {
        println!(
            "redactor: nothing to uninstall — {} does not exist",
            claude_dir.display()
        );
        return Ok(0);
    }

    if dry_run {
        println!("[dry-run] would remove {}", claude_dir.display());
        return Ok(0);
    }

    std::fs::remove_dir_all(&claude_dir)
        .with_context(|| format!("remove {}", claude_dir.display()))?;
    println!("redactor: removed {}", claude_dir.display());
    Ok(0)
}

// ──────────────────────────────────────────────
// Status
// ──────────────────────────────────────────────

/// Report plugin installation state.
pub fn run_plugin_status(global: bool, target: Option<&Path>) -> Result<i32> {
    if global {
        let claude_dir = global_claude_dir()?;
        let settings_path = claude_dir.join("settings.json");
        let claudemd_path = claude_dir.join("CLAUDE.md");
        println!("=== global plugin status ===");
        println!("claude_dir: {}", claude_dir.display());
        check_settings_status(&settings_path);
        check_claudemd_status(&claudemd_path);
    }

    let local_dir = target.unwrap_or_else(|| Path::new("."));
    let claude_dir = local_dir.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    let claudemd_path = claude_dir.join("CLAUDE.md");
    println!("=== local plugin status ({}) ===", local_dir.display());
    println!("claude_dir: {}", claude_dir.display());
    check_settings_status(&settings_path);
    check_claudemd_status(&claudemd_path);
    Ok(0)
}

fn check_settings_status(path: &Path) {
    if !path.exists() {
        println!("  settings.json: missing");
        return;
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            println!("  settings.json: error reading — {e}");
            return;
        }
    };
    let installed: Vec<&str> = GLOBAL_HOOKS
        .iter()
        .filter(|hd| raw.contains(hd.command))
        .map(|hd| hd.command)
        .collect();
    let total = GLOBAL_HOOKS.len();
    println!(
        "  settings.json: {}/{} redactor hooks present",
        installed.len(),
        total
    );
}

fn check_claudemd_status(path: &Path) {
    if !path.exists() {
        println!("  CLAUDE.md: missing");
        return;
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            println!("  CLAUDE.md: error reading — {e}");
            return;
        }
    };
    if raw.contains(GLOBAL_CLAUDEMD_START) {
        println!("  CLAUDE.md: managed block present");
    } else if raw.contains("redactor") {
        println!("  CLAUDE.md: exists, mentions redactor (no managed block)");
    } else {
        println!("  CLAUDE.md: exists, no redactor content");
    }
}

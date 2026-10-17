//! `classify-merge` — interactively review `.redactorignore.suggested` and
//! append accepted entries to `~/.redactorignore`.
//!
//! The suggestions file is written by `classify-files`. Each entry is a
//! `# confidence=… labels=… evidence=…` comment-block followed by a path
//! line. This module parses that shape back, prompts per entry, and
//! appends the accepted paths to the active ignorefile.
//!
//! Comment lines from `.suggested` are **not** propagated — only the path
//! lines. The target ignorefile keeps its own existing comments untouched.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// One suggestion parsed back from `.suggested`. We keep the raw metadata
/// (confidence/labels/evidence comments that preceded the path line) so we
/// can render them to the user when prompting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSuggestion {
    pub path: String,
    pub meta_lines: Vec<String>,
}

/// User decision for a single entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeDecision {
    Accept,
    Reject,
    /// `skip-rest` — reject this entry and stop prompting; remaining
    /// entries are treated as Reject too.
    SkipRest,
    Quit,
}

/// Parse a `.suggested` file body into entries. Comment lines accumulate
/// into `meta_lines` of the next non-comment line.
pub fn parse_suggestions(text: &str) -> Vec<ParsedSuggestion> {
    let mut out = Vec::new();
    let mut pending_meta: Vec<String> = Vec::new();

    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            // blank line resets pending meta — keeps stray header comments
            // from sticking to the next path entry
            pending_meta.clear();
            continue;
        }
        if let Some(after) = trimmed.strip_prefix('#') {
            pending_meta.push(after.trim().to_string());
            continue;
        }
        // path line
        out.push(ParsedSuggestion {
            path: trimmed.to_string(),
            meta_lines: std::mem::take(&mut pending_meta),
        });
    }
    out
}

/// Read existing entries from the target ignorefile so we can deduplicate.
/// Returns a HashSet of normalized path strings already present. Missing
/// file → empty set.
fn existing_entries(target: &Path) -> HashSet<String> {
    let Ok(txt) = std::fs::read_to_string(target) else {
        return HashSet::new();
    };
    txt.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.trim_start_matches('!').trim().to_string())
        .collect()
}

/// Print the entry header + the user's prompt to stderr. Returns the user's
/// decision parsed from `reader` (one keystroke + Enter, lowercased).
fn prompt_decision(
    idx: usize,
    total: usize,
    s: &ParsedSuggestion,
    reader: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<MergeDecision> {
    writeln!(out)?;
    writeln!(out, "[{}/{}] candidate path:", idx + 1, total)?;
    writeln!(out, "    {}", s.path)?;
    for m in &s.meta_lines {
        writeln!(out, "    # {m}")?;
    }
    write!(
        out,
        "  add to ~/.redactorignore? [y]es / [n]o / [s]kip-rest / [q]uit: "
    )?;
    out.flush().ok();

    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(MergeDecision::Quit); // EOF
    }
    let ch = line
        .trim()
        .chars()
        .next()
        .unwrap_or('n')
        .to_ascii_lowercase();
    Ok(match ch {
        'y' => MergeDecision::Accept,
        'n' => MergeDecision::Reject,
        's' => MergeDecision::SkipRest,
        'q' => MergeDecision::Quit,
        // any other key = reject (safer default — don't smuggle into the
        // ignorefile on accidental Enter)
        _ => MergeDecision::Reject,
    })
}

/// Append the accepted paths to `target`, deduplicating against existing
/// content. Creates the file (and parent dir) if missing.
fn append_accepted(target: &Path, accepted: &[String]) -> Result<()> {
    if accepted.is_empty() {
        return Ok(());
    }
    let existing = existing_entries(target);
    let new_lines: Vec<String> = accepted
        .iter()
        .filter(|p| !existing.contains(p.trim_start_matches('!').trim()))
        .cloned()
        .collect();
    if new_lines.is_empty() {
        return Ok(());
    }

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut existing_text = std::fs::read_to_string(target).unwrap_or_default();
    let needs_blank = !existing_text.is_empty() && !existing_text.ends_with('\n');
    if needs_blank {
        existing_text.push('\n');
    }
    let header = format!(
        "\n# Added by `redactor classify-merge` on {}\n",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%z")
    );
    let body: String = new_lines
        .iter()
        .map(|l| format!("{l}\n"))
        .collect::<Vec<_>>()
        .concat();

    let final_text = format!("{existing_text}{header}{body}");
    std::fs::write(target, final_text).with_context(|| format!("write {}", target.display()))?;
    Ok(())
}

/// Arguments for the subcommand. Lives in this module so `main.rs` can
/// `#[command(flatten)]`-style consume it.
#[derive(Debug, Clone, clap::Args)]
pub struct ClassifyMergeArgs {
    /// Path to the `.redactorignore.suggested` file produced by
    /// `redactor classify-files`. Default: `~/.redactorignore.suggested`.
    pub suggested: Option<PathBuf>,

    /// Target ignorefile. Defaults to `~/.redactorignore` (or whatever
    /// `REDACTOR_IGNOREFILE_PATH` overrides to).
    #[arg(long)]
    pub target: Option<PathBuf>,

    /// Skip the interactive prompt — accept every suggested entry.
    #[arg(long, conflicts_with = "dry_run")]
    pub yes: bool,

    /// Print what would happen without modifying the target.
    #[arg(long)]
    pub dry_run: bool,

    /// Phase 6c — Review the keyword-suggestion stream
    /// (`~/.redactorignore.keywords.suggested`) instead of the path stream.
    /// When set, accepted entries are appended as keywords (lowercased) to
    /// `~/.redactorignore`.
    #[arg(long, conflicts_with = "paths")]
    pub keywords: bool,

    /// Phase 6c — Default mode (kept for symmetry with `--keywords`).
    /// Reviews the path-suggestion stream.
    #[arg(long, conflicts_with = "keywords")]
    pub paths: bool,

    /// Phase 6c — Review both streams sequentially (paths first, then keywords).
    #[arg(long, conflicts_with_all = ["keywords", "paths"])]
    pub all: bool,
}

/// Entry point dispatched from `main.rs`.
pub fn run(args: ClassifyMergeArgs) -> Result<i32> {
    let target_path = match &args.target {
        Some(p) => p.clone(),
        None => crate::ignorefile::ignorefile_path()
            .context("no home dir for default target ignorefile")?,
    };

    // Default mode: paths. --keywords flips to keyword review.
    // --all loops over both streams.
    let do_paths = args.all || (!args.keywords);
    let do_keywords = args.all || args.keywords;

    let home = dirs::home_dir().context("no home dir")?;

    if do_paths {
        let suggested_path = args
            .suggested
            .clone()
            .unwrap_or_else(|| home.join(".redactorignore.suggested"));
        run_path_merge(&args, &suggested_path, &target_path)?;
    }

    if do_keywords {
        let kw_path = if args.all {
            home.join(".redactorignore.keywords.suggested")
        } else {
            args.suggested
                .clone()
                .unwrap_or_else(|| home.join(".redactorignore.keywords.suggested"))
        };
        if kw_path.exists() {
            run_keyword_merge(&args, &kw_path, &target_path)?;
        } else if !args.all {
            eprintln!(
                "classify-merge: no keyword-suggested file at {}",
                kw_path.display()
            );
        }
    }
    Ok(0)
}

/// Phase 6c — review the path-suggestion stream and persist decisions
/// to the classifier state file.
fn run_path_merge(
    args: &ClassifyMergeArgs,
    suggested_path: &Path,
    target_path: &Path,
) -> Result<()> {
    if !suggested_path.exists() {
        eprintln!(
            "classify-merge: no suggestions file at {} (skipping path review)",
            suggested_path.display()
        );
        return Ok(());
    }
    let text = std::fs::read_to_string(suggested_path)
        .with_context(|| format!("read {}", suggested_path.display()))?;
    let parsed = parse_suggestions(&text);

    if parsed.is_empty() {
        eprintln!(
            "classify-merge: no path entries found in {}",
            suggested_path.display()
        );
        return Ok(());
    }

    eprintln!(
        "classify-merge: {} path candidates from {}",
        parsed.len(),
        suggested_path.display()
    );

    let mut accepted: Vec<String> = Vec::new();
    let mut accepted_meta: Vec<&ParsedSuggestion> = Vec::new();
    let mut rejected_meta: Vec<&ParsedSuggestion> = Vec::new();
    let mut skipped_rest = 0usize;

    if args.yes {
        for s in &parsed {
            accepted.push(s.path.clone());
            accepted_meta.push(s);
        }
    } else {
        let stdin = std::io::stdin();
        let stderr = std::io::stderr();
        let mut reader = stdin.lock();
        let mut writer = stderr.lock();
        let total = parsed.len();

        for (idx, s) in parsed.iter().enumerate() {
            let decision = prompt_decision(idx, total, s, &mut reader, &mut writer)?;
            match decision {
                MergeDecision::Accept => {
                    accepted.push(s.path.clone());
                    accepted_meta.push(s);
                }
                MergeDecision::Reject => rejected_meta.push(s),
                MergeDecision::SkipRest => {
                    skipped_rest = total - idx - 1;
                    break;
                }
                MergeDecision::Quit => {
                    eprintln!("classify-merge: aborted by user; nothing written.");
                    return Ok(());
                }
            }
        }
    }

    if args.dry_run {
        eprintln!(
            "classify-merge (dry-run): would append {} new entries to {}",
            accepted.len(),
            target_path.display()
        );
        for p in &accepted {
            eprintln!("    + {p}");
        }
        return Ok(());
    }

    append_accepted(target_path, &accepted)?;

    // Phase 6c — persist accept/reject to the state file.
    persist_path_decisions(&accepted_meta, &rejected_meta);

    eprintln!(
        "classify-merge: paths — accepted {}, rejected {}, skipped {} → wrote {}",
        accepted.len(),
        rejected_meta.len(),
        skipped_rest,
        target_path.display()
    );
    Ok(())
}

/// Phase 6c — review the keyword-suggestion stream.
fn run_keyword_merge(
    args: &ClassifyMergeArgs,
    suggested_path: &Path,
    target_path: &Path,
) -> Result<()> {
    let text = std::fs::read_to_string(suggested_path)
        .with_context(|| format!("read {}", suggested_path.display()))?;
    let parsed = parse_suggestions(&text);

    if parsed.is_empty() {
        eprintln!(
            "classify-merge: no keyword entries found in {}",
            suggested_path.display()
        );
        return Ok(());
    }

    eprintln!(
        "classify-merge: {} keyword candidates from {}",
        parsed.len(),
        suggested_path.display()
    );

    let mut accepted: Vec<String> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    let mut skipped_rest = 0usize;

    if args.yes {
        accepted.extend(parsed.iter().map(|s| s.path.clone()));
    } else {
        let stdin = std::io::stdin();
        let stderr = std::io::stderr();
        let mut reader = stdin.lock();
        let mut writer = stderr.lock();
        let total = parsed.len();
        for (idx, s) in parsed.iter().enumerate() {
            let decision = prompt_decision(idx, total, s, &mut reader, &mut writer)?;
            match decision {
                MergeDecision::Accept => accepted.push(s.path.clone()),
                MergeDecision::Reject => rejected.push(s.path.clone()),
                MergeDecision::SkipRest => {
                    skipped_rest = total - idx - 1;
                    break;
                }
                MergeDecision::Quit => {
                    eprintln!("classify-merge: aborted by user; nothing written.");
                    return Ok(());
                }
            }
        }
    }

    // Normalize accepted keywords to lowercase before appending (per §B.2).
    let accepted_lc: Vec<String> = accepted.iter().map(|k| k.trim().to_lowercase()).collect();

    if args.dry_run {
        eprintln!(
            "classify-merge (dry-run): would append {} new keywords to {}",
            accepted_lc.len(),
            target_path.display()
        );
        for k in &accepted_lc {
            eprintln!("    + {k}");
        }
        return Ok(());
    }

    append_accepted(target_path, &accepted_lc)?;
    persist_keyword_decisions(&accepted_lc, &rejected);

    eprintln!(
        "classify-merge: keywords — accepted {}, rejected {}, skipped {} → wrote {}",
        accepted_lc.len(),
        rejected.len(),
        skipped_rest,
        target_path.display()
    );
    Ok(())
}

/// Phase 6c — update file decisions in the state file. Errors are logged
/// to stderr but never fail the merge (the user already saw the accept/reject
/// and the ignorefile got updated).
fn persist_path_decisions(accepted: &[&ParsedSuggestion], rejected: &[&ParsedSuggestion]) {
    let Some(state_path) = crate::classify_state::state_path() else {
        return;
    };
    let mut state = crate::classify_state::load(&state_path).unwrap_or_else(|e| {
        eprintln!("classify-merge: warning: state load failed: {e}");
        crate::classify_state::State::empty()
    });
    let now = chrono::Utc::now();
    for s in accepted {
        if let Some(entry) = state.files.get_mut(&s.path) {
            entry.decision = crate::classify_state::Decision::Accepted;
            entry.decision_at = Some(now);
        }
    }
    for s in rejected {
        if let Some(entry) = state.files.get_mut(&s.path) {
            entry.decision = crate::classify_state::Decision::Rejected;
            entry.decision_at = Some(now);
        }
    }
    if let Err(e) = crate::classify_state::save(&state_path, &state) {
        eprintln!("classify-merge: warning: state save failed: {e}");
    }
}

/// Phase 6c — update keyword decisions in the state file. `accepted_lc`
/// are already lowercase per §B.2 — they're inserted as-is.
fn persist_keyword_decisions(accepted_lc: &[String], rejected: &[String]) {
    let Some(state_path) = crate::classify_state::state_path() else {
        return;
    };
    let mut state = crate::classify_state::load(&state_path).unwrap_or_else(|e| {
        eprintln!("classify-merge: warning: state load failed: {e}");
        crate::classify_state::State::empty()
    });
    let now = chrono::Utc::now();
    for kw in accepted_lc {
        let entry = state.keywords.entry(kw.clone()).or_insert_with(|| {
            crate::classify_state::KeywordEntry {
                decision: crate::classify_state::Decision::Pending,
                decision_at: None,
                first_seen_in: PathBuf::new(),
                occurrence_count: 0,
                entity_type: "UNKNOWN".to_string(),
                score_avg: 0.0,
            }
        });
        entry.decision = crate::classify_state::Decision::Accepted;
        entry.decision_at = Some(now);
    }
    for kw in rejected {
        let normalized = kw.trim().to_lowercase();
        let entry = state.keywords.entry(normalized).or_insert_with(|| {
            crate::classify_state::KeywordEntry {
                decision: crate::classify_state::Decision::Pending,
                decision_at: None,
                first_seen_in: PathBuf::new(),
                occurrence_count: 0,
                entity_type: "UNKNOWN".to_string(),
                score_avg: 0.0,
            }
        });
        entry.decision = crate::classify_state::Decision::Rejected;
        entry.decision_at = Some(now);
    }
    if let Err(e) = crate::classify_state::save(&state_path, &state) {
        eprintln!("classify-merge: warning: state save failed: {e}");
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::tempdir;

    #[test]
    fn parse_empty_returns_empty() {
        assert!(parse_suggestions("").is_empty());
        assert!(parse_suggestions("# just a comment\n").is_empty());
        assert!(parse_suggestions("\n\n\n").is_empty());
    }

    #[test]
    fn parse_single_entry_with_metadata() {
        let text = "\
# confidence=0.92  labels=TAX_DOC,FINANCIAL_RECORD
# evidence=\"Detected 'Einkommensteuer'...\"
/Users/x/Steuer/2024.pdf
";
        let p = parse_suggestions(text);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].path, "/Users/x/Steuer/2024.pdf");
        assert_eq!(p[0].meta_lines.len(), 2);
        assert!(p[0].meta_lines[0].contains("confidence=0.92"));
    }

    #[test]
    fn parse_blank_line_resets_pending_meta() {
        let text = "\
# stray header comment

# confidence=0.7
/a/b
";
        let p = parse_suggestions(text);
        assert_eq!(p.len(), 1);
        // only the comment after the blank line should stick
        assert_eq!(p[0].meta_lines.len(), 1);
        assert!(p[0].meta_lines[0].contains("confidence=0.7"));
    }

    #[test]
    fn parse_multiple_entries() {
        let text = "\
# header
# generated: 2026-05-12

# confidence=0.9
/a/b.pdf

# confidence=0.8
/c/d.kdbx
";
        let p = parse_suggestions(text);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].path, "/a/b.pdf");
        assert_eq!(p[1].path, "/c/d.kdbx");
        assert_eq!(p[0].meta_lines, vec!["confidence=0.9"]);
        assert_eq!(p[1].meta_lines, vec!["confidence=0.8"]);
    }

    #[test]
    fn append_skips_existing_entries() {
        let td = tempdir().unwrap();
        let target = td.path().join(".redactorignore");
        std::fs::write(&target, "Alice\n/a/b.pdf\n").unwrap();

        append_accepted(&target, &["/a/b.pdf".to_string(), "/new.pdf".to_string()]).unwrap();
        let after = std::fs::read_to_string(&target).unwrap();
        assert!(after.contains("Alice"));
        assert!(after.contains("/new.pdf"));
        // /a/b.pdf appears only ONCE (dedup)
        assert_eq!(after.matches("/a/b.pdf").count(), 1);
    }

    #[test]
    fn append_creates_file_when_missing() {
        let td = tempdir().unwrap();
        let target = td.path().join("sub/.redactorignore");
        append_accepted(&target, &["/x/y".to_string()]).unwrap();
        let after = std::fs::read_to_string(&target).unwrap();
        assert!(after.contains("/x/y"));
        assert!(after.contains("Added by"));
    }

    #[test]
    fn append_dedup_respects_negation_prefix() {
        let td = tempdir().unwrap();
        let target = td.path().join(".redactorignore");
        // Existing entry without negation prefix should match a suggested
        // entry without prefix — they're the same path.
        std::fs::write(&target, "/a/b\n").unwrap();
        append_accepted(&target, &["/a/b".to_string()]).unwrap();
        let after = std::fs::read_to_string(&target).unwrap();
        assert_eq!(after.matches("/a/b").count(), 1);
    }

    #[test]
    fn append_empty_is_noop() {
        let td = tempdir().unwrap();
        let target = td.path().join(".redactorignore");
        std::fs::write(&target, "Alice\n").unwrap();
        append_accepted(&target, &[]).unwrap();
        let after = std::fs::read_to_string(&target).unwrap();
        assert_eq!(after.trim(), "Alice");
    }

    #[test]
    fn prompt_yes_returns_accept() {
        let s = ParsedSuggestion {
            path: "/x".into(),
            meta_lines: vec![],
        };
        let mut input = Cursor::new(b"y\n".to_vec());
        let mut output = Vec::new();
        let d = prompt_decision(0, 1, &s, &mut input, &mut output).unwrap();
        assert_eq!(d, MergeDecision::Accept);
    }

    #[test]
    fn prompt_no_returns_reject() {
        let s = ParsedSuggestion {
            path: "/x".into(),
            meta_lines: vec![],
        };
        let mut input = Cursor::new(b"n\n".to_vec());
        let mut output = Vec::new();
        let d = prompt_decision(0, 1, &s, &mut input, &mut output).unwrap();
        assert_eq!(d, MergeDecision::Reject);
    }

    #[test]
    fn prompt_s_returns_skip_rest() {
        let s = ParsedSuggestion {
            path: "/x".into(),
            meta_lines: vec![],
        };
        let mut input = Cursor::new(b"s\n".to_vec());
        let mut output = Vec::new();
        let d = prompt_decision(0, 1, &s, &mut input, &mut output).unwrap();
        assert_eq!(d, MergeDecision::SkipRest);
    }

    #[test]
    fn prompt_q_returns_quit() {
        let s = ParsedSuggestion {
            path: "/x".into(),
            meta_lines: vec![],
        };
        let mut input = Cursor::new(b"q\n".to_vec());
        let mut output = Vec::new();
        let d = prompt_decision(0, 1, &s, &mut input, &mut output).unwrap();
        assert_eq!(d, MergeDecision::Quit);
    }

    #[test]
    fn prompt_unknown_key_defaults_to_reject() {
        let s = ParsedSuggestion {
            path: "/x".into(),
            meta_lines: vec![],
        };
        let mut input = Cursor::new(b"\n".to_vec()); // just Enter
        let mut output = Vec::new();
        let d = prompt_decision(0, 1, &s, &mut input, &mut output).unwrap();
        assert_eq!(d, MergeDecision::Reject);
    }

    #[test]
    fn append_preserves_existing_content_with_header() {
        let td = tempdir().unwrap();
        let target = td.path().join(".redactorignore");
        std::fs::write(&target, "# my header\nAlice\n").unwrap();
        append_accepted(&target, &["/new".to_string()]).unwrap();
        let after = std::fs::read_to_string(&target).unwrap();
        assert!(after.starts_with("# my header\nAlice"));
        assert!(after.contains("# Added by `redactor classify-merge`"));
        assert!(after.contains("/new"));
    }
}

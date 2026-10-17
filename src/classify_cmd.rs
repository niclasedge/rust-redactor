//! End-to-end orchestration for `redactor classify-files <dir>`.
//!
//! Glue between the three pure-data modules:
//!
//! 1. [`crate::classify_walk`] — walkdir + skip + binary-filter
//! 2. [`crate::classify`]      — JSON IPC with the Python sidecar
//! 3. [`crate::classify_suggest`] — writers for the `.suggested` file
//!
//! Plus exit-code mapping per spec §4.5:
//!
//! | Failure                       | Exit |
//! |-------------------------------|------|
//! | sidecar NotInstalled          | 2    |
//! | sidecar Crashed / BadResponse | 3    |
//! | sidecar Timeout               | 0 + warning |
//! | input dir not readable        | 4    |
//!
//! Phase-4 scope: `--apply` is a stub — wiring to `~/.redactorignore` is a
//! Phase-5 deliverable (`classify-merge`).

use crate::classify::{self, ClassifierError, ClassifierResult, EntityHit, FileEntry};
use crate::classify_state::{self, Decision, FileEntry as StateFileEntry, State, StoredEntity};
use crate::classify_suggest::{
    self, KeywordReport, KeywordSuggestion, Suggestion, SuggestionReport,
};
use crate::classify_walk::{self, FileCandidate, WalkOptions};
use crate::config;
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, ValueEnum};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Default suggestion-file path when `--output` is not provided.
const DEFAULT_OUTPUT_REL: &str = ".redactorignore.suggested";

/// Embedded fallback for `labels.txt` — same content the installer writes.
/// Used when the user has not run `classifier-install` yet and did not pass
/// `--labels-file`.
const EMBEDDED_DEFAULT_LABELS: &str = include_str!("../classifier-py/defaults/labels.txt");

/// Output format. Mirrors the value enum on the CLI.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ClassifyOutputFormat {
    Text,
    Json,
    Yaml,
}

/// Classification backend selector (Phase 6b+).
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ClassifyBackend {
    /// Local Ollama LLM (default; `qwen3:8b` unless overridden via
    /// `REDACTOR_OLLAMA_MODEL`). Best recall on free-form
    /// PERSON/ORG/LOCATION spans (German + English), slower
    /// (~3-15s/file on CPU). Requires `ollama serve` on localhost:11434.
    Ollama,
    /// GLiNER + spaCy Python sidecar. PII-specialised, fast on recognised
    /// PII shapes (tax numbers, IBANs, emails), conservative on generic
    /// names/orgs. Requires `redactor classifier-install` first.
    Gliner,
}

/// CLI surface for `redactor classify-files <dir>` (spec §4.1).
#[derive(Args, Debug)]
pub struct ClassifyFilesArgs {
    /// Directory to scan recursively.
    pub directory: PathBuf,

    /// Cap walk depth. Default = unlimited.
    #[arg(long)]
    pub max_depth: Option<usize>,

    /// Per-file size cap. Accepts plain bytes or suffixed values like
    /// `5MB`, `1024K`, `2GB`. Default = 5 MB.
    #[arg(long, default_value = "5MB")]
    pub max_file_size: String,

    /// Only suggestions with `confidence >= threshold` land in the output
    /// file. 0.0 means "include everything the sidecar returned".
    #[arg(long, default_value_t = 0.6)]
    pub threshold: f64,

    /// Output file path. Default `~/.redactorignore.suggested`.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = ClassifyOutputFormat::Text)]
    pub format: ClassifyOutputFormat,

    /// Append suggestions directly to `~/.redactorignore` instead of writing
    /// the `.suggested` file. Phase-4 stub — wiring lands in Phase 5
    /// (`classify-merge`).
    #[arg(long)]
    pub apply: bool,

    /// Override the labels file. Default search order:
    /// `<config>/classifier/labels.txt`, then the in-binary default set.
    #[arg(long)]
    pub labels_file: Option<PathBuf>,

    /// Suppress per-phase progress lines on stderr (one-line summary still
    /// emitted at the end).
    #[arg(long)]
    pub quiet: bool,

    /// Phase 6a — Bypass the state-file cache and re-classify every file.
    #[arg(long)]
    pub force: bool,

    /// Phase 6c — Re-process files previously rejected by `classify-merge`.
    /// Without this flag they're silently skipped.
    #[arg(long)]
    pub reconsider_rejected: bool,

    /// Phase 6c — Re-process files previously accepted into `~/.redactorignore`.
    /// Only useful when you've removed an accepted entry and want it suggested again.
    #[arg(long)]
    pub reconsider_accepted: bool,

    /// Phase 6b — Emit only the path-suggestion stream. Suppresses
    /// `.redactorignore.keywords.suggested`.
    #[arg(long, conflicts_with = "keywords_only")]
    pub paths_only: bool,

    /// Phase 6b — Emit only the keyword-suggestion stream. Suppresses
    /// `.redactorignore.suggested`.
    #[arg(long, conflicts_with = "paths_only")]
    pub keywords_only: bool,

    /// Phase 6b — Output path for keyword suggestions. Default:
    /// `~/.redactorignore.keywords.suggested`.
    #[arg(long)]
    pub keywords_output: Option<PathBuf>,

    /// Phase 6b — Min GLiNER score for keyword candidates (range 0.0–1.0).
    /// Default 0.5. The downstream quality heuristics (key-shape check,
    /// dotted-hostname check, capitalised-PERSON check) catch most FPs
    /// even at this lower threshold, so we err on the side of recall.
    /// Raise to 0.7+ if you want only the strongest hits.
    #[arg(long, default_value_t = 0.5)]
    pub keyword_min_score: f64,

    /// Phase 6b — Print every GLiNER entity hit per file to stderr.
    /// Useful for diagnosing why no keyword candidates land in the
    /// `.suggested` output.
    #[arg(long)]
    pub show_entities: bool,

    /// Phase 6b+ — Backend for the actual classification step. `ollama`
    /// (default) calls a local Ollama instance with `qwen3:8b`; override
    /// the model via `REDACTOR_OLLAMA_MODEL`. Set to `gliner` to use the
    /// Python sidecar instead (requires `classifier-install`).
    #[arg(long, value_enum, default_value_t = ClassifyBackend::Ollama)]
    pub backend: ClassifyBackend,
}

/// Run `redactor classify-files`. Returns the desired process exit code.
///
/// Errors that map to a specific exit code per spec §4.5 are surfaced as
/// `Ok(<exit>)`; truly unexpected failures (e.g. cannot write to stdout)
/// bubble up as `Err` and the caller prints + exits 1.
pub fn run_classify_files(args: ClassifyFilesArgs) -> Result<i32> {
    // --apply is Phase 5. Surface that cleanly before doing any work.
    if args.apply {
        eprintln!(
            "redactor: --apply is a Phase-5 stub. Use `classify-merge` (coming in v0.7.x) \
             to interactively merge the .suggested file into ~/.redactorignore."
        );
        return Ok(2);
    }

    // 1. Validate the input directory.
    let root = match args.directory.canonicalize() {
        Ok(p) if p.is_dir() => p,
        Ok(p) => {
            eprintln!("redactor: {} is not a directory", p.display());
            return Ok(4);
        }
        Err(e) => {
            eprintln!("redactor: cannot read {}: {e}", args.directory.display());
            return Ok(4);
        }
    };

    // 2. Parse the size cap and assemble walker options.
    let max_file_size_bytes = parse_size(&args.max_file_size)
        .with_context(|| format!("--max-file-size: invalid value '{}'", args.max_file_size))?;
    let walk_opts = WalkOptions {
        max_depth: args.max_depth,
        max_file_size_bytes,
        follow_symlinks: false,
    };

    // 3. Load labels.
    let labels = load_labels(args.labels_file.as_deref())?;
    if labels.is_empty() {
        bail!("classify-files: no labels loaded (label file is empty)");
    }

    // 4. Walk the tree.
    if !args.quiet {
        eprintln!("redactor: walking {}", root.display());
    }
    let candidates = classify_walk::walk_for_classification(&root, &walk_opts);
    let files_scanned = candidates.len();
    if !args.quiet {
        eprintln!("redactor: {files_scanned} candidate files discovered");
    }

    // 4b. Phase 6a — load the state file and split candidates into
    //     "skip" (decision is final + content unchanged) vs "classify".
    let state_path = classify_state::state_path();
    let mut state = if let Some(ref sp) = state_path {
        classify_state::load(sp).unwrap_or_else(|e| {
            eprintln!("redactor: warning: state file load failed ({e}) — starting fresh");
            State::empty()
        })
    } else {
        State::empty()
    };

    let mut candidates_to_classify: Vec<&FileCandidate> = Vec::with_capacity(candidates.len());
    let mut skipped_cached = 0usize;
    for c in &candidates {
        let key = c.path.display().to_string();
        let skip = if args.force {
            false
        } else if let Some(entry) = state.files.get(&key) {
            classify_state::should_skip(
                &c.path,
                entry,
                args.reconsider_rejected,
                args.reconsider_accepted,
            )
        } else {
            false
        };
        if skip {
            skipped_cached += 1;
        } else {
            candidates_to_classify.push(c);
        }
    }
    if !args.quiet && skipped_cached > 0 {
        eprintln!(
            "redactor: {skipped_cached} files skipped via state-cache (final decision + unchanged content)"
        );
    }
    if !args.quiet {
        eprintln!(
            "redactor: {} files queued for classification",
            candidates_to_classify.len()
        );
    }

    // 5. Talk to the sidecar (or the Ollama LLM backend).
    let entries: Vec<FileEntry> = candidates_to_classify
        .iter()
        .map(|c| candidate_to_entry(c))
        .collect();
    // Track every entity-hit per file (used by the Phase 6b keyword aggregator).
    let mut per_file_entities: Vec<(PathBuf, Vec<EntityHit>)> = Vec::new();

    // Crash-safety: tell the Ollama backend to stream every per-file
    // entity-hit to `<keywords-output>.live.jsonl`. If SIGTERM hits
    // mid-run, the final pretty `.keywords.suggested` won't be written,
    // but every hit so far is on disk and can be aggregated post-mortem.
    // We compute the path here (without writing) so the env var matches
    // the same resolution rules used by the final write below.
    let live_jsonl_path: Option<PathBuf> =
        if !args.paths_only && matches!(args.backend, ClassifyBackend::Ollama) {
            match resolve_keywords_output_path(args.keywords_output.as_deref()) {
                Ok(kw) => {
                    let mut live = kw.clone();
                    let fname = live
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "keywords".to_string());
                    live.set_file_name(format!("{fname}.live.jsonl"));
                    // Truncate any stale live-file from a previous run so we
                    // don't mix old hits into a new sweep.
                    let _ = std::fs::remove_file(&live);
                    // SAFETY: set_var is not multi-thread-safe in Rust 2024;
                    // we're still single-threaded at this point of the run.
                    unsafe {
                        std::env::set_var("REDACTOR_LIVE_KEYWORDS_FILE", &live);
                    }
                    Some(live)
                }
                Err(_) => None,
            }
        } else {
            None
        };

    // The set of paths visited by *this* walk. We aggregate the output
    // streams from `state.files` (the source of truth), but we MUST scope
    // that aggregation to the current walk — otherwise a previous run over
    // a different directory would leak its hits into this run's
    // `.suggested` file.
    let walked_paths: std::collections::HashSet<String> = candidates
        .iter()
        .map(|c| c.path.display().to_string())
        .collect();

    let scan_time = Utc::now();
    let timed_out = match args.backend {
        ClassifyBackend::Gliner => {
            // Batch path: GLiNER processes all entries in one sidecar call,
            // so we can't flush per-file. We still write the state once at
            // the end (atomic) and rely on `--force` to re-run on next
            // invocation if the user wants a fresh pass.
            let classifier_result = classify::run_classifier(entries, labels.clone());
            match classifier_result {
                Ok(resp) => {
                    update_state_batch(
                        &mut state,
                        &candidates_to_classify,
                        &resp.results,
                        scan_time,
                    );
                    for w in resp.warnings {
                        eprintln!("redactor: classifier warning: {w}");
                    }
                    false
                }
                Err(e) => match e {
                    ClassifierError::NotInstalled(p) => {
                        eprintln!(
                            "redactor: classifier sidecar not installed at {}.\n\
                             Run `redactor classifier-install` first (one-time setup, ~550 MB).",
                            p.display()
                        );
                        return Ok(2);
                    }
                    ClassifierError::Crashed { exit, stderr } => {
                        eprintln!("redactor: classifier sidecar crashed (exit {exit}): {stderr}");
                        return Ok(3);
                    }
                    ClassifierError::BadResponse { parse_error } => {
                        eprintln!(
                            "redactor: classifier sidecar produced bad output: {parse_error}"
                        );
                        return Ok(3);
                    }
                    ClassifierError::Timeout(d) => {
                        eprintln!(
                            "redactor: classifier sidecar timed out after {d:?} — writing \
                             partial results (which may be empty)."
                        );
                        true
                    }
                },
            }
        }
        ClassifyBackend::Ollama => {
            // Streaming path: persist state after every file. If the
            // process is killed mid-run, state.json reflects every
            // already-classified file and the next invocation (without
            // --force) picks up exactly where we left off.
            //
            // Persistence cost: ~MB-sized JSON rewrite per file. On a
            // 10k-file tree that's still cheap relative to the 1-15s LLM
            // call per file. If profile shows this is a problem we can
            // batch flushes (e.g. every N files).
            let state_path_for_cb = state_path.clone();
            let state_ref = &mut state;
            let result =
                crate::classify_llm::run_classifier_streaming(entries, labels.clone(), |r| {
                    persist_one_file(state_ref, &state_path_for_cb, r, scan_time);
                });
            match result {
                Ok(resp) => {
                    for w in resp.warnings {
                        eprintln!("redactor: classifier warning: {w}");
                    }
                    false
                }
                Err(ClassifierError::NotInstalled(p)) => {
                    eprintln!(
                        "redactor: Ollama not reachable at {}.\n\
                         Start `ollama serve` and ensure the model is pulled \
                         (REDACTOR_OLLAMA_MODEL={}).",
                        p.display(),
                        std::env::var("REDACTOR_OLLAMA_MODEL")
                            .unwrap_or_else(|_| "gemma4:latest".into())
                    );
                    return Ok(2);
                }
                Err(ClassifierError::Crashed { exit, stderr }) => {
                    eprintln!("redactor: ollama backend crashed (exit {exit}): {stderr}");
                    return Ok(3);
                }
                Err(ClassifierError::BadResponse { parse_error }) => {
                    eprintln!("redactor: ollama backend produced bad output: {parse_error}");
                    return Ok(3);
                }
                Err(ClassifierError::Timeout(d)) => {
                    eprintln!("redactor: ollama timed out after {d:?} — writing partial results.");
                    true
                }
            }
        }
    };

    // 5b. Final state bookkeeping. Records the wall-clock of the scan even
    // when classification is a no-op (e.g. everything cached).
    state.last_full_scan = Some(scan_time);
    if let Some(ref sp) = state_path {
        if let Err(e) = classify_state::save(sp, &state) {
            eprintln!("redactor: warning: failed to persist state file: {e}");
        }
    }

    // 6. Build path suggestions from `state.files`, scoped to the current
    // walk. This is the dedup step: BTreeMap keys are absolute paths, so
    // there can only ever be one entry per file — including files that
    // were skipped via the hash cache (their entry persists from a prior
    // run). Accepted/Rejected decisions are honoured unless --reconsider-*.
    let mut suggestions: Vec<Suggestion> = state
        .files
        .iter()
        .filter(|(k, _)| walked_paths.contains(k.as_str()))
        .filter_map(|(k, e)| {
            if e.confidence < args.threshold {
                return None;
            }
            if e.labels.is_empty() {
                return None;
            }
            match e.decision {
                Decision::Accepted if !args.reconsider_accepted => return None,
                Decision::Rejected if !args.reconsider_rejected => return None,
                _ => {}
            }
            Some(Suggestion {
                path: PathBuf::from(k),
                confidence: e.confidence,
                labels: e.labels.clone(),
                evidence: build_evidence_from_stored(&e.entities),
            })
        })
        .collect();
    suggestions.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let files_above_threshold = suggestions.len();

    // 6a. Build the per-file-entities stream the keyword aggregator needs,
    // also scoped to the current walk. Same dedup-via-BTreeMap guarantee.
    for (k, e) in state.files.iter() {
        if !walked_paths.contains(k.as_str()) {
            continue;
        }
        if e.entities.is_empty() {
            continue;
        }
        let hits: Vec<EntityHit> = e
            .entities
            .iter()
            .map(|se| EntityHit {
                text: se.text.clone(),
                label: se.label.clone(),
                score: se.score,
                entity_type: se.entity_type.clone(),
            })
            .collect();
        per_file_entities.push((PathBuf::from(k), hits));
    }

    if args.show_entities {
        eprintln!("redactor: --show-entities — per-file GLiNER hits:");
        for (path, ents) in &per_file_entities {
            if ents.is_empty() {
                continue;
            }
            eprintln!("  {}", path.display());
            for e in ents {
                eprintln!(
                    "    [{}] {:?} (label={}, score={:.2})",
                    e.entity_type, e.text, e.label, e.score
                );
            }
        }
    }
    let keyword_candidates = if args.paths_only {
        Vec::new()
    } else {
        aggregate_keywords(
            &per_file_entities,
            &mut state,
            args.reconsider_rejected,
            args.keyword_min_score,
        )
    };

    // Write path stream (unless --keywords-only).
    if !args.keywords_only {
        let report = SuggestionReport {
            generated_at: Utc::now().to_rfc3339(),
            input_root: root.clone(),
            files_scanned,
            files_above_threshold,
            threshold: args.threshold,
        };
        let output_path = resolve_output_path(args.output.as_deref())?;
        write_suggestions(&output_path, args.format, &report, &suggestions)
            .with_context(|| format!("write {}", output_path.display()))?;
        eprintln!(
            "redactor: wrote {} ({} / {} files above threshold {:.2})",
            output_path.display(),
            files_above_threshold,
            files_scanned,
            args.threshold
        );
    }

    // Write keyword stream (unless --paths-only).
    if !args.paths_only && !keyword_candidates.is_empty() {
        let kw_report = KeywordReport {
            generated_at: Utc::now().to_rfc3339(),
            input_root: root.clone(),
            files_scanned,
            keywords_proposed: keyword_candidates.len(),
        };
        let kw_path = resolve_keywords_output_path(args.keywords_output.as_deref())?;
        write_keyword_suggestions(&kw_path, args.format, &kw_report, &keyword_candidates)
            .with_context(|| format!("write {}", kw_path.display()))?;
        eprintln!(
            "redactor: wrote {} ({} keyword candidates)",
            kw_path.display(),
            keyword_candidates.len()
        );

        // Persist pending keyword entries to the state file so
        // classify-merge can attach decisions and re-runs can dedup.
        if let Some(ref sp) = state_path {
            for kw in &keyword_candidates {
                let entry = classify_state::KeywordEntry {
                    decision: Decision::Pending,
                    decision_at: None,
                    first_seen_in: kw.first_seen_in.clone(),
                    occurrence_count: kw.occurrence_count,
                    entity_type: kw.entity_type.clone(),
                    score_avg: kw.score_avg,
                };
                state.keywords.entry(kw.text.clone()).or_insert(entry);
            }
            let _ = classify_state::save(sp, &state);
        }
    } else if !args.paths_only && !args.quiet {
        eprintln!("redactor: no keyword candidates above filter thresholds");
    }

    // Crash-safety hint: if the run completed normally, the live JSONL
    // is now redundant — keep it as audit trail unless the user opts in
    // to delete. We only mention it when present.
    if let Some(ref lp) = live_jsonl_path {
        if lp.exists() && !args.quiet {
            eprintln!(
                "redactor: per-file hits also streamed to {} (delete if not needed)",
                lp.display()
            );
        }
    }

    // 8. Exit code. Timeout = 0 with a warning already printed; success otherwise.
    let _ = timed_out;
    Ok(0)
}

/// Phase 7 — Persist a single classifier result into the state file.
/// Called from the Ollama streaming loop after every file so a SIGTERM
/// mid-run leaves a recoverable state.json on disk. On the next invocation
/// without `--force`, `should_skip` honours the entry (hash-matched) and
/// the file is skipped — only missing/changed files are re-classified.
fn persist_one_file(
    state: &mut State,
    state_path: &Option<PathBuf>,
    r: &ClassifierResult,
    scan_time: DateTime<Utc>,
) {
    let key = r.path.clone();
    let path_obj = Path::new(&r.path);
    let meta = match std::fs::metadata(path_obj) {
        Ok(m) => m,
        Err(_) => return, // file vanished between walk and classify — skip
    };
    let hash = classify_state::sha256_file(path_obj).unwrap_or_default();
    let entities = r
        .entities
        .iter()
        .map(|e| StoredEntity {
            text: e.text.clone(),
            label: e.label.clone(),
            score: e.score,
            entity_type: e.entity_type.clone(),
        })
        .collect();
    let entry = StateFileEntry {
        sha256: hash,
        size_bytes: meta.len(),
        mtime_ns: classify_state::file_mtime_ns(&meta),
        classified_at: scan_time,
        decision: Decision::Pending,
        decision_at: None,
        labels: r.labels.clone(),
        confidence: r.confidence,
        entities,
    };
    state.files.insert(key, entry);
    if let Some(sp) = state_path {
        if let Err(e) = classify_state::save(sp, state) {
            eprintln!("redactor: warning: state persist failed: {e}");
        }
    }
}

/// Phase 7 — Batched state update for backends that can't flush per-file
/// (GLiNER returns all results from one sidecar call). One save at the
/// end; `--force` is the recovery path if the user wants a fresh run.
fn update_state_batch(
    state: &mut State,
    candidates: &[&FileCandidate],
    results: &[ClassifierResult],
    scan_time: DateTime<Utc>,
) {
    let by_path: std::collections::HashMap<&str, &ClassifierResult> =
        results.iter().map(|r| (r.path.as_str(), r)).collect();
    for cand in candidates {
        let key = cand.path.display().to_string();
        let meta = match std::fs::metadata(&cand.path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let hash = classify_state::sha256_file(&cand.path).unwrap_or_default();
        let r = by_path.get(key.as_str()).copied();
        let entities = r
            .map(|r| {
                r.entities
                    .iter()
                    .map(|e| StoredEntity {
                        text: e.text.clone(),
                        label: e.label.clone(),
                        score: e.score,
                        entity_type: e.entity_type.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let entry = StateFileEntry {
            sha256: hash,
            size_bytes: meta.len(),
            mtime_ns: classify_state::file_mtime_ns(&meta),
            classified_at: scan_time,
            decision: Decision::Pending,
            decision_at: None,
            labels: r.map(|r| r.labels.clone()).unwrap_or_default(),
            confidence: r.map(|r| r.confidence).unwrap_or(0.0),
            entities,
        };
        state.files.insert(key, entry);
    }
}

/// Phase 7 — Build a short evidence blurb from cached entity hits. Mirror
/// of `classify_llm::build_evidence` but operating on the persisted form.
fn build_evidence_from_stored(entities: &[StoredEntity]) -> String {
    if entities.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<&StoredEntity> = entities.iter().collect();
    sorted.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let parts: Vec<String> = sorted
        .iter()
        .take(3)
        .map(|e| format!("'{}' ({}, score={:.2})", e.text, e.label, e.score))
        .collect();
    let mut out = format!("Detected {}", parts.join(", "));
    if out.chars().count() > 280 {
        out = out.chars().take(279).collect::<String>() + "…";
    }
    out
}

fn aggregate_keywords(
    per_file: &[(PathBuf, Vec<EntityHit>)],
    state: &mut State,
    reconsider_rejected: bool,
    min_score: f64,
) -> Vec<KeywordSuggestion> {
    const MIN_TEXT_LEN: usize = 3;
    // Only these entity-types feed the keyword stream.
    fn is_keyword_type(t: &str) -> bool {
        matches!(
            t,
            "PERSON"
                | "ORGANIZATION"
                | "LOCATION"
                | "URL"
                | "EMAIL"
                | "HOSTNAME"
                | "PASSWORD"
                | "SECRET"
                | "API_KEY"
        )
    }

    // Load existing keywords from ~/.redactorignore for dedup.
    let existing: std::collections::HashSet<String> = crate::ignorefile::autoload()
        .map(|f| f.keywords.iter().map(|k| k.trim().to_lowercase()).collect())
        .unwrap_or_default();

    // Phase 6b — keyword allowlist from `.redactor.toml [allow] keywords`.
    // Each entry is a case-insensitive substring; any candidate whose
    // (lowercased) text contains one of these substrings is dropped from
    // suggestions. `discover_project_config` walks from cwd up to root, so
    // putting a `.redactor.toml` at `~/` makes the allowlist effectively
    // global.
    let allow_substrings: Vec<String> = {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        crate::config::autoload_project_allow(&cwd)
            .map(|a| {
                a.keywords
                    .iter()
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };

    // Aggregate: key = normalized text.
    use std::collections::HashMap;
    struct Agg {
        display: String,
        entity_type: String,
        files: std::collections::HashSet<PathBuf>,
        first_seen: PathBuf,
        scores: Vec<f64>,
    }
    let mut agg: HashMap<String, Agg> = HashMap::new();
    for (path, entities) in per_file {
        for ent in entities {
            if !is_keyword_type(&ent.entity_type) {
                continue;
            }
            if ent.score < min_score {
                continue;
            }
            let text = ent.text.trim();
            if text.chars().count() < MIN_TEXT_LEN {
                continue;
            }
            if text.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            // Public-internet noise filter: URL/HOSTNAME entities pointing at
            // a well-known public domain are not useful as global keywords —
            // redacting `github.com` would shred every Markdown link's
            // context. Only suggest internal/private hostnames (or names that
            // don't look like a domain at all).
            if matches!(ent.entity_type.as_str(), "URL" | "HOSTNAME") && is_public_url_or_host(text)
            {
                continue;
            }
            // Phase 6b — entity-type-specific quality heuristics to drop
            // typical GLiNER false positives (e.g. "session-start" labelled
            // as API_KEY, bare word "github" labelled HOSTNAME, lowercase
            // "claude" labelled PERSON).
            if crate::classify_filter::should_drop_entity(text, &ent.entity_type) {
                continue;
            }
            let normalized = text.to_lowercase();
            if existing.contains(&normalized) {
                continue;
            }
            // Keyword allowlist (Phase 6b) — substring match, case-insensitive.
            if allow_substrings.iter().any(|s| normalized.contains(s)) {
                continue;
            }
            // Respect prior rejection.
            if !reconsider_rejected {
                if let Some(prior) = state.keywords.get(&normalized) {
                    if matches!(prior.decision, Decision::Rejected | Decision::Accepted) {
                        continue;
                    }
                }
            }
            let e = agg.entry(normalized).or_insert_with(|| Agg {
                display: text.to_string(),
                entity_type: ent.entity_type.clone(),
                files: std::collections::HashSet::new(),
                first_seen: path.clone(),
                scores: Vec::new(),
            });
            e.files.insert(path.clone());
            e.scores.push(ent.score);
        }
    }

    let mut out: Vec<KeywordSuggestion> = agg
        .into_iter()
        .map(|(text, a)| {
            let avg = if a.scores.is_empty() {
                0.0
            } else {
                a.scores.iter().sum::<f64>() / a.scores.len() as f64
            };
            KeywordSuggestion {
                text,
                display: a.display,
                entity_type: a.entity_type,
                occurrence_count: a.files.len() as u32,
                score_avg: avg,
                first_seen_in: a.first_seen,
            }
        })
        .collect();
    // Phase 6b — group by entity-type for the output file. Primary sort key
    // is the type-order (PERSON first, fuzzy/low-trust types like API_KEY last)
    // so the user reviews the strongest signals first. Within each group:
    // higher occurrence_count → higher score → alphabetical.
    out.sort_by(|a, b| {
        entity_type_order(&a.entity_type)
            .cmp(&entity_type_order(&b.entity_type))
            .then_with(|| b.occurrence_count.cmp(&a.occurrence_count))
            .then_with(|| {
                b.score_avg
                    .partial_cmp(&a.score_avg)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.text.cmp(&b.text))
    });
    out
}

/// Stable ordering of entity-type buckets for the keyword stream. Lower
/// number = listed first. Strongest/most useful signals on top.
fn entity_type_order(t: &str) -> u32 {
    match t {
        "PERSON" => 0,
        "ORGANIZATION" => 1,
        "LOCATION" => 2,
        "EMAIL" => 3,
        "URL" => 4,
        "HOSTNAME" => 5,
        "API_KEY" => 6,
        "SECRET" => 7,
        "PASSWORD" => 8,
        _ => 99,
    }
}

/// Phase 6b — Distinguishes a "public internet" URL/hostname from something
/// that looks internal. Internal hosts are useful as global keywords; public
/// ones (github.com, googleapis.com, …) are noise and would shred markdown
/// link context if redacted.
///
/// Public iff (any of):
/// - Host ends in a well-known public TLD (`.com` / `.org` / `.io` / `.net`
///   / `.dev` / `.app` / `.ai` / `.co` / `.gov` / `.edu` / `.de` / `.uk` /
///   `.eu`) — most of the public web.
/// - Bare domain matches a curated allowlist of mega-providers (github.com,
///   stackoverflow.com, …) — also covers their subdomains (`raw.github.com`,
///   `gist.github.com`, …).
///
/// Internal iff:
/// - Ends in `.corp` / `.intern` / `.internal` / `.lan` / `.local` /
///   `.home.arpa` — caught here AND by the pattern-mode `internal_hostname`
///   rule (Phase 7h), so they get redacted at the regex layer too.
/// - Or doesn't look like a domain at all (single word, no dots).
pub(crate) fn is_public_url_or_host(raw: &str) -> bool {
    // Strip scheme + path so we work on the host alone.
    let after_scheme = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
    let host = after_scheme
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }

    // Internal-TLD short-circuit — never treat as public.
    const INTERNAL_TLDS: &[&str] = &[
        ".corp",
        ".intern",
        ".internal",
        ".lan",
        ".local",
        ".home.arpa",
    ];
    for tld in INTERNAL_TLDS {
        if host.ends_with(tld) {
            return false;
        }
    }

    // Public mega-provider allowlist. Suffix match so `gist.github.com`,
    // `raw.githubusercontent.com`, etc. all count.
    const PUBLIC_PROVIDERS: &[&str] = &[
        "github.com",
        "githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        "stackoverflow.com",
        "stackexchange.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "youtube.com",
        "youtu.be",
        "apple.com",
        "icloud.com",
        "microsoft.com",
        "msftconnecttest.com",
        "live.com",
        "office.com",
        "anthropic.com",
        "claude.ai",
        "openai.com",
        "huggingface.co",
        "pypi.org",
        "crates.io",
        "npmjs.com",
        "wikipedia.org",
        "wikimedia.org",
        "mozilla.org",
        "amazon.com",
        "amazonaws.com",
        "cloudflare.com",
        "fastly.net",
        "jsdelivr.net",
        "unpkg.com",
        "fontawesome.com",
        "medium.com",
        "substack.com",
        "reddit.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "facebook.com",
        "instagram.com",
        "discord.com",
        "discord.gg",
        "slack.com",
        "notion.so",
        "obsidian.md",
        "atlassian.com",
        "jira.com",
    ];
    for p in PUBLIC_PROVIDERS {
        // Exact or subdomain match.
        if host == *p || host.ends_with(&format!(".{p}")) {
            return true;
        }
    }

    // Public-TLD heuristic — must have a dot AND end in a known public TLD.
    const PUBLIC_TLDS: &[&str] = &[
        ".com", ".org", ".net", ".io", ".dev", ".app", ".ai", ".co", ".gov", ".edu", ".int", ".de",
        ".uk", ".eu", ".fr", ".it", ".es", ".nl", ".se", ".no", ".dk", ".fi", ".pl", ".cz", ".at",
        ".ch", ".be", ".pt", ".ie", ".info", ".biz", ".me", ".tv", ".cc", ".to", ".xyz", ".tech",
        ".cloud", ".online", ".site", ".store", ".blog", ".news", ".email",
    ];
    if host.contains('.') {
        for tld in PUBLIC_TLDS {
            if host.ends_with(tld) {
                return true;
            }
        }
    }

    // No dot at all → looks like a hostname token, not a public domain.
    false
}

fn resolve_keywords_output_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(home) = dirs::home_dir() {
        return Ok(home.join(".redactorignore.keywords.suggested"));
    }
    if let Some(cfg) = config::config_dir() {
        return Ok(cfg.join(".redactorignore.keywords.suggested"));
    }
    bail!("could not determine keywords output path (no $HOME, no config dir)");
}

fn write_keyword_suggestions(
    path: &Path,
    format: ClassifyOutputFormat,
    report: &KeywordReport,
    keywords: &[KeywordSuggestion],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent {}", parent.display()))?;
        }
    }
    let f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut w = BufWriter::new(f);
    match format {
        ClassifyOutputFormat::Text | ClassifyOutputFormat::Yaml => {
            classify_suggest::write_keywords_text(report, keywords, &mut w)?
        }
        ClassifyOutputFormat::Json => {
            classify_suggest::write_keywords_json(report, keywords, &mut w)?
        }
    }
    w.flush()?;
    Ok(())
}

fn candidate_to_entry(c: &FileCandidate) -> FileEntry {
    FileEntry {
        path: c.path.display().to_string(),
        filename: c.filename.clone(),
        size_bytes: c.size_bytes,
        content_preview: c.content_preview.clone(),
    }
}

/// Parse a size string like `5MB`, `1024K`, `2GB`, `1024` (bytes).
///
/// Suffixes are interpreted in binary units (K = 1024). Case insensitive.
/// A bare number is treated as bytes. Decimals are not supported on
/// purpose — keep parsing trivial and unambiguous.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty size string");
    }
    let lower = s.to_ascii_lowercase();
    // Strip optional 'b' tail ("5mb", "10kb"); keep the bare-byte case ("1024").
    let (num_part, mult): (&str, u64) = if let Some(stripped) = lower.strip_suffix("gb") {
        (stripped, 1024 * 1024 * 1024)
    } else if let Some(stripped) = lower.strip_suffix("mb") {
        (stripped, 1024 * 1024)
    } else if let Some(stripped) = lower.strip_suffix("kb") {
        (stripped, 1024)
    } else if let Some(stripped) = lower.strip_suffix('g') {
        (stripped, 1024 * 1024 * 1024)
    } else if let Some(stripped) = lower.strip_suffix('m') {
        (stripped, 1024 * 1024)
    } else if let Some(stripped) = lower.strip_suffix('k') {
        (stripped, 1024)
    } else if let Some(stripped) = lower.strip_suffix('b') {
        (stripped, 1)
    } else {
        (lower.as_str(), 1)
    };
    let n: u64 = num_part
        .trim()
        .parse()
        .map_err(|e| anyhow!("could not parse '{num_part}' as integer: {e}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| anyhow!("size '{s}' overflows u64"))
}

/// Load labels from (in order): `--labels-file`, `<config>/classifier/labels.txt`,
/// or the embedded default set. Comments (`#`) and blank lines are skipped.
fn load_labels(explicit: Option<&Path>) -> Result<Vec<String>> {
    if let Some(p) = explicit {
        let body = std::fs::read_to_string(p)
            .with_context(|| format!("read labels file {}", p.display()))?;
        return Ok(parse_labels(&body));
    }
    if let Some(dir) = classify::classifier_dir() {
        let path = dir.join("labels.txt");
        if path.exists() {
            if let Ok(body) = std::fs::read_to_string(&path) {
                let parsed = parse_labels(&body);
                if !parsed.is_empty() {
                    return Ok(parsed);
                }
            }
        }
    }
    Ok(parse_labels(EMBEDDED_DEFAULT_LABELS))
}

fn parse_labels(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|s| s.to_string())
        .collect()
}

fn resolve_output_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    // Default: `~/.redactorignore.suggested`. Falls back to the resolved
    // config dir's parent if a HOME isn't available (rare on dev/test).
    if let Some(home) = dirs::home_dir() {
        return Ok(home.join(DEFAULT_OUTPUT_REL));
    }
    if let Some(cfg) = config::config_dir() {
        return Ok(cfg.join(DEFAULT_OUTPUT_REL));
    }
    bail!("could not determine output path (no $HOME, no config dir)");
}

fn write_suggestions(
    path: &Path,
    format: ClassifyOutputFormat,
    report: &SuggestionReport,
    suggestions: &[Suggestion],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent {}", parent.display()))?;
        }
    }
    let f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut w = BufWriter::new(f);
    match format {
        ClassifyOutputFormat::Text => classify_suggest::write_text(report, suggestions, &mut w)?,
        ClassifyOutputFormat::Json => classify_suggest::write_json(report, suggestions, &mut w)?,
        ClassifyOutputFormat::Yaml => classify_suggest::write_yaml(report, suggestions, &mut w)?,
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify_filter::is_low_quality_keyword_hit;

    // ========================================================================
    // Phase 6b — public-URL / internal-host filter
    // ========================================================================

    #[test]
    fn public_url_filter_drops_github_and_googleapis() {
        assert!(is_public_url_or_host("https://github.com"));
        assert!(is_public_url_or_host("https://github.com/foo/bar"));
        assert!(is_public_url_or_host("https://fonts.googleapis.com"));
        assert!(is_public_url_or_host("https://fonts.gstatic.com"));
        assert!(is_public_url_or_host("github.com"));
        assert!(is_public_url_or_host("raw.githubusercontent.com"));
    }

    #[test]
    fn public_url_filter_keeps_internal_corp_intern_lan() {
        assert!(!is_public_url_or_host("https://dc01.corp"));
        assert!(!is_public_url_or_host("printer.office.lan"));
        assert!(!is_public_url_or_host("vault.intern"));
        assert!(!is_public_url_or_host("server01.internal"));
        assert!(!is_public_url_or_host("router.home.arpa"));
    }

    #[test]
    fn public_url_filter_keeps_bare_hostnames() {
        // No dot → likely a NetBIOS-style host, keep as keyword candidate.
        assert!(!is_public_url_or_host("dc01"));
        assert!(!is_public_url_or_host("vpn-gateway"));
    }

    #[test]
    fn public_url_filter_drops_public_tld_unknowns() {
        // Random `.com` we've never heard of — still public-internet noise.
        assert!(is_public_url_or_host("https://tfthacker.com/article"));
        assert!(is_public_url_or_host("example-blog.dev"));
        assert!(is_public_url_or_host("foo.ai"));
    }

    #[test]
    fn public_url_filter_handles_path_query_port() {
        assert!(is_public_url_or_host("https://github.com:443/foo?a=1#b"));
        assert!(is_public_url_or_host("github.com/owner/repo"));
    }

    // ========================================================================
    // Phase 6b — keyword allowlist (.redactor.toml [allow] keywords)
    // ========================================================================

    // ========================================================================
    // Phase 6b — entity-type quality heuristics
    // ========================================================================

    #[test]
    fn quality_filter_drops_short_api_key() {
        // "session-start" is too short and has no digits → FP for API_KEY.
        assert!(is_low_quality_keyword_hit("session-start", "API_KEY"));
        assert!(is_low_quality_keyword_hit("taskmd web start", "API_KEY"));
    }

    #[test]
    fn quality_filter_keeps_real_api_key() {
        // 32-char hex-ish → keep.
        assert!(!is_low_quality_keyword_hit(
            "0123456789abcdef0123456789abcdef",
            "API_KEY"
        ));
        // 24-char alphanumeric with digit → keep.
        assert!(!is_low_quality_keyword_hit(
            "sk_live_abc12345xyz9876def",
            "API_KEY"
        ));
    }

    #[test]
    fn quality_filter_drops_bare_word_hostname() {
        assert!(is_low_quality_keyword_hit("github", "HOSTNAME"));
        assert!(is_low_quality_keyword_hit("vpn", "HOSTNAME"));
    }

    #[test]
    fn quality_filter_keeps_dotted_hostname() {
        assert!(!is_low_quality_keyword_hit("vmw01.corp", "HOSTNAME"));
        assert!(!is_low_quality_keyword_hit("dc.example.lan", "HOSTNAME"));
    }

    #[test]
    fn quality_filter_drops_single_lowercase_person() {
        // Single lowercase token → ambiguous (brand/tool/noun). Drop.
        assert!(is_low_quality_keyword_hit("claude", "PERSON"));
        assert!(is_low_quality_keyword_hit("obsidian", "PERSON"));
        assert!(is_low_quality_keyword_hit("alice", "PERSON"));
    }

    #[test]
    fn quality_filter_keeps_capitalised_person() {
        assert!(!is_low_quality_keyword_hit("Niclas Edge", "PERSON"));
        assert!(!is_low_quality_keyword_hit("Max Müller", "PERSON"));
    }

    #[test]
    fn quality_filter_drops_single_given_name_person() {
        assert!(is_low_quality_keyword_hit("Alice", "PERSON"));
        assert!(is_low_quality_keyword_hit("Niclas", "PERSON"));
        assert!(is_low_quality_keyword_hit("claude", "PERSON"));
    }

    #[test]
    fn quality_filter_keeps_multitoken_lowercase_person() {
        // 2+ tokens — likely a real name even when GLiNER returned it
        // in lowercase (which can happen when the source text was already
        // lowercase, e.g. notes typed in a hurry).
        assert!(!is_low_quality_keyword_hit("peter schmidt", "PERSON"));
        assert!(!is_low_quality_keyword_hit("max mustermann", "PERSON"));
    }

    #[test]
    fn quality_filter_passes_through_unknown_types() {
        // EMAIL / LOCATION → no heuristic, trust the model.
        assert!(!is_low_quality_keyword_hit("foo@bar.com", "EMAIL"));
        assert!(!is_low_quality_keyword_hit("123 Main St", "LOCATION"));
    }

    #[test]
    fn quality_filter_drops_short_org_acronyms() {
        assert!(is_low_quality_keyword_hit("GF", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("ITK", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("ITSB", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("ikt", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("dsb", "ORGANIZATION"));
        // Real-world false positives observed in classifier runs.
        assert!(is_low_quality_keyword_hit("xyz", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("isn", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("nbe", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("XYZ", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("gf2", "ORGANIZATION"));
    }

    #[test]
    fn quality_filter_drops_software_brands_as_org() {
        assert!(is_low_quality_keyword_hit("sharepoint", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("github", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("claude", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("obsidian", "ORGANIZATION"));
    }

    #[test]
    fn quality_filter_drops_consonant_only_acronym() {
        // 5-6 char all-consonant strings → very likely an acronym.
        assert!(is_low_quality_keyword_hit("SPVTBL", "ORGANIZATION"));
        assert!(is_low_quality_keyword_hit("PSCFG", "ORGANIZATION"));
        // Names with vowels still pass the consonant-only check (other
        // filters like brand-list / length may still drop them, so we
        // pick proper-noun examples NOT in the brand list).
        assert!(!is_low_quality_keyword_hit("Bosch", "ORGANIZATION"));
        assert!(!is_low_quality_keyword_hit("Siemens", "ORGANIZATION"));
    }

    #[test]
    fn quality_filter_drops_kebab_slug_org() {
        // ≥2 hyphens + no space → task-id or path-slug.
        assert!(is_low_quality_keyword_hit(
            "ssl-60-anderungen",
            "ORGANIZATION"
        ));
        assert!(is_low_quality_keyword_hit(
            "acme-it-software-ticket",
            "ORGANIZATION"
        ));
        // 1 hyphen is fine (could be "Coca-Cola").
        assert!(!is_low_quality_keyword_hit("Coca-Cola", "ORGANIZATION"));
    }

    #[test]
    fn quality_filter_keeps_real_organization() {
        // Mixed case, >4 chars, not in brand list → keep.
        assert!(!is_low_quality_keyword_hit(
            "Example Corp AG",
            "ORGANIZATION"
        ));
        assert!(!is_low_quality_keyword_hit("Initech", "ORGANIZATION"));
    }

    #[test]
    fn quality_filter_drops_filepath_as_hostname() {
        assert!(is_low_quality_keyword_hit("claude.md", "HOSTNAME"));
        assert!(is_low_quality_keyword_hit(
            "knowledge/claude.md",
            "HOSTNAME"
        ));
        assert!(is_low_quality_keyword_hit("data.csv", "HOSTNAME"));
    }

    #[test]
    fn quality_filter_drops_filename_as_org() {
        assert!(is_low_quality_keyword_hit(
            "test-results.csv",
            "ORGANIZATION"
        ));
        assert!(is_low_quality_keyword_hit("readme.md", "ORGANIZATION"));
    }

    #[test]
    fn aggregate_keywords_respects_allow_substrings_via_toml() {
        // Drop into a tempdir and set CWD there so autoload_project_allow
        // picks up the local .redactor.toml.
        let td = tempfile::tempdir().unwrap();
        let toml_path = td.path().join(".redactor.toml");
        std::fs::write(
            &toml_path,
            r#"[allow]
keywords = ["obsidian", "lorem ipsum"]
"#,
        )
        .unwrap();
        let saved_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(td.path()).unwrap();

        let entities = vec![
            crate::classify::EntityHit {
                text: "Obsidian Vaults - Toolbox for Thought".into(),
                label: "ORGANIZATION".into(),
                score: 0.9,
                entity_type: "ORGANIZATION".into(),
            },
            crate::classify::EntityHit {
                text: "Example Corp AG".into(),
                label: "ORGANIZATION".into(),
                score: 0.9,
                entity_type: "ORGANIZATION".into(),
            },
        ];
        let per_file = vec![(PathBuf::from("/tmp/a.md"), entities)];
        let mut state = crate::classify_state::State::empty();
        let out = aggregate_keywords(&per_file, &mut state, false, 0.7);

        std::env::set_current_dir(&saved_cwd).unwrap();

        // Obsidian-FP should be filtered; Example Corp should survive.
        assert!(!out.iter().any(|s| s.text.contains("obsidian")));
        assert!(out.iter().any(|s| s.text.contains("example corp")));
    }

    use std::fs;
    #[cfg(unix)]
    use std::sync::Mutex;
    use tempfile::tempdir;

    // Tests in this module mutate REDACTOR_CLASSIFIER_PYTHON. Serialize on
    // a single mutex (same pattern as src/classify.rs).
    #[cfg(unix)]
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    fn write_mock_python(dir: &Path, stdout_body: &str, exit_code: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("mock_python.sh");
        let body = format!(
            "#!/bin/sh\n\
             cat > /dev/null\n\
             cat <<'EOF'\n{stdout_body}\nEOF\n\
             exit {exit_code}\n"
        );
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    fn args_for(dir: &Path, output: &Path) -> ClassifyFilesArgs {
        ClassifyFilesArgs {
            directory: dir.to_path_buf(),
            max_depth: None,
            max_file_size: "5MB".to_string(),
            threshold: 0.6,
            output: Some(output.to_path_buf()),
            format: ClassifyOutputFormat::Text,
            apply: false,
            labels_file: None,
            quiet: true,
            force: false,
            reconsider_rejected: false,
            reconsider_accepted: false,
            paths_only: true, // tests focus on path stream by default
            keywords_only: false,
            keywords_output: None,
            keyword_min_score: 0.5,
            show_entities: false,
            // Tests use the mock GLiNER sidecar (see write_mock_python),
            // so override the new Ollama default here.
            backend: ClassifyBackend::Gliner,
        }
    }

    /// Set REDACTOR_CLASSIFIER_STATE_FILE to a fresh tempdir for each
    /// test so the global state file doesn't leak between cases.
    #[cfg(unix)]
    fn with_isolated_state(dir: &Path) {
        std::env::set_var("REDACTOR_CLASSIFIER_STATE_FILE", dir.join("state.json"));
    }
    #[cfg(unix)]
    fn clear_isolated_state() {
        std::env::remove_var("REDACTOR_CLASSIFIER_STATE_FILE");
    }

    #[test]
    fn parse_size_handles_common_suffixes() {
        assert_eq!(parse_size("100").unwrap(), 100);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("5MB").unwrap(), 5 * 1024 * 1024);
        assert_eq!(parse_size("5mb").unwrap(), 5 * 1024 * 1024);
        assert_eq!(parse_size("1024K").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1024k").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("2GB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("512B").unwrap(), 512);
    }

    #[test]
    fn parse_size_rejects_garbage() {
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("5.5MB").is_err());
    }

    #[test]
    fn parse_labels_strips_comments_and_blanks() {
        let body = "# header\n\nTAX_DOC\n   # indented comment\nCREDENTIAL\n\n";
        assert_eq!(parse_labels(body), vec!["TAX_DOC", "CREDENTIAL"]);
    }

    #[test]
    fn load_labels_falls_back_to_embedded() {
        let labels = load_labels(None).unwrap();
        assert!(labels.contains(&"TAX_DOC".to_string()));
        assert!(labels.contains(&"CREDENTIAL".to_string()));
    }

    #[test]
    fn load_labels_explicit_file_wins() {
        let td = tempdir().unwrap();
        let p = td.path().join("labels.txt");
        fs::write(&p, "# header\nCUSTOM_LABEL\n").unwrap();
        let labels = load_labels(Some(&p)).unwrap();
        assert_eq!(labels, vec!["CUSTOM_LABEL"]);
    }

    #[cfg(unix)]
    #[test]
    fn end_to_end_with_mock_sidecar_writes_text_output() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let input = tempdir().unwrap();
        // Two text files. One will be referenced by the canned response.
        fs::write(input.path().join("steuer.txt"), b"Einkommensteuer 2024\n").unwrap();
        fs::write(input.path().join("readme.md"), b"# readme\n").unwrap();

        let out_dir = tempdir().unwrap();
        let output = out_dir.path().join("out.suggested");

        // Output paths are aggregated from `state.files`, whose keys are
        // the canonical paths produced by the walk. The mock response must
        // therefore also use canonical paths so the lookup matches (macOS
        // tmpdirs are symlinks: /var/folders → /private/var/folders).
        let input_canon = input.path().canonicalize().unwrap();
        // Canned response: pretend the first file is high-confidence,
        // second is below threshold.
        let canned = format!(
            r#"{{"version":1,"results":[
                {{"path":"{p1}","confidence":0.92,"labels":["TAX_DOC"],"evidence":"Einkommensteuer detected"}},
                {{"path":"{p2}","confidence":0.30,"labels":["NOTE"],"evidence":"low signal"}}
            ],"warnings":[]}}"#,
            p1 = input_canon.join("steuer.txt").display(),
            p2 = input_canon.join("readme.md").display(),
        );
        let mock_dir = tempdir().unwrap();
        let script = write_mock_python(mock_dir.path(), &canned, 0);
        std::env::set_var("REDACTOR_CLASSIFIER_PYTHON", &script);
        let state_dir = tempdir().unwrap();
        std::env::set_var(
            "REDACTOR_CLASSIFIER_STATE_FILE",
            state_dir.path().join("state.json"),
        );

        let mut args = args_for(input.path(), &output);
        args.threshold = 0.6;
        let exit = run_classify_files(args).unwrap();
        std::env::remove_var("REDACTOR_CLASSIFIER_PYTHON");
        std::env::remove_var("REDACTOR_CLASSIFIER_STATE_FILE");

        assert_eq!(exit, 0);
        let body = fs::read_to_string(&output).unwrap();
        assert!(body.contains("# threshold: 0.60"));
        assert!(body.contains("steuer.txt"));
        // readme was below threshold — must not appear as an entry.
        assert!(!body.contains("# confidence=0.30"));
        assert!(body.contains("# confidence=0.92"));
    }

    #[cfg(unix)]
    #[test]
    fn json_format_is_honored() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let input = tempdir().unwrap();
        fs::write(input.path().join("a.txt"), b"hello\n").unwrap();
        let out_dir = tempdir().unwrap();
        let output = out_dir.path().join("out.json");

        let input_canon = input.path().canonicalize().unwrap();
        let canned = format!(
            r#"{{"version":1,"results":[
                {{"path":"{p}","confidence":0.99,"labels":["X"],"evidence":""}}
            ],"warnings":[]}}"#,
            p = input_canon.join("a.txt").display(),
        );
        let mock_dir = tempdir().unwrap();
        let script = write_mock_python(mock_dir.path(), &canned, 0);
        std::env::set_var("REDACTOR_CLASSIFIER_PYTHON", &script);
        let state_dir = tempdir().unwrap();
        std::env::set_var(
            "REDACTOR_CLASSIFIER_STATE_FILE",
            state_dir.path().join("state.json"),
        );

        let mut args = args_for(input.path(), &output);
        args.format = ClassifyOutputFormat::Json;
        args.threshold = 0.0;
        let exit = run_classify_files(args).unwrap();
        std::env::remove_var("REDACTOR_CLASSIFIER_PYTHON");
        clear_isolated_state();

        assert_eq!(exit, 0);
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        assert_eq!(v["report"]["files_above_threshold"], 1);
        assert_eq!(v["suggestions"][0]["confidence"], 0.99);
    }

    #[cfg(unix)]
    #[test]
    fn threshold_zero_keeps_all_results() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let input = tempdir().unwrap();
        fs::write(input.path().join("a.txt"), b"hello\n").unwrap();
        let out_dir = tempdir().unwrap();
        let output = out_dir.path().join("out.suggested");

        let input_canon = input.path().canonicalize().unwrap();
        let canned = format!(
            r#"{{"version":1,"results":[
                {{"path":"{p}","confidence":0.05,"labels":["X"],"evidence":""}}
            ],"warnings":[]}}"#,
            p = input_canon.join("a.txt").display(),
        );
        let mock_dir = tempdir().unwrap();
        let script = write_mock_python(mock_dir.path(), &canned, 0);
        std::env::set_var("REDACTOR_CLASSIFIER_PYTHON", &script);
        let state_dir = tempdir().unwrap();
        with_isolated_state(state_dir.path());

        let mut args = args_for(input.path(), &output);
        args.threshold = 0.0;
        let exit = run_classify_files(args).unwrap();
        std::env::remove_var("REDACTOR_CLASSIFIER_PYTHON");
        clear_isolated_state();

        assert_eq!(exit, 0);
        let body = fs::read_to_string(&output).unwrap();
        assert!(body.contains("# confidence=0.05"));
        assert!(body.contains("1 above threshold"));
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_not_installed_returns_exit_2_with_hint() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let input = tempdir().unwrap();
        fs::write(input.path().join("a.txt"), b"x\n").unwrap();
        let out_dir = tempdir().unwrap();
        let output = out_dir.path().join("out.suggested");

        let missing = tempdir().unwrap().path().join("nope/python");
        std::env::set_var("REDACTOR_CLASSIFIER_PYTHON", &missing);

        let exit = run_classify_files(args_for(input.path(), &output)).unwrap();
        std::env::remove_var("REDACTOR_CLASSIFIER_PYTHON");

        assert_eq!(exit, 2);
        // .suggested must not be written when the sidecar isn't installed.
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_crash_returns_exit_3() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let input = tempdir().unwrap();
        fs::write(input.path().join("a.txt"), b"x\n").unwrap();
        let out_dir = tempdir().unwrap();
        let output = out_dir.path().join("out.suggested");

        let mock_dir = tempdir().unwrap();
        let script = mock_dir.path().join("crash.sh");
        fs::write(
            &script,
            "#!/bin/sh\ncat > /dev/null\necho 'boom' >&2\nexit 7\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("REDACTOR_CLASSIFIER_PYTHON", &script);

        let exit = run_classify_files(args_for(input.path(), &output)).unwrap();
        std::env::remove_var("REDACTOR_CLASSIFIER_PYTHON");

        assert_eq!(exit, 3);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_timeout_returns_exit_0_with_partial_results() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let input = tempdir().unwrap();
        fs::write(input.path().join("a.txt"), b"x\n").unwrap();
        let out_dir = tempdir().unwrap();
        let output = out_dir.path().join("out.suggested");

        // Sleep longer than the 1s timeout we set below.
        let mock_dir = tempdir().unwrap();
        let script = mock_dir.path().join("slow.sh");
        fs::write(&script, "#!/bin/sh\ncat > /dev/null\nsleep 3\necho '{}'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("REDACTOR_CLASSIFIER_PYTHON", &script);
        std::env::set_var("REDACTOR_CLASSIFIER_TIMEOUT_SECS", "1");

        let exit = run_classify_files(args_for(input.path(), &output)).unwrap();
        std::env::remove_var("REDACTOR_CLASSIFIER_PYTHON");
        std::env::remove_var("REDACTOR_CLASSIFIER_TIMEOUT_SECS");

        assert_eq!(exit, 0);
        // We wrote a (likely empty) `.suggested` so the user sees the partial result.
        assert!(output.exists());
        let body = fs::read_to_string(&output).unwrap();
        assert!(body.contains("0 above threshold"));
    }

    #[test]
    fn missing_input_dir_returns_exit_4() {
        let out_dir = tempdir().unwrap();
        let output = out_dir.path().join("out.suggested");
        let missing = out_dir.path().join("this/does/not/exist");
        let exit = run_classify_files(args_for(&missing, &output)).unwrap();
        assert_eq!(exit, 4);
        assert!(!output.exists());
    }

    #[test]
    fn apply_flag_is_a_stub_returning_exit_2() {
        let out_dir = tempdir().unwrap();
        let input = tempdir().unwrap();
        let mut args = args_for(input.path(), &out_dir.path().join("o"));
        args.apply = true;
        let exit = run_classify_files(args).unwrap();
        assert_eq!(exit, 2);
    }
}

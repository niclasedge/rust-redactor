//! Phase 6 — Classifier state-file.
//!
//! Tracks two things per classifier project:
//!
//! 1. **File-level cache** — keyed by absolute path. Records the file's
//!    SHA-256, size, mtime and the user's last decision (`accepted` /
//!    `rejected` / `pending`). Used by `classify-files` to short-circuit
//!    files whose content hasn't changed and whose decision is final.
//!
//! 2. **Keyword decisions** — keyed by the normalized (lowercased) keyword
//!    text. Records the decision plus first-seen-in path, occurrence count
//!    and entity-type metadata for the keyword-suggestion stream
//!    (`.redactorignore.keywords.suggested`).
//!
//! Storage: JSON file under `<config>/classifier-state.json` (note: sits
//! *outside* the `<config>/classifier/` sidecar tree so it survives a
//! `classifier-uninstall` + reinstall cycle — Plan §N.4 #1).
//!
//! Writes are atomic: serialize to `state.json.tmp` in the same parent dir,
//! then `rename()` over the existing file. The state file is small (~MB)
//! even for 10k files, so we always read+write the whole document — no
//! incremental persistence layer.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Schema version of the on-disk state file. Bump when we change the JSON
/// structure in a backwards-incompatible way.
pub const STATE_VERSION: u32 = 1;

/// Final decisions a user can make on a suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Appended to `~/.redactorignore`. Skip in future runs.
    Accepted,
    /// User explicitly rejected. Skip in future runs unless `--reconsider-rejected`.
    Rejected,
    /// Written to a `.suggested` file but not yet reviewed.
    Pending,
}

/// Per-file cache entry. `sha256` is the content hash at `classified_at`
/// time; if the live file disagrees, the entry is invalid and the file
/// gets re-classified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub sha256: String,
    pub size_bytes: u64,
    /// File mtime in nanoseconds since UNIX epoch. Used as a cheap pre-check
    /// before computing the SHA-256 (if mtime differs we recompute).
    pub mtime_ns: u128,
    pub classified_at: DateTime<Utc>,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub confidence: f64,
    /// Per-entity hits captured at classify time. Persisted so the output
    /// files (`.suggested` + `.keywords.suggested`) can be regenerated from
    /// the state alone — re-runs only classify missing/changed files and
    /// the cached entities feed the keyword aggregator without re-calling
    /// the LLM.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<StoredEntity>,
}

/// Entity hit serialised into the state file. Mirrors `classify::EntityHit`
/// but lives in the state crate so it can be persisted independently of the
/// IPC types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEntity {
    pub text: String,
    pub label: String,
    pub score: f64,
    pub entity_type: String,
}

/// Per-keyword decision entry. Survives across runs so the user's `rejected`
/// answer for "Berlin" doesn't reappear next week.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeywordEntry {
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_at: Option<DateTime<Utc>>,
    pub first_seen_in: PathBuf,
    /// Distinct number of files this keyword has been observed in. Refreshed
    /// every time `classify-files` runs over the same tree.
    pub occurrence_count: u32,
    pub entity_type: String,
    #[serde(default)]
    pub score_avg: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_full_scan: Option<DateTime<Utc>>,
    #[serde(default)]
    pub files: BTreeMap<String, FileEntry>,
    #[serde(default)]
    pub keywords: BTreeMap<String, KeywordEntry>,
}

impl State {
    /// Fresh empty state with the current schema version.
    pub fn empty() -> Self {
        Self {
            version: STATE_VERSION,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Resolve the on-disk location of the state file.
///
/// Override order:
/// 1. `$REDACTOR_CLASSIFIER_STATE_FILE` — full path (mostly for tests).
/// 2. `<config_dir>/classifier-state.json` (lives outside `<config>/classifier/`
///    so `classifier-uninstall` doesn't blow away decision history).
pub fn state_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("REDACTOR_CLASSIFIER_STATE_FILE") {
        return Some(PathBuf::from(p));
    }
    crate::config::config_dir().map(|d| d.join("classifier-state.json"))
}

// ---------------------------------------------------------------------------
// Load / Save
// ---------------------------------------------------------------------------

/// Load the state file. Returns an empty state if the file doesn't exist;
/// parse errors are surfaced (we don't want to silently nuke decision
/// history on a corrupt file).
pub fn load(path: &Path) -> Result<State> {
    if !path.exists() {
        return Ok(State::empty());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read state file {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(State::empty());
    }
    let state: State = serde_json::from_str(&raw)
        .with_context(|| format!("parse state file {}", path.display()))?;
    Ok(state)
}

/// Atomic save: write `path.tmp`, then rename over the target. Creates
/// parent dirs if missing.
pub fn save(path: &Path, state: &State) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create state parent {}", parent.display()))?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(state).context("serialize state")?;
    std::fs::write(&tmp, body).with_context(|| format!("write tmp state {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// SHA-256 of a file's full content. Returns the lowercase hex digest.
/// Caller decides when to compute (we don't cache here).
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    use std::io::Read;
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// File mtime in nanoseconds since UNIX epoch, or 0 on platforms that don't
/// expose it.
pub fn file_mtime_ns(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Skip-logic
// ---------------------------------------------------------------------------

/// Returns `true` iff the file at `path` should be SKIPPED on the current
/// classify-files run, given `entry`.
///
/// Skip iff: the file is already classified (any decision, incl. `Pending`)
/// AND the live content still matches the cached hash (mtime+size pre-check;
/// no SHA recompute — if mtime drifts we conservatively reclassify).
///
/// Rationale for skipping `Pending`: re-running the LLM on a file whose
/// content hasn't changed produces (nearly) the same entities at high cost.
/// To force a fresh pass on Pending entries, the caller should use
/// `--force` (handled one layer up).
///
/// `reconsider_rejected` / `reconsider_accepted` flip the corresponding
/// final-decision branches back to "reclassify".
pub fn should_skip(
    path: &Path,
    entry: &FileEntry,
    reconsider_rejected: bool,
    reconsider_accepted: bool,
) -> bool {
    match entry.decision {
        Decision::Rejected if reconsider_rejected => return false,
        Decision::Accepted if reconsider_accepted => return false,
        _ => {}
    }
    // mtime + size cheap-check. SHA recompute is avoided on purpose
    // (cost on a 10k-file tree); a stale-but-unchanged mtime would skip
    // incorrectly, but the user can always `--force`.
    let Ok(meta) = std::fs::metadata(path) else {
        return false; // file missing → reclassify
    };
    if meta.len() != entry.size_bytes {
        return false;
    }
    if file_mtime_ns(&meta) != entry.mtime_ns {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_entry(decision: Decision) -> FileEntry {
        FileEntry {
            sha256: "deadbeef".into(),
            size_bytes: 10,
            mtime_ns: 0,
            classified_at: Utc::now(),
            decision,
            decision_at: None,
            labels: vec![],
            confidence: 0.0,
            entities: vec![],
        }
    }

    #[test]
    fn empty_state_roundtrips_through_save_load() {
        let td = tempdir().unwrap();
        let p = td.path().join("state.json");
        let s = State::empty();
        save(&p, &s).unwrap();
        let s2 = load(&p).unwrap();
        assert_eq!(s2.version, STATE_VERSION);
        assert!(s2.files.is_empty());
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let td = tempdir().unwrap();
        let p = td.path().join("missing.json");
        let s = load(&p).unwrap();
        assert_eq!(s.version, STATE_VERSION);
    }

    #[test]
    fn save_load_preserves_file_entry() {
        let td = tempdir().unwrap();
        let p = td.path().join("s.json");
        let mut s = State::empty();
        s.files
            .insert("/abs/path.txt".into(), dummy_entry(Decision::Accepted));
        save(&p, &s).unwrap();
        let s2 = load(&p).unwrap();
        assert_eq!(s2.files.len(), 1);
        assert!(matches!(
            s2.files["/abs/path.txt"].decision,
            Decision::Accepted
        ));
    }

    #[test]
    fn should_skip_pending_with_matching_hash_skips() {
        // Phase 7: Pending is "already classified once"; if file content is
        // unchanged we skip to avoid re-running an expensive LLM. Force the
        // user to `--force` if they want a fresh pass.
        let td = tempdir().unwrap();
        let f = td.path().join("a.txt");
        std::fs::write(&f, "x").unwrap();
        let meta = std::fs::metadata(&f).unwrap();
        let entry = FileEntry {
            sha256: "x".into(),
            size_bytes: meta.len(),
            mtime_ns: file_mtime_ns(&meta),
            classified_at: Utc::now(),
            decision: Decision::Pending,
            decision_at: None,
            labels: vec![],
            confidence: 0.0,
            entities: vec![],
        };
        assert!(should_skip(&f, &entry, false, false));
    }

    #[test]
    fn should_skip_pending_with_changed_file_reclassifies() {
        let td = tempdir().unwrap();
        let f = td.path().join("a.txt");
        std::fs::write(&f, "x").unwrap();
        let entry = FileEntry {
            sha256: "x".into(),
            size_bytes: 99, // wrong size → cache invalid
            mtime_ns: 0,
            classified_at: Utc::now(),
            decision: Decision::Pending,
            decision_at: None,
            labels: vec![],
            confidence: 0.0,
            entities: vec![],
        };
        assert!(!should_skip(&f, &entry, false, false));
    }

    #[test]
    fn should_skip_accepted_with_unchanged_file() {
        let td = tempdir().unwrap();
        let f = td.path().join("a.txt");
        std::fs::write(&f, "hello").unwrap();
        let meta = std::fs::metadata(&f).unwrap();
        let entry = FileEntry {
            sha256: "x".into(),
            size_bytes: meta.len(),
            mtime_ns: file_mtime_ns(&meta),
            classified_at: Utc::now(),
            decision: Decision::Accepted,
            decision_at: None,
            labels: vec![],
            confidence: 0.0,
            entities: vec![],
        };
        assert!(should_skip(&f, &entry, false, false));
    }

    #[test]
    fn should_skip_returns_false_when_size_differs() {
        let td = tempdir().unwrap();
        let f = td.path().join("a.txt");
        std::fs::write(&f, "hello world").unwrap();
        let entry = FileEntry {
            sha256: "x".into(),
            size_bytes: 99, // wrong
            mtime_ns: 0,
            classified_at: Utc::now(),
            decision: Decision::Accepted,
            decision_at: None,
            labels: vec![],
            confidence: 0.0,
            entities: vec![],
        };
        assert!(!should_skip(&f, &entry, false, false));
    }

    #[test]
    fn should_skip_reconsider_rejected_overrides() {
        let td = tempdir().unwrap();
        let f = td.path().join("a.txt");
        std::fs::write(&f, "x").unwrap();
        let meta = std::fs::metadata(&f).unwrap();
        let entry = FileEntry {
            sha256: "x".into(),
            size_bytes: meta.len(),
            mtime_ns: file_mtime_ns(&meta),
            classified_at: Utc::now(),
            decision: Decision::Rejected,
            decision_at: None,
            labels: vec![],
            confidence: 0.0,
            entities: vec![],
        };
        // Without reconsider: skip
        assert!(should_skip(&f, &entry, false, false));
        // With reconsider: re-process
        assert!(!should_skip(&f, &entry, true, false));
    }

    #[test]
    fn sha256_file_matches_known_value() {
        let td = tempdir().unwrap();
        let f = td.path().join("a.txt");
        std::fs::write(&f, "hello\n").unwrap();
        let hash = sha256_file(&f).unwrap();
        // sha256("hello\n") = 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
        assert_eq!(
            hash,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    #[test]
    fn save_creates_parent_dir() {
        let td = tempdir().unwrap();
        let p = td.path().join("nested/deeper/state.json");
        save(&p, &State::empty()).unwrap();
        assert!(p.exists());
    }
}

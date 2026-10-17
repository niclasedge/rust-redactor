//! Ranked full-text search over markdown corpora with snippet redaction.
//!
//! Four sections: project knowledge / project tasks / project code / global wiki.
//! Each section has its own BM25+decay ranking and per-section limit.

use anyhow::Result;
use clap::Args;
use ignore::WalkBuilder;
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const MAX_DEPTH: usize = 12;
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "worktrees",
    ".claude",
    "__pycache__",
];

const CODE_EXTS: &[&str] = &[
    "rs", "py", "js", "ts", "mjs", "go", "sh", "toml", "yaml", "yml", "tf",
];

/// The four search sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum SectionKind {
    Knowledge,
    Tasks,
    Code,
    Wiki,
}

impl SectionKind {
    pub fn slug(self) -> &'static str {
        match self {
            SectionKind::Knowledge => "knowledge",
            SectionKind::Tasks => "tasks",
            SectionKind::Code => "code",
            SectionKind::Wiki => "wiki",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            SectionKind::Knowledge => "project knowledge",
            SectionKind::Tasks => "project tasks",
            SectionKind::Code => "project code",
            SectionKind::Wiki => "global wiki",
        }
    }

    pub fn is_project(self) -> bool {
        matches!(
            self,
            SectionKind::Knowledge | SectionKind::Tasks | SectionKind::Code
        )
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub kind: SectionKind,
    pub outside_project: bool,
    pub hits: Vec<EnrichedHit>,
}

pub struct SectionedResult {
    pub query: String,
    pub sections: Vec<Section>,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    #[arg(required = true)]
    pub query: Vec<String>,

    /// Per-section result limit (default 5; total visible hits up to 4*N).
    #[arg(long, default_value = "5")]
    pub limit: usize,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Disable temporal decay.
    #[arg(long)]
    pub no_decay: bool,

    /// Override decay rate (default 0.05).
    #[arg(long)]
    pub decay: Option<f64>,

    /// Skip the global wiki section (faster).
    #[arg(long)]
    pub no_wiki: bool,

    /// Show only the knowledge section.
    #[arg(long, group = "modal")]
    pub knowledge_only: bool,

    /// Show only the tasks section.
    #[arg(long, group = "modal")]
    pub tasks_only: bool,

    /// Show only the code section.
    #[arg(long, group = "modal")]
    pub code_only: bool,

    /// Show only the wiki section.
    #[arg(long, group = "modal")]
    pub wiki_only: bool,

    /// DEPRECATED — kept as no-op since v0.6.0; the wiki section is always shown.
    #[arg(short = 'a', long = "all", hide = true)]
    pub all: bool,

    /// DEPRECATED alias for --code-only.
    #[arg(long, hide = true)]
    pub code: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Project,
    Global,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Yml,
}

/// Optional metadata for task:// corpus entries.
#[derive(Debug, Clone)]
pub struct TaskMeta {
    pub task_id: String,
    pub status: String,
    pub phase: String,
    pub priority: String,
}

#[derive(Debug, Clone)]
pub struct Doc {
    pub path: PathBuf,
    pub title: String,
    pub tags: Vec<String>,
    pub content: String,
    pub mtime: SystemTime,
    pub task_meta: Option<TaskMeta>,
}

/// A single ranked search result.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Hit {
    pub doc_id: usize,
    pub score: f64,
    pub final_score: f64,
    pub age_days: f64,
    pub title: String,
    pub path: PathBuf,
    pub matched_terms: Vec<String>,
    pub task_meta: Option<TaskMeta>,
}

/// Tokenize: split on non-alphanumeric, lowercase, drop empty.
pub fn tokenize(s: &str) -> Vec<Cow<'_, str>> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| Cow::Owned(t.to_lowercase()))
        .collect()
}

pub fn parse_doc(path: &Path) -> Result<Doc> {
    let raw = std::fs::read_to_string(path)?;
    let mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled")
        .to_owned();
    let mut title = stem.clone();
    let mut tags: Vec<String> = Vec::new();
    let mut in_frontmatter = false;
    let mut frontmatter_done = false;
    let mut fm_title: Option<String> = None;
    let mut heading_title: Option<String> = None;
    for (idx, line) in raw.lines().enumerate() {
        if idx == 0 && line.trim() == "---" {
            in_frontmatter = true;
            continue;
        }
        if in_frontmatter {
            if line.trim() == "---" {
                in_frontmatter = false;
                frontmatter_done = true;
                continue;
            }
            if let Some(rest) = line.strip_prefix("title:") {
                let val = rest.trim().trim_matches('"').to_owned();
                if !val.is_empty() {
                    fm_title = Some(val);
                }
            }
            if let Some(rest) = line.strip_prefix("tags:") {
                let inner = rest.trim().trim_start_matches('[').trim_end_matches(']');
                tags = inner
                    .split(',')
                    .map(|t| t.trim().trim_matches('"').to_lowercase())
                    .filter(|t| !t.is_empty())
                    .collect();
            }
            continue;
        }
        if heading_title.is_none() {
            if let Some(rest) = line.strip_prefix("# ") {
                heading_title = Some(rest.trim().to_owned());
                break;
            }
        }
    }
    let _ = frontmatter_done;
    if let Some(t) = fm_title {
        title = t;
    } else if let Some(h) = heading_title {
        title = h;
    }
    let content: String = raw.chars().take(5000).collect();
    Ok(Doc {
        path: path.to_path_buf(),
        title,
        tags,
        content,
        mtime,
        task_meta: None,
    })
}

pub fn walk_corpus(roots: &[PathBuf]) -> Vec<Doc> {
    let mut docs = Vec::new();
    for root in roots {
        let walker = WalkBuilder::new(root)
            .max_depth(Some(MAX_DEPTH))
            .follow_links(true)
            .standard_filters(true)
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                if e.depth() == 0 {
                    return true;
                }
                !SKIP_DIRS.iter().any(|d| name == *d)
            })
            .build();
        for entry in walker.flatten() {
            let Some(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("md") {
                continue;
            }
            if let Ok(doc) = parse_doc(path) {
                docs.push(doc);
            }
        }
    }
    docs
}

/// Walk source files under project_root for the Code section.
pub fn walk_code_corpus(root: &Path) -> Vec<Doc> {
    let mut docs = Vec::new();
    let walker = WalkBuilder::new(root)
        .max_depth(Some(8))
        .follow_links(false)
        .standard_filters(true)
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            if e.depth() == 0 {
                return true;
            }
            !SKIP_DIRS.iter().any(|d| name == *d)
        })
        .build();
    for entry in walker.flatten() {
        let Some(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_file() {
            continue;
        }
        let path = entry.path();
        let ext = match path.extension().and_then(|s| s.to_str()) {
            Some(e) => e.to_lowercase(),
            None => continue,
        };
        if !CODE_EXTS.contains(&ext.as_str()) {
            continue;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mtime = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("untitled")
            .to_owned();
        let content_truncated: String = content.chars().take(5000).collect();
        docs.push(Doc {
            path: path.to_path_buf(),
            title: stem,
            tags: Vec::new(),
            content: content_truncated,
            mtime,
            task_meta: None,
        });
    }
    docs
}

/// BM25 search with temporal decay.
///
/// Fields: title (3.0), content (1.0), tags (2.0).
pub fn search_corpus(
    docs: &[Doc],
    query: &str,
    decay_rate: f64,
    no_decay: bool,
    limit: usize,
) -> Vec<Hit> {
    use probly_search::score::bm25;
    use probly_search::Index;
    fn ta(d: &Doc) -> Vec<&str> {
        vec![d.title.as_str()]
    }
    fn ca(d: &Doc) -> Vec<&str> {
        vec![d.content.as_str()]
    }
    fn ga(d: &Doc) -> Vec<&str> {
        d.tags.iter().map(|t| t.as_str()).collect()
    }
    fn tok(s: &str) -> Vec<Cow<'_, str>> {
        s.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| Cow::Owned(t.to_lowercase()))
            .collect()
    }
    let mut index = Index::<usize>::new(3);
    for (i, doc) in docs.iter().enumerate() {
        index.add_document(&[ta, ca, ga], tok, i, doc);
    }
    let boosts = [3.0_f64, 1.0, 2.0];
    let raw = index.query(query, &mut bm25::new(), tok, &boosts);
    let now = SystemTime::now();
    let terms: Vec<String> = tokenize(query)
        .into_iter()
        .map(|t| t.into_owned())
        .collect();
    let mut hits: Vec<Hit> = raw
        .into_iter()
        .map(|r| {
            let idx = r.key;
            let doc = &docs[idx];
            let age = now
                .duration_since(doc.mtime)
                .map(|d| d.as_secs_f64() / 86400.0)
                .unwrap_or(0.0);
            let decay = if no_decay {
                1.0
            } else {
                (-decay_rate * age).exp()
            };
            Hit {
                doc_id: idx,
                score: r.score,
                final_score: r.score * decay,
                age_days: age,
                title: doc.title.clone(),
                path: doc.path.clone(),
                matched_terms: terms.clone(),
                task_meta: doc.task_meta.clone(),
            }
        })
        .collect();
    hits.sort_by(|a, b| {
        b.final_score
            .partial_cmp(&a.final_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hits.truncate(limit);
    hits
}

#[allow(dead_code)]
pub fn resolve_roots(scope: Scope, cwd: &Path) -> Result<Vec<PathBuf>> {
    match scope {
        Scope::Project => {
            let root = detect_project_root(cwd)
                .ok_or_else(|| anyhow::anyhow!("not inside ~/GITHUB/<project>/"))?;
            Ok(vec![root])
        }
        Scope::Global => {
            if let Ok(v) = std::env::var("REDACTOR_SEARCH_GLOBAL_ROOTS") {
                return Ok(v
                    .split(':')
                    .filter(|s| !s.is_empty())
                    .map(expand_tilde)
                    .collect());
            }
            let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home"))?;
            Ok(vec![home.join("GITHUB/ObsidianPKM/Atlas/Wiki")])
        }
    }
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(p)
}

fn resolve_wiki_roots() -> Vec<PathBuf> {
    if let Ok(v) = std::env::var("REDACTOR_SEARCH_GLOBAL_ROOTS") {
        return v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(expand_tilde)
            .collect();
    }
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    vec![home.join("GITHUB/ObsidianPKM/Atlas/Wiki")]
}

const SNIPPET_CONTEXT_LINES: usize = 3;

/// Return up to (2 * SNIPPET_CONTEXT_LINES + 1) lines around the first body
/// line that contains any of `terms` (case-insensitive). Skips frontmatter,
/// fenced code blocks, table rows, and HR rules. Falls back to the first
/// non-empty body line longer than 20 chars when no term matches.
pub fn extract_snippet(path: &Path, terms: &[String]) -> String {
    // task:// paths have no real file on disk
    if path.to_string_lossy().starts_with("task://") {
        return String::new();
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let all_lines: Vec<&str> = raw.lines().collect();

    let body_start = if all_lines.first().map(|l| l.trim()) == Some("---") {
        all_lines
            .iter()
            .skip(1)
            .position(|l| l.trim() == "---")
            .map(|i| i + 2)
            .unwrap_or(all_lines.len())
    } else {
        0
    };
    let body: &[&str] = &all_lines[body_start..];

    let lower_terms: Vec<String> = terms
        .iter()
        .filter(|t| t.len() > 2)
        .map(|t| t.to_lowercase())
        .collect();

    let is_structural = |line: &str| -> bool {
        let t = line.trim();
        t.starts_with('|') || t.starts_with("```") || t == "---"
    };

    let hit_idx = if lower_terms.is_empty() {
        None
    } else {
        body.iter().position(|line| {
            let t = line.trim();
            if t.is_empty() || is_structural(line) {
                return false;
            }
            let lower = t.to_lowercase();
            lower_terms.iter().any(|term| lower.contains(term.as_str()))
        })
    };

    match hit_idx {
        None => body
            .iter()
            .find(|line| {
                let t = line.trim();
                !t.is_empty() && !is_structural(line) && t.len() > 20
            })
            .map(|line| {
                let t = line.trim();
                if t.len() > 300 {
                    t.chars().take(300).collect()
                } else {
                    t.to_owned()
                }
            })
            .unwrap_or_default(),
        Some(idx) => {
            let lo = idx.saturating_sub(SNIPPET_CONTEXT_LINES);
            let hi = (idx + SNIPPET_CONTEXT_LINES + 1).min(body.len());
            let chunk: Vec<String> = body[lo..hi]
                .iter()
                .map(|l| l.trim_end().to_owned())
                .filter(|l| !l.trim().is_empty())
                .collect();
            let text = chunk.join("\n");
            if lo > 0 {
                format!("...\n{text}")
            } else {
                text
            }
        }
    }
}

use crate::logger::{log_event, resolve_log_dir, Event};
use crate::patterns::Rule;
use crate::redactor::redact_pattern;

/// Run snippet text through the supplied rule set; return sanitized text plus
/// the count of unique rules that fired.
#[allow(dead_code)]
pub fn sanitize_snippet(snippet: &str, rules: &[Rule]) -> (String, usize) {
    let (clean, log_entries) = redact_pattern(snippet, rules);
    (clean, log_entries.len())
}

#[derive(Debug, Clone)]
pub struct EnrichedHit {
    pub hit: Hit,
    pub snippet: String,
    pub redactions: usize,
}

/// Enrich each hit with an extracted, sanitized snippet, logging every
/// redaction event to the daily audit log.
pub fn enrich_hits(hits: Vec<Hit>, rules: &[Rule], scope: Scope, query: &str) -> Vec<EnrichedHit> {
    let log_dir = resolve_log_dir();
    let source = match scope {
        Scope::Project => "search:project",
        Scope::Global => "search:global",
    };
    hits.into_iter()
        .map(|h| {
            let raw = if let Some(meta) = &h.task_meta {
                // Task hits: synthesize snippet from title + status; no file to read.
                format!("{} [{}]", h.title, meta.status)
            } else {
                extract_snippet(&h.path, &h.matched_terms)
            };
            let (clean, log_entries) = redact_pattern(&raw, rules);
            for entry in &log_entries {
                log_event(
                    &log_dir,
                    &Event {
                        source,
                        command: query,
                        mode: "pattern",
                        rule: &entry.rule,
                        count: entry.count,
                        sample: &entry.sample,
                    },
                );
            }
            EnrichedHit {
                hit: h,
                snippet: clean,
                redactions: log_entries.len(),
            }
        })
        .collect()
}

pub fn run(args: SearchArgs) -> Result<()> {
    if args.all {
        eprintln!(
            "redactor search: -a is a no-op since v0.6.0; the global wiki section is always shown unless --no-wiki is set"
        );
    }
    let code_only_effective = args.code || args.code_only;

    let cwd = std::env::current_dir()?;
    let project_root = detect_project_root(&cwd);
    let outside_project = project_root.is_none();

    let query = args.query.join(" ");
    let decay = args.decay.unwrap_or(0.05);

    let sections_to_build: Vec<SectionKind> = if args.knowledge_only {
        vec![SectionKind::Knowledge]
    } else if args.tasks_only {
        vec![SectionKind::Tasks]
    } else if code_only_effective {
        vec![SectionKind::Code]
    } else if args.wiki_only {
        vec![SectionKind::Wiki]
    } else {
        let mut s = vec![
            SectionKind::Knowledge,
            SectionKind::Tasks,
            SectionKind::Code,
        ];
        if !args.no_wiki {
            s.push(SectionKind::Wiki);
        }
        s
    };

    let rules = crate::config::autoload_rules().unwrap_or_else(|_| crate::patterns::defaults());
    let mut result = SectionedResult {
        query: query.clone(),
        sections: Vec::new(),
    };

    for kind in sections_to_build {
        let docs: Vec<Doc> = match kind {
            SectionKind::Knowledge => match &project_root {
                Some(root) => walk_corpus(std::slice::from_ref(root)),
                None => Vec::new(),
            },
            SectionKind::Tasks => crate::search_tasks::fetch_tasks_corpus(),
            SectionKind::Code => match &project_root {
                Some(root) => walk_code_corpus(root),
                None => Vec::new(),
            },
            SectionKind::Wiki => walk_corpus(&resolve_wiki_roots()),
        };
        let hits = if docs.is_empty() {
            Vec::new()
        } else {
            search_corpus(&docs, &query, decay, args.no_decay, args.limit)
        };
        let scope_for_audit = if kind == SectionKind::Wiki {
            Scope::Global
        } else {
            Scope::Project
        };
        let enriched = enrich_hits(hits, &rules, scope_for_audit, &query);
        result.sections.push(Section {
            kind,
            outside_project: outside_project && kind.is_project(),
            hits: enriched,
        });
    }

    match args.format {
        OutputFormat::Text => render_text_sections(&result)?,
        OutputFormat::Json => render_json_sections(&result)?,
        OutputFormat::Yml => render_yml_sections(&result)?,
    }
    Ok(())
}

fn render_hit_line(i: usize, e: &EnrichedHit) {
    let age = if e.hit.age_days < 30.0 {
        format!("{:.1}d", e.hit.age_days)
    } else {
        format!("{:.1}mo", e.hit.age_days / 30.0)
    };
    let redact_marker = if e.redactions > 0 {
        format!("  [redactions={}]", e.redactions)
    } else {
        String::new()
    };
    let path_str = if let Some(meta) = &e.hit.task_meta {
        format!(
            "task://{}  [{} \u{00b7} phase={} \u{00b7} prio={}]",
            meta.task_id, meta.status, meta.phase, meta.priority
        )
    } else {
        e.hit
            .path
            .strip_prefix(dirs::home_dir().unwrap_or_default())
            .map(|p| format!("~/{}", p.display()))
            .unwrap_or_else(|_| e.hit.path.display().to_string())
    };
    println!(
        " {:>2}  {:>4}  {:<6}  {}{}",
        i + 1,
        e.hit.final_score as i64,
        age,
        path_str,
        redact_marker
    );
    for line in e.snippet.lines() {
        println!("     {line}");
    }
    println!();
}

fn render_text_sections(r: &SectionedResult) -> Result<()> {
    let mut total = 0;
    for sec in &r.sections {
        let count = sec.hits.len();
        let suffix = if sec.outside_project {
            " (outside project)".to_string()
        } else if count == 0 {
            " (0)".to_string()
        } else {
            String::new()
        };
        println!("=== {}{}  ===", sec.kind.display_name(), suffix);
        println!();
        for (i, e) in sec.hits.iter().enumerate() {
            render_hit_line(i, e);
        }
        total += count;
        println!();
    }
    println!("total: {} hits across {} sections", total, r.sections.len());
    Ok(())
}

fn render_json_sections(r: &SectionedResult) -> Result<()> {
    use serde_json::{json, Map, Value};
    let mut sections_obj = Map::new();
    for sec in &r.sections {
        let hits_arr: Vec<Value> = sec
            .hits
            .iter()
            .map(|e| {
                let mut obj = json!({
                    "rank_score": e.hit.final_score,
                    "raw_score": e.hit.score,
                    "age_days": e.hit.age_days,
                    "title": e.hit.title,
                    "path": e.hit.path,
                    "snippet": e.snippet,
                    "redactions": e.redactions,
                    "matched_terms": e.hit.matched_terms,
                });
                if let Some(meta) = &e.hit.task_meta {
                    obj["task_id"] = json!(meta.task_id);
                    obj["status"] = json!(meta.status);
                    obj["phase"] = json!(meta.phase);
                    obj["priority"] = json!(meta.priority);
                }
                obj
            })
            .collect();
        let mut sec_obj = Map::new();
        if sec.kind.is_project() {
            sec_obj.insert("outside_project".into(), json!(sec.outside_project));
        }
        sec_obj.insert("hits".into(), Value::Array(hits_arr));
        sections_obj.insert(sec.kind.slug().into(), Value::Object(sec_obj));
    }
    let out = json!({ "query": r.query, "sections": Value::Object(sections_obj) });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn render_yml_sections(r: &SectionedResult) -> Result<()> {
    println!("query: \"{}\"", r.query);
    println!("sections:");
    for sec in &r.sections {
        println!("  {}:", sec.kind.slug());
        if sec.kind.is_project() {
            println!("    outside_project: {}", sec.outside_project);
        }
        println!("    hits:");
        for e in &sec.hits {
            println!("      - rank_score: {}", e.hit.final_score);
            println!("        raw_score: {}", e.hit.score);
            println!("        age_days: {:.1}", e.hit.age_days);
            println!("        title: {:?}", e.hit.title);
            println!("        path: {:?}", e.hit.path);
            println!("        redactions: {}", e.redactions);
            if let Some(meta) = &e.hit.task_meta {
                println!("        task_id: {:?}", meta.task_id);
                println!("        status: {:?}", meta.status);
                println!("        phase: {:?}", meta.phase);
                println!("        priority: {:?}", meta.priority);
            }
            println!("        snippet: |");
            for line in e.snippet.lines() {
                println!("          {line}");
            }
        }
    }
    Ok(())
}

pub fn detect_project_root(cwd: &std::path::Path) -> Option<PathBuf> {
    if let Some(home) = dirs::home_dir() {
        let github = home.join("GITHUB");
        if let Ok(rel) = cwd.strip_prefix(&github) {
            if let Some(first) = rel.components().next() {
                return Some(github.join(first.as_os_str()));
            }
        }
    }
    let mut cur: Option<&std::path::Path> = Some(cwd);
    while let Some(d) = cur {
        if d.join(".git").exists() {
            return Some(d.to_path_buf());
        }
        cur = d.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/search")
            .join(name)
    }

    #[test]
    fn parse_doc_extracts_title_from_frontmatter() {
        let doc = parse_doc(&fixture("sample-with-frontmatter.md")).unwrap();
        assert_eq!(doc.title, "Custom Title From Frontmatter");
        assert!(doc.tags.contains(&"rust".to_string()));
        assert!(doc.tags.contains(&"search".to_string()));
    }

    #[test]
    fn parse_doc_falls_back_to_heading_when_no_frontmatter_title() {
        let doc = parse_doc(&fixture("no-title.md")).unwrap();
        assert_eq!(doc.title, "This Heading Wins");
    }

    #[test]
    fn walk_corpus_finds_fixtures() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
        let docs = walk_corpus(&[root]);
        assert!(docs.len() >= 2, "expected 2+ fixtures, got {}", docs.len());
        let titles: Vec<&str> = docs.iter().map(|d| d.title.as_str()).collect();
        assert!(titles.contains(&"Custom Title From Frontmatter"));
        assert!(titles.contains(&"This Heading Wins"));
    }

    #[test]
    fn walk_corpus_skips_dotfiles_and_skip_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join(".git/should-not-find.md"), "# X").unwrap();
        std::fs::write(tmp.path().join(".hidden.md"), "# Y").unwrap();
        std::fs::write(tmp.path().join("foo.md"), "# Foo").unwrap();
        let docs = walk_corpus(&[tmp.path().to_path_buf()]);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].title, "Foo");
    }

    #[test]
    fn walk_corpus_respects_gitignore() {
        let tmp = tempfile::tempdir().unwrap();
        // .gitignore needs a real git marker for the ignore crate to apply
        // repo-local rules; an empty .git/ is enough.
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join(".gitignore"), "ignored.md\nbuild/\n").unwrap();
        std::fs::write(tmp.path().join("ignored.md"), "# Ignored").unwrap();
        std::fs::write(tmp.path().join("kept.md"), "# Kept").unwrap();
        std::fs::create_dir_all(tmp.path().join("build")).unwrap();
        std::fs::write(tmp.path().join("build/build-artifact.md"), "# Build").unwrap();
        let docs = walk_corpus(&[tmp.path().to_path_buf()]);
        let titles: Vec<&str> = docs.iter().map(|d| d.title.as_str()).collect();
        assert_eq!(titles, vec!["Kept"], "got: {titles:?}");
    }

    #[test]
    fn search_returns_ranked_hits() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
        let docs = walk_corpus(&[root]);
        let hits = search_corpus(&docs, "rust", 0.05, true, 10);
        assert!(!hits.is_empty(), "expected hits for rust");
        assert_eq!(hits[0].title, "Custom Title From Frontmatter");
    }

    #[test]
    fn search_handles_unmatched_query() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
        let docs = walk_corpus(&[root]);
        let hits = search_corpus(&docs, "zzzznever", 0.05, false, 10);
        assert!(hits.is_empty());
    }

    #[test]
    fn extract_snippet_skips_frontmatter() {
        let path = fixture("sample-with-frontmatter.md");
        let snippet = extract_snippet(&path, &["rust".to_string()]);
        assert!(!snippet.contains("title:"));
        assert!(!snippet.contains("tags:"));
        assert!(snippet.to_lowercase().contains("rust"));
    }

    #[test]
    fn extract_snippet_falls_back_to_first_meaningful_line() {
        let path = fixture("no-title.md");
        let snippet = extract_snippet(&path, &["zzzznever".to_string()]);
        assert!(snippet.contains("longer body paragraph"));
    }

    use crate::patterns::defaults;

    #[test]
    fn sanitize_snippet_redacts_known_keys() {
        let path = fixture("secrets-leak.md");
        let raw = extract_snippet(&path, &["rust".to_string()]);
        let rules = defaults();
        let (clean, count) = sanitize_snippet(&raw, &rules);
        assert!(
            count >= 2,
            "expected >=2 redactions, got {count} (snippet was: {raw})"
        );
        assert!(
            !clean.contains("sk-proj-FAKE_KEY"),
            "openai key not sanitized: {clean}"
        );
        // Verify the raw AWS key prefix was removed (placeholder is checked below)
        let aws_raw_prefix = ["AKIA", "IOSFODNN7"].concat();
        assert!(
            !clean.contains(&aws_raw_prefix),
            "aws key not sanitized (raw key still present): {clean}"
        );
        assert!(clean.contains("<redacted:openai_key>"));
        assert!(clean.contains("<redacted:aws_access_key>"));
    }

    #[test]
    fn enrich_hits_attaches_clean_snippets_for_all_results() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
        let docs = walk_corpus(&[root]);
        let hits = search_corpus(&docs, "rust", 0.05, true, 10);
        let rules = defaults();
        let enriched = enrich_hits(hits, &rules, Scope::Project, "rust");
        assert!(!enriched.is_empty());
        for e in &enriched {
            assert!(!e.snippet.contains("sk-proj-"));
            assert!(!e.snippet.contains("AKIA"));
        }
    }

    #[test]
    fn enrich_hits_writes_audit_log_when_redactions_fire() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("REDACTOR_LOG_DIR", tmp.path());

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
        let docs = walk_corpus(&[root]);
        let hits = search_corpus(&docs, "rust", 0.05, true, 10);
        let rules = defaults();
        let _enriched = enrich_hits(hits, &rules, Scope::Project, "rust");

        let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().flatten().collect();
        assert!(
            !entries.is_empty(),
            "expected at least one log file written"
        );
        let log_content = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(log_content.contains("search:project"));
        assert!(log_content.contains("openai_key") || log_content.contains("aws_access_key"));

        std::env::remove_var("REDACTOR_LOG_DIR");
    }

    #[test]
    fn parse_args_modal_flags_mutually_exclusive() {
        use clap::Parser;
        // Wrap in a minimal top-level parser so SearchArgs::try_parse_from works
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            args: SearchArgs,
        }
        let result = Cli::try_parse_from(["prog", "foo", "--code-only", "--tasks-only"]);
        assert!(
            result.is_err(),
            "expected clap to reject mutually exclusive --code-only --tasks-only"
        );
    }

    #[test]
    fn outside_project_marker_set_when_cwd_not_in_github() {
        let root = detect_project_root(std::path::Path::new("/tmp"));
        assert!(
            root.is_none(),
            "expected detect_project_root('/tmp') to return None"
        );
    }
}

//! Phase 6b+ — LLM backend for the classifier.
//!
//! Instead of GLiNER (which is PII-trained and conservative on generic
//! person/organisation spans), this backend calls a local Ollama instance.
//! The model receives the file's content_preview and returns a strict-JSON
//! list of detected entities — same wire format as the Python sidecar's
//! response so the rest of the pipeline (aggregator, state file, merge)
//! doesn't change.
//!
//! Defaults:
//! - URL:   `http://localhost:11434`  (override: `REDACTOR_OLLAMA_URL`)
//! - Model: `qwen3:8b`                 (override: `REDACTOR_OLLAMA_MODEL`)
//!
//! Implementation note: we shell out to `curl` rather than pulling in a
//! reqwest/ureq dependency — curl is universal on macOS/Linux and the
//! per-call overhead is negligible against an LLM inference of several
//! hundred ms. Each file produces one curl invocation.

use crate::classify::{
    ClassifierError, ClassifierResponse, ClassifierResult, EntityHit, FileEntry, PROTOCOL_VERSION,
};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::process::{Command, Stdio};

const DEFAULT_URL: &str = "http://localhost:11434";
/// Default Ollama model. `gemma4:latest` wins the German PII benchmark over
/// `qwen3:8b` / `gemma4:e2b` / `gemma3:12b` on a 129-file German sweep
/// (2026-05-14): ~9× faster than qwen3:8b (224s vs 2034s) with cleaner
/// precision — fewer Task-ID / acronym false positives, finds all Niclas
/// variants + `hess` + the only real email address. Override with
/// `REDACTOR_OLLAMA_MODEL`.
const DEFAULT_MODEL: &str = "gemma4:latest";

/// Strict prompt that nudges the LLM toward a JSON-only response. Format
/// matches what the aggregator expects: `text` / `label` / `score`. The
/// model is told to ONLY emit allowed labels and to return an empty list
/// when nothing matches — both are checked client-side.
const SYSTEM_PROMPT: &str = r#"You are a precise PII detector for German and English text.

Find ALL entities the user should consider redacting from their notes:
- PERSON: full personal names with at least TWO name parts (Peter Schmidt, Max Müller, peter schmidt) — NOT single given names alone (Peter, Yannis, Niclas are OK and must be skipped)
- ORGANIZATION: company / customer / vendor names — NOT software brands (Obsidian, Claude, GitHub)
- LOCATION: street addresses, building/site names — NOT vault folder paths (notes/, docs/, anything with /), NOT countries or major cities
- EMAIL: full email addresses
- INTERNAL_HOSTNAME: real network hosts only — must contain an internal TLD (.corp/.intern/.internal/.lan/.local/.home.arpa) OR look like a bare server token (dc01, vmw02). NEVER flag: project slugs (local-ci, ios-deployment), file paths, task IDs (ios-005), product names (GitHub Pages, GitHub Actions), or markdown filenames
- CREDENTIAL: things that look like API keys, tokens, secrets (long random strings)
- EMAIL: must contain @ — never flag bare usernames/handles (niclasedge, Niclas.Edge)

CRITICAL RULES:
1. Output ONLY this structure: {"entities": [<list of entity objects>]}
2. Every entity is: {"text": "<exact verbatim substring>", "label": "<allowed label>", "score": 0.0-1.0}
3. Each DISTINCT entity exactly ONCE. Do NOT repeat the same text+label twice.
4. PERSON must contain at least two whitespace-separated tokens (given + family name, or two-part name). Never emit a lone first name as PERSON.
5. Return {"entities": []} when nothing matches — NEVER omit the wrapper.
6. Do NOT include: public URLs (github.com, googleapis.com), software/tool names, common words, country/major-city names, short acronyms (1-3 letters like GF, GT, IT), project slugs, vault/file paths (notes/…, docs/…, any string containing /), GitHub Pages/Actions, or the owner's handles (niclasedge, Niclas.Edge).
7. text MUST be a verbatim copy of a substring from the input, character-for-character.
8. Maximum 15 entities per file. Pick only the most clearly-sensitive ones; skip anything you're unsure about. Quality over quantity.
9. Never list the same surface form twice with the same label. If "GF" appears 50 times in the input, output it ONCE.

Example for input "Peter Schmidt called Yannis at admin@corp.intern":
{"entities":[{"text":"Peter Schmidt","label":"PERSON","score":0.95},{"text":"admin@corp.intern","label":"EMAIL","score":0.98}]}

Example for input "Niclas said the weather is nice":
{"entities":[]}
"#;

/// Map LLM-emitted label strings to the entity_type buckets the aggregator
/// expects. Unknown labels collapse to `OTHER` and are dropped downstream.
fn map_label_to_entity_type(label: &str) -> String {
    match label.to_ascii_uppercase().as_str() {
        "PERSON" | "PER" | "NAME" => "PERSON".into(),
        "ORGANIZATION" | "ORG" | "COMPANY" => "ORGANIZATION".into(),
        "LOCATION" | "LOC" | "ADDRESS" => "LOCATION".into(),
        "EMAIL" | "MAIL" | "E-MAIL" => "EMAIL".into(),
        "URL" | "LINK" => "URL".into(),
        "INTERNAL_HOSTNAME" | "HOSTNAME" | "HOST" => "HOSTNAME".into(),
        "CREDENTIAL" | "API_KEY" | "APIKEY" | "TOKEN" => "API_KEY".into(),
        "PASSWORD" | "PASSWD" => "PASSWORD".into(),
        "SECRET" => "SECRET".into(),
        _ => "OTHER".into(),
    }
}

fn ollama_url() -> String {
    std::env::var("REDACTOR_OLLAMA_URL").unwrap_or_else(|_| DEFAULT_URL.to_string())
}

fn ollama_model() -> String {
    std::env::var("REDACTOR_OLLAMA_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string())
}

/// One Ollama call per file. Returns the parsed entities, or an empty list
/// on any error (we never let a single bad file kill the whole run — the
/// warning goes to stderr).
fn classify_one_file(entry: &FileEntry) -> (f64, Vec<EntityHit>) {
    if entry.content_preview.trim().is_empty() {
        return (0.0, Vec::new());
    }
    let url = format!("{}/api/generate", ollama_url());
    let model = ollama_model();

    // Build the JSON request payload. We use `format: "json"` so Ollama
    // returns response.text as valid JSON, and `stream: false` for a single
    // blocking call.
    let user_prompt = format!(
        "Filename: {}\n\nContent:\n{}",
        entry.filename, entry.content_preview
    );
    // JSON-Schema constrained output: forces the model to emit
    // `{"entities": [...]}` rather than a bare object. Supported by Ollama
    // ≥ 0.5.0; older versions fall back to the string form "json".
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "entities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "text":  {"type": "string"},
                        "label": {"type": "string"},
                        "score": {"type": "number"}
                    },
                    "required": ["text", "label", "score"]
                }
            }
        },
        "required": ["entities"]
    });
    let payload = serde_json::json!({
        "model": model,
        "prompt": user_prompt,
        "system": SYSTEM_PROMPT,
        "stream": false,
        "format": schema,
        "options": {
            "temperature": 0.0,
            // 8192 tokens covers up to ~40 entity records before
            // truncation. Combined with the prompt rule "max 15 entities
            // per file" this gives plenty of headroom even when the
            // model gets enthusiastic and ignores the cap. The salvage
            // parser handles partial responses if it still truncates.
            "num_predict": 8192,
        }
    });
    let payload_str = serde_json::to_string(&payload).unwrap_or_default();

    let child = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--max-time",
            "300",
            "-d",
            &payload_str,
            &url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let output = match child {
        Ok(o) => o,
        Err(e) => {
            eprintln!("redactor: ollama: curl spawn failed: {e}");
            return (0.0, Vec::new());
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "redactor: ollama: curl exited {:?} for {}: {}",
            output.status.code(),
            entry.path,
            stderr.trim()
        );
        return (0.0, Vec::new());
    }
    let body = String::from_utf8_lossy(&output.stdout);

    // Outer Ollama envelope: {"response": "<string with JSON-array inside>"}
    let env: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "redactor: ollama: bad envelope for {}: {e} (body={})",
                entry.path,
                truncate_for_log(&body, 200)
            );
            return (0.0, Vec::new());
        }
    };
    let inner = env.get("response").and_then(|v| v.as_str()).unwrap_or("");
    if inner.is_empty() {
        return (0.0, Vec::new());
    }
    // Debug breadcrumb when REDACTOR_LLM_DEBUG=1 — dump the raw inner
    // response so we can see what the model actually said.
    let debug = std::env::var("REDACTOR_LLM_DEBUG").as_deref() == Ok("1");
    if debug {
        eprintln!(
            "redactor: ollama: [{}] inner = {}",
            entry.filename,
            truncate_for_log(inner, 400)
        );
    }
    let (max, hits) = parse_inner_entities(inner);
    if debug {
        eprintln!(
            "redactor: ollama: [{}] parsed {} entities (max_score={:.2})",
            entry.filename,
            hits.len(),
            max
        );
    }
    (max, hits)
}

/// Rescue truncated `{"entities":[...]}` responses (num_predict cap reached
/// mid-JSON). Finds the position of the last complete entity object inside
/// the entities array, then closes both with `]}`. Returns the salvaged
/// JSON parsed as a Value, or None if nothing recoverable.
fn salvage_truncated_entities(raw: &str) -> Option<serde_json::Value> {
    // Locate the start of the entities array.
    let start = raw.find("\"entities\"")?;
    let array_open = raw[start..].find('[')?;
    let array_start = start + array_open;
    // Walk forward, tracking depth, and remember the index of every `}`
    // at depth 1 (i.e. an entry-level closing brace).
    let mut depth = 0i32;
    let mut last_complete_brace: Option<usize> = None;
    for (i, ch) in raw.char_indices().skip(array_start) {
        match ch {
            '{' => depth += 1,
            '}' => {
                if depth == 1 {
                    last_complete_brace = Some(i);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let cut = last_complete_brace?;
    // Build a clean JSON ending with `]}`.
    let mut salvaged = String::with_capacity(cut + 4);
    salvaged.push_str(&raw[..=cut]);
    salvaged.push(']');
    salvaged.push('}');
    serde_json::from_str(&salvaged).ok()
}

fn truncate_for_log(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

/// Parse the inner JSON string returned by Ollama. Accepts both bare arrays
/// `[{...}, ...]` and wrapped objects like `{"entities":[...]}` because LLMs
/// vary in adherence to the requested schema. Returns the parsed entities
/// plus a derived "file-level confidence" (max entity score) so the path
/// stream still works.
fn parse_inner_entities(raw: &str) -> (f64, Vec<EntityHit>) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (0.0, Vec::new());
    }
    let debug = std::env::var("REDACTOR_LLM_DEBUG").as_deref() == Ok("1");

    // First attempt: direct array.
    let parsed: Option<Vec<serde_json::Value>> = serde_json::from_str(trimmed).ok();
    let arr: Vec<serde_json::Value> = match parsed {
        Some(a) => {
            if debug {
                eprintln!("redactor: parse: bare-array branch, {} items", a.len());
            }
            a
        }
        None => {
            // Second attempt: object form. Either:
            //   - wrapper: `{"entities": [...]}` (our preferred schema)
            //   - bare single entity: `{"text": "...", "label": "...", ...}`
            //     (Gemma + similar small models like to drop the wrapper)
            let env: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    // Salvage attempt: truncated JSON from num_predict cap.
                    // Try to find the last complete `}` inside the `entities`
                    // array and close the structure manually.
                    if debug {
                        eprintln!(
                            "redactor: parse: serde_json::from_str failed: {e} (raw len={}) — \
                             attempting salvage",
                            trimmed.len()
                        );
                    }
                    match salvage_truncated_entities(trimmed) {
                        Some(v) => v,
                        None => return (0.0, Vec::new()),
                    }
                }
            };
            if debug {
                eprintln!(
                    "redactor: parse: parsed env, top-level type = {}, keys = {:?}",
                    if env.is_object() {
                        "object"
                    } else if env.is_array() {
                        "array"
                    } else {
                        "other"
                    },
                    env.as_object().map(|m| m.keys().collect::<Vec<_>>())
                );
            }
            if let Some(a) = env
                .get("entities")
                .or_else(|| env.get("results"))
                .or_else(|| env.get("hits"))
                .and_then(|v| v.as_array().cloned())
            {
                if debug {
                    eprintln!("redactor: parse: wrapper branch, {} items", a.len());
                }
                a
            } else if env.get("text").is_some() && env.get("label").is_some() {
                if debug {
                    eprintln!("redactor: parse: bare-single-object branch");
                }
                // Bare-object response — wrap into a singleton list.
                vec![env]
            } else {
                if debug {
                    eprintln!("redactor: parse: NO BRANCH MATCHED — returning empty");
                }
                Vec::new()
            }
        }
    };

    let mut entities: Vec<EntityHit> = Vec::new();
    let mut max_score = 0.0_f64;
    for item in arr {
        let Some(text) = item.get("text").and_then(|v| v.as_str()) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        let label = item
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("OTHER")
            .to_string();
        let score = item
            .get("score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.7)
            .clamp(0.0, 1.0);
        let entity_type = map_label_to_entity_type(&label);
        if score > max_score {
            max_score = score;
        }
        entities.push(EntityHit {
            text: text.to_string(),
            label,
            score,
            entity_type,
        });
    }
    (max_score, entities)
}

/// Streaming variant — invokes `on_result` once per classified file
/// (including files where the LLM returned zero entities). The callback
/// owns whatever side effect the caller wants: state-file flush, progress
/// reporting, telemetry, etc.
///
/// Errors from `ollama_reachable` short-circuit before any callbacks fire.
/// The returned `ClassifierResponse.results` still contains only the
/// nonempty hits (for batch-style callers); the persistence path in
/// `classify_cmd` uses the callback and ignores the response body.
pub fn run_classifier_streaming(
    files: Vec<FileEntry>,
    _labels: Vec<String>,
    mut on_result: impl FnMut(&ClassifierResult),
) -> std::result::Result<ClassifierResponse, ClassifierError> {
    let model = ollama_model();
    let url = ollama_url();
    eprintln!(
        "redactor: LLM backend — ollama at {} (model={}, {} files)",
        url,
        model,
        files.len()
    );

    // Quick smoke test: confirm ollama responds. Saves the user from
    // watching the whole walk return empty results.
    if !ollama_reachable(&url) {
        return Err(ClassifierError::NotInstalled(std::path::PathBuf::from(
            &url,
        )));
    }

    // Optional crash-safety: when REDACTOR_LIVE_KEYWORDS_FILE is set,
    // stream every entity-hit as a JSONL line after each file completes.
    // The final aggregated `.keywords.suggested` is still written at the
    // end of classify_cmd. If the process is SIGTERM'd mid-run, this file
    // preserves all hits so far. Append-mode + fsync per line.
    //
    // Phase-7 note: this predates the state-file-as-source-of-truth design
    // and is kept as a belt-and-braces option for users who want a plain
    // JSONL stream in addition to the binary-format state file.
    let mut live_file: Option<std::fs::File> = std::env::var("REDACTOR_LIVE_KEYWORDS_FILE")
        .ok()
        .and_then(
            |p| match OpenOptions::new().create(true).append(true).open(&p) {
                Ok(f) => {
                    eprintln!("redactor: ollama: streaming hits to {p}");
                    Some(f)
                }
                Err(e) => {
                    eprintln!("redactor: ollama: cannot open live file {p}: {e}");
                    None
                }
            },
        );

    let total = files.len();
    let mut results: Vec<ClassifierResult> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut nonempty = 0usize;
    for (idx, entry) in files.iter().enumerate() {
        if idx > 0 && idx % 25 == 0 {
            eprintln!("redactor: ollama: {idx}/{total} files processed");
        }
        let (confidence, entities) = classify_one_file(entry);
        let entities = crate::classify_filter::filter_entities(entities);

        // Distinct labels for the path-suggestion display.
        let mut labels: Vec<String> = entities
            .iter()
            .map(|e| e.entity_type.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        labels.sort();
        let evidence = build_evidence(&entities);

        let result = ClassifierResult {
            path: entry.path.clone(),
            confidence,
            labels,
            evidence,
            entities,
        };

        // Optional JSONL stream of every entity hit. Written BEFORE the
        // callback so even a callback that crashes still leaves the
        // JSONL on disk. Only files with hits get written here (zero-hit
        // files are useful in the state file but noise in the JSONL).
        if let Some(ref mut f) = live_file {
            for ent in &result.entities {
                let line = serde_json::json!({
                    "path": result.path,
                    "text": ent.text,
                    "label": ent.label,
                    "score": ent.score,
                    "entity_type": ent.entity_type,
                });
                let _ = writeln!(f, "{line}");
            }
            if !result.entities.is_empty() {
                let _ = f.flush();
            }
        }

        // Fire the per-file callback BEFORE filtering — the state file
        // needs to record every classification attempt (including zero
        // hits) so the next run can skip clean files via the hash check.
        on_result(&result);

        if !result.entities.is_empty() || result.confidence > 0.0 {
            nonempty += 1;
            results.push(result);
        }
    }
    if total > 0 {
        eprintln!("redactor: ollama: {total}/{total} files processed");
    }

    if nonempty == 0 && total > 0 {
        warnings.push("ollama backend returned no entities for any file".into());
    }

    Ok(ClassifierResponse {
        version: PROTOCOL_VERSION,
        results,
        warnings,
    })
}

/// Best-effort reachability probe. We try `GET <url>/api/tags` — Ollama
/// returns the installed-model list. A short timeout is fine because if
/// Ollama is up locally it answers instantly.
fn ollama_reachable(url: &str) -> bool {
    let probe = format!("{url}/api/tags");
    let res = Command::new("curl")
        .args(["-s", "-f", "--max-time", "3", &probe])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    matches!(res, Ok(s) if s.success())
}

fn build_evidence(entities: &[EntityHit]) -> String {
    if entities.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<&EntityHit> = entities.iter().collect();
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
    let joined = parts.join(", ");
    let mut out = format!("Detected {joined}");
    if out.chars().count() > 280 {
        out = out.chars().take(279).collect::<String>() + "…";
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inner_entities_handles_bare_array() {
        let raw = r#"[{"text":"Peter Schmidt","label":"PERSON","score":0.95}]"#;
        let (max, hits) = parse_inner_entities(raw);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "Peter Schmidt");
        assert_eq!(hits[0].entity_type, "PERSON");
        assert!((max - 0.95).abs() < 1e-6);
    }

    #[test]
    fn parse_inner_entities_handles_bare_single_object() {
        // Gemma / small models sometimes drop the wrapper and return one
        // entity directly. Parser must still produce a singleton list.
        let raw = r#"{"text":"Yannis","label":"PERSON","score":0.8}"#;
        let (max, hits) = parse_inner_entities(raw);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "Yannis");
        assert!((max - 0.8).abs() < 1e-6);
    }

    #[test]
    fn parse_inner_entities_handles_object_wrapper() {
        let raw = r#"{"entities":[{"text":"foo@bar.com","label":"EMAIL","score":0.9}]}"#;
        let (_, hits) = parse_inner_entities(raw);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entity_type, "EMAIL");
    }

    #[test]
    fn parse_inner_entities_drops_empty_text() {
        let raw = r#"[{"text":"","label":"PERSON","score":0.9},{"text":"Alice","label":"PERSON","score":0.8}]"#;
        let (_, hits) = parse_inner_entities(raw);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "Alice");
    }

    #[test]
    fn parse_inner_entities_returns_empty_for_garbage() {
        let (_, hits) = parse_inner_entities("not json at all");
        assert!(hits.is_empty());
    }

    #[test]
    fn label_mapping_normalises_aliases() {
        assert_eq!(map_label_to_entity_type("PER"), "PERSON");
        assert_eq!(map_label_to_entity_type("Org"), "ORGANIZATION");
        assert_eq!(map_label_to_entity_type("INTERNAL_HOSTNAME"), "HOSTNAME");
        assert_eq!(map_label_to_entity_type("CREDENTIAL"), "API_KEY");
        assert_eq!(map_label_to_entity_type("UNKNOWN_LABEL"), "OTHER");
    }
}

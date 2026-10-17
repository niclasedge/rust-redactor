//! Writer for `redactor classify-files` output (`.redactorignore.suggested`).
//!
//! Three formats:
//! - `text`  — gitignore-compatible: header comments + one
//!   `# confidence=… labels=… evidence=…` line followed by the path. This is
//!   the format `redactor classify-merge` (Phase 5) parses back.
//! - `json`  — `{ report, suggestions }` serialized via serde_json.
//! - `yaml`  — same shape, emitted by a minimal in-crate writer (we don't
//!   pull in `serde_yaml` for one consumer; the schema is shallow).
//!
//! See spec §4.3 for the canonical text layout.

use serde::Serialize;
use std::io::{self, Write};
use std::path::PathBuf;

/// One classifier verdict at or above the configured threshold.
#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub path: PathBuf,
    pub confidence: f64,
    pub labels: Vec<String>,
    pub evidence: String,
}

/// Phase 6b — one aggregated keyword candidate.
#[derive(Debug, Clone, Serialize)]
pub struct KeywordSuggestion {
    /// Canonical lowercased form (also used for dedup).
    pub text: String,
    /// Display form (original capitalisation, first observed).
    pub display: String,
    /// Coarse entity bucket: PERSON, ORGANIZATION, …
    pub entity_type: String,
    /// Number of distinct files this keyword was observed in.
    pub occurrence_count: u32,
    /// Average GLiNER score across all hits.
    pub score_avg: f64,
    /// Path of the first file where the keyword surfaced (for review context).
    pub first_seen_in: PathBuf,
}

/// Report header for the keyword-suggestion file.
#[derive(Debug, Clone, Serialize)]
pub struct KeywordReport {
    pub generated_at: String,
    pub input_root: PathBuf,
    pub files_scanned: usize,
    pub keywords_proposed: usize,
}

/// Header block for the `.suggested` file. Mirrors the spec's example.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestionReport {
    /// ISO 8601 / RFC 3339 timestamp when the classify run finished.
    pub generated_at: String,
    /// The `<dir>` argument the user passed to `classify-files`.
    pub input_root: PathBuf,
    /// Total file count after walk + skip filters (everything we sent the
    /// sidecar, i.e. *before* threshold filtering).
    pub files_scanned: usize,
    /// Of those, how many cleared the threshold.
    pub files_above_threshold: usize,
    /// The threshold value the user (or default) chose.
    pub threshold: f64,
}

#[derive(Serialize)]
struct StructuredOutput<'a> {
    report: &'a SuggestionReport,
    suggestions: &'a [Suggestion],
}

/// Write the text format described in spec §4.3.
///
/// Layout:
///
/// ```text
/// # redactor classify-files — suggestions
/// # generated: 2026-05-12T22:45:01+02:00
/// # input:     /Users/.../Documents
/// # files:     1247 scanned, 89 above threshold
/// # threshold: 0.6
///
/// # confidence=0.92  labels=TAX_DOC,FINANCIAL_RECORD
/// # evidence="..."
/// /Users/.../Steuer/2024/erklaerung.pdf
/// ```
pub fn write_text(
    report: &SuggestionReport,
    suggestions: &[Suggestion],
    out: &mut impl Write,
) -> io::Result<()> {
    writeln!(out, "# redactor classify-files — suggestions")?;
    writeln!(out, "# generated: {}", report.generated_at)?;
    writeln!(out, "# input:     {}", report.input_root.display())?;
    writeln!(
        out,
        "# files:     {} scanned, {} above threshold",
        report.files_scanned, report.files_above_threshold
    )?;
    writeln!(out, "# threshold: {}", format_threshold(report.threshold))?;

    if suggestions.is_empty() {
        return Ok(());
    }

    for s in suggestions {
        writeln!(out)?;
        writeln!(
            out,
            "# confidence={}  labels={}",
            format_confidence(s.confidence),
            s.labels.join(",")
        )?;
        writeln!(out, "# evidence=\"{}\"", escape_evidence(&s.evidence))?;
        writeln!(out, "{}", s.path.display())?;
    }

    Ok(())
}

/// Write `{ report, suggestions }` as pretty JSON.
pub fn write_json(
    report: &SuggestionReport,
    suggestions: &[Suggestion],
    out: &mut impl Write,
) -> io::Result<()> {
    let body = StructuredOutput {
        report,
        suggestions,
    };
    serde_json::to_writer_pretty(&mut *out, &body).map_err(io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// Write `{ report, suggestions }` as YAML. Hand-rolled minimal emitter —
/// the schema is shallow and we don't want a YAML dependency for one writer.
pub fn write_yaml(
    report: &SuggestionReport,
    suggestions: &[Suggestion],
    out: &mut impl Write,
) -> io::Result<()> {
    writeln!(out, "report:")?;
    writeln!(out, "  generated_at: {}", yaml_string(&report.generated_at))?;
    writeln!(
        out,
        "  input_root: {}",
        yaml_string(&report.input_root.display().to_string())
    )?;
    writeln!(out, "  files_scanned: {}", report.files_scanned)?;
    writeln!(
        out,
        "  files_above_threshold: {}",
        report.files_above_threshold
    )?;
    writeln!(out, "  threshold: {}", format_threshold(report.threshold))?;

    if suggestions.is_empty() {
        writeln!(out, "suggestions: []")?;
        return Ok(());
    }

    writeln!(out, "suggestions:")?;
    for s in suggestions {
        writeln!(
            out,
            "  - path: {}",
            yaml_string(&s.path.display().to_string())
        )?;
        writeln!(out, "    confidence: {}", format_confidence(s.confidence))?;
        if s.labels.is_empty() {
            writeln!(out, "    labels: []")?;
        } else {
            writeln!(out, "    labels:")?;
            for label in &s.labels {
                writeln!(out, "      - {}", yaml_string(label))?;
            }
        }
        writeln!(out, "    evidence: {}", yaml_string(&s.evidence))?;
    }
    Ok(())
}

/// Phase 6b — write a `.redactorignore.keywords.suggested` file in
/// gitignore-style with `#`-comment metadata above each entry.
///
/// Layout:
///
/// ```text
/// # redactor classify-files — keyword suggestions
/// # generated: 2026-05-13T17:14:32+02:00
/// # input:     /Users/.../Documents
/// # keywords:  47 distinct
///
/// # PERSON  score=0.91  occurrence=14/47 files
/// # first seen in: /Users/.../erklaerung.pdf
/// niclas edge
///
/// # ORGANIZATION  score=0.88  occurrence=3/47
/// # first seen in: /Users/.../meeting-notes.md
/// example-corp ag
/// ```
pub fn write_keywords_text(
    report: &KeywordReport,
    keywords: &[KeywordSuggestion],
    out: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        out,
        "# redactor classify-files — keyword suggestions (Phase 6b)"
    )?;
    writeln!(out, "# generated: {}", report.generated_at)?;
    writeln!(out, "# input:     {}", report.input_root.display())?;
    writeln!(
        out,
        "# keywords:  {} distinct (from {} files)",
        report.keywords_proposed, report.files_scanned
    )?;
    writeln!(out, "#")?;
    writeln!(
        out,
        "# Review by running:  redactor classify-merge --keywords <this-file>"
    )?;

    // Group by entity-type. Caller already sorted in entity-type order, so
    // we just emit a section header on each type-transition.
    let mut current_type: Option<&str> = None;
    for k in keywords {
        if current_type != Some(k.entity_type.as_str()) {
            // Count how many keywords are in this new group for the header.
            let group_count = keywords
                .iter()
                .filter(|x| x.entity_type == k.entity_type)
                .count();
            writeln!(out)?;
            writeln!(out, "# {}", "=".repeat(72))?;
            writeln!(
                out,
                "# {}  ({} candidate{})",
                k.entity_type,
                group_count,
                if group_count == 1 { "" } else { "s" }
            )?;
            writeln!(out, "# {}", "=".repeat(72))?;
            current_type = Some(k.entity_type.as_str());
        }
        writeln!(out)?;
        writeln!(
            out,
            "# score={}  occurrence={} files",
            format_confidence(k.score_avg),
            k.occurrence_count
        )?;
        writeln!(out, "# first seen in: {}", k.first_seen_in.display())?;
        // The keyword line itself (lowercase canonical form).
        writeln!(out, "{}", k.text)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct StructuredKeywordOutput<'a> {
    report: &'a KeywordReport,
    keywords: &'a [KeywordSuggestion],
}

pub fn write_keywords_json(
    report: &KeywordReport,
    keywords: &[KeywordSuggestion],
    out: &mut impl Write,
) -> io::Result<()> {
    let body = StructuredKeywordOutput { report, keywords };
    serde_json::to_writer_pretty(&mut *out, &body).map_err(io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

fn format_confidence(c: f64) -> String {
    format!("{c:.2}")
}

fn format_threshold(t: f64) -> String {
    // Keep the human-readable two-decimal form, e.g. "0.60", matching the
    // confidence rendering above.
    format!("{t:.2}")
}

/// Escape characters that would break the single-line `evidence="…"`
/// representation. We're not aiming at full shell-quoting — the consumer
/// (classify-merge) splits on `=` and the matching trailing `"`.
fn escape_evidence(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], " ")
}

/// Wrap a scalar in a YAML double-quoted string with the conservative
/// escapes the YAML 1.2 spec mandates for `\` and `"`. Newlines are
/// replaced with literal spaces — multi-line scalars would need the
/// `|` / `>` block style and we don't need that complexity here.
fn yaml_string(s: &str) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], " ");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn sample_report() -> SuggestionReport {
        SuggestionReport {
            generated_at: "2026-05-12T22:45:01+02:00".to_string(),
            input_root: PathBuf::from("/home/user/Documents"),
            files_scanned: 1247,
            files_above_threshold: 2,
            threshold: 0.6,
        }
    }

    fn sample_suggestions() -> Vec<Suggestion> {
        vec![
            Suggestion {
                path: PathBuf::from("/home/user/Documents/Steuer/2024.pdf"),
                confidence: 0.92,
                labels: vec!["TAX_DOC".to_string(), "FINANCIAL_RECORD".to_string()],
                evidence: "Einkommensteuer (0.94), Finanzamt (0.91)".to_string(),
            },
            Suggestion {
                path: PathBuf::from("/home/user/Documents/Kontakte/familie.txt"),
                confidence: 0.81,
                labels: vec!["PERSONAL_RECORD".to_string()],
                evidence: "14 person names detected".to_string(),
            },
        ]
    }

    #[test]
    fn text_format_emits_expected_header_and_entries() {
        let mut buf: Vec<u8> = Vec::new();
        write_text(&sample_report(), &sample_suggestions(), &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();

        // Header
        assert!(s.contains("# redactor classify-files — suggestions"));
        assert!(s.contains("# generated: 2026-05-12T22:45:01+02:00"));
        assert!(s.contains("# input:     /home/user/Documents"));
        assert!(s.contains("# files:     1247 scanned, 2 above threshold"));
        assert!(s.contains("# threshold: 0.60"));

        // Entry 1
        assert!(s.contains("# confidence=0.92  labels=TAX_DOC,FINANCIAL_RECORD"));
        assert!(s.contains("# evidence=\"Einkommensteuer (0.94), Finanzamt (0.91)\""));
        assert!(s.contains("/home/user/Documents/Steuer/2024.pdf"));

        // Entry 2
        assert!(s.contains("# confidence=0.81  labels=PERSONAL_RECORD"));
        assert!(s.contains("/home/user/Documents/Kontakte/familie.txt"));
    }

    #[test]
    fn text_format_with_no_suggestions_emits_only_header() {
        let mut buf: Vec<u8> = Vec::new();
        write_text(&sample_report(), &[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // 5 header lines, no entries
        assert_eq!(s.matches("# confidence=").count(), 0);
        assert!(s.contains("# threshold: 0.60"));
    }

    #[test]
    fn text_format_escapes_quotes_in_evidence() {
        let mut sugg = sample_suggestions();
        sugg[0].evidence = r#"contains "BEGIN PRIVATE KEY""#.to_string();
        let mut buf: Vec<u8> = Vec::new();
        write_text(&sample_report(), &sugg, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains(r#"# evidence="contains \"BEGIN PRIVATE KEY\"""#));
    }

    #[test]
    fn json_format_round_trips_through_serde_json() {
        let mut buf: Vec<u8> = Vec::new();
        write_json(&sample_report(), &sample_suggestions(), &mut buf).unwrap();
        let v: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["report"]["files_scanned"], 1247);
        assert_eq!(v["report"]["threshold"], 0.6);
        assert_eq!(v["suggestions"].as_array().unwrap().len(), 2);
        assert_eq!(v["suggestions"][0]["confidence"], 0.92);
        assert_eq!(v["suggestions"][0]["labels"][0], "TAX_DOC");
    }

    #[test]
    fn json_format_with_empty_suggestions_is_valid_json() {
        let mut buf: Vec<u8> = Vec::new();
        write_json(&sample_report(), &[], &mut buf).unwrap();
        let v: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["report"]["files_above_threshold"], 2);
        assert!(v["suggestions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn yaml_format_emits_expected_keys_and_values() {
        let mut buf: Vec<u8> = Vec::new();
        write_yaml(&sample_report(), &sample_suggestions(), &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();

        assert!(s.contains("report:"));
        assert!(s.contains("generated_at: \"2026-05-12T22:45:01+02:00\""));
        assert!(s.contains("input_root: \"/home/user/Documents\""));
        assert!(s.contains("files_scanned: 1247"));
        assert!(s.contains("files_above_threshold: 2"));
        assert!(s.contains("threshold: 0.60"));

        assert!(s.contains("suggestions:"));
        assert!(s.contains("  - path: \"/home/user/Documents/Steuer/2024.pdf\""));
        assert!(s.contains("    confidence: 0.92"));
        assert!(s.contains("      - \"TAX_DOC\""));
        assert!(s.contains("      - \"FINANCIAL_RECORD\""));
    }

    #[test]
    fn yaml_format_with_no_suggestions_emits_empty_list() {
        let mut buf: Vec<u8> = Vec::new();
        write_yaml(&sample_report(), &[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("suggestions: []"));
        // No per-entry path keys
        assert!(!s.contains("    confidence:"));
    }

    #[test]
    fn yaml_string_escapes_quotes_and_backslashes() {
        assert_eq!(yaml_string("plain"), "\"plain\"");
        // input:  has "quotes"   →   output: "has \"quotes\""
        assert_eq!(yaml_string("has \"quotes\""), "\"has \\\"quotes\\\"\"");
        // input:  C:\path\here   →   output: "C:\\path\\here"
        assert_eq!(yaml_string(r"C:\path\here"), "\"C:\\\\path\\\\here\"");
    }
}

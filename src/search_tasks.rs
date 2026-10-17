//! Project task corpus integration for `redactor search`.
//!
//! Pulls tasks (title+body+metadata) and notes from the `task` CLI and
//! converts them into searchable `Doc` values with BM25 field-mapping:
//! title=task title, tags=phase+status+priority+user_tags, content=body+notes.

use crate::search::{Doc, TaskMeta};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

#[derive(Debug, Deserialize)]
pub struct TaskJson {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    pub status: String,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub phase_id: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FeedEvent {
    pub task_id: String,
    pub kind: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// Pure function — testable without shell-out.
pub fn parse_tasks_corpus(list_json: &str, feed_json: &str) -> Vec<Doc> {
    let tasks: Vec<TaskJson> = match serde_json::from_str(list_json) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let events: Vec<FeedEvent> = serde_json::from_str(feed_json).unwrap_or_default();

    // Derive prefix set from list (rred-44 -> "rred")
    let prefix_set: HashSet<String> = tasks
        .iter()
        .filter_map(|t| t.id.split('-').next().map(|p| p.to_string()))
        .collect();

    // Group notes by task_id, filtered to project prefixes
    let mut notes_by_id: HashMap<String, Vec<String>> = HashMap::new();
    for event in events {
        if event.kind != "note" {
            continue;
        }
        let prefix = match event.task_id.split('-').next() {
            Some(p) => p.to_string(),
            None => continue,
        };
        if !prefix_set.contains(&prefix) {
            continue;
        }
        if let Some(text) = event.note {
            notes_by_id.entry(event.task_id).or_default().push(text);
        }
    }

    tasks
        .into_iter()
        .map(|t| {
            let phase = t.phase_id.clone().unwrap_or_default();
            let phase_short = phase.split(':').next_back().unwrap_or(&phase).to_string();
            let priority = t.priority.clone().unwrap_or_default();
            let user_tags = t.tags.clone().unwrap_or_default().join(" ");
            let tags_joined = format!("{} {} {} {}", phase_short, t.status, priority, user_tags);
            let notes_joined = notes_by_id
                .get(&t.id)
                .map(|v| v.join("\n\n"))
                .unwrap_or_default();
            let content = if notes_joined.is_empty() {
                t.body.clone()
            } else {
                format!("{}\n\n{}", t.body, notes_joined)
            };
            let mtime = parse_rfc3339(t.updated_at.as_deref()).unwrap_or(SystemTime::UNIX_EPOCH);
            Doc {
                path: PathBuf::from(format!("task://{}", t.id)),
                title: t.title,
                tags: vec![tags_joined],
                content,
                mtime,
                task_meta: Some(TaskMeta {
                    task_id: t.id,
                    status: t.status,
                    phase: phase_short,
                    priority,
                }),
            }
        })
        .collect()
}

fn parse_rfc3339(s: Option<&str>) -> Option<SystemTime> {
    use chrono::DateTime;
    let s = s?;
    let dt = DateTime::parse_from_rfc3339(s).ok()?;
    Some(SystemTime::from(dt))
}

/// Shell out to the `task` CLI; returns empty Vec on any failure (with
/// stderr warning). The wrapper for production use; tests should call
/// `parse_tasks_corpus` directly.
pub fn fetch_tasks_corpus() -> Vec<Doc> {
    let list_out = match Command::new("task")
        .args(["list", "--format", "json", "--limit", "1000"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            eprintln!(
                "redactor search: task corpus unavailable (task list exit {}); continuing with file corpus only",
                o.status
            );
            return vec![];
        }
        Err(e) => {
            eprintln!(
                "redactor search: task corpus unavailable ({e}); continuing with file corpus only"
            );
            return vec![];
        }
    };

    let feed_out = match Command::new("task")
        .args(["feed", "--limit", "1000", "--format", "json"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => Vec::new(),
    };

    let list_str = String::from_utf8_lossy(&list_out);
    let feed_str = String::from_utf8_lossy(&feed_out);
    parse_tasks_corpus(&list_str, &feed_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST_JSON: &str = r#"[
        {"id":"rred-90","title":"Test alpha","body":"alpha body","status":"completed","priority":"medium","phase_id":"rust-redactor:alpha","updated_at":"2026-04-29T10:00:00+00:00"},
        {"id":"rred-91","title":"Test beta","body":"beta body","status":"pending","priority":"low","phase_id":"rust-redactor:beta","updated_at":"2026-05-01T10:00:00+00:00"}
    ]"#;

    const FEED_JSON: &str = r#"[
        {"task_id":"rred-90","kind":"note","note":"deployed in commit abc123"},
        {"task_id":"other-1","kind":"note","note":"unrelated note from another project"},
        {"task_id":"rred-91","kind":"status_change","note":null}
    ]"#;

    #[test]
    fn parse_tasks_corpus_with_fixtures() {
        let docs = parse_tasks_corpus(LIST_JSON, FEED_JSON);
        assert_eq!(docs.len(), 2);

        let alpha = docs.iter().find(|d| d.title == "Test alpha").unwrap();
        assert!(alpha.content.contains("alpha body"));
        assert!(alpha.content.contains("deployed in commit abc123"));

        let beta = docs.iter().find(|d| d.title == "Test beta").unwrap();
        assert_eq!(beta.content, "beta body");

        let unrelated = docs.iter().find(|d| d.title.contains("unrelated"));
        assert!(
            unrelated.is_none(),
            "feed event from other project should be filtered"
        );

        let alpha_meta = alpha.task_meta.as_ref().unwrap();
        assert_eq!(alpha_meta.task_id, "rred-90");
        assert_eq!(alpha_meta.status, "completed");
        assert_eq!(alpha_meta.phase, "alpha");
        assert_eq!(alpha_meta.priority, "medium");

        let alpha_path_str = alpha.path.to_string_lossy();
        assert_eq!(alpha_path_str, "task://rred-90");
    }
}

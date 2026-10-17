//! Shared false-positive filters for classifier entity hits (GLiNER + Ollama).

use crate::classify::EntityHit;

/// User / owner handles that must never become keyword candidates.
const IGNORED_IDENTITIES: &[&str] = &["niclasedge", "niclas.edge", "niclas edge"];

/// Product / platform names the LLM often mislabels as HOSTNAME or ORG.
const PLATFORM_NOISE: &[&str] = &[
    "github pages",
    "github actions",
    "codeberg pages",
    "forgejo actions",
    "gitlab ci",
    "gitlab pages",
];

/// Obsidian-PKM / vault path prefixes mislabeled as LOCATION.
const VAULT_PATH_PREFIXES: &[&str] = &[
    "atlas/",
    "efforts/",
    "calendar/",
    "archive/",
    "raw/",
    "logs/",
    "tasks/",
    "wiki/",
    "+/",
];

fn looks_like_vault_or_file_path(text: &str) -> bool {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/') || trimmed.contains('\\') {
        return true;
    }
    if lower.ends_with('/') {
        return true;
    }
    VAULT_PATH_PREFIXES
        .iter()
        .any(|p| lower.starts_with(p) || lower.contains(&format!("/{p}")))
}
pub fn should_drop_entity(text: &str, entity_type: &str) -> bool {
    if is_ignored_identity(text) {
        return true;
    }
    is_low_quality_keyword_hit(text, entity_type)
}

/// Filter a hit list in-place semantics — returns kept hits.
pub fn filter_entities(entities: Vec<EntityHit>) -> Vec<EntityHit> {
    entities
        .into_iter()
        .filter(|e| !should_drop_entity(&e.text, &e.entity_type))
        .collect()
}

fn normalize_identity(s: &str) -> String {
    s.trim().to_ascii_lowercase().replace([' ', '_'], "")
}

fn is_ignored_identity(text: &str) -> bool {
    let norm = normalize_identity(text);
    let dotted = text.trim().to_ascii_lowercase();
    IGNORED_IDENTITIES
        .iter()
        .any(|id| normalize_identity(id) == norm || dotted == *id)
}

/// Quality heuristics for keyword candidates and LLM entity hits.
pub fn is_low_quality_keyword_hit(text: &str, entity_type: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let trimmed = text.trim();

    if PLATFORM_NOISE.iter().any(|p| lower == *p) {
        return true;
    }

    match entity_type {
        "EMAIL" => {
            // Must look like an email, not a bare username/handle.
            !trimmed.contains('@')
        }
        "API_KEY" | "SECRET" | "PASSWORD" => {
            if trimmed.chars().count() < 16 {
                return true;
            }
            let has_digit = trimmed.chars().any(|c| c.is_ascii_digit());
            let hex_ratio = trimmed
                .chars()
                .filter(|c| c.is_ascii_hexdigit() || matches!(c, '-' | '_'))
                .count() as f64
                / trimmed.chars().count() as f64;
            !has_digit && hex_ratio < 0.85
        }
        "HOSTNAME" => {
            // Not a hostname: slugs, paths, task ids, product names, files.
            if lower.contains('/') || lower.contains('\\') {
                return true;
            }
            const FILE_EXTS: &[&str] = &[
                ".md", ".txt", ".json", ".csv", ".tsv", ".yaml", ".yml", ".toml", ".log", ".html",
                ".js", ".ts", ".py", ".rs", ".pdf", ".docx", ".xlsx", ".pptx",
            ];
            if FILE_EXTS.iter().any(|e| lower.ends_with(e)) {
                return true;
            }
            // Real hostnames have a dot (internal TLD) or port — not bare slugs.
            if !lower.contains('.') && !lower.contains(':') {
                return true;
            }
            // Kebab/project slug with dotless label (local-ci, ios-deployment).
            if lower.contains('-') && !lower.contains('.') {
                return true;
            }
            false
        }
        "ORGANIZATION" => {
            if trimmed.chars().count() <= 3 {
                return true;
            }
            if trimmed.chars().count() <= 4
                && trimmed.chars().all(|c| c.is_ascii_alphanumeric())
                && (trimmed
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    || trimmed
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
            {
                return true;
            }
            if trimmed.chars().count() <= 6
                && trimmed.chars().all(|c| c.is_ascii_alphabetic())
                && !trimmed
                    .chars()
                    .any(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u' | 'y'))
            {
                return true;
            }
            if trimmed.matches('-').count() >= 2 && !trimmed.contains(' ') {
                return true;
            }
            const SOFTWARE_BRANDS: &[&str] = &[
                "github",
                "gitlab",
                "obsidian",
                "claude",
                "anthropic",
                "openai",
                "sharepoint",
                "onedrive",
                "google",
                "microsoft",
                "apple",
                "ollama",
                "huggingface",
                "discord",
                "slack",
                "notion",
                "linear",
                "jira",
                "asana",
                "trello",
                "codeberg",
                "forgejo",
            ];
            if SOFTWARE_BRANDS.contains(&lower.as_str()) {
                return true;
            }
            if lower.contains('/')
                || lower.ends_with(".md")
                || lower.ends_with(".csv")
                || lower.ends_with(".json")
            {
                return true;
            }
            false
        }
        "PERSON" => trimmed.split_whitespace().count() < 2,
        "LOCATION" => {
            // Session logs label vault folder paths as LOCATION constantly.
            if looks_like_vault_or_file_path(trimmed) {
                return true;
            }
            // Project/doc titles in path style (Acme-Development Übersicht).
            if trimmed.contains('-') && trimmed.split_whitespace().count() >= 2 {
                let last = trimmed.split_whitespace().next_back().unwrap_or("");
                if matches!(
                    last.to_ascii_lowercase().as_str(),
                    "übersicht" | "overview" | "readme" | "changelog" | "index"
                ) {
                    return true;
                }
            }
            false
        }
        "URL" => !lower.contains('.') && !lower.starts_with("http"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_session_log_false_positives() {
        let fps = [
            ("local-ci", "HOSTNAME"),
            ("local-ci-pipeline-spec.md", "HOSTNAME"),
            ("ios-deployment", "HOSTNAME"),
            (
                "notes/ios/ios-deployment/specs/local-ci-pipeline-spec.md",
                "HOSTNAME",
            ),
            ("GitHub Pages", "HOSTNAME"),
            ("GitHub Actions", "HOSTNAME"),
            ("ios-005", "HOSTNAME"),
            ("niclasedge", "EMAIL"),
            ("Niclas.Edge", "EMAIL"),
        ];
        for (text, ty) in fps {
            assert!(
                should_drop_entity(text, ty),
                "expected drop for {text:?} ({ty})"
            );
        }
    }

    #[test]
    fn keeps_real_email_and_internal_host() {
        assert!(!should_drop_entity("admin@corp.intern", "EMAIL"));
        assert!(!should_drop_entity("vmw01.corp", "HOSTNAME"));
        assert!(!should_drop_entity("Peter Schmidt", "PERSON"));
    }

    #[test]
    fn drops_vault_paths_as_location() {
        let fps = [
            ("docs/reference/repos/", "LOCATION"),
            (
                "Projects/acme/Acme-Development/Acme-Development Übersicht",
                "LOCATION",
            ),
        ];
        for (text, ty) in fps {
            assert!(
                should_drop_entity(text, ty),
                "expected drop for {text:?} ({ty})"
            );
        }
    }

    #[test]
    fn keeps_real_location() {
        assert!(!should_drop_entity("Musterstraße 12, Köln", "LOCATION"));
    }

    #[test]
    fn ignores_owner_handles_across_types() {
        assert!(should_drop_entity("niclasedge", "PERSON"));
        assert!(should_drop_entity("Niclas.Edge", "ORGANIZATION"));
    }
}

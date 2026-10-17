//! Network-guard: blocks network-out commands (curl/wget/ssh/git/etc.)
//! whose target URL/domain is not whitelisted in a project-level
//! `.redactor-urls.json`.
//!
//! When no config file is found, the network-guard is **disabled** (no
//! blocking) — opt-in via creating the config file.

use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const URL_CONFIG_FILE: &str = ".redactor-urls.json";

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UrlConfig {
    pub erlaubte_domains: Vec<String>,
    pub erlaubte_urls: Vec<String>,
    pub blockierte_domains: Vec<String>,
    pub fail_closed: bool,
}

fn discover_url_config(start: &Path) -> Option<PathBuf> {
    let mut cur: Option<&Path> = Some(start);
    while let Some(d) = cur {
        let candidate = d.join(URL_CONFIG_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        cur = d.parent();
    }
    None
}

pub fn load_url_config(start: &Path) -> Option<UrlConfig> {
    let path = discover_url_config(start)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<UrlConfig>(&text) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                eprintln!(
                    "[redactor] warning: failed to parse {}: {e}",
                    path.display()
                );
                None
            }
        },
        Err(e) => {
            eprintln!("[redactor] warning: failed to read {}: {e}", path.display());
            None
        }
    }
}

pub fn extract_hosts(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let re_url = regex::Regex::new(r"https?://([A-Za-z0-9._\-]+)").unwrap();
    for c in re_url.captures_iter(cmd) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_ascii_lowercase());
        }
    }
    let re_git = regex::Regex::new(r"\bgit@([A-Za-z0-9._\-]+):").unwrap();
    for c in re_git.captures_iter(cmd) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_ascii_lowercase());
        }
    }
    let re_ssh =
        regex::Regex::new(r"\b(?:ssh|scp|sftp|rsync)\s+(?:[A-Za-z0-9_\-]+@)?([A-Za-z0-9._\-]+)")
            .unwrap();
    for c in re_ssh.captures_iter(cmd) {
        if let Some(m) = c.get(1) {
            let host = m.as_str().to_ascii_lowercase();
            if host.contains('.') || host.contains('-') {
                out.push(host);
            }
        }
    }
    out
}

pub fn host_matches(host: &str, pattern: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let p = pattern.to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        return h == suffix || h.ends_with(&format!(".{suffix}"));
    }
    h == p
}

pub fn check(cmd: &str, cfg: &UrlConfig) -> Option<String> {
    let hosts = extract_hosts(cmd);
    if hosts.is_empty() {
        return None;
    }
    for host in &hosts {
        if cfg.blockierte_domains.iter().any(|p| host_matches(host, p)) {
            return Some(format!(
                "redactor network-guard: domain '{host}' is on the block list"
            ));
        }
        let in_url_allow = cfg.erlaubte_urls.iter().any(|u| cmd.contains(u));
        let in_domain_allow = cfg.erlaubte_domains.iter().any(|p| host_matches(host, p));
        if !in_url_allow && !in_domain_allow {
            return Some(format!(
                "redactor network-guard: host '{host}' is not whitelisted (add to .redactor-urls.json erlaubte_domains)"
            ));
        }
    }
    None
}

pub fn check_with_cwd(cmd: &str) -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let cfg = load_url_config(&cwd)?;
    check(cmd, &cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(domains: &[&str], blocked: &[&str]) -> UrlConfig {
        UrlConfig {
            erlaubte_domains: domains.iter().map(|s| s.to_string()).collect(),
            erlaubte_urls: vec![],
            blockierte_domains: blocked.iter().map(|s| s.to_string()).collect(),
            fail_closed: true,
        }
    }

    #[test]
    fn extract_https_url() {
        let hosts = extract_hosts("curl -L https://api.acme.com/v1/users");
        assert_eq!(hosts, vec!["api.acme.com"]);
    }

    #[test]
    fn extract_git_ssh() {
        let hosts = extract_hosts("git push git@github.com:user/repo main");
        assert_eq!(hosts, vec!["github.com"]);
    }

    #[test]
    fn extract_ssh_command() {
        let hosts = extract_hosts("ssh user@bastion.acme.com -L 8080");
        assert_eq!(hosts[0], "bastion.acme.com");
    }

    #[test]
    fn host_glob_wildcard() {
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("example.com", "*.example.com"));
        assert!(!host_matches("evil.example", "*.example.com"));
    }

    #[test]
    fn host_glob_exact() {
        assert!(host_matches("github.com", "github.com"));
        assert!(!host_matches("api.github.com", "github.com"));
    }

    #[test]
    fn check_blocks_unlisted() {
        let c = cfg(&["github.com"], &[]);
        let block = check("curl https://evil.example.com/", &c);
        assert!(block.is_some());
        assert!(block.unwrap().contains("evil.example.com"));
    }

    #[test]
    fn check_allows_whitelisted() {
        let c = cfg(&["github.com", "*.crates.io"], &[]);
        assert!(check("git push git@github.com:u/r", &c).is_none());
        assert!(check("curl https://static.crates.io/x", &c).is_none());
    }

    #[test]
    fn check_blocks_explicitly_blocked() {
        let c = cfg(&["*.evil.example"], &["*.evil.example"]);
        let block = check("curl https://api.evil.example/", &c);
        assert!(block.is_some());
        assert!(block.unwrap().contains("block list"));
    }

    #[test]
    fn check_passes_when_no_urls() {
        let c = cfg(&[], &[]);
        assert!(check("ls -la", &c).is_none());
        assert!(check("cargo build --release", &c).is_none());
    }
}

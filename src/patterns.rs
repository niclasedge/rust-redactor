//! Built-in regex patterns for common secret shapes.
//!
//! Each pattern has a stable `name` (used in logs and replacement label) and a
//! replacement string. Replacement uses backrefs where the pattern has capture
//! groups so prefixes (e.g. "password=") stay readable.

use regex::Regex;

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub regex: Regex,
    pub replacement: String,
}

impl Rule {
    pub fn new(name: &str, pattern: &str, replacement: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            name: name.to_string(),
            regex: Regex::new(pattern)?,
            replacement: replacement.to_string(),
        })
    }
}

/// Built-in pattern set — covers the most common credential shapes seen in
/// logs, configs and stack traces.
///
/// Order matters: more-specific rules first (so e.g. `crypto_container_path`
/// gets to consume `/foo/bar.pfx` before any later `*.key`-style pattern
/// re-matches part of the result).
pub fn defaults() -> Vec<Rule> {
    // Build static rules. Dynamic env-derived rules (current_username) are
    // appended by `with_runtime_rules()` below.
    let raw: &[(&str, &str, &str)] = &[
        // ---------- Phase 7a: crypto-container PATHS ----------
        // Match path-like tokens ending in a crypto-container extension and
        // redact the full path (not just the extension). The pre-bash hook
        // already blocks reads of these files; this pattern catches mentions
        // in tool output (e.g. `ls "OneDrive/Certs/"` listing of *.pfx names).
        (
            "crypto_container_path",
            r#"(?i)[/\\][^/\\\s'"<>:|?*]+\.(kdbx|kdb|gpg|pgp|asc|age|p12|pfx|keychain-db)\b"#,
            "<redacted:crypto_container_path>",
        ),
        // ---------- Phase 7c: Windows / Unix Home-Dir paths ----------
        // Matches `C:\Users\<name>` (or `c:/users/<name>`) and redacts the
        // username segment only — path tail stays visible so tool output
        // remains roughly traceable. Default-on; opt out per project via
        // `[policy] mask_username = false` in .redactor.toml.
        (
            "windows_home_dir",
            r#"(?i)([A-Za-z]:[\\/])Users([\\/])([^\\/\s'"<>:|?*]+)"#,
            "$1Users$2<redacted:username>",
        ),
        // Matches `/home/<name>` and `/Users/<name>` (macOS) — anchored to a
        // non-alphanumeric prefix so `xs/home/foo` does NOT match but
        // `cd /home/foo` does.
        (
            "unix_home_dir",
            r#"(^|[\s'"=:(<])/(?:home|Users|root)/([^/\s'"<>:|?*]+)"#,
            "$1/home/<redacted:username>",
        ),
        // ---------- Phase 7b: PowerShell / PSD1 secret fields ----------
        // Generic PowerShell-style key=value heuristic for credential fields
        // that don't fit the GUID / thumbprint regexes. Length >= 8 to avoid
        // matching empty / placeholder values; quotes optional.
        (
            "ps_secret_field",
            r#"(?i)\b(ClientSecret|RefreshToken|AccessToken|ApiKey|AppPassword|PSCred|VaultPassword|SafeMode(?:Admin)?Password|ServicePassword)\s*=\s*["']?([^"'\s,;]{8,})["']?"#,
            "$1=<redacted:ps_secret>",
        ),
        // ---------- Phase 7g: IPv6 ----------
        // Conservative IPv6 — only public unicast scope. Loopback (::1),
        // link-local (fe80::/10), unique-local (fc00::/7) and unspecified
        // (::) are passed through by the FP filter in redactor.rs. Pattern
        // requires at least 3 colon-separated hex groups to avoid matching
        // `HH:MM:SS` timestamps. Handles zero-compression (`::`) by allowing
        // a trailing run of `:HHHH` groups after the leading colon-set.
        (
            "ipv6",
            r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}(?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?|[0-9A-Fa-f]{1,4})\b",
            "<redacted:ipv6>",
        ),
        // ---------- Phase 7h: internal hostnames ----------
        // Hostnames with known internal TLDs that should never leak. The
        // pattern requires the host to have at least one label before the
        // TLD so isolated `.local` strings in prose aren't matched.
        (
            "internal_hostname",
            r"(?i)\b[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.(?:corp|intern|internal|lan|home\.arpa)\b",
            "<redacted:internal_hostname>",
        ),
        // ---------- Original v0.7 ruleset (keep below new additions) ----------
        (
            "anthropic_key",
            r"\bsk-ant-(?:api03-)?[A-Za-z0-9_\-]{20,}",
            "<redacted:anthropic_key>",
        ),
        (
            "openai_key",
            r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
            "<redacted:openai_key>",
        ),
        (
            "aws_access_key",
            r"\bAKIA[0-9A-Z]{16}\b",
            "<redacted:aws_access_key>",
        ),
        (
            "github_token",
            r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
            "<redacted:github_token>",
        ),
        (
            "slack_token",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            "<redacted:slack_token>",
        ),
        (
            "stripe_live",
            r"\b(?:sk|pk|rk)_live_[A-Za-z0-9]{20,}\b",
            "<redacted:stripe_live>",
        ),
        (
            "jwt",
            r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
            "<redacted:jwt>",
        ),
        (
            "pem_private",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            "<redacted:private_key>",
        ),
        // ---------- EU PII (rred-1) ----------
        (
            "email",
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            "<redacted:email>",
        ),
        (
            "iban_de",
            r"\b[A-Z]{2}\d{2}\s?(?:\d{4}\s?){2,7}\d{0,4}\b",
            "<redacted:iban>",
        ),
        (
            "birthdate_de",
            r"\b(0[1-9]|[12]\d|3[01])[.\-/](0[1-9]|1[0-2])[.\-/](19|20)\d{2}\b",
            "<redacted:birthdate>",
        ),
        ("svn_de", r"\b\d{2}[A-Z]\d{6}[A-Z]\d{3}\b", "<redacted:svn>"),
        // ---------- IPv4 (rred-2) — FP filter in redactor.rs ----------
        (
            "ipv4",
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "<redacted:ipv4>",
        ),
        // ---------- DB / service connection strings (rred-3) ----------
        (
            "conn_string",
            r"(?i)(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://\S+",
            "<redacted:conn_string>",
        ),
        // ---------- Azure credentials (rred-4 / rred-5) ----------
        (
            "azure_cred_guid",
            r#"(?i)(TenantId|ClientId|AppId|ApplicationId|ObjectId|SubscriptionId|DirectoryId|PrincipalId)["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?"#,
            "$1=<redacted:azure_guid>",
        ),
        (
            "cert_thumbprint",
            r#"(?i)(CertificateThumbprint|Thumbprint|FingerPrint)["']?\s*[:=]\s*["']?[0-9A-Fa-f]{40}["']?"#,
            "$1=<redacted:cert_thumbprint>",
        ),
        (
            "client_secret",
            r#"(?i)(ClientSecret|client_secret)["']?\s*[:=]\s*["']?\S{8,}["']?"#,
            "$1=<redacted:client_secret>",
        ),
        // HTTP auth-style headers — `\S.*` swallows whitespace-separated values too
        // (e.g. `Authorization: Bearer eyJhb...`), where generic_assign stops at the
        // first whitespace. Word-boundary `\b` prevents matches on `Reauthorization`.
        (
            "auth_header",
            r#"(?i)\b(authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token)\s*([:=])\s*\S.*"#,
            "$1$2 <redacted:auth_header>",
        ),
        // `Bearer <token>` / `Basic <token>` / `Digest <token>` with whitespace
        // separator — covers cases without an explicit Authorization: prefix.
        // Min length 16 keeps "basic auth" / "the bearer of news" out.
        (
            "bearer_token",
            r#"(?i)\b(Bearer|Basic|Digest)\s+([A-Za-z0-9._\-+/=]{16,})"#,
            "$1 <redacted:bearer_token>",
        ),
        // generic "password=..." / "api_key: ..." style assignments — keep prefix
        (
            "generic_assign",
            r#"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|bearer)\s*([:=])\s*['"]?([^\s'"]{6,})['"]?"#,
            "$1$2<redacted>",
        ),
    ];

    raw.iter()
        .map(|(name, pat, sub)| Rule::new(name, pat, sub).expect("built-in pattern compiles"))
        .collect()
}

/// Phase 7c: dynamic per-process Rule that matches the current user's username
/// when it appears as a standalone token (whitespace-bounded or path-segment).
/// Returns `None` if no `USERNAME`/`USER`/`LOGNAME` env var is set or if the
/// value is too short (< 2 chars) to match safely without massive FP risk.
///
/// The pattern is case-insensitive and bounded by either `[\s/\\:=,(]` or the
/// start-of-string. Tail bound is identical — keeps `Niclas.Edge` from matching
/// inside `Niclas.Edges` (different person).
pub fn dynamic_username_rule() -> Option<Rule> {
    let username = std::env::var("USERNAME")
        .ok()
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("LOGNAME").ok())?;
    let username = username.trim().to_string();
    if username.len() < 2 {
        return None;
    }
    // Skip obviously bogus / shared-account usernames.
    const SKIP_USERNAMES: &[&str] = &["root", "admin", "user", "system", "nobody"];
    if SKIP_USERNAMES.contains(&username.to_ascii_lowercase().as_str()) {
        return None;
    }
    let pat = format!(
        r#"(?i)(^|[\s/\\:=,(<'"])({})($|[\s/\\:=,)>'".])"#,
        regex::escape(&username)
    );
    Rule::new("current_username", &pat, "$1<redacted:username>$3").ok()
}

/// Custom rule loaded from JSON file: `[{"name":"x","re":"...","sub":"..."}]`
#[derive(serde::Deserialize)]
pub struct CustomRule {
    pub name: String,
    pub re: String,
    #[serde(default)]
    pub sub: Option<String>,
}

pub fn load_custom(path: &std::path::Path) -> anyhow::Result<Vec<Rule>> {
    let raw = std::fs::read_to_string(path)?;
    let parsed: Vec<CustomRule> = serde_json::from_str(&raw)?;
    parsed
        .into_iter()
        .map(|c| {
            let sub = c.sub.unwrap_or_else(|| format!("<redacted:{}>", c.name));
            Rule::new(&c.name, &c.re, &sub).map_err(anyhow::Error::from)
        })
        .collect()
}

/// Build literal-keyword rules from a comma-separated list (case-insensitive).
pub fn from_keywords(keywords: &str) -> Vec<Rule> {
    keywords
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|kw| {
            let pat = format!("(?i){}", regex::escape(kw));
            Rule::new("keyword", &pat, "<redacted:keyword>").ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_compile() {
        let rules = defaults();
        assert!(rules.len() >= 8);
    }

    #[test]
    fn openai_key_matches() {
        let rules = defaults();
        let r = rules.iter().find(|r| r.name == "openai_key").unwrap();
        let out = r.regex.replace_all(
            "OPENAI_API_KEY=sk-proj-abcdefghij1234567890XYZ",
            &r.replacement[..],
        );
        assert!(out.contains("<redacted:openai_key>"));
        assert!(!out.contains("sk-proj-abcdefghij"));
    }

    // Regression: `sk-` inside a word (e.g. `task-…`) must not trigger the
    // openai_key rule. Without a left word-boundary the regex greedily ate
    // normal filenames like `…/tasks/task-070-pipeline-based-task-FOO.md`.
    #[test]
    fn openai_key_negative_inside_word() {
        let r = rule("openai_key");
        let path = "Pfad: @notes/tasks/task-070-pipeline-based-task-implementation-details-here.md";
        assert!(
            r.regex.find(path).is_none(),
            "openai_key matched inside a normal filename: {:?}",
            r.regex.find(path)
        );
    }

    #[test]
    fn anthropic_key_negative_inside_word() {
        let r = rule("anthropic_key");
        // `flask-anthropic-…` contains the literal substring `sk-ant-` mid-word.
        let s = "see flask-anthropic-integration-runner-notes here";
        assert!(
            r.regex.find(s).is_none(),
            "anthropic_key matched inside a normal word: {:?}",
            r.regex.find(s)
        );
    }

    #[test]
    fn keyword_case_insensitive() {
        let rules = from_keywords("FooBar");
        let out = rules[0]
            .regex
            .replace_all("found foobar in log", &rules[0].replacement[..]);
        assert_eq!(out, "found <redacted:keyword> in log");
    }

    fn rule(name: &str) -> Rule {
        defaults()
            .into_iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("rule not found: {name}"))
    }

    // ---------- rred-1 EU PII ----------
    #[test]
    fn iban_de_matches_with_spaces() {
        let r = rule("iban_de");
        let out = r
            .regex
            .replace_all("IBAN: DE89 3704 0044 0532 0130 00 ende", &r.replacement[..]);
        assert!(out.contains("<redacted:iban>"));
    }
    #[test]
    fn iban_de_matches_compact() {
        let r = rule("iban_de");
        let out = r
            .regex
            .replace_all("acct=DE89370400440532013000;", &r.replacement[..]);
        assert!(out.contains("<redacted:iban>"));
    }
    #[test]
    fn birthdate_de_matches_dot_format() {
        let r = rule("birthdate_de");
        let out = r
            .regex
            .replace_all("born 15.03.1985 in DE", &r.replacement[..]);
        assert!(out.contains("<redacted:birthdate>"));
    }
    #[test]
    fn birthdate_de_matches_dash_format() {
        let r = rule("birthdate_de");
        let out = r.regex.replace_all("dob 15-03-1985 ok", &r.replacement[..]);
        assert!(out.contains("<redacted:birthdate>"));
    }
    #[test]
    fn birthdate_de_negative_invalid_month() {
        let r = rule("birthdate_de");
        assert!(r.regex.find("date 32.13.1985 bogus").is_none());
    }
    #[test]
    fn svn_de_matches_correct_shape() {
        let r = rule("svn_de");
        let out = r
            .regex
            .replace_all("svn 12A123456B789 yep", &r.replacement[..]);
        assert!(out.contains("<redacted:svn>"));
    }
    #[test]
    fn svn_de_negative_too_short() {
        let r = rule("svn_de");
        assert!(r.regex.find("svn 12X123456 short").is_none());
    }

    // ---------- rred-2 IPv4 raw pattern (FP filter tested in redactor.rs) ----------
    #[test]
    fn ipv4_pattern_matches_dotted_quad() {
        let r = rule("ipv4");
        assert!(r.regex.find("see 8.8.8.8 done").is_some());
        assert!(r.regex.find("see 192.168.1.1 done").is_some());
    }

    // ---------- rred-3 connection strings ----------
    #[test]
    fn conn_string_matches_postgres() {
        let r = rule("conn_string");
        let out = r.regex.replace_all(
            "DATABASE_URL=postgres://admin:s3cret@db:5432/app extra",
            &r.replacement[..],
        );
        assert!(out.contains("<redacted:conn_string>"));
        assert!(!out.contains("s3cret"));
    }
    #[test]
    fn conn_string_matches_mongodb_srv() {
        let r = rule("conn_string");
        let out = r.regex.replace_all(
            "uri=mongodb+srv://u:p@cluster/test others",
            &r.replacement[..],
        );
        assert!(out.contains("<redacted:conn_string>"));
    }
    #[test]
    fn conn_string_negative_https() {
        let r = rule("conn_string");
        assert!(r
            .regex
            .find("see https://example.com/postgres-guide")
            .is_none());
    }
    #[test]
    fn conn_string_negative_word_postgres() {
        let r = rule("conn_string");
        assert!(r.regex.find("Use postgres for storage.").is_none());
    }

    // ---------- rred-4 azure GUIDs ----------
    #[test]
    fn azure_cred_guid_matches_tenant_id() {
        let r = rule("azure_cred_guid");
        let out = r.regex.replace_all(
            "TenantId: 11111111-2222-3333-4444-555555555555 trailing",
            &r.replacement[..],
        );
        assert!(out.contains("<redacted:azure_guid>"));
        assert!(out.starts_with("TenantId="));
    }
    #[test]
    fn azure_cred_guid_matches_client_id_quoted() {
        let r = rule("azure_cred_guid");
        let s = r#""ClientId": "aabbccdd-1122-3344-5566-778899aabbcc""#;
        let out = r.regex.replace_all(s, &r.replacement[..]);
        assert!(out.contains("<redacted:azure_guid>"));
    }
    #[test]
    fn azure_cred_guid_negative_orderid() {
        let r = rule("azure_cred_guid");
        assert!(r
            .regex
            .find("OrderId: 11111111-2222-3333-4444-555555555555")
            .is_none());
    }
    #[test]
    fn azure_cred_guid_negative_not_a_guid() {
        let r = rule("azure_cred_guid");
        assert!(r.regex.find("TenantId: nicht-eine-guid").is_none());
    }

    // ---------- rred-5 cert thumbprint + client secret ----------
    #[test]
    fn cert_thumbprint_matches_40hex_unquoted() {
        let r = rule("cert_thumbprint");
        let s = "Thumbprint: 0123456789ABCDEF0123456789ABCDEF01234567 done";
        let out = r.regex.replace_all(s, &r.replacement[..]);
        assert!(out.contains("<redacted:cert_thumbprint>"));
    }
    #[test]
    fn cert_thumbprint_matches_quoted_lowercase() {
        let r = rule("cert_thumbprint");
        let s = r#"Thumbprint = "0123456789abcdef0123456789abcdef01234567""#;
        let out = r.regex.replace_all(s, &r.replacement[..]);
        assert!(out.contains("<redacted:cert_thumbprint>"));
    }
    #[test]
    fn cert_thumbprint_negative_too_short() {
        let r = rule("cert_thumbprint");
        assert!(r
            .regex
            .find("Thumbprint: 0123456789abcdef0123456789abcdef0123456")
            .is_none());
    }
    #[test]
    fn client_secret_matches_basic() {
        let r = rule("client_secret");
        let out = r
            .regex
            .replace_all("ClientSecret=abcdef1234567890", &r.replacement[..]);
        assert!(out.contains("<redacted:client_secret>"));
    }
    #[test]
    fn client_secret_matches_snake_case() {
        let r = rule("client_secret");
        let s = r#"client_secret: "S3cretPwd!Long""#;
        let out = r.regex.replace_all(s, &r.replacement[..]);
        assert!(out.contains("<redacted:client_secret>"));
    }
    #[test]
    fn client_secret_negative_too_short() {
        let r = rule("client_secret");
        assert!(r.regex.find("ClientSecret=short").is_none());
    }
    #[test]
    fn client_secret_negative_empty_value() {
        let r = rule("client_secret");
        assert!(r.regex.find("ClientSecret=").is_none());
    }

    // ---------- email ----------
    #[test]
    fn email_matches_basic() {
        let r = rule("email");
        let out = r
            .regex
            .replace_all("contact: alice@example.com here", &r.replacement[..]);
        assert!(out.contains("<redacted:email>"));
        assert!(!out.contains("alice"));
    }
    #[test]
    fn email_matches_plus_tag_and_subdomain() {
        let r = rule("email");
        let out = r.regex.replace_all(
            "from=user.name+tag@mail.example-corp.io;",
            &r.replacement[..],
        );
        assert!(out.contains("<redacted:email>"));
        assert!(!out.contains("user.name"));
    }
    #[test]
    fn email_negative_no_at_sign() {
        let r = rule("email");
        assert!(r.regex.find("plain text without an at sign").is_none());
    }
    #[test]
    fn email_negative_no_tld() {
        let r = rule("email");
        assert!(r.regex.find("user@hostname").is_none());
    }

    // ---------- auth_header (HTTP Authorization-style headers) ----------
    #[test]
    fn auth_header_matches_authorization_colon_bearer() {
        let r = rule("auth_header");
        let out = r
            .regex
            .replace_all("authorization: Bearer eyJhbGciOi", &r.replacement[..]);
        assert!(out.contains("<redacted:auth_header>"));
        assert!(!out.contains("eyJhbGciOi"));
        assert!(!out.contains("Bearer"));
    }
    #[test]
    fn auth_header_matches_authorization_equals() {
        let r = rule("auth_header");
        let out = r
            .regex
            .replace_all("Authorization=eyJhbsomesecret", &r.replacement[..]);
        assert!(out.contains("<redacted:auth_header>"));
        assert!(!out.contains("eyJhb"));
    }
    #[test]
    fn auth_header_matches_x_api_key() {
        let r = rule("auth_header");
        let out = r
            .regex
            .replace_all("X-API-Key: abc123def456", &r.replacement[..]);
        assert!(out.contains("<redacted:auth_header>"));
        assert!(!out.contains("abc123def456"));
    }
    #[test]
    fn auth_header_matches_x_auth_token() {
        let r = rule("auth_header");
        let out = r
            .regex
            .replace_all("x-auth-token: my-secret-token-value", &r.replacement[..]);
        assert!(out.contains("<redacted:auth_header>"));
    }
    #[test]
    fn auth_header_negative_no_value() {
        let r = rule("auth_header");
        assert!(r.regex.find("Authorization:").is_none());
        assert!(r.regex.find("Authorization: ").is_none());
    }
    #[test]
    fn auth_header_negative_word_boundary() {
        let r = rule("auth_header");
        // "Reauthorization" should not trigger
        assert!(r.regex.find("Reauthorization: see notes").is_none());
    }

    // ---------- Phase 7a: crypto_container_path ----------
    #[test]
    fn crypto_container_path_matches_pfx_in_path() {
        let r = rule("crypto_container_path");
        let s = r"C:\Users\foo\OneDrive\Certs\cert-prod.pfx done";
        let out = r.regex.replace_all(s, &r.replacement[..]);
        assert!(out.contains("<redacted:crypto_container_path>"));
        assert!(!out.contains("cert-prod.pfx"));
    }
    #[test]
    fn crypto_container_path_matches_kdbx_unix() {
        let r = rule("crypto_container_path");
        let out = r
            .regex
            .replace_all("ls /Users/x/Passwords/vault.kdbx ok", &r.replacement[..]);
        assert!(out.contains("<redacted:crypto_container_path>"));
    }
    #[test]
    fn crypto_container_path_matches_gpg_in_listing() {
        let r = rule("crypto_container_path");
        let out = r
            .regex
            .replace_all("data: /home/x/secrets/backup.gpg here", &r.replacement[..]);
        assert!(out.contains("<redacted:crypto_container_path>"));
    }
    #[test]
    fn crypto_container_path_negative_bare_word() {
        // "pfx" without a path-prefix should not match — avoids matching
        // "the pfx format" in prose.
        let r = rule("crypto_container_path");
        assert!(r.regex.find("pfx is a container format").is_none());
        assert!(r.regex.find("kdbx files are great").is_none());
    }
    #[test]
    fn crypto_container_path_negative_extension_only() {
        let r = rule("crypto_container_path");
        // ".pfx" alone (no path-segment before) — must not match.
        assert!(r.regex.find("change .pfx to .pem").is_none());
    }

    // ---------- Phase 7b: ps_secret_field ----------
    #[test]
    fn ps_secret_field_matches_client_secret() {
        let r = rule("ps_secret_field");
        let out = r
            .regex
            .replace_all("ClientSecret = 's3cretValue123abc'", &r.replacement[..]);
        assert!(out.contains("<redacted:ps_secret>"));
        assert!(out.starts_with("ClientSecret="));
    }
    #[test]
    fn ps_secret_field_matches_refresh_token() {
        let r = rule("ps_secret_field");
        let out = r.regex.replace_all(
            r#"RefreshToken="abcdef12345xyz" trailing"#,
            &r.replacement[..],
        );
        assert!(out.contains("<redacted:ps_secret>"));
    }
    #[test]
    fn ps_secret_field_negative_short_value() {
        let r = rule("ps_secret_field");
        assert!(r.regex.find("ApiKey = 'short'").is_none());
    }

    // ---------- Phase 7c: windows_home_dir, unix_home_dir ----------
    #[test]
    fn windows_home_dir_redacts_username_segment() {
        let r = rule("windows_home_dir");
        let out = r.regex.replace_all(
            r"C:\Users\Niclas.Edge\Documents\foo.txt",
            &r.replacement[..],
        );
        assert!(out.contains("<redacted:username>"));
        assert!(out.contains("Documents"));
        assert!(!out.contains("Niclas.Edge"));
    }
    #[test]
    fn windows_home_dir_handles_forward_slashes() {
        let r = rule("windows_home_dir");
        let out = r
            .regex
            .replace_all("c:/Users/bob/AppData", &r.replacement[..]);
        assert!(out.contains("<redacted:username>"));
    }
    #[test]
    fn unix_home_dir_redacts_macos_users_path() {
        let r = rule("unix_home_dir");
        let out = r
            .regex
            .replace_all("cd /Users/alice/Documents/foo", &r.replacement[..]);
        assert!(out.contains("<redacted:username>"));
    }
    #[test]
    fn unix_home_dir_redacts_linux_home_path() {
        let r = rule("unix_home_dir");
        let out = r
            .regex
            .replace_all("error in /home/bob/.bashrc", &r.replacement[..]);
        assert!(out.contains("<redacted:username>"));
    }

    // ---------- Phase 7g: ipv6 ----------
    #[test]
    fn ipv6_pattern_matches_full_address() {
        let r = rule("ipv6");
        assert!(r.regex.find("2001:db8:85a3::8a2e:370:7334").is_some());
        assert!(r.regex.find("2606:4700:4700::1111").is_some());
    }
    #[test]
    fn ipv6_pattern_finds_loopback_string() {
        // Pattern itself matches; the FP filter in redactor.rs short-circuits.
        let r = rule("ipv6");
        // The bare-words ::1 / :: are too short for the pattern (needs 2+ segments).
        assert!(r.regex.find("::1").is_none());
    }

    // ---------- Phase 7h: internal_hostname ----------
    #[test]
    fn internal_hostname_matches_corp_tld() {
        let r = rule("internal_hostname");
        let out = r.regex.replace_all("ssh dc01.corp ok", &r.replacement[..]);
        assert!(out.contains("<redacted:internal_hostname>"));
        assert!(!out.contains("dc01.corp"));
    }
    #[test]
    fn internal_hostname_matches_lan_subdomain() {
        let r = rule("internal_hostname");
        let out = r
            .regex
            .replace_all("host: printer.office.lan up", &r.replacement[..]);
        assert!(out.contains("<redacted:internal_hostname>"));
    }
    #[test]
    fn internal_hostname_matches_home_arpa() {
        let r = rule("internal_hostname");
        let out = r
            .regex
            .replace_all("router.home.arpa is up", &r.replacement[..]);
        assert!(out.contains("<redacted:internal_hostname>"));
    }

    // ---------- bearer_token (scheme + value, with whitespace) ----------
    #[test]
    fn bearer_token_matches_bearer_with_jwt() {
        let r = rule("bearer_token");
        let out = r.regex.replace_all(
            "header value: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            &r.replacement[..],
        );
        assert!(out.contains("<redacted:bearer_token>"));
        assert!(!out.contains("eyJhbGciOi"));
    }
    #[test]
    fn bearer_token_matches_basic_long_value() {
        let r = rule("bearer_token");
        let out = r
            .regex
            .replace_all("Basic dXNlcjpwYXNzd29yZA==", &r.replacement[..]);
        assert!(out.contains("<redacted:bearer_token>"));
        assert!(!out.contains("dXNlcjpwYXNzd29yZA"));
    }
    #[test]
    fn bearer_token_negative_short_word() {
        let r = rule("bearer_token");
        // "Bearer" followed by short word should NOT match (avoids prose FPs)
        assert!(r.regex.find("the bearer of news").is_none());
        assert!(r.regex.find("basic auth").is_none());
    }
    #[test]
    fn bearer_token_negative_no_value() {
        let r = rule("bearer_token");
        assert!(r.regex.find("Bearer").is_none());
    }

    // ---------- Phase 7c: dynamic_username_rule ----------
    #[test]
    fn dynamic_username_rule_matches_when_env_set() {
        // Save+restore the env so we don't leak state across tests.
        let saved = std::env::var("USERNAME").ok();
        std::env::set_var("USERNAME", "PhaseSevenC.Tester");
        let rule = dynamic_username_rule().expect("rule built");
        let out = rule
            .regex
            .replace_all("running as PhaseSevenC.Tester user", &rule.replacement[..]);
        assert!(out.contains("<redacted:username>"));
        assert!(!out.contains("PhaseSevenC.Tester"));
        // Restore.
        match saved {
            Some(v) => std::env::set_var("USERNAME", v),
            None => std::env::remove_var("USERNAME"),
        }
    }
    #[test]
    fn dynamic_username_rule_skips_root() {
        let saved_user = std::env::var("USER").ok();
        let saved_username = std::env::var("USERNAME").ok();
        std::env::set_var("USERNAME", "root");
        std::env::remove_var("USER");
        std::env::remove_var("LOGNAME");
        assert!(dynamic_username_rule().is_none());
        match saved_username {
            Some(v) => std::env::set_var("USERNAME", v),
            None => std::env::remove_var("USERNAME"),
        }
        if let Some(u) = saved_user {
            std::env::set_var("USER", u);
        }
    }
}

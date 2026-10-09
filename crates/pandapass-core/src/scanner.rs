//! Secret scanning engine.
//!
//! This is the M4 secret-scan backend: a small, dependency-free regular
//! expression scanner that detects common secret formats (AWS keys, GitHub
//! tokens, private keys, JWTs, ...) inside decrypted secret values.
//!
//! The [`Scanner`] trait is the seam where a heavier backend (e.g. trufflehog)
//! could be plugged in later without touching callers. The built-in
//! [`RegexScanner`] keeps the project self-contained: no external binary, no
//! network, deterministic tests.
//!
//! # Privacy invariant
//!
//! A [`ScanFinding`] deliberately carries **no plaintext fragment**. It records
//! the secret *key* that held the match, the rule that fired, and the byte
//! offsets of the match inside the scanned value. This mirrors the audit
//! contract (`AuditContext.secret_key` only — never a value) and is what allows
//! scan results to be persisted in the database and shown in the web UI.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Severity of a detected secret, used for triage ordering in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanSeverity {
    High,
    Medium,
    Low,
}

impl ScanSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// A built-in detection rule.
#[derive(Debug, Clone)]
pub struct ScanRule {
    /// Stable machine-readable identifier (e.g. `aws_secret_access_key`).
    pub id: &'static str,
    /// Human-readable name shown in the UI (e.g. "AWS Secret Access Key").
    pub name: &'static str,
    pub severity: ScanSeverity,
    regex: Regex,
}

impl ScanRule {
    pub fn new(id: &'static str, name: &'static str, severity: ScanSeverity, pattern: &str) -> Self {
        Self {
            id,
            name,
            severity,
            regex: Regex::new(pattern).expect("built-in scan rule regex must compile"),
        }
    }
}

/// A single detection: which rule fired, where, and on which secret key.
///
/// No plaintext is stored here — `secret_key` is the environment-unique secret
/// name, and `match_start`/`match_end` are byte offsets into the scanned value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub secret_key: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: ScanSeverity,
    pub match_start: usize,
    pub match_end: usize,
}

/// Scanning backend abstraction. A future trufflehog integration would
/// implement this trait against the external binary and swap in.
pub trait Scanner: Send + Sync {
    /// Scan one decrypted secret value, returning all matches found.
    fn scan(&self, secret_key: &str, value: &str) -> Vec<ScanFinding>;
}

/// Regex-based scanner over a fixed rule set.
#[derive(Debug)]
pub struct RegexScanner {
    rules: &'static [ScanRule],
}

impl RegexScanner {
    pub fn new(rules: &'static [ScanRule]) -> Self {
        Self { rules }
    }

    /// The scanner used by the server, backed by [`builtin_rules`].
    pub fn builtin() -> Self {
        Self { rules: builtin_rules() }
    }
}

impl Scanner for RegexScanner {
    fn scan(&self, secret_key: &str, value: &str) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        for rule in self.rules {
            for m in rule.regex.find_iter(value) {
                // Skip obvious placeholder/example values that would flood
                // results in development environments.
                let snippet = m.as_str();
                if is_placeholder(snippet) {
                    continue;
                }
                findings.push(ScanFinding {
                    secret_key: secret_key.to_string(),
                    rule_id: rule.id.to_string(),
                    rule_name: rule.name.to_string(),
                    severity: rule.severity,
                    match_start: m.start(),
                    match_end: m.end(),
                });
            }
        }
        findings
    }
}

/// Heuristic: is this matched snippet a placeholder/example rather than a real
/// secret? Keeps `example`, `xxxx`, `your-` style documentation values out of
/// scan results.
fn is_placeholder(snippet: &str) -> bool {
    let lower = snippet.to_ascii_lowercase();
    if lower.contains("example") || lower.contains("your-") || lower.contains("xxxx") || lower.contains("changeme") {
        return true;
    }
    // All-placeholder patterns like "..." or "___"
    if snippet.chars().all(|c| c == '.' || c == '_' || c == '-') {
        return true;
    }
    false
}

/// The built-in rule set.
///
/// Patterns target high-signal formats (long random suffixes, characteristic
/// prefixes) rather than bare words like "password", to keep false positives
/// low in a vault full of ordinary configuration values.
pub fn builtin_rules() -> &'static [ScanRule] {
    static RULES: OnceLock<Vec<ScanRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            ScanRule::new(
                "aws_access_key_id",
                "AWS Access Key ID",
                ScanSeverity::High,
                r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
            ),
            ScanRule::new(
                "aws_secret_access_key",
                "AWS Secret Access Key",
                ScanSeverity::High,
                r#"(?i)\baws[_-]?secret[_-]?access[_-]?key\b["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#,
            ),
            ScanRule::new(
                "github_pat",
                "GitHub Personal Access Token",
                ScanSeverity::High,
                r"\bghp_[A-Za-z0-9]{36}\b",
            ),
            ScanRule::new(
                "github_fine_grained",
                "GitHub Fine-Grained Token",
                ScanSeverity::High,
                r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
            ),
            ScanRule::new(
                "github_oauth",
                "GitHub OAuth Token",
                ScanSeverity::High,
                r"\bgho_[A-Za-z0-9]{36}\b",
            ),
            ScanRule::new(
                "github_app_token",
                "GitHub App Token",
                ScanSeverity::High,
                r"\bghu_[A-Za-z0-9]{36}\b",
            ),
            ScanRule::new(
                "slack_token",
                "Slack Token",
                ScanSeverity::High,
                r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
            ),
            ScanRule::new(
                "stripe_secret_key",
                "Stripe Secret Key",
                ScanSeverity::High,
                r"\bsk_live_[0-9a-zA-Z]{24,}\b",
            ),
            ScanRule::new(
                "stripe_restricted_key",
                "Stripe Restricted Key",
                ScanSeverity::High,
                r"\brk_live_[0-9a-zA-Z]{24,}\b",
            ),
            ScanRule::new(
                "google_api_key",
                "Google API Key",
                ScanSeverity::Medium,
                r"\bAIza[0-9A-Za-z_-]{35}\b",
            ),
            ScanRule::new(
                "sendgrid_api_key",
                "SendGrid API Key",
                ScanSeverity::High,
                r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b",
            ),
            ScanRule::new(
                "twilio_api_key",
                "Twilio API Key",
                ScanSeverity::High,
                r"\bSK[0-9a-fA-F]{32}\b",
            ),
            ScanRule::new(
                "jwt",
                "JWT",
                ScanSeverity::Medium,
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            ),
            ScanRule::new(
                "private_key_pem",
                "Private Key (PEM)",
                ScanSeverity::High,
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            ),
            ScanRule::new(
                "generic_api_key",
                "Generic API Key",
                ScanSeverity::Low,
                r#"(?i)\b(?:api[_-]?key|apikey|secret|token)\b["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?"#,
            ),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> RegexScanner {
        RegexScanner::builtin()
    }

    #[test]
    fn detects_aws_access_key_id() {
        // AKIA + 16 base62 chars. Avoids the docs' "...EXAMPLE" placeholder,
        // which the scanner deliberately skips.
        let findings = scanner().scan("AWS_KEY", "AKIA1234567890123456");
        assert!(findings.iter().any(|f| f.rule_id == "aws_access_key_id"));
    }

    #[test]
    fn detects_aws_secret_key_with_label() {
        let findings = scanner().scan("AWS_SECRET", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYABCDEFGHIJ");
        assert!(findings.iter().any(|f| f.rule_id == "aws_secret_access_key"));
    }

    #[test]
    fn detects_github_pat() {
        let findings = scanner().scan("GH", "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ");
        assert!(findings.iter().any(|f| f.rule_id == "github_pat"));
    }

    #[test]
    fn detects_jwt() {
        // Bare "header.payload.signature" must NOT match — real JWTs need
        // base64url segments.
        let bare = scanner().scan("TOKEN", "header.payload.signature");
        assert!(!bare.iter().any(|f| f.rule_id == "jwt"));

        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let findings = scanner().scan("JWT", jwt);
        assert!(findings.iter().any(|f| f.rule_id == "jwt"));
    }

    #[test]
    fn detects_private_key() {
        let findings = scanner().scan("KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----");
        assert!(findings.iter().any(|f| f.rule_id == "private_key_pem"));
    }

    #[test]
    fn detects_slack_token() {
        let findings = scanner().scan("SLACK", "xoxb-123456789012-abcdefghij");
        assert!(findings.iter().any(|f| f.rule_id == "slack_token"));
    }

    #[test]
    fn skips_placeholder_example_values() {
        // AWS docs use AKIAIOSFODNN7EXAMPLE — the EXAMPLE suffix is a placeholder.
        let findings = scanner().scan("AWS_KEY", "AKIAIOSFODNN7EXAMPLE");
        // Actually the regex requires 16 chars after prefix; EXAMPLE is 7 so
        // this doesn't match at all. Use a real-length placeholder check below.
        let findings2 = scanner().scan("GH", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert!(!findings2.iter().any(|f| f.rule_id == "github_pat"));
    }

    #[test]
    fn finding_carries_no_plaintext() {
        let secret_value = "aws_secret_access_key = SUPERSEKRETVALUE1234567890";
        let findings = scanner().scan("AWS_SECRET", secret_value);
        for f in &findings {
            let rendered = format!("{:?}", f);
            assert!(!rendered.contains("SUPERSEKRETVALUE"), "finding must not carry plaintext: {rendered}");
            assert!(f.match_start < f.match_end);
            assert!(f.match_end <= secret_value.len());
        }
    }

    #[test]
    fn multi_match_reports_each() {
        let findings = scanner().scan("KEYS", "AKIA1111111111111111 AKIA2222222222222222");
        let aws: Vec<_> = findings.iter().filter(|f| f.rule_id == "aws_access_key_id").collect();
        assert!(aws.len() >= 2);
    }

    #[test]
    fn severity_round_trip() {
        assert_eq!(ScanSeverity::High.as_str(), "high");
        assert_eq!(serde_json::to_string(&ScanSeverity::High).unwrap(), "\"high\"");
    }
}
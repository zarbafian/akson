//! SARIF 2.1.0 profile parser (design §14.2, §10.3): SARIF is an output *report*,
//! not an authority record, so it is parsed as **hostile input**.
//!
//! - **Strict limits.** The bytes go through the I-JSON parser first (bounded size,
//!   nesting depth, and node count; duplicate keys and unsafe integers rejected),
//!   then structural extraction is bounded (result count, message length).
//! - **Byte preservation.** The original bytes are digested as-is
//!   ([`SarifReport::digest`]); an attestation covers *that* digest — SARIF is never
//!   assumed to sign itself, and re-serialization never changes what was attested.
//! - **No URI fetch.** `$schema`, `artifactLocation.uri`, `helpUri`, and external
//!   property references are never dereferenced. This parser reads only the finding
//!   fields it needs and ignores every URI.
//!
//! It answers "is this structurally a SARIF 2.1.0 log, and what are its bounded
//! findings?" — never "is the review correct?" (design §14.2).
//!
//! What you write:
//! ```
//! use axon_evidence::{parse_sarif, SarifLimits};
//! let bytes = br#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clippy"}},
//!   "results":[{"ruleId":"unwrap","level":"warning","message":{"text":"avoid unwrap"}}]}]}"#;
//! let report = parse_sarif(bytes, &SarifLimits::default()).unwrap();
//! assert_eq!(report.tool_name, "clippy");
//! assert_eq!(report.findings.len(), 1);
//! assert_eq!(report.digest.len(), 64);
//! ```

use axon_ext::ijson;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bounds applied while parsing hostile SARIF (design §14.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SarifLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    /// Cap on the number of findings extracted (excess are counted, not returned).
    pub max_findings: usize,
    /// Cap on a finding message length (longer messages are truncated).
    pub max_message_len: usize,
}

impl Default for SarifLimits {
    fn default() -> Self {
        Self {
            max_bytes: 4 * 1024 * 1024,
            max_depth: 64,
            max_findings: 4096,
            max_message_len: 1024,
        }
    }
}

/// A SARIF result level (design §14.2). Unknown levels map to `None`, never fetched
/// or inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SarifLevel {
    Error,
    Warning,
    Note,
    None,
}

impl SarifLevel {
    fn parse(s: Option<&str>) -> Self {
        match s {
            Some("error") => SarifLevel::Error,
            Some("warning") => SarifLevel::Warning,
            Some("note") => SarifLevel::Note,
            // SARIF default level is "warning" when absent; anything unknown is None.
            None => SarifLevel::Warning,
            _ => SarifLevel::None,
        }
    }
}

/// One bounded finding extracted from a SARIF result (design §14.2). URIs are never
/// carried through — only the rule id, level, and a bounded message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifFinding {
    pub rule_id: String,
    pub level: SarifLevel,
    pub message: String,
}

/// The result of parsing a SARIF log as hostile input (design §14.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SarifReport {
    /// SHA-256 (hex) over the **original** bytes — the digest an attestation covers.
    pub digest: String,
    pub byte_length: usize,
    pub tool_name: String,
    pub findings: Vec<SarifFinding>,
    /// Findings beyond `max_findings` that were counted but not returned (so a
    /// truncated view never silently looks complete).
    pub truncated_findings: usize,
}

/// Why SARIF failed to parse under the profile.
#[derive(Debug, thiserror::Error)]
pub enum SarifError {
    #[error("sarif is {actual} bytes, over the {limit}-byte limit")]
    TooLarge { actual: usize, limit: usize },
    #[error("sarif is not valid I-JSON: {0}")]
    IJson(#[from] ijson::IJsonError),
    #[error("not a SARIF 2.1.0 log: {0}")]
    NotSarif(&'static str),
}

/// Parses `bytes` as a SARIF 2.1.0 log under the hostile-input profile (design
/// §14.2). Returns the preserved-byte digest, the tool name, and the bounded
/// findings. Never fetches a `$schema`, artifact, or help URI.
pub fn parse_sarif(bytes: &[u8], limits: &SarifLimits) -> Result<SarifReport, SarifError> {
    if bytes.len() > limits.max_bytes {
        return Err(SarifError::TooLarge {
            actual: bytes.len(),
            limit: limits.max_bytes,
        });
    }
    // Digest the ORIGINAL bytes before any parsing — this is what an attestation
    // covers (byte preservation, §14.2).
    let digest = hex::encode(Sha256::digest(bytes));

    // Parse under I-JSON limits (size, depth, node count, duplicate keys).
    let value = ijson::parse_with_limits(bytes, limits.max_bytes, limits.max_depth)?;
    let obj = value
        .as_object()
        .ok_or(SarifError::NotSarif("top level is not an object"))?;

    match obj.get("version").and_then(|v| v.as_str()) {
        Some("2.1.0") => {}
        _ => return Err(SarifError::NotSarif("version is not 2.1.0")),
    }
    let runs = obj
        .get("runs")
        .and_then(|v| v.as_array())
        .ok_or(SarifError::NotSarif("runs is not an array"))?;
    let first_run = runs.first().ok_or(SarifError::NotSarif("no runs"))?;

    // tool.driver.name — read as an opaque string; no URI is touched.
    let tool_name = first_run
        .get("tool")
        .and_then(|t| t.get("driver"))
        .and_then(|d| d.get("name"))
        .and_then(|n| n.as_str())
        .ok_or(SarifError::NotSarif("missing tool.driver.name"))?
        .to_owned();

    let mut findings = Vec::new();
    let mut truncated_findings = 0usize;
    // Aggregate results across EVERY run under the global cap — a malicious report
    // must not hide findings in a later run behind a benign first (codex review).
    for r in runs.iter().flat_map(|run| {
        run.get("results")
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }) {
        if findings.len() >= limits.max_findings {
            truncated_findings += 1;
            continue;
        }
        let rule_id = r
            .get("ruleId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let level = SarifLevel::parse(r.get("level").and_then(|v| v.as_str()));
        let mut message = r
            .get("message")
            .and_then(|m| m.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_owned();
        if message.len() > limits.max_message_len {
            message.truncate(nearest_char_boundary(&message, limits.max_message_len));
        }
        findings.push(SarifFinding {
            rule_id,
            level,
            message,
        });
    }

    Ok(SarifReport {
        digest,
        byte_length: bytes.len(),
        tool_name,
        findings,
        truncated_findings,
    })
}

/// The largest char boundary `<= max` (so a truncate never splits a UTF-8 char).
fn nearest_char_boundary(s: &str, max: usize) -> usize {
    let mut i = max.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"{
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "clippy", "helpUri": "https://example.com/ignored"}},
            "results": [
                {"ruleId": "unwrap_used", "level": "warning", "message": {"text": "avoid unwrap"}},
                {"ruleId": "panic", "level": "error", "message": {"text": "no panics"}}
            ]
        }]
    }"#;

    #[test]
    fn parses_a_valid_log_and_digests_original_bytes() {
        let report = parse_sarif(SAMPLE, &SarifLimits::default()).unwrap();
        assert_eq!(report.tool_name, "clippy");
        assert_eq!(report.byte_length, SAMPLE.len());
        assert_eq!(report.digest, hex::encode(Sha256::digest(SAMPLE)));
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].level, SarifLevel::Warning);
        assert_eq!(report.findings[1].level, SarifLevel::Error);
        assert_eq!(report.truncated_findings, 0);
    }

    #[test]
    fn findings_hidden_in_a_later_run_are_still_counted() {
        // A benign first run, error findings hidden in a second run: all must count.
        let multi = br#"{
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "reviewer"}}, "results": [
                    {"message": {"text": "looks fine"}}
                ]},
                {"tool": {"driver": {"name": "reviewer"}}, "results": [
                    {"level": "error", "message": {"text": "hidden bug"}},
                    {"level": "error", "message": {"text": "another"}}
                ]}
            ]
        }"#;
        let report = parse_sarif(multi, &SarifLimits::default()).unwrap();
        assert_eq!(
            report.findings.len(),
            3,
            "findings from every run are aggregated"
        );
        assert!(report.findings.iter().any(|f| f.level == SarifLevel::Error));
    }

    #[test]
    fn rejects_wrong_version_and_non_sarif() {
        let wrong = br#"{"version": "2.0.0", "runs": []}"#;
        assert!(matches!(
            parse_sarif(wrong, &SarifLimits::default()),
            Err(SarifError::NotSarif(_))
        ));
        assert!(matches!(
            parse_sarif(b"[]", &SarifLimits::default()),
            Err(SarifError::NotSarif(_))
        ));
    }

    #[test]
    fn enforces_the_byte_limit() {
        let limits = SarifLimits {
            max_bytes: 8,
            ..SarifLimits::default()
        };
        assert!(matches!(
            parse_sarif(SAMPLE, &limits),
            Err(SarifError::TooLarge { .. })
        ));
    }

    #[test]
    fn caps_and_reports_truncated_findings() {
        let limits = SarifLimits {
            max_findings: 1,
            ..SarifLimits::default()
        };
        let report = parse_sarif(SAMPLE, &limits).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.truncated_findings, 1);
    }

    #[test]
    fn rejects_deeply_nested_hostile_input() {
        // A pathologically nested document is refused by the I-JSON depth cap.
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(matches!(
            parse_sarif(deep.as_bytes(), &SarifLimits::default()),
            Err(SarifError::IJson(_))
        ));
    }

    #[test]
    fn an_absent_level_defaults_to_warning() {
        let bytes = br#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
            "results":[{"ruleId":"r","message":{"text":"m"}}]}]}"#;
        let report = parse_sarif(bytes, &SarifLimits::default()).unwrap();
        assert_eq!(report.findings[0].level, SarifLevel::Warning);
    }
}

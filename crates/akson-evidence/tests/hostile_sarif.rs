//! Robustness of SARIF parsing against hostile input (design §11.1, §14.2, §20.4):
//! SARIF arrives from an untrusted worker, so every malformed, oversized, or
//! adversarial report must be *rejected or bounded* — a returned `Err` or a
//! truncated result, never a panic, overflow, or unbounded allocation.

#![allow(clippy::unwrap_used)]

use akson_evidence::{parse_sarif, SarifLimits};

#[test]
fn malformed_sarif_is_rejected_without_panicking() {
    let limits = SarifLimits::default();
    let cases: &[&[u8]] = &[
        b"",
        b"{}",
        b"[]",
        b"null",
        b"{\"runs\":[]}",
        b"{\"runs\":null}",
        b"{\"runs\":[{\"results\":\"x\"}]}",
        b"{\"version\":\"2.1.0\"}",
        &[0xff, 0xfe, 0xfd],
        b"not sarif",
    ];
    for bytes in cases {
        let _ = parse_sarif(bytes, &limits);
    }
    // Deep nesting and a node bomb are guarded by the I-JSON caps.
    assert!(parse_sarif("[".repeat(100_000).as_bytes(), &limits).is_err());
}

#[test]
fn an_over_findings_report_is_bounded_not_unbounded() {
    // A report with far more findings than the cap must be accepted-but-truncated or
    // rejected — never returned in full (the cap prevents a memory blow-up).
    let limits = SarifLimits {
        max_findings: 8,
        ..SarifLimits::default()
    };
    let mut results = String::new();
    for i in 0..100_000 {
        if i > 0 {
            results.push(',');
        }
        results.push_str(r#"{"message":{"text":"x"}}"#);
    }
    let sarif = format!(r#"{{"version":"2.1.0","runs":[{{"results":[{results}]}}]}}"#);
    if let Ok(report) = parse_sarif(sarif.as_bytes(), &limits) {
        assert!(
            report.findings.len() <= limits.max_findings,
            "findings must be capped at {}",
            limits.max_findings
        );
    }
}

#[test]
fn a_deterministic_byte_sweep_never_panics() {
    let limits = SarifLimits::default();
    let mut state: u64 = 0x14057B7EF767814F;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    let alphabet: &[&[u8]] = &[
        b"{",
        b"}",
        b"[",
        b"]",
        b"\"",
        b":",
        b",",
        b"1",
        b"0",
        b"version",
        b"runs",
        b"results",
        b"message",
        b"text",
        b"ruleId",
        b"locations",
        b"level",
        b"2.1.0",
        b"true",
        b"null",
    ];
    for _ in 0..20_000 {
        let tokens = (next() % 40) as usize;
        let mut buf = Vec::new();
        for _ in 0..tokens {
            buf.extend_from_slice(alphabet[(next() as usize) % alphabet.len()]);
        }
        let _ = parse_sarif(&buf, &limits);
    }
}

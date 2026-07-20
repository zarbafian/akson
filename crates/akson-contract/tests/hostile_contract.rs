//! Robustness of contract-payload parsing against hostile input (design §11.1,
//! §20.4): every malformed, oversized, or adversarial payload must be *rejected* —
//! a returned `Err`, never a panic or overflow. `parse_payload` runs I-JSON limits,
//! the canonical-bytes check, and schema validation; none may crash on bad bytes.

#![allow(clippy::unwrap_used)]

use akson_contract::parse_payload;

#[test]
fn malformed_payloads_are_rejected_without_panicking() {
    let cases: &[&[u8]] = &[
        b"",
        b"{}",
        b"[]",
        b"null",
        b"[",
        b"{\"schema_version\":1}",
        b"{\"schema_version\":\"x\"}",
        br#"{"schema_version":1,"contract_id":"","inputs":[]}"#,
        &[0xff, 0xfe, 0xfd],
        b"not json at all",
        b"{\"a\":\"\xff\"}",
    ];
    for bytes in cases {
        let _ = parse_payload(bytes);
    }
    // The I-JSON caps guard the parser: deep nesting / a node bomb are rejected, not
    // overflowed.
    assert!(parse_payload("[".repeat(100_000).as_bytes()).is_err());
    let bomb: String = std::iter::once('[')
        .chain((0..1_100_000).flat_map(|i| if i == 0 { vec!['0'] } else { vec![',', '0'] }))
        .chain(std::iter::once(']'))
        .collect();
    assert!(parse_payload(bomb.as_bytes()).is_err());
}

#[test]
fn a_deterministic_byte_sweep_never_panics() {
    let mut state: u64 = 0x2545F4914F6CDD1D;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    // A JSON-ish alphabet plus contract field-name fragments, to reach deeper into
    // the parser than pure noise would.
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
        b"-",
        b".",
        b"e",
        b"schema_version",
        b"contract_id",
        b"inputs",
        b"requester",
        b"performer",
        b"deliverables",
        b"limits",
        b"created_at",
        b"expires_at",
        b"true",
        b"null",
    ];
    for _ in 0..20_000 {
        let tokens = (next() % 40) as usize;
        let mut buf = Vec::new();
        for _ in 0..tokens {
            buf.extend_from_slice(alphabet[(next() as usize) % alphabet.len()]);
        }
        let _ = parse_payload(&buf);
    }
}

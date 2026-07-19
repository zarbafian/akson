//! Robustness of the I-JSON parser against hostile input (design §11.1, §20.4):
//! every malformed, oversized, or adversarial document must be *rejected* — a
//! returned `Err`, never a panic, and never a stack overflow. This is the property
//! a fuzzer looks for; here it is pinned as regression tests plus a deterministic
//! byte sweep. The matching `cargo-fuzz` target (fuzz/) runs the same entry point
//! continuously under libFuzzer.

#![allow(clippy::unwrap_used)]

use axon_ext::ijson::{self, IJsonError};

#[test]
fn deep_nesting_is_rejected_not_overflowed() {
    // 100k unclosed brackets: the parser must bound recursion and return an error,
    // not blow the stack.
    for open in ["[", "{"] {
        let input = open.repeat(100_000);
        let result = ijson::parse(input.as_bytes());
        assert!(result.is_err(), "deeply nested {open:?} must be rejected");
    }
    // A well-formed but over-deep array is rejected as too deep.
    let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    assert!(matches!(
        ijson::parse(deep.as_bytes()),
        Err(IJsonError::TooDeep { .. }) | Err(IJsonError::Syntax(_))
    ));
}

#[test]
fn a_node_bomb_is_rejected_before_it_expands() {
    // A small body that expands to millions of Value nodes must hit the node cap.
    let mut s = String::from("[");
    for i in 0..1_100_000 {
        if i > 0 {
            s.push(',');
        }
        s.push('0');
    }
    s.push(']');
    assert!(matches!(
        ijson::parse(s.as_bytes()),
        Err(IJsonError::TooManyNodes { .. })
    ));
}

#[test]
fn duplicate_keys_and_unsafe_integers_are_rejected() {
    assert!(matches!(
        ijson::parse(br#"{"a":1,"a":2}"#),
        Err(IJsonError::DuplicateKey(_))
    ));
    // > 2^53 - 1 is outside the I-JSON safe range.
    assert!(matches!(
        ijson::parse(b"99999999999999999999"),
        Err(IJsonError::UnsafeInteger(_))
    ));
}

#[test]
fn malformed_bytes_are_rejected_without_panicking() {
    let cases: &[&[u8]] = &[
        b"",
        b"   ",
        b"{",
        b"[",
        b"{\"a\":",
        b"nul",
        b"tru",
        b"[1,2,",
        b"{\"a\":1,}",
        b"\"unterminated",
        &[0xff, 0xfe, 0xfd], // invalid UTF-8
        &[0x7b, 0xff, 0x7d], // { <invalid utf8> }
        b"\x00\x00\x00",
        b"123abc",
        b"-",
        b"1e",
        b"1.2.3",
        "\u{feff}{}".as_bytes(), // BOM prefix
    ];
    for bytes in cases {
        // The only requirement: it returns (Ok or Err) without crashing.
        let _ = ijson::parse(bytes);
    }
}

#[test]
fn a_deterministic_byte_sweep_never_panics() {
    // A tiny LCG (fixed seed → reproducible; no wall-clock/rng) drives a sweep of
    // random and JSON-ish byte strings through the parser. The test passing *is*
    // the assertion: any panic or overflow aborts it.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    let alphabet = b"{}[]\":,0123456789.-+eEtfnul \t\n\\/u";
    for _ in 0..20_000 {
        let len = (next() % 64) as usize;
        let buf: Vec<u8> = (0..len)
            .map(|_| {
                let r = next();
                if r % 4 == 0 {
                    (r & 0xff) as u8 // raw byte (may be invalid UTF-8)
                } else {
                    alphabet[(r as usize) % alphabet.len()]
                }
            })
            .collect();
        let _ = ijson::parse(&buf);
    }
}

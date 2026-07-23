//! The identity token (design §8.2 steps 1–2, ADR-0013): the public,
//! hand-carried commitment to an endpoint's identity root key.
//!
//! What you write:
//! ```
//! # use akson_crypto::token::{encode_token, decode_token, split_presentation};
//! let token = encode_token(&[7u8; 32]);
//! assert!(token.starts_with("akson1"));
//! assert_eq!(token.len(), 65);
//! let (tok, hint) = split_presentation("akson1abc@198.51.100.7:18444");
//! assert_eq!((tok, hint), ("akson1abc", Some("198.51.100.7:18444")));
//! # assert_eq!(decode_token(&token).unwrap().root_key, [7u8; 32]);
//! ```
//!
//! The container is bech32m (BIP-350): HRP `akson`, payload
//! `version (1 byte) ‖ root public key (32 bytes)`, 65 characters, lowercase
//! canonical. Everything here is entry-time integrity — checksum, case,
//! length, version, all checked before anything is stored — because the token
//! travels through hands and QR codes, and a misread character must fail at
//! `peer add`, never later as a plausible wrong identity. The `@host:port`
//! presentation suffix is deliberately *outside* the checksum: it is the
//! unauthenticated routing hint the introduction treats as untrusted.
//!
//! Implemented in-crate (~100 lines) rather than as a dependency: the codec
//! is checksum arithmetic over a fixed table, and the golden vectors in
//! `spec/vectors/token/` hold this implementation and any second one to the
//! same bytes (§3.1 conditions 5 and 7).

/// The token version this implementation emits and accepts: Ed25519 root key,
/// RFC 7638 thumbprints, SHA-256 digests (ADR-0013).
pub const TOKEN_VERSION: u8 = 0x01;

/// The human-readable part every identity token carries.
pub const TOKEN_HRP: &str = "akson";

/// bech32m's validity bound (BIP-173, retained by BIP-350): past 90
/// characters the guaranteed error-detection properties no longer hold.
const MAX_TOKEN_CHARS: usize = 90;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// A decoded identity token: the out-of-band commitment `peer add` stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityToken {
    pub version: u8,
    /// The endpoint's identity root public key (its agent-card key, §8.1).
    pub root_key: [u8; 32],
}

/// Why a token failed at entry. Each maps to one line of CLI guidance; none
/// leaves partial state behind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("the token is over bech32m's 90-character bound")]
    TooLong,
    #[error("the token mixes upper and lower case")]
    MixedCase,
    #[error("the token is not an akson identity token")]
    BadHrp,
    #[error("the token contains an invalid character at position {0}")]
    BadChar(usize),
    #[error("the token checksum does not verify — re-copy it")]
    BadChecksum,
    #[error("the token version {0:#04x} is not supported by this build")]
    UnknownVersion(u8),
    #[error("the token payload is not a version byte plus a 32-byte key")]
    BadLength,
}

/// Splits the `<token>[@host:port]` presentation form (ADR-0013): the suffix
/// after the last `@` is the unauthenticated routing hint, outside the
/// checksum by design.
pub fn split_presentation(s: &str) -> (&str, Option<&str>) {
    match s.rsplit_once('@') {
        Some((token, hint)) if !hint.is_empty() => (token, Some(hint)),
        Some((token, _)) => (token, None),
        None => (s, None),
    }
}

/// Encodes `root_key` as this endpoint's identity token — lowercase
/// canonical, [`TOKEN_VERSION`], 65 characters.
pub fn encode_token(root_key: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(33);
    payload.push(TOKEN_VERSION);
    payload.extend_from_slice(root_key);
    let data = to_five_bit(&payload);
    let checksum = checksum(TOKEN_HRP, &data);
    let mut out = String::with_capacity(TOKEN_HRP.len() + 1 + data.len() + 6);
    out.push_str(TOKEN_HRP);
    out.push('1');
    for d in data.iter().chain(checksum.iter()) {
        out.push(CHARSET[*d as usize] as char);
    }
    out
}

/// Decodes and fully validates an identity token (case, length, charset,
/// checksum, HRP, version, payload shape — in that order, all fail-closed).
pub fn decode_token(s: &str) -> Result<IdentityToken, TokenError> {
    if s.len() > MAX_TOKEN_CHARS {
        return Err(TokenError::TooLong);
    }
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(TokenError::MixedCase);
    }
    let s = s.to_ascii_lowercase();

    // The separator is the LAST '1' (BIP-173); an HRP may itself contain '1'.
    let sep = s.rfind('1').ok_or(TokenError::BadHrp)?;
    let (hrp, rest) = (&s[..sep], &s[sep + 1..]);
    if rest.len() < 6 {
        return Err(TokenError::BadChecksum);
    }
    let mut data = Vec::with_capacity(rest.len());
    for (i, ch) in rest.bytes().enumerate() {
        let v = CHARSET
            .iter()
            .position(|c| *c == ch)
            .ok_or(TokenError::BadChar(sep + 1 + i))?;
        data.push(v as u8);
    }
    if !verify_checksum(hrp, &data) {
        return Err(TokenError::BadChecksum);
    }
    if hrp != TOKEN_HRP {
        return Err(TokenError::BadHrp);
    }
    let payload = to_eight_bit(&data[..data.len() - 6]).ok_or(TokenError::BadLength)?;
    let (&version, key) = payload.split_first().ok_or(TokenError::BadLength)?;
    if version != TOKEN_VERSION {
        return Err(TokenError::UnknownVersion(version));
    }
    let root_key: [u8; 32] = key.try_into().map_err(|_| TokenError::BadLength)?;
    Ok(IdentityToken { version, root_key })
}

// ---- bech32m arithmetic (BIP-350) ----

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = (chk & 0x1ff_ffff) << 5 ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    hrp.bytes()
        .map(|b| b >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|b| b & 31))
        .collect()
}

fn checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let values = hrp_expand(hrp)
        .into_iter()
        .chain(data.iter().copied())
        .chain([0u8; 6]);
    let pm = polymod(values) ^ BECH32M_CONST;
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = ((pm >> (5 * (5 - i))) & 31) as u8;
    }
    out
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    polymod(hrp_expand(hrp).into_iter().chain(data.iter().copied())) == BECH32M_CONST
}

/// 8-bit bytes → 5-bit groups, zero-padded (encode direction).
fn to_five_bit(bytes: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::with_capacity(bytes.len() * 8 / 5 + 1);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// 5-bit groups → 8-bit bytes; `None` if the padding is over-long or
/// non-zero (BIP-173's strictness — a sloppy encoder is rejected).
fn to_eight_bit(groups: &[u8]) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::with_capacity(groups.len() * 5 / 8);
    for g in groups {
        acc = (acc << 5) | u32::from(*g);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The golden key `000102…1f` — matches `spec/vectors/token/`.
    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    const GOLDEN: &str = "akson1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7lykl4d";

    #[test]
    fn golden_roundtrip() {
        assert_eq!(encode_token(&key()), GOLDEN);
        assert_eq!(GOLDEN.len(), 65);
        let t = decode_token(GOLDEN).unwrap();
        assert_eq!(t.version, TOKEN_VERSION);
        assert_eq!(t.root_key, key());
    }

    #[test]
    fn uppercase_is_accepted_mixed_case_is_not() {
        assert_eq!(
            decode_token(&GOLDEN.to_ascii_uppercase()).unwrap().root_key,
            key()
        );
        let mut mixed = GOLDEN.to_owned();
        mixed.replace_range(0..1, "A");
        assert_eq!(decode_token(&mixed), Err(TokenError::MixedCase));
    }

    #[test]
    fn one_flipped_character_is_caught() {
        // Flip each data character in turn; the checksum must catch every one
        // (bech32m guarantees ≤4 substitutions detected).
        for i in 6..GOLDEN.len() {
            let orig = GOLDEN.as_bytes()[i];
            let swap = if orig == b'q' { b'p' } else { b'q' };
            let mut broken = GOLDEN.as_bytes().to_vec();
            broken[i] = swap;
            let broken = String::from_utf8(broken).unwrap();
            assert!(
                decode_token(&broken).is_err(),
                "flip at {i} must not decode"
            );
        }
    }

    #[test]
    fn wrong_hrp_and_unknown_version_are_refused() {
        // Both strings carry VALID bech32m checksums — the refusal is the
        // akson layer's, not the codec's.
        let wrong_hrp = "aksom1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7ufaaqs";
        assert_eq!(decode_token(wrong_hrp), Err(TokenError::BadHrp));
        let v2 = "akson1qgqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7cvqhsa";
        assert_eq!(decode_token(v2), Err(TokenError::UnknownVersion(0x02)));
    }

    #[test]
    fn wrong_payload_length_is_refused() {
        // 1 + 31 bytes, valid checksum.
        let short = "akson1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50qwtfnl2";
        assert_eq!(decode_token(short), Err(TokenError::BadLength));
    }

    #[test]
    fn over_length_and_bad_charset_are_refused() {
        let long = format!("akson1{}", "q".repeat(90));
        assert_eq!(decode_token(&long), Err(TokenError::TooLong));
        // 'b' is not in the bech32 charset.
        let bad = GOLDEN.replace('l', "b");
        assert!(matches!(decode_token(&bad), Err(TokenError::BadChar(_))));
    }

    #[test]
    fn presentation_split() {
        assert_eq!(
            split_presentation("akson1abc@198.51.100.7:18444"),
            ("akson1abc", Some("198.51.100.7:18444"))
        );
        assert_eq!(split_presentation("akson1abc"), ("akson1abc", None));
        assert_eq!(split_presentation("akson1abc@"), ("akson1abc", None));
        // The LAST '@' splits, so an IPv6-ish hint with '@' upstream survives.
        assert_eq!(
            split_presentation("akson1abc@host:18444"),
            ("akson1abc", Some("host:18444"))
        );
    }

    #[test]
    fn bip350_checksum_vectors() {
        // Valid bech32m strings from BIP-350 — the checksum layer accepts
        // them (the akson layer would then refuse the HRP, tested above).
        for s in [
            "A1LQFN3A",
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "?1v759aa",
        ] {
            let lower = s.to_ascii_lowercase();
            let sep = lower.rfind('1').unwrap();
            let data: Vec<u8> = lower[sep + 1..]
                .bytes()
                .map(|c| CHARSET.iter().position(|x| *x == c).unwrap() as u8)
                .collect();
            assert!(verify_checksum(&lower[..sep], &data), "{s} must verify");
        }
        // Invalid: bech32 (not m) checksum must NOT verify under bech32m.
        let bech32_not_m = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let lower = bech32_not_m.to_ascii_lowercase();
        let sep = lower.rfind('1').unwrap();
        let data: Vec<u8> = lower[sep + 1..]
            .bytes()
            .map(|c| CHARSET.iter().position(|x| *x == c).unwrap() as u8)
            .collect();
        assert!(!verify_checksum(&lower[..sep], &data));
    }
}

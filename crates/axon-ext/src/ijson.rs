//! Strict I-JSON (RFC 7493) parsing for Axon extension payloads.
//!
//! Design §10.2: JSON contract payloads conform to I-JSON constraints and
//! reject duplicate keys; §11.1 sets hard limits enforced before structured
//! validation. This parser enforces, in order: byte cap, well-formed UTF-8
//! and syntax (via `serde_json`), nesting depth, duplicate object keys, and
//! the I-JSON safe integer range (±(2⁵³−1)) so a later RFC 8785
//! canonicalization is lossless. Floats are kept as parsed `f64`; JSON has no
//! literal for non-finite values and out-of-range floats fail at the syntax
//! layer.

use std::cell::RefCell;
use std::fmt;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Hard cap on input bytes (matches the design §11.1 total-body target;
/// callers pass lower caps for individual Parts).
pub const MAX_BYTES: usize = 8 * 1024 * 1024;

/// Hard cap on container nesting depth (design §11.1).
pub const MAX_DEPTH: usize = 64;

/// Largest integer magnitude exactly representable as an IEEE 754 double.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IJsonError {
    #[error("input of {actual} bytes exceeds the {limit}-byte limit")]
    TooLarge { actual: usize, limit: usize },
    #[error("nesting exceeds the maximum depth of {limit}")]
    TooDeep { limit: usize },
    #[error("duplicate object key {0:?}")]
    DuplicateKey(String),
    #[error("integer {0} is outside the I-JSON safe range")]
    UnsafeInteger(String),
    #[error("invalid JSON: {0}")]
    Syntax(String),
}

/// Parses `bytes` under the default limits. Fails closed on any violation.
pub fn parse(bytes: &[u8]) -> Result<Value, IJsonError> {
    parse_with_limits(bytes, MAX_BYTES, MAX_DEPTH)
}

/// Parses `bytes` with explicit limits; `max_bytes`/`max_depth` may only be
/// lowered by callers, never raised above the module constants (design §11.1).
pub fn parse_with_limits(
    bytes: &[u8],
    max_bytes: usize,
    max_depth: usize,
) -> Result<Value, IJsonError> {
    let max_bytes = max_bytes.min(MAX_BYTES);
    let max_depth = max_depth.min(MAX_DEPTH);
    if bytes.len() > max_bytes {
        return Err(IJsonError::TooLarge {
            actual: bytes.len(),
            limit: max_bytes,
        });
    }
    let violation = RefCell::new(None);
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let seed = ValueSeed {
        violation: &violation,
        depth: 0,
        max_depth,
    };
    let parsed = seed.deserialize(&mut de).and_then(|v| {
        de.end()?;
        Ok(v)
    });
    match parsed {
        Ok(value) => Ok(value),
        // A violation detected by the visitor surfaces as a serde error; the
        // side channel preserves the precise cause. Anything else is syntax.
        Err(e) => Err(violation
            .into_inner()
            .unwrap_or_else(|| IJsonError::Syntax(e.to_string()))),
    }
}

struct ValueSeed<'a> {
    violation: &'a RefCell<Option<IJsonError>>,
    depth: usize,
    max_depth: usize,
}

impl<'a> ValueSeed<'a> {
    fn fail<E: serde::de::Error>(&self, err: IJsonError) -> E {
        let msg = err.to_string();
        *self.violation.borrow_mut() = Some(err);
        E::custom(msg)
    }
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an I-JSON value")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(self.fail(IJsonError::UnsafeInteger(v.to_string())));
        }
        Ok(Value::from(v))
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        if v > MAX_SAFE_INTEGER {
            return Err(self.fail(IJsonError::UnsafeInteger(v.to_string())));
        }
        Ok(Value::from(v))
    }

    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        // JSON syntax cannot produce NaN/inf, but fail closed regardless.
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| self.fail(IJsonError::UnsafeInteger(v.to_string())))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= self.max_depth {
            return Err(self.fail(IJsonError::TooDeep {
                limit: self.max_depth,
            }));
        }
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(ValueSeed {
            violation: self.violation,
            depth: self.depth + 1,
            max_depth: self.max_depth,
        })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= self.max_depth {
            return Err(self.fail(IJsonError::TooDeep {
                limit: self.max_depth,
            }));
        }
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            let value = access.next_value_seed(ValueSeed {
                violation: self.violation,
                depth: self.depth + 1,
                max_depth: self.max_depth,
            })?;
            if map.insert(key.clone(), value).is_some() {
                return Err(self.fail(IJsonError::DuplicateKey(key)));
            }
        }
        Ok(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_object() {
        let v = parse(br#"{"a": 1, "b": [true, null, "x"], "c": {"d": 1.5}}"#);
        assert!(v.is_ok());
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert_eq!(
            parse(br#"{"a": 1, "a": 2}"#),
            Err(IJsonError::DuplicateKey("a".into()))
        );
    }

    #[test]
    fn rejects_nested_duplicate_keys() {
        assert_eq!(
            parse(br#"{"outer": [{"k": 1, "k": 1}]}"#),
            Err(IJsonError::DuplicateKey("k".into()))
        );
    }

    #[test]
    fn rejects_unsafe_integers() {
        // 2^53 is one past the largest safe integer.
        assert_eq!(
            parse(b"9007199254740992"),
            Err(IJsonError::UnsafeInteger("9007199254740992".into()))
        );
        assert_eq!(
            parse(b"-9007199254740992"),
            Err(IJsonError::UnsafeInteger("-9007199254740992".into()))
        );
        assert!(parse(b"9007199254740991").is_ok());
        assert!(parse(b"-9007199254740991").is_ok());
    }

    #[test]
    fn rejects_oversized_input() {
        let big = vec![b' '; 32];
        assert_eq!(
            parse_with_limits(&big, 16, MAX_DEPTH),
            Err(IJsonError::TooLarge {
                actual: 32,
                limit: 16
            })
        );
    }

    #[test]
    fn rejects_too_deep() {
        let mut s = String::new();
        for _ in 0..65 {
            s.push('[');
        }
        for _ in 0..65 {
            s.push(']');
        }
        assert_eq!(
            parse(s.as_bytes()),
            Err(IJsonError::TooDeep { limit: MAX_DEPTH })
        );
    }

    #[test]
    fn depth_at_limit_is_accepted() {
        let mut s = String::new();
        for _ in 0..64 {
            s.push('[');
        }
        for _ in 0..64 {
            s.push(']');
        }
        assert!(parse(s.as_bytes()).is_ok());
    }

    #[test]
    fn limits_cannot_be_raised() {
        let mut s = String::new();
        for _ in 0..65 {
            s.push('[');
        }
        for _ in 0..65 {
            s.push(']');
        }
        assert_eq!(
            parse_with_limits(s.as_bytes(), MAX_BYTES, 1000),
            Err(IJsonError::TooDeep { limit: MAX_DEPTH })
        );
    }

    #[test]
    fn rejects_syntax_and_trailing_data() {
        assert!(matches!(parse(b"{"), Err(IJsonError::Syntax(_))));
        assert!(matches!(parse(b"1 2"), Err(IJsonError::Syntax(_))));
        assert!(matches!(parse(b"NaN"), Err(IJsonError::Syntax(_))));
    }

    #[test]
    fn rejects_invalid_utf8_and_lone_surrogates() {
        assert!(matches!(parse(b"\"\xff\xfe\""), Err(IJsonError::Syntax(_))));
        // Unpaired surrogate escape violates I-JSON.
        assert!(matches!(parse(br#""\ud800""#), Err(IJsonError::Syntax(_))));
    }
}

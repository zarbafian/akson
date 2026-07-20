# ADR-0010: Unknown-field handling for standard A2A objects

Status: accepted
Date: 2026-07-16

## Context

Design §18 fixes the compatibility rule: readers **reject unknown
safety-critical enum values** and **preserve non-critical unknown standard
fields**; §4.2/§18 add that unknown extensions are preserved for forwarding
when safe or ignored, and Akson tests with at least two SDKs. Lines 1222/1587
add the mechanism constraint: "a parser's normalized representation never
replaces the signed [original bytes]."

The generated pbjson deserializers, by default, reject any unknown field
(`_ => Err(unknown_field(...))`), which contradicts §18 for *standard* A2A
objects (Codex review finding M13). A newer A2A minor version that adds a
benign field would otherwise hard-fail an object Akson should still accept.

Akson **extension** objects are the opposite case: they are closed,
safety-critical schemas validated by the JSON Schema registry
(`additionalProperties: false`) over strict I-JSON, and must keep
reject-unknown.

## Decision

Enable `pbjson_build::Builder::ignore_unknown_fields()` for the generated A2A
types, and **do not** enable `ignore_unknown_enum_variants()`. This is exactly
§18: unknown *standard fields* are ignored by the typed view (not rejected),
while unknown values of a safety-critical enum still fail closed.

Two further rules make the preservation faithful:

- **Original bytes are the source of truth.** For dedup digest (RFC 9530
  Content-Digest), signature coverage, and forwarding, Akson uses the exact
  received bytes — never a re-serialization of the typed model, which has
  dropped the ignored fields (design §1222). The reliable-delivery layer
  already retains the exact body (M5-core).
- **Signatures verify over received bytes.** Agent Card JWS verification
  canonicalizes the *received* card JSON (minus `signatures`/defaults), not a
  pbjson round-trip, so a card carrying an unknown standard field still
  verifies. `card_sig` gains this when the receive path that retains the raw
  card lands (M5); today's vectors carry no unknown fields, so the current
  round-trip is byte-identical.

Extension objects are unaffected: they do not go through pbjson, and their
strict schemas stay authoritative.

## Consequences

- One-line codegen change (`build.rs`); a benign field from a newer A2A minor
  no longer hard-rejects a standard object. Closes Codex finding M13.
- A test asserts a standard object with an extra field parses (field ignored),
  while an unknown safety-critical enum value still errors.
- The "verify/forward over original bytes, not the typed re-serialization"
  rule is tracked to M5's receive path; until then, standard objects with
  unknown fields parse but must not be re-serialized for signature or digest
  purposes.
- If a future need arises to *retain and re-emit* specific unknown standard
  fields (rather than only forward original bytes), that is a new ADR.

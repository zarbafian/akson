# ADR-0012: One DSSE-envelope media type for all signed extension objects

Status: accepted
Date: 2026-07-17

## Context

A signed Akson extension object (a contract revision, a contract decision, and
later a result manifest, evidence statement, or outcome) travels as a DSSE
envelope carried in the `data` value of an A2A `Part`. An A2A `Part` also has a
`media_type` field (a2a.proto field 7, available for all part types).

Two media types are therefore in play, and design §10.2 makes them distinct:

- the **`Part.media_type`** — what §10.2 calls the "versioned contract-envelope
  media type" — labels the Part so a receiver can locate the one contract-control
  Part among all Parts (and reject a missing or second one). It is **not** covered
  by the signature.
- the **DSSE `payloadType`** inside the envelope
  (`application/vnd.akson-dev.contract.v1+json`, via
  `namespace::payload_media_type`) labels the signed payload bytes and **is**
  covered by the DSSE PAE, so it is the trust-bearing discriminator.

§10.2 describes the Part media type as the per-object "contract-envelope media
type." Taken literally that implies a distinct, versioned envelope type per
signed object (e.g. `…contract-envelope.v1+json`,
`…decision-envelope.v1+json`, …).

## Decision

Use **one uniform envelope media type for every signed extension object**:

```
application/vnd.akson-dev.dsse.v1+json
```

exposed as `akson_ext::namespace::DSSE_ENVELOPE_MEDIA_TYPE`. The DSSE
`payloadType` remains the per-object, per-version discriminator of the content.
A receiver finds the signed Part by this single envelope media type, parses the
DSSE envelope, and then dispatches on `payloadType` (contract v1, decision v1, …).

The `v1` here is the version of the Akson DSSE-envelope profile (single signature,
thumbprint keyid, strict Ed25519 — see `akson-ext::dsse`), independent of any
payload schema version.

**Deviation from §10.2, made deliberately (maintainer decision).** This uses a
generic DSSE-envelope type rather than a per-object "contract-envelope" type. The
rationale:

- The Part media type is a routing label, not a trust anchor — the signature
  binds `payloadType`, not `Part.media_type` — so collapsing it to one value
  removes nothing security-relevant.
- Uniform Part handling: one code path locates and parses every signed Part
  regardless of object type, and `payloadType` (which *is* signed) decides what
  it is. This is idiomatic DSSE: the envelope is content-agnostic; the payload
  type names the content.
- Fewer media types to register at Phase 0.

## Consequences

- `DSSE_ENVELOPE_MEDIA_TYPE` is the Part media type for all signed objects; the
  contract Part-extraction step (M7) selects the one Part carrying it, and later
  milestones reuse it for decisions, result manifests, evidence, and outcomes.
- The value is in the `vnd.akson-dev` placeholder tree and is gated by
  `NAMESPACE_IS_PLACEHOLDER`; the real media type is assigned through
  registration in Phase 0 (design §14.2, §3.1), together with the payload types.
- Interop note for a second implementation: match the signed Part by the DSSE
  envelope media type, then trust only `payloadType` for content routing. A
  future §10.2 text revision should record that the "contract-envelope media
  type" is realized as this one generic DSSE-envelope type.
- No new golden vector: this is a constant, exercised by the M7 Part-extraction
  tests once that step lands.

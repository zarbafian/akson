# Golden vectors

Implementation-independent test vectors for every canonical byte sequence,
digest, and signature Akson produces: JCS canonicalization, JWK thumbprints,
DSSE pre-authentication encoding and signatures, Agent Card JWS signatures
(`jws/`), reliable-delivery Content-Digest and covered-value commitments
(`delivery/`), identity-token and introduction transcripts (`token/`,
`introduction/` — the pairing-era families were removed with ADR-0015),
the coordination surface's staged digests, cursors, replies, and refusals
(`coordination/`, ADR-0016), I-JSON acceptance, schema validation,
input-manifest digests, result manifests, and outcomes.

Layout: one directory per family, one JSON file per case:

~~~json
{
  "name": "jcs/basic-object",
  "description": "what the case exercises",
  "input": { },
  "expected": { }
}
~~~

Rules:

- Vectors are written by hand or generated once and then frozen; the Rust
  implementation and the independent Python cross-checker (`xcheck/`) must
  both reproduce `expected` in CI.
- Signature vectors include the private key (test keys only — never real
  ones) so both implementations can re-sign deterministically.
- A vector file is immutable once merged; fixes are new cases.

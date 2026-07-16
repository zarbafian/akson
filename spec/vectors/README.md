# Golden vectors

Implementation-independent test vectors for every canonical byte sequence,
digest, and signature Axon produces: JCS canonicalization, JWK thumbprints,
DSSE pre-authentication encoding and signatures, input-manifest digests,
delivery deduplication tuples, result manifests, and outcomes.

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

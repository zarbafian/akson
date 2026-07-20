# Pinned A2A definitions

`proto/` contains the vendored A2A 1.0 Protocol Buffer definitions — the
normative source of truth per ADR-0002 — plus their transitive `google/api`
imports. `PIN` records the upstream repositories, tag, commits, and per-file
SHA-256 digests.

Rules:

- Every file under `proto/` is a **byte-exact upstream copy**. Never edit one;
  upgrading A2A is an explicit re-vendor plus a `PIN` diff reviewed under the
  design §18 compatibility rules.
- `crates/akson-proto` compiles these files at build time with `protox`
  (pure-Rust, no system protoc, no network) and generates types with `prost`
  and the standard proto3 JSON mapping with `pbjson`.
- The A2A HTTP+JSON binding is this JSON mapping over HTTPS with
  `application/a2a+json` (design §3); Akson's v1 profile restrictions
  (required extensions, nonblocking operation, disabled streaming/push) are
  validation layered on top, never edits to these definitions.

The Akson v1 profile mapping document and A2A conformance vectors land here
with the rest of milestone M2.

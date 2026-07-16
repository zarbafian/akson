# ADR-0002: Vendored A2A definitions as source of truth

Status: accepted
Date: 2026-07-16

## Context

Design §3 requires generating standard A2A types from A2A's normative
Protocol Buffer definitions rather than maintaining a competing schema, and
§3.3 requires pinning each external protocol to a reviewed version.

## Decision

The pinned A2A 1.0 protobuf definitions are vendored into `spec/a2a/`
together with a `PIN` file recording the upstream repository, tag, and commit
hash. Rust types are generated at build time with `prost` from the vendored
files only — never from a network fetch. The HTTP+JSON binding uses the A2A
standard JSON mapping; Axon's profile restrictions (required extensions,
nonblocking operation, disabled streaming/push) are validation layered on
top in `axon-proto`, not edits to the vendored definitions.

## Consequences

- Upgrading A2A is an explicit diff of `spec/a2a/` plus re-run conformance
  vectors, governed by design §18.
- JSON Schema is used only for Axon extension objects (`spec/ext/`), never
  for standard A2A objects.
- `axon-proto` is the single crate allowed to expose generated A2A types.

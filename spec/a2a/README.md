# Pinned A2A definitions

This directory will contain the vendored A2A 1.0 Protocol Buffer definitions
(the normative source of truth per ADR-0002), a `PIN` file recording the
upstream repository, tag, and commit hash, the Axon v1 profile mapping
document, and A2A conformance vectors.

Vendoring happens in milestone M2. Nothing in this directory may be edited by
hand except `PIN`, the mapping document, and vectors; the `.proto` files are
byte-exact upstream copies.

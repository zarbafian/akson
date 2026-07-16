# Axon extension registry

The versioned JSON Schemas (Draft 2020-12) for every Axon extension object
(design §3.2): contract, decision, ordered input manifest, identity/key
binding, passive delivery, result manifest, evidence reference, verifier
summary, outcome. One file per schema version; published schemas are
immutable — a change is a new version.

## Namespace placeholder

Extension URIs and media types require a project-controlled HTTPS namespace
(design §3.1, a Phase 0 release gate). That domain is **not secured yet**.
Until it is, every URI uses the placeholder prefix defined in one place —
`crates/axon-ext/src/namespace.rs` — and schemas refer to URIs through it.
No stable release may ship while the placeholder is in effect.

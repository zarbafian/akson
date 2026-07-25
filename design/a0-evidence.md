# A0 evidence ledger — capability & maturity prerequisites

Status of every A0 checklist item (checklist:
`design/2026-07-25-byom-exchange-coordination-surface.md` §"A0 — capability &
maturity checklist"; program plan `2026-07-25-kovee-byom-implementation-plan.md`
§A0). A0 gates C4 and I2. Evidence, not features: each row records what exists
in-tree today and what remains. Honest by construction — nothing below is
claimed "pinned/consumable" that has not passed its gate.

Date: 2026-07-25

| # | Item | Status | Current evidence | What remains |
|---|---|---|---|---|
| A0.1 | Pinned release artifacts (aksond, akson, akson-mcp, adapters) with SBOM/provenance | **open** | `spec/family-lock.pin.json` (vendored family-lock *pointer* — a manifest digest, explicitly "local PINs alone are never provenance"); `deny.toml` (cargo-deny dependency policy); `GOVERNANCE.md` promises signed releases with SBOMs; all four artifact crates exist (`crates/aksond`, `crates/akson-cli`, `crates/akson-mcp`, `adapters/*` via `crates/akson-adapter-sdk`) | No release pipeline: `.github/workflows/ci.yml` / `fuzz.yml` have no release, SBOM, or attestation steps. Need pinned release artifacts + SBOM/provenance + lock-manifest rows and build attestation |
| A0.2 | ADR-0015 introduction vectors pinned; no PAIR-port assumption in any fleet/bench script | **in-progress** | ADR-0015 is `Status: proposed` (`spec/adr/0015-introduction-protocol.md:3`). Vectors: `spec/vectors/introduction/transcript.json` **only** (one responder-role transcript canonical-bytes + digest + PoP case). Scripts grep-clean of PAIR ports/listeners: `bench/*.sh` use `akson token` / `peer add` / `peer ping` on the RECEIVE surface only; `harness/interop/scenario-pairing.sh` is introduction-based (`--import`/`introduce`). Bench doc fallout sweep (AK-08) done in this commit: `bench/README.md` no longer names PAIR ports 19443/19444, `pair invite\|accept`, or `peer confirm` | Vector set incomplete per ADR-0015's own consequences: both-role transcripts + PAE, the hello body, both proof bodies, refusal shapes. Not "pinned/consumable" until live interop passes and the ADR is promoted from `proposed`. Stale doc: `spec/vectors/README.md:7` still lists a `pairing/` vector family that no longer exists |
| A0.3 | Key custody status recorded honestly (interim custody a named residual carried into every I2 claim) | **met (as recording; custody itself remains interim)** | `design/2026-07-19-threat-model.md`: T13 residual — interim custody (ADR-0009) has no external counter, rollback is *undetectable*, daemon degrades to operate-but-flagged; T14 — root-key concentration accepted under the same interim sealed custody; §residuals — "Key custody is interim (ADR-0009): the master secret and DEK live in a file"; external keystore backend named as the remaining custody work | Carry the residual verbatim into every I2 claim; the actual custody hardening (external keystore backend, external rollback counter) is separate, still-open work |
| A0.4a | Extension-URI namespace | **met** | `crates/akson-ext/src/namespace.rs:15` — `EXTENSION_NAMESPACE = "https://akson.cc/ext"` (project-controlled); regression test `the_namespace_is_a_real_project_controlled_https_origin` refuses reserved TLDs | Nothing |
| A0.4b | Payload media-type registration | **open (provisional — release gate)** | `crates/akson-ext/src/namespace.rs:19` — `MEDIA_TYPES_ARE_PROVISIONAL: bool = true`; all payload types and `DSSE_ENVELOPE_MEDIA_TYPE` are in the unregistered `vnd.akson-dev` tree; test `the_media_types_are_still_the_unregistered_development_tree` pins the constant to the tree | IANA registration (RFC 6838 §3.2, design §14.2 Phase 0); release tooling must refuse to ship while the constant is true (M15) |
| A0.4c | Licensing | **open (Apache-2.0 proposed — release gate)** | `LICENSE` (Apache License 2.0 text) and workspace `Cargo.toml:34` `license = "Apache-2.0"` are in-tree — but the program plan classifies the choice as an open maintainer decision, not yet ratified | Maintainer ratification recorded as a decision; release-gate closure |
| A0.5 | Hardened deployment profile: separate Unix identities per daemon, hardened service units, explicit egress policy | **open** | `akson service install` writes a user unit and a `--system` unit (`crates/akson-cli/src/main.rs:547`, `:623`): `Delegate=yes`, `RuntimeDirectory=akson` mode `0700`, refuses to run as root — but a **single** operator identity, no hardening directives (no `NoNewPrivileges`/`ProtectSystem`/`ProtectHome`/`IPAddressDeny`), no unit-level egress policy. The per-daemon UID graph (e.g. `AKSON_COORD_UID`) is sketched in `design/2026-07-25-byom-exchange-coordination-surface.md` and deferred to the C4 UID-graph ADR | Profile doc + hardened unit files: separate Unix identities per daemon with the mediation boundary specified, hardening directives, explicit egress policy |
| A0.6 | Test proving no inherited SSH/cloud credentials are reachable from workers | **open (partial local evidence)** | Sandbox launches with bwrap `--clearenv` + `--unshare-all` + `--cap-drop ALL` (`crates/akson-sandbox/src/launcher.rs:342`); live test `live_bwrap_isolates_the_worker` (`launcher.rs`, `#[ignore]`, CI isolation job) proves from *inside* the sandbox that host env is stripped and the host filesystem (hence `~/.ssh`, `~/.aws`) is unreachable | A **named test in the fleet harness** (`harness/`) asserting specifically that no inherited SSH/cloud credentials (agent sockets, key files, cloud metadata/config) are reachable from workers on the fleet hosts |

## Open items discovered during this sweep (outside the checklist rows)

- `spec/vectors/README.md:7` — references the removed `pairing/` vector family
  (ADR-0015 fallout; the directory is gone, the prose survived).
- `bench/cooperate.sh` header comments are stale relative to the script body:
  the usage example names `REQUESTER_SSH`/`PERFORMER_SSH` but the script
  requires `ALICE_SSH`/`BOB_SSH`; and it says "serve.sh with ROLE=peer does
  that" but `serve.sh` has no `peer` role (its two-way roles are
  `alice`/`bob`). Comment-only; the script logic itself carries no PAIR-era
  mechanism. Per the AK-08 sweep rule (documentation only), left untouched and
  recorded here.
- No bench or fleet script references a removed mechanism (pairing listener,
  PAIR port, invitation secret, `pair invite|accept`, `peer confirm`) in its
  executable logic — the grep for A0.2 came back clean.
- `cargo fmt --all --check` fails on the pristine tree under the pinned
  toolchain (`rust-toolchain.toml` → 1.95.0 / rustfmt 1.9.0): the committed
  code predates that rustfmt's formatting. Pre-existing, unrelated to this
  commit (documentation-only); relevant to A0.1 release hygiene.

# The coordination surface (`akson_byom_exchange_v1`) and the A0 checklist

Status: **built, with named gaps.** This was the proposed design note that
opened the C4 milestone of the kovee+byom program (plan
`2026-07-25-kovee-byom-implementation-plan.md` §5, family contract
`byom/design/2026-07-25-family-contract.md`); it fixed the shape and the
constraints, and [ADR-0016](../spec/adr/0016-coordination-surface.md) is the
normative decision it asked for. C4 slices 1a, 1b, 2 and 3 have since landed, so
the body below is **the proposal, kept as the record of what was asked for** —
"What shipped, and what did not" immediately after it is what is true today, and
where the two disagree the reconciliation wins.

Date: 2026-07-25 (reconciled against the build 2026-07-28)

## What shipped, and what did not

| Proposed here | Built today | Where |
|---|---|---|
| a third socket, `coord.sock`, bound only when a coordination UID is configured | **yes** — `AKSON_COORD_UID` is read at `aksond serve`; unset or empty ⇒ the socket is not created at all; a non-numeric value is fatal at startup | `crates/aksond/src/socket.rs`, `crates/aksond/src/main.rs` |
| `SO_PEERCRED` admission against a named UID | **yes**, plus the daemon's own UID so an operator can diagnose the surface without a second account | `Admission::coord` |
| `0600` + an ACL entry, *or* `0660` + a dedicated group — "ADR decides" | **`0660`**, and no ACL and no group are created by akson. Reachability is the deployment's one visible OS act (the runtime directory's mode and ownership); admission is still the `SO_PEERCRED` check, and the file mode is explicitly *not* the boundary | `bind_coord_socket`, `deploy/akson-daemon.service` |
| deny-by-absence registry of eight ops | **yes**, all eight answer; everything else on coord returns `403 forbidden-surface`, and the surface matrix is asserted over a real socket for *every* control op | `crates/aksond/src/control.rs`, `crates/aksond/tests/coord_boundary.rs` |
| admin may invoke coord ops; no coord connection may invoke an admin op | **yes** — `Surface::Coord` dominates nothing, including `Worker` | `control.rs::authorize` |
| consent minted on **admin**, risk-card first, one-shot | **yes** — `stage_consent` / `akson stage consent <ref>`, which returns the card *and* the receipt from one call over the row it is minted against | `coord.rs::stage_consent` |
| `dispatch` atomically consumes the receipt and dispatches | **yes**, and the bytes now actually leave: one store transaction spends the receipt and commits the row, then a carrier POSTs the staged bytes to the pinned recipient over the same mutual TLS every other peer-to-peer byte uses | `coord.rs::dispatch`, `coord_egress.rs` |
| a durable, cursored coordination event feed | **yes** — a dedicated `coord_events` table; the cursor's only content is the row sequence, so it cannot address anything else | store schema V21 |
| an in-tree carrier schema through the ADR + golden-vector process (D5) | **yes** — `spec/ext/coord-dispatch.v1.schema.json`, media type `application/vnd.akson-dev.coord-dispatch.v1+json`, `additionalProperties: false`, with 27 golden vectors under `spec/vectors/coordination/` | ADR-0016 §5 |

**Corrections — where this note describes something that was not built that
way.** Each of these is a claim in the body below that the code does not
support:

- **Admission is not configured at `aksond init`, and there is no config-file
  path.** `AKSON_COORD_UID` is an environment variable read once at
  `aksond serve`. `aksond init` does not record it and `akson doctor`
  (`diagnose`) does not report the coordination surface at all — the startup log
  line is the only place the daemon says whether it bound one. Open question 1
  below asked about exactly that interaction; this is the answer, and it is
  thinner than the question assumed.
- **`stage_show` has three statuses, not six.** `staged`, `consented`,
  `dispatched`. There is no `delivered`, no `verified` and no `failed` status:
  a coordination dispatch is not a contract, so no result manifest and no
  requester outcome will ever exist for it. Where the *bytes* got to is a
  separate durable column (`egress.state`: `pending` / `sent` / `failed`), which
  is what `delivered` was reaching for.
- **The event kinds are not the ones listed below.** Outbound: `staged`,
  `consent_recorded`, `dispatched`, and `egress_recorded` — one per carriage
  *attempt*, which is deliberately not a dispatch. On a *receiving* endpoint:
  `dispatch_received` and `dispatch_refused`. `delivery_received`,
  `verification_completed` and `failed` do not exist.
- **`task_status` reports acknowledgement, not verification.**
  `verification.state` is `acknowledged` exactly when the pinned recipient echoed
  this staged digest and `unacknowledged` otherwise; `result_manifest_digest` and
  `outcome_state` are **permanently** null for the same reason as above. The
  fields stay present because a driver parses them.
- **The consent receipt has `max_uses`/`uses` but no expiry.** Open question 2
  asked for both; the `coord_consents` row carries the one-shot counters and a
  sealed body, and nothing time-bounds a minted receipt. What bounds it instead
  is the ledger: once a staging has been dispatched, `stage_consent` refuses
  `409 already-dispatched`, so a stale receipt cannot be joined by a second one.

**Still unbuilt, and named rather than implied:**

1. **The receiving side does not retain a coordination payload.** It verifies the
   envelope, acknowledges, records one `dispatch_received` event with the digests
   and the sender's root — and drops the bytes. Reading one back would need an
   inbound coordination op the registry deliberately does not have, and storage
   without a reader is an unbounded liability. This is the natural next decision.
2. **The envelope is unsigned.** Authenticity is the channel's (pinned mutual
   TLS on both sides) and integrity is the digest chain; there is no key purpose
   for a coordination dispatch, and borrowing `contract-proposal` to sign a
   non-contract would break one-key-one-role. So a coordination dispatch is
   authenticated but **not non-repudiable**: a recipient cannot prove to a third
   party who sent it. A future ADR that needs that adds the purpose.
3. **Crash tests do not yet cover the coordination commit points.** The test
   surface below asked for crash tests at stage / consent / dispatch. What exists
   is narrower and should be read as such: a spent receipt is still refused after
   the daemon restarts, the dispatch row is `pending` by schema *default* so a
   crash between the commit and the send is honest by construction, and a failed
   carriage is proven resumable under the same `execution_key` without
   re-spending consent. `crates/aksond/tests/crash_matrix.rs` has no coordination
   row.
4. **Open question 4 — the `RestoreLineage` re-staging hint — is untouched.**
   `stage` takes `task_type`, `performer` and `payload_base64` and nothing else.
5. **Live cross-implementation interop.** Everything is producer-only: golden
   vectors re-derived by `xcheck/`, in-process tests, and one two-process
   scenario (`harness/interop/scenario-coord-dispatch.sh`) in which both
   endpoints are akson. No second implementation has run against this surface.

**The assurance is a developer one, and it bounds all of the above.** Admission
is a Unix UID via `SO_PEERCRED` — which *user* connected, not which program, so
there is no attested process identity and anything running as that UID reaches
the surface. The default profile has no UID separation at all: `coord.sock` is
simply absent until one is configured, and the separate-identity arrangement
lives in [`deploy/`](../deploy/README.md), whose units have never been scored by
`systemd-analyze security` (it needs them installed as root), so no hardening
number is claimed for them. The media types are in the unregistered
`vnd.akson-dev` tree (A0.4b), which is why a stable release is refused.

---

*Everything below this line is the design note as proposed on 2026-07-25. Read it
with the reconciliation above: where they disagree, the reconciliation is what
the code does.*

## Why a third socket

**Kovee's `byom_akson_dispatch_v1` driver is the sole caller of this surface**
— byom's delegation engine *authorizes* (issues the act and consumed permit)
and never calls akson or holds any akson credential (byom §17.2, family
contract L62–L63). The driver must stage and dispatch outbound contracts and
read coordination state — and it **must not** hold or reach akson's admin
surface. The admin
socket cannot be profile-scoped for this: a scoped token on a broad listener
is explicitly rejected (plan C4), and the control protocol's same-UID rule is
exactly what makes admin unreachable from a separately-identified driver.
So: a third socket, with its own audience, admission rule, credential family,
and deny-by-absence op registry.

~~~text
| Socket | Path                              | Admission                        | For |
|--------|-----------------------------------|----------------------------------|-----|
| admin  | $XDG_RUNTIME_DIR/akson/admin.sock | same UID                         | operator authority (unchanged) |
| worker | $XDG_RUNTIME_DIR/akson/worker.sock| same UID (sandboxed worker)      | result submit, brokered call (unchanged) |
| coord  | $XDG_RUNTIME_DIR/akson/coord.sock | **configured allowed peer UID**  | stage / dispatch / read — the exchange surface |
~~~

Admission for `coord`: `SO_PEERCRED` UID must equal a UID explicitly named at
`aksond init` (`AKSON_COORD_UID` / config; empty ⇒ socket not bound). In the
hardened deployment profile the kovee/byom driver runs as its own Unix user;
that user is the one named. The socket is `0600`-owned by the daemon user with
an ACL entry for the coordination UID (or `0660` + dedicated group — ADR
decides). *(Shipped: an environment variable read at `aksond serve`, not
`aksond init` and not a config file; mode `0660`, with no ACL and no group
created by akson. See the reconciliation.)* Admin never dominates coord in the
*outward* direction that matters:
coord ops are also callable from admin for diagnostics, but **no coord
connection can ever invoke an admin op** (deny-by-absence, same
`forbidden-surface` rule as today).

## The op registry (deny-by-absence; everything absent is forbidden)

*All eight ops answer today. The **semantics** of three of them are narrower than
this table says — `stage_show`'s status set, `events_read`'s event kinds, and
what `task_status` can report — because a coordination dispatch is not a
contract. The reconciliation lists each; `spec/control-protocol.md` is the
reference for what a reply actually contains.*

| Op | Semantics |
|---|---|
| `coord_whoami` | daemon identity + endpoint fingerprint + protocol/feature versions (mirrors `who_am_i`, read-only) |
| `peer_show` | verified peer identity tuple + card claims for a named paired peer; never enumerates beyond the caller's query |
| `stage` | **inert idempotent staging**: full task payload (task_type URI + byom-owned payload per D5); returns `{stage_ref, staged_digest}`; idempotent on content digest — same bytes, same ref; arrival-side nothing happens (staging is local, outbound) |
| `stage_show` | staged contract status: `staged \| consented \| dispatched \| delivered \| verified \| failed`, digests, consent-receipt ref if any |
| `dispatch` | one-shot: requires `{stage_ref, consent_receipt_ref, execution_key}`; atomically consumes the (unconsumed) consent receipt and dispatches the staged bytes; same `execution_key` retry returns the same dispatch receipt; a consumed receipt cannot be re-consumed under a different key |
| `task_status` | result/evidence verification status for a dispatched task (verified digests, outcome state); read-only |
| `events_read` | durable cursored coordination events (`staged`, `consent_recorded`, `dispatched`, `delivery_received`, `verification_completed`, `failed`) with opaque cursors; the driver's projection feed |
| `capability_evidence` | `FederationCapabilityEvidence` for a peer: rollback detection, key expiry, confinement, budget dimensions, evidence schemas — each marked `peer_asserted \| locally_observed`; consumed by byom's fail-closed capability matrix |

**Explicitly absent — and the point:** no approve/deny (consent to a staged
contract is a human act on the admin surface: a new `stage consent <ref>`
admin op / `akson stage consent` CLI verb mints the one-shot consent receipt,
risk-card first), no inbound-approval op of any kind, no pairing, no peer
import, no processor or credential ops, no `task send`/`fulfill`/`deliver`,
no configuration. A compromised driver can stage bytes (inert) and burn its
own consent receipts — it cannot mint consent, reach a credential, or touch
inbound authority.

## Invariants carried over

- **Arrival is not execution** — unchanged; staging is outbound-local and inert.
- **Durable-before-effect** — stage/consent/dispatch each commit before any
  visible effect; dispatch's consent consumption is atomic with egress
  (`ExternalAuthorizationConsumption { phase: atomic_with_egress }` on the
  kovee side, family contract L64).
- **Introduction protocol** — ADR-0015 unchanged: first contact on the RECEIVE
  surface, no pairing listener; the coordination surface is local-only and
  never crosses the wire.
- **Schema changes through the front door** (plan D5 as revised): exchange
  payloads ride `task_type` with byom-owned schemas where a payload suffices;
  where a phase needs a carrier akson's closed schemas cannot hold, C4 adds an
  in-tree akson schema version through the ADR + golden-vector process. The
  four phase-owned signed shapes — `AksonByomRequestClassification`,
  `AksonByomAcceptanceClassification`, `AksonByomResultClassification`,
  `AksonByomAdmissionClassification` — are payload content validated
  byom-side; the C4 carrier table names each shape's exact carrier.

## Test surface (C4 exit, producer-only)

Golden vectors for every op request/reply and every coordination event; a
conformance driver (not K6/B5) proving: stage idempotency (same bytes → same
ref), dispatch one-shot semantics (retry returns same receipt; second key on
a spent receipt fails closed), consent-required (dispatch without a consent
receipt fails), cursor recovery, `forbidden-surface` for every admin op on
coord; crash tests at stage/consent/dispatch commit points.

*Shipped: 27 golden vectors in `spec/vectors/coordination/` (request wire, reply
field sets, the staged-digest derivation and its idempotency, the dispatch
envelope, the cursor encoding, and every refusal body), re-derived independently
by `xcheck/`; `crates/aksond/tests/coord_boundary.rs` asserts the surface matrix
over a **real socket** for every control op, not just the admin ones;
`coord_dispatch.rs` and `coord_egress_e2e.rs` cover idempotency, one-shot
semantics, consent-required, cursor recovery, a lost acknowledgement, a silent
peer, a misrouted or tampered envelope, and a resent refusal; and
`harness/interop/scenario-coord-dispatch.sh` runs the chain across two processes
and real mutual TLS. **Not shipped: crash tests at the commit points** — see
"Still unbuilt" above for what stands in for them.*

## A0 — capability & maturity checklist (gates C4 and I2)

Evidence, not features. Each row is recorded with its artifact when satisfied:

| # | Item | Evidence |
|---|---|---|
| A0.1 | Pinned release artifacts (aksond, akson, akson-mcp, adapters) with SBOM/provenance | lock-manifest rows + build attestation |
| A0.2 | ADR-0015 introduction vectors pinned; no PAIR-port assumption in any fleet/bench script | vector refs; grep-clean fleet scripts |
| A0.3 | Key custody status recorded honestly (interim custody is a named residual carried into every I2 claim) | threat-model residual entry |
| A0.4a | Extension-URI namespace: **met** (`https://akson.cc/ext` secured) | namespace.rs constant |
| A0.4b | Payload media-type registration: **provisional** (`MEDIA_TYPES_ARE_PROVISIONAL = true`) — release gate | status note |
| A0.4c | Licensing: **open** (Apache-2.0 proposed, maintainer decision) — release gate | status note |
| A0.5 | Hardened deployment profile: separate Unix identities per daemon, hardened service units, explicit egress policy | profile doc + unit files |
| A0.6 | Test proving no inherited SSH/cloud credentials are reachable from workers | named test in the fleet harness |

*The live status of every row above is `design/a0-evidence.md`, not this table.
Two have moved since: A0.1 now has a **prerelease tagged in-tree and unpushed**
(so no artifact is published and nothing verifies yet), and A0.5's units exist
but have never been scored by `systemd-analyze security`.*

## Open ADR questions (decided at C4 start)

1. Coord admission: named-UID ACL vs dedicated group (`0660`); interaction
   with `aksond init` config and `doctor`.
2. Consent receipt shape: reuse the decision/DSSE machinery vs a dedicated
   sealed receipt row; expiry and `max_uses:1` representation.
3. Coordination event durability: same store, dedicated table + outbox
   discipline; cursor epoch integration with state-generation recovery (§15.5).
4. Whether `stage` accepts a byom-side `RestoreLineage` hint for re-staging
   after a byom restore (family contract L15/L65 interplay).

*Where these landed. **1 — decided** by ADR-0016 §1: a named UID, not a group,
checked by `SO_PEERCRED`; the socket is `0660` with no ACL; the configuration is
an environment variable at `aksond serve`, and `doctor` does not report the
surface at all. **2 — decided by what shipped**, not by a further ADR: a
dedicated sealed `coord_consents` row with `max_uses`/`uses`, not the
decision/DSSE machinery — and **without** an expiry, which the question asked
for; the dispatch ledger's `409 already-dispatched` is what stops a second
consent instead. **3 — decided by what shipped**: the same store, a dedicated
`coord_events` table, and an opaque cursor whose only content is the row
sequence. No outbox discipline and no cursor-epoch integration with §15.5
state-generation recovery were built; a driver that survives a store rollback
would re-read from its cursor with no epoch to tell it that happened, which is
the part of question 3 that is still genuinely open. **4 — untouched.***

# The coordination surface (`akson_byom_exchange_v1`) and the A0 checklist

Status: proposed design note — opens the C4 milestone of the kovee+byom
program (plan `2026-07-25-kovee-byom-implementation-plan.md` §5, family
contract `byom/design/2026-07-25-family-contract.md`). The normative ADR is
authored when C4 starts; this note fixes the shape and the constraints.

Date: 2026-07-25

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
decides). Admin never dominates coord in the *outward* direction that matters:
coord ops are also callable from admin for diagnostics, but **no coord
connection can ever invoke an admin op** (deny-by-absence, same
`forbidden-surface` rule as today).

## The op registry (deny-by-absence; everything absent is forbidden)

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

## Open ADR questions (decided at C4 start)

1. Coord admission: named-UID ACL vs dedicated group (`0660`); interaction
   with `aksond init` config and `doctor`.
2. Consent receipt shape: reuse the decision/DSSE machinery vs a dedicated
   sealed receipt row; expiry and `max_uses:1` representation.
3. Coordination event durability: same store, dedicated table + outbox
   discipline; cursor epoch integration with state-generation recovery (§15.5).
4. Whether `stage` accepts a byom-side `RestoreLineage` hint for re-staging
   after a byom restore (family contract L15/L65 interplay).

# ADR-0016 — The coordination surface (`akson_byom_exchange_v1`)

Status: proposed

Date: 2026-07-26

Relates to: [ADR-0012](0012-dsse-envelope-media-type.md) (payload typing),
[ADR-0015](0015-introduction-protocol.md) (first contact),
`design/2026-07-25-byom-exchange-coordination-surface.md` (the design note this
decides),
`design/a0-evidence.md` A0.5 (the identity graph).

## Context

A sibling system (byom, via kovee's driver) needs to stage outbound contracts,
dispatch them once a human has consented, and read coordination state. It must
**not** be able to reach the admin surface: byom's own design forbids it
holding akson admin authority, and the kovee+byom program's R0 review rejected
"a scoped token on the broad admin listener" as an adequate boundary.

Akson has two control sockets today (`spec/control-protocol.md`): **admin**
(authority-bearing) and **worker** (narrow, for the sandboxed adapter). Both
admit only the daemon's own UID via `SO_PEERCRED`, and `Surface::satisfies`
gives admin dominance over worker.

The question this ADR settles: how does a *different* local principal get a
bounded surface, and what exactly is on it?

## Decision

### 1. A third socket, admitted by a configured UID

`coord.sock`, alongside the existing two, bound **only** when
`AKSON_COORD_UID` names an allowed peer UID. Unset ⇒ the socket is not created
at all — the same "absent rather than guarded" posture ADR-0015 took when it
removed the bootstrap listener (an unmounted endpoint cannot be probed).

Admission: the connecting peer's `SO_PEERCRED` UID must equal the configured
UID, **or** the daemon's own UID (so the operator can diagnose the surface
without a second account). Everything else is refused before the request line
is read.

**Chosen: a named UID, not a group.** A group grants membership transitively
and is edited by tools far from akson; a single UID is checkable in one
comparison, appears verbatim in the unit file
(`deploy/akson-coord.service`'s `User=akson-coord`), and makes the boundary an
OS access domain that an operator can read off `ls -l`. The cost — one
identity per driver rather than a pool — is the property we want.

### 2. The registry is deny-by-absence, and asymmetric

| Op | On coord | Purpose |
|---|---|---|
| `coord_whoami` | yes | identity + protocol/feature versions |
| `peer_show` | yes | verified peer identity tuple + card claims |
| `stage` | yes | **inert, idempotent** staging of outbound bytes |
| `stage_show` | yes | staged contract status + digests |
| `dispatch` | yes | one-shot: consumes a consent receipt, dispatches |
| `task_status` | yes | verification status of a dispatched task |
| `events_read` | yes | durable cursored coordination events |
| `capability_evidence` | yes | `FederationCapabilityEvidence` per peer |
| *everything else* | **no** | `forbidden-surface` |

Absent by design and worth naming: no approve/deny of an inbound task, no
pairing, no peer import, no processor or credential operation, no
`task send`/`fulfill`/`deliver`, no configuration. A compromised driver can
stage inert bytes and burn consent receipts it was already given. It cannot
mint consent, reach a credential, or touch inbound authority.

**The asymmetry is deliberate:** admin may invoke coord ops (diagnostics), but
a coord connection can never invoke an admin op. So `Surface` gains `Coord`
with admin dominating it, and `Coord` dominating nothing.

### 3. Consent stays on admin

`dispatch` requires a consent receipt it cannot create. Minting one is an
admin operation (`stage consent <ref>`, CLI `akson stage consent`) that shows
the operator the risk card for the exact staged digest first. This is the
§5.2 explicit-decision invariant applied to the federation path: the outward
disclosure is never automatic, and never the driver's to authorize.

### 4. Staging is inert

`stage` writes bytes and returns a reference. It starts no model, mints no
authority, touches no workspace, invokes no tool, opens no socket — the §6.3
"arrival is not execution" invariant, applied to the outbound direction.
Idempotency is on the content digest: the same bytes yield the same reference
and no second record.

## Threat cases

| Threat | Outcome |
|---|---|
| the driver is compromised and tries to approve an inbound task | the op does not exist on coord → `forbidden-surface`; it is not merely unauthorized, it is unaddressable |
| …tries to mint its own consent | consent is admin-only; a coord connection cannot reach it |
| …tries to dispatch bytes a human never saw | `dispatch` requires a receipt bound to the exact staged digest |
| …replays a spent receipt | one-shot: the receipt is consumed atomically with the dispatch |
| …reads a processor credential | no credential op exists on coord; the broker never leaves the daemon |
| a foreign local user connects to `coord.sock` | UID mismatch, refused before the request is read |
| `AKSON_COORD_UID` is unset but a driver exists | the socket was never created; there is nothing to connect to |
| the operator wants to inspect the surface | admin dominates coord, so `akson` diagnostics work without a second identity |

## Consequences

- `spec/control-protocol.md` gains a third surface and its op table; the
  document's "who may connect" section stops being "same UID" universally and
  becomes per-socket.
- `Surface` grows a third variant, so `satisfies` is no longer a two-case
  match — the dominance relation is stated explicitly rather than implied.
- Golden vectors cover each coord op's request/reply and every refusal shape,
  re-derived by `xcheck/`.
- The four open questions in the design note narrow to three: this ADR settles
  admission (question 1). Consent-receipt shape, coordination-event durability,
  and the `RestoreLineage` re-staging hint remain open and are decided as the
  ops that need them land.
- A second driver identity would need a second UID; if that becomes common,
  revisit — but do it deliberately, not by widening this one to a group.

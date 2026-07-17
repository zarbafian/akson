# Working groups: coordinating sovereign endpoints

Status: **Proposal / draft** — both forks resolved and design-reviewed. Hardened
against the review (mesh-not-relay topology, roster/removal model, immutable-order
authorization, untrusted/non-evidence signals). **Gated**: per §9.4 and §19 Phase
4, groups need removal/rekey + formal modelling + independent review before any
v1 code. Not yet normative.
Date: 2026-07-17
Relates to: pairing (§8), reliable delivery (§9), task contract (§10), local
authority (§12), risk card (§5).

## A concrete example

Three developers, three machines, one demo goal — *ship the checkout flow*:

- **Session A** (frontend repo, human *Ana*): can run the UI, knows the component
  layout.
- **Session B** (payments service, human *Ben*): can reach the staging payment
  gateway — with credentials Ana and Cara do not have.
- **Session C** (infra repo, human *Cara*): can deploy; holds the deploy keys.

No single agent — and no single harness — has all three repos, all three
credentials, or all three humans' knowledge. They form a working group,
`demo-checkout`. A's agent coordinates: it asks B's agent to verify the gateway
(B runs it *with B's credentials* and shares the **result**), asks Cara's human
"which environment is the demo on?", and assembles the answers into a plan.

Nobody handed over a repo, a credential, or control of their machine. They pooled
*outputs and knowledge* over a shared coordination context. Everything smart — the
decomposition, who to ask, how to merge — was done by the orchestrating agent.
Everything Axon did was carry the coordination and keep the authority bounded.

## The principle

> A working group lets **sovereign endpoints** pool what they each uniquely have —
> knowledge, access, tools, humans — **without pooling trust or authority.**

This is the line between a working group and a harness's sub-agents. A harness
*owns* its sub-agents: same context, same trust, same authority. A group
*federates* endpoints that no one owns — each keeps its own directory, knowledge,
credentials, human, and local authority. So:

- A group is a shared **coordination context**, not a shared trust or authority
  domain. Joining a group never collapses trust.
- Every member's **sharing** is gated by that member's own human/policy; every
  member's **work** is authorized locally (§12). A group coordinator can *ask*,
  never *command* — the same coordinator-not-commander property as delegation.
- You still only trust who you have vetted. A group gives you a *context* to
  coordinate in and a *bounded* way to interact with members you were introduced
  to — it does not silently extend your trust to strangers.

## Why (what a harness's sub-agents cannot do)

Every motivating case is an instance of *no single harness has it all*:

- **Disjoint access / credentials** — each member can reach a system the others
  cannot (prod DB, a cloud account, hardware, a private repo). The group succeeds
  *without anyone handing over a credential*: you run it on your box, share the
  result, not the secret. The most Axon-native case — authority never leaves the
  endpoint (§12).
- **Disjoint / complementary information** — the stated case; each member holds a
  piece.
- **Human-knowledge federation** — the point is to reach the *humans* behind the
  endpoints: "why does this config exist?" fans out; each human answers what they
  know.
- **Multiple sessions, different directories, one goal** — the stated case
  (repos/services coordinated toward a single deliverable).
- **Cross-organization / cross-trust-domain** — a joint task between organizations
  that do not merge trust (incident response, a supply-chain audit).
- **On-demand consultation / escalation** — an agent stuck on a task pulls a
  contact in for a bounded consult, then the group disbands.
- **Follow-the-sun continuity** — a group carries a task across shifts, timezones,
  and humans with shared context.
- **Sovereign verification quorum** — independent members cross-check work;
  stronger than same-harness cross-check because the verifiers genuinely do not
  share a brain.

A lifetime dimension cuts across these: **ad-hoc / per-task** groups vs **standing
teams** that recur across many tasks.

## Non-goals (the orchestrating agent's job, not Axon's)

Axon carries coordination and bounds authority. It does **not** do the
intelligence:

- task **decomposition** and assignment (who does which part);
- result **merging** / aggregation;
- deciding **what to share**, **whom to invite**, or **what to ask** the humans.

Those live in the orchestrating agent (a harness like Claude). Axon never
interprets a group's internal structure; slots and subtasks are opaque labels to
it. This keeps Axon a thin, auditable communication + safety substrate.

## What Axon provides (thin)

Sketched here; the normative shapes land as schemas/ADRs once the forks below are
settled.

- **Group identity + roster + roles.** A group is a shared context (building on the
  A2A `context_id`) with a membership roster and a role per member (e.g.
  coordinator, member, observer, specialist).
- **Formation protocols** for the three modes (below): ad-hoc among connections,
  invite/assign by allowed contacts or configurable roles, and public forums.
- **Role → default permission set, adjustable on join/accept.** A member accepts a
  bounded default when joining and may raise/lower it — the risk-card / allow-once
  model (§5) applied at group-join time. Permissions here bound *communication and
  coordination rights within the group* (post signals, be assigned contracts,
  invite others, see a sub-channel), never execution — execution stays locally
  authorized.
- **Introduction / vetting** for members not bilaterally paired (see the trust
  fork). Introductions are explicit, default-bounded, and human-gated — never
  automatic.
- **Coordination signals** — a small `coordination.v1` message extension correlated
  by the group context: `assign | progress | status | complete | cancel`, carrying
  an agent-chosen `slot` and a `ref` to the contract/task it concerns. Inert at the
  daemon (never causes execution, like all receive-path data), but the review
  sharpened three rules the orchestrator layer must honour: (a) `slot`/`ref` are
  **untrusted, length-bounded** free text — an orchestrator must treat them as
  hostile input, not control-plane it can trust; (b) `status`/`complete` are
  **self-asserted claims, never evidence and never a trust class** (trust is
  derived locally, §14.4–5) — a coordinator cannot aggregate them into "the group
  verified X"; (c) `cancel` is advisory and scoped — a member honours a cancel of
  *its own* `ref` only as the work order's `remote_cancel` caveat allows (§9.3),
  never as ambient kill authority.
- **Delegation bounds** — the `delegate` capability (§12.1) for a coordinator that
  fans work out *on behalf of* an upstream requester: roster, depth, fan-out, cost
  budget. Keeps a coordinator from over-delegating.
- **A group management API** (see below) — the local control surface that creates
  and manages groups over already-paired contacts.
- **Discovery / forums** — *future*, layered on the management API; not in v1.

Actual work stays ordinary signed contracts (coordinator → member), so results,
evidence, and idempotency flow exactly as today.

## Formation modes

- **Ad-hoc among connections** and **invite / assign by allowed contacts or
  roles** fit cleanly: group-join messages between *already-paired* peers, gated by
  the default-permission accept step. "Assign" and "invite" differ only in framing
  (a role/policy places you vs a contact asks you); both end in the invitee's local
  accept.
- **Public forums** is the one genuine architectural departure. Axon today is
  pairing-only — you pin exactly who you paired with. Forums add **discovery** and
  interaction with members you did *not* bilaterally pair. Desirable, but it makes
  the trust model the crux: forum-introduced members are **low-trust by default**,
  and the group is where an **introduction** happens — explicit, bounded by the
  default permission set, human-gated.

## Topology, transport, and roster (review-hardened)

The adversarial review found the load-bearing gap: the *transport* was left
implicit, and the natural star reading (coordinator relays everyone's coordination)
would make the **coordinator a relay of the coordination plane** — exactly the
"compromised relay" adversary the base design forbids in v1 (§1: no relay). So v1
is pinned to the only reading that stays legal:

- **A group is a mesh of existing bilateral edges.** You coordinate only with
  members you are *directly paired* with; the coordinator **never relays** B↔C
  traffic. If B and C must interact directly, they must be directly paired (or use
  the deferred introduction path). No coordinator-in-the-middle of another pair's
  messages.
- **The group id is access-controlled, not a bare correlation label.** Reusing the
  A2A `context_id` is a correlation *hint*, not a security field; every inbound
  group-tagged message MUST be checked against the local roster before it is
  admitted to the group context. Knowing a `context_id` grants nothing. (Note: a
  shared id across N endpoints is a linkable identifier — it belongs in the §9.4
  metadata-leakage inventory.)
- **The roster needs a defined consistency and removal-enforcement model.** "Local
  records" alone is insufficient: members can diverge on who is in the group, and
  removal that is only *advertised* leaves a removed member live on any edge it
  still holds. v1 must define roster authority, per-inbound-message membership
  enforcement, and a removal-propagation guarantee.

**This whole feature is gated by the base design.** §9.4 requires "removal and
rekey behaviour *before* groups are enabled," and §19 Phase 4 requires groups to
have "formal modelling and independent protocol review before release." So working
groups stay a **design track** until that modelling and review are done — not
something to build into v1 code ahead of the gate.

## Trust model within a group

Per-edge trust is preserved. Membership does not make members trust each other;
it provides a context and a bounded interaction channel. Concretely:

- A member you bilaterally paired with is trusted as today (pinned identity, §8).
- A member introduced *via* the group (forum or friend-of-a-friend) starts
  low-trust: the default permission set bounds what they can do with you, and
  raising it is an explicit, human-gated act — exactly the pairing-lifecycle
  posture (§8.4), scoped to the group.
- Removing/suspending a member from a group denies further group interaction the
  same way peer removal denies work (§8.4), without touching any bilateral pairing.
- **Co-membership confers nothing.** The roster is a trust-*shaped* object handed to
  the exact component (the orchestrating agent) tempted to infer trust from it — so
  the invariant for orchestrator implementers is explicit: never derive
  authorization from roster or role; a co-member you did not vet is a stranger.

## Authorization model (resolves fork #1)

Identity and authority are fully separate, and authority is incremental.

- **Pairing — and any group/forum introduction — grants identity, never
  authority.** An introduction gives a verified channel to a party you now
  recognise; it confers zero authority. A friend-of-a-friend is an introduced
  identity with no trust attached — there is no transitive authority to leak. This
  rule is uniform for paired, introduced, and forum-met parties.
- **Authority is incremental and bidirectional**, in the §12.1 capability
  vocabulary. Each side may raise (or lower) the standing authorization it holds
  for another party, and a party may *request* authorizations for itself
  preemptively (to avoid prompting mid-task). A standing authorization is still
  materialised into a one-shot work order per actual execution (§12.3).
- **Obtain-on-gap during execution (never mutate a running order).** When an
  attempt reaches a point needing an authorization it lacks, it neither fails
  destructively nor proceeds without authority. The daemon tries to obtain the
  increment, in order: a standing local policy (auto-grant on match — *only* if the
  peer binding has not changed, §12.4), else the human (risk card, §5), else an
  **authoritative agent** (bounded — see below). If none grants, the attempt
  **cancels fail-closed**; it never proceeds without authority.

**The one-shot work order is immutable and this must not weaken that.** A work
order is MAC'd and digested over its whole form, its budget/nonce reserved
atomically at claim (§12.3); it **cannot be "extended" in place**. So authority
never grows *inside* a running order. Two ways to obtain more, in increasing
complexity:

1. **v1 — fail-and-reissue.** The attempt ends cleanly reporting "needs authority
   X" (an inert result, not a command); the daemon obtains X; a *new* work order —
   own nonce, own atomic claim, own budget and deadline — re-runs the work. No
   paused state, no mid-attempt re-entry, no re-derivation of the effect-safety
   argument. This is the safe default.
2. **later — increment-as-new-order.** To avoid re-running, model each increment as
   a *separate* one-shot order the paused parent attempt explicitly waits on, with
   the executor re-issued a fresh descriptor. If this is built, a `paused /
   awaiting-authorization` state is **post-claim** and MUST be swept to `ambiguous`
   by crash recovery exactly like `claimed`/`running` (or a crash-after-effect
   fails open — the fatal bug the reviewer caught). Resume is defined strictly
   *after* the last durably-committed effect, and output-gate counters are made
   durable on the attempt row (not the worker process) so limits hold across the
   gap. The worker's authority-request is treated as inert data bounded to the
   accepted contract's declared `requested_capabilities` — never a command, and
   never wider than the contract envelope.

**The "authoritative agent" is a locally-configured, bounded deferral — never
ambient.** The performer's own policy names which agent it defers to *for which
capability class*; the granted increment MUST be ⊆ the accepted contract's
declared envelope AND ⊆ the performer's own standing ceiling for that peer; the
deferral is **suspended on any binding change** of the authoritative agent's key
(§12.4), and deferral depth is bounded (no defer-to-my-authoritative-agent
chains). Because a coordinator can be named here, this is the one place group
structure touches authority — so it is floored by the local policy ceiling (§10.3)
and surfaced on every risk card. Without these bounds, "obtain from an
authoritative agent" is a privilege-escalation backdoor, especially in unattended
(follow-the-sun) runs where the human is absent by design.

## Management API and v1 scope (resolves fork #2)

v1 has **no discovery and no forums.** Groups are created and managed explicitly
through a **simple local management API** over parties you have already paired
with. The API is the stable substrate; richer behavior — public forums, capability
advertisement, automated self-assembly — becomes a *future consumer* of the same
API, not a v1 surface or a later rewrite.

- The management API is a **local control-plane** surface (the admin socket,
  §16.2), driveable by the human operator (CLI) or by a local orchestrating agent
  — which is the path to orchestrating more complex behavior later.
- Operations (illustrative): create / list / show a group; invite or assign an
  already-paired contact with a role; accept / decline an invitation (adjusting the
  default permission set on accept, per the authorization model); set a member's
  role; raise / lower a member's standing authorization; remove a member or leave.
- The daemon translates management operations into the existing peer transport (an
  invite becomes a message to the contact; membership, roles, and authorizations
  are local records). No new trust or discovery surface is introduced — members are
  paired identities, organised into groups and roles locally.

## Delivery sketch

Both forks are settled, so this is the standards-first order:

1. **`coordination.v1` signal schema** (+ golden vectors + xcheck) — the inert
   coordination-message extension.
2. **Group membership / role model + the management API** — local control-plane
   operations (§16.2) and the invite / assign / accept protocol over paired peers,
   with the role → default-permission model.
3. **Incremental authorization** — standing per-peer authorization grants and the
   request-for-self protocol (§12.1 vocabulary), plus the `paused /
   awaiting-authorization` attempt state and the worker authority-request channel
   (the fork-#1 follow-ons).
4. **`delegate` capability** in `axon-authority` (roster / depth / fan-out /
   budget).
5. **Future:** discovery / forums, layered on the management API.

The orchestration engine (decompose / assign / merge) is **not** an Axon
deliverable — it lives in the harness.

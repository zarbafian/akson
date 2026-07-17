# Working groups: coordinating sovereign endpoints

Status: **Proposal / draft** (two open forks, below) — not yet normative.
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
- **Coordination signals** — a small, inert `coordination.v1` message extension
  correlated by the group context: `assign | progress | status | complete |
  cancel`, carrying an opaque agent-chosen `slot` and a `ref` to the contract/task
  it concerns. Signals can never cause execution (inert, like all receive-path
  data).
- **Delegation bounds** — the `delegate` capability (§12.1) for a coordinator that
  fans work out *on behalf of* an upstream requester: roster, depth, fan-out, cost
  budget. Keeps a coordinator from over-delegating.
- **Discovery** — only for the public-forum mode (see the discovery fork).

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

## Open forks (decide before schema)

1. **The introduction / trust model** for members not directly paired
   (forum- or group-introduced). This is the heart of the design: how a group
   safely lets me interact with a friend-of-a-friend without pretending I trust
   them. Options range from *no transitive introduction* (you must bilaterally
   pair before you interact, the group only correlates) to *coordinator-vouched
   introduction* (the coordinator introduces two members, each still gating with a
   bounded default) to *forum-attested* (a forum vouches identities).

2. **How much discovery** to include in v1: from **none** (invite/assign among
   existing contacts only — no forums) up to **public forums** with capability
   advertisement and self-assembly. Discovery is the biggest new surface and the
   biggest new attack surface.

## Delivery sketch (after the forks are settled)

Standards-first, in likely order: a `coordination.v1` signal schema (+ golden
vectors + xcheck); the group membership/role model and the join/invite/assign
protocol; the `delegate` capability in `axon-authority`; then discovery/forums if
in scope. The orchestration engine (decompose/merge) is **not** an Axon
deliverable — it lives in the harness.

# Properties: design ↔ code ↔ model

Traceability for every machine-checked property, plus what remains. "Design §"
refers to `../design/2026-07-16-threads-enterprise-agent-communication.md`,
"TM" to `../design/2026-07-19-threat-model.md`.

## Checked

### specs/TaskLifecycle.tla — the task/attempt lifecycle

One requester, one performer, an at-least-once network (every message
replayable forever), daemon crashes at every commit point. The attempt machine
is the implemented transition table from `akson-authority/src/attempt.rs`;
recovery is `akson-store::resolve_crashed_attempts` (`claimed|running →
ambiguous`, `pending` untouched).

| Model invariant | Design | Threat model | Enforcing code |
|---|---|---|---|
| `AtMostOnceEffect` | §6.3 effects are one-shot and crash-honest | T7 | `attempt.rs::next` (no edge out of `Ambiguous`), `resolve_crashed_attempts` |
| `DurableBeforeEffect` | §12.3 claim atomicity; §13.1 | T7 | `store::claim_attempt`, `store::advance_attempt` (CAS `WHERE state=prior`) |
| `NoAuthorityWithoutApproval` | §6.3 arrival is not execution; authority is endpoint-local | T11 | `aksond/receive.rs::dispatch_proposal` (handed only `&Store`); `issue.rs::issue_for_accepted` (requires `HeadState::Locked`) |
| `NoDuplicateTask` | §9.2 dedup covered values | T10 | `store::receive_request`/`peek`/`decide` |
| `OneShotWorkOrder` | §12.3 one-use nonce | — | `store::claim_attempt` (`AlreadyClaimed`/`NonceReused`) |
| `CompletedIsCommitted` | §14.1 completion atomicity | — | `store::complete_attempt_with_result` (one transaction) |
| `AmbiguousNeverDone` | §6.3 crash-honest; §10.1 ambiguous→`FAILED` | T7 | `attempt.rs` (`Ambiguous` terminal), bootstrap recovery |
| `CancelledMeansNoEffect` | §6.3 cancellation is not implicit kill authority | — | `attempt.rs` (`Pending\|Claimed --Cancel--> Cancelled`, `Running --Cancel--> Ambiguous`) |
| `OutcomeIsGrounded` | §14.5 outcomes | T8 | `aksond/outcome.rs::finalize_result` |

### specs/ContractChain.tla — the contract CAS head

`CanAdvance`/`Accept` are 1:1 transcriptions of
`akson-contract/src/chain.rs::apply_revision`/`accept_head`, under adversarial
delivery (replays, competing siblings, skipped revisions, forged
predecessors, stale acceptances).

| Model invariant | Design | Enforcing code |
|---|---|---|
| `LockIsFinal` | §9.3 no retroactive cancel | `apply_revision` (`Locked ⇒ HeadLocked`) |
| `AtMostOneLock` | §10.2 acceptance locks exactly one digest | `accept_head` (`AlreadyLocked`) |
| `ChainIntegrity` | §10.2 predecessor-digest chaining | `apply_revision` (`NonSequential`, `PredecessorMismatch`) |
| `HeadMatchesHistory` | §9.3 single CAS head | `store::submit_revision` |
| `LockedWasAdvanced` | §10.2 decision binds the exact digest | `accept_head` (`DigestMismatch`) |

### specs/ReceivePipeline.tla — the split receive commits

`dispatch_proposal`'s real commit order — peek → validate → head write →
input persist → idempotency commit — with crashes between any two writes and
an adversarial sender (any body under any message id, forever). Convergence
rests on three code facts, each transcribed: the task id is a pure function
of the proposal digest (`receive.rs:99`), `submit_revision` returns Stale as
`Ok` and `receive.rs:104` discards it, and the response is recomputed
deterministically.

| Model invariant | Design | Enforcing code |
|---|---|---|
| `OneTaskPerBody` | §9.3 CAS head; content-addressed task id | `submit_revision`, `receive.rs:99` |
| `RecordImpliesTask` | §9.2 durable-before-response (no lost receipt) | commit order in `dispatch_proposal` |
| `RecordIsFinal` | §9.2 byte-identical duplicate responses | `store::decide` |
| `LockedStaysLocked` | §9.3 no retroactive change by replay | `apply_revision` Stale on `Locked` |

Probes (deliberately false claims, refuted by TLC — see negative-checks.sh):
`OneTaskPerMid` — in the pre-commit crash window a reused message id with a
*different* body escapes Conflict detection, so one mid can leave two inert,
expiring tasks (benign; the honest invariant is per-body).
`CrashReplayNeverCompletes` — the post-crash replay does converge; the
`stale-aborts` differential shows this depends on the discarded Stale verdict.

### specs/Introduction.tla — first contact over identity tokens

The import / introduction / epoch machine for one relationship (design §8.2,
ADR-0015) transcribed: `add_peer_import`/`remove_peer_import` (removal
tombstones and advances the epoch in one statement), the hello admission
gate's epoch snapshot (`introduce.rs`), and the `commit_introduced_peer`
CAS (idempotent re-introduction; divergent material suspends per §8.4). The
adversary holds hellos open across remove + re-add (the ABA case) and
presents divergent material at will.

| Model invariant | Design | Enforcing code |
|---|---|---|
| `ActiveImpliesLiveImport` | §8.2 no admission without import; removal kills stale handshakes | hello gate + epoch snapshot + commit CAS + removal cascade |
| `OneMaterialPerEpoch` | §8.4 divergent material suspends, never re-pins or forks | `commit_introduced_peer` detect-change / suspend path |
| `ActiveEpochIsReal` | an active pin belongs to an admitted epoch | epoch snapshot in the per-connection state |
| `SuspensionHoldsMaterial` | suspension holds the disputed material for review | suspend branch leaves the pinned record in place |

### specs/BrokerBudget.tla — processor calls under one work order

`akson-broker/src/subattempt.rs` transition table plus
`store::prepare_call`'s in-transaction row count against `max_operations`;
crashes map `dispatching → ambiguous` (`resolve_crashed_calls`), never
retried.

| Model invariant | Design | Enforcing code |
|---|---|---|
| `BudgetBound` | §12.3/§13.1 lifetime operation budget | `prepare_call` (`BudgetExhausted`) |
| `AtMostOneTransmit` | §13.1 ambiguous never auto-retried | `subattempt.rs::next` |
| `WireBoundedByBudget` | §13.1 disclosure/cost bounded on the wire | both of the above |
| `DurableBeforeWire` | TM T7 'dispatching' before the first byte | `advance_call` |

### specs/RollbackAdversary.tla — TM T13, both ways

The §15.5/ADR-0009 state-generation scheme against an adversary who restores
DB snapshots. With `Detection = TRUE` (protected external counter),
`OneShotNonceForever` **holds**: a rolled-back DB is detected at open and
refuses authority. With `Detection = FALSE` (interim file-KEK custody,
`rollback_detection: unavailable`), negative-checks.sh requires TLC to
produce the attack trace — the threat model's residual risk as a
machine-checked counterexample instead of prose.

### specs/TaskLiveness.tla — the one honest liveness claim

Every issued work order eventually reaches a terminal state or expires
(§8.5 1-hour TTL; restart cannot extend it — the model's clock is world
time, untouched by crashes). Assumptions, stated as fairness: time advances,
a crashed daemon eventually restarts, the daemon enforces deadlines when up,
crashes are finite. The worker gets **no** fairness — termination holds even
if it never claims or hangs forever. The `no-expiry-fairness` negative check
shows the property genuinely depends on deadline enforcement.

> **Gap between this model and the code (be honest about it).** The spec's
> `KillClaimed`/`Expire` fairness assumes the daemon *drives claimed and
> unclaimed attempts to a terminal state at their deadline*. The daemon does
> **not** yet do this: a wall-clock ceiling now bounds a worker once `task run`
> starts (`worker_run.rs`), which corresponds to `KillRunning`, but an attempt
> that is approved and then **never run** stays `claimed` past its deadline —
> there is no sweeper emitting `Cancel`, and `AttemptState` has no expiry
> transition. So `Termination` is proved of the *model*, and holds of the code
> only for attempts that are actually run. Closing it needs a deadline sweeper
> over claimed/unclaimed attempts (tracked follow-up); until then this liveness
> claim is aspirational for the un-run case, and this note is the honest record
> of that (codex review).

### conformance/ — model ↔ code, as CI

`cargo test` in `conformance/` asserts, for **every** (state, event) pair,
that the implemented pure functions equal the TLA+ transition relations:
`akson-authority::next` ↔ TaskLifecycle.tla (49 pairs),
`akson-broker::next` ↔ BrokerBudget.tla (36 pairs), and
`akson-contract::apply_revision`/`accept_head` ↔ ContractChain.tla's guards
against real parsed contracts. A change to either side that forgets the
other fails the suite.

> **What conformance does and does not catch (be honest about it).** The oracle
> is a hand-transcribed `spec(...)` table in `conformance/src/lib.rs`, not a
> parse of the `.tla` files. So it catches **code drift** — a change to a Rust
> `next` function that contradicts the transcribed relation fails the suite —
> but not **model-only drift**: editing a `.tla` action *and nothing else* does
> not fail conformance, because the transcription is a third, independent copy.
> The transcription also flattens the specs' auxiliary guards (`spawned`,
> `inflight`): the Rust `next` functions are pure `(state, event) -> state` and
> do not track them, so those guards are verified by TLC over the full model,
> not by the pair-wise oracle. Deeper coupling would mean generating the oracle
> from the specs (tracked follow-up); the current guarantee is "the code cannot
> silently diverge from the transcribed relation," which is the drift that
> actually bit c2c (codex review).

### specs/PairingLedgerInd.tla + specs/RollbackAdversaryInd.tla — inductive proofs (Apalache)

`make inductive` discharges, per module, the three obligations of an
inductive proof (base `Init ⇒ IndInv`, consecution `IndInv ∧ Next ⇒ IndInv′`,
implication `IndInv ⇒ TargetInv`) with Apalache 0.58.3 — removing TLC's
run-length bound entirely:

- (The invitation-era PairingLedgerInd inductive proof was retired with
  invitation pairing; an inductive proof over Introduction is follow-up.)
-   steps. The strengthening pins `peers`/`consumedWrites` to `everConsumed`
  and threads `dead ⇒ ¬active ⇒ ¬everConsumed`.
- **RollbackAdversaryInd**: `OneShotNonceForever` holds for **arbitrary
  `MaxGen`** (`ConstInit == MaxGen ∈ Nat`) and any number of
  snapshot/restore cycles. The inductive chain: normal mode ⇒ `gen = ext`
  (A); at the newest generation every issued nonce is in `used` (D); a
  backup taken at the newest generation contains them all (E, which pushes D
  through a restore); backups never come from the future. A side product:
  A+D prove the TLC spec's `issued[n] < 2` state-space cap never binds.

Vacuity is guarded (negative-checks: `IndInit` proven satisfiable via a
false-invariant probe), and the `ind-no-detection` mutant shows consecution
collapses the moment rollback detection is removed — the induction genuinely
rests on the protected counter.

### Harness self-tests (negative-checks.sh)

19 checks: 10 TLC mutations that must each yield a counterexample, 4 probes
whose deliberately-false claims must be refuted, 1 differential (mutant must
make a refutable probe hold), 1 temporal-fairness dependency, 2 induction
vacuity guards, 1 induction-collapse mutant.

## Remaining

1. **Extend induction.** Two modules are proven unbounded; the other five
   remain TLC-bounded (exhaustive at their configured sizes). BrokerBudget
   and ContractChain are the natural next candidates (sums and sequences
   need Apalache folds).
2. **Context-id overwrite nuance.** `set_task_context` lets a replay of the
   same body under a new message id overwrite the shared task's A2A context
   id (observed while modeling; low-stakes metadata, but worth an upstream
   look).
3. **Coverage upstream.** The akson workspace still has no property-based
   tests of its own; the conformance crate here could migrate into the akson
   repo's CI if wanted.

## What model checking does not cover

Crypto soundness (Ed25519, HMAC, DSSE — modeled as perfect), sandbox escape
(kernel-level), byte-level parsing (covered by akson's fuzz targets and
`xcheck/`), and timing/side channels (out of scope in TM).

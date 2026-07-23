# Machine-checked proofs of the Akson protocol

TLC (the TLA+ model checker) exhaustively explores every interleaving of the
protocol's state machines — crashes, replays, adversarial deliveries included —
and proves a set of named safety invariants over all of them.

Run everything from this directory:

~~~text
make             # exhaustively check every spec        (needs Java 11+)
make inductive   # Apalache inductive proofs: same invariants, ANY run length
make negative    # prove the checks can fail: mutations must yield counterexamples
make conformance # cargo tests: Rust state machines == TLA+ transition relations
make full        # all of the above
~~~

`make` and `make inductive` download their own checkers into `tools/` on first
use; nothing is vendored. The one part needing no setup is conformance, because
`conformance/` is a workspace member — plain `cargo test --workspace` from the
repository root runs it, so a Rust change that contradicts a spec cannot land.

A passing check ends like this:

~~~text
Model checking completed. No error has been found.
1602 states generated, 697 distinct states found, 0 states left on queue.
~~~

`make negative` guards against a vacuous harness — each mutation breaks one
protocol rule on purpose, and TLC must produce a counterexample trace:

~~~text
ok    probe: settlement is reachable
ok    retry-after-crash: Invariant OneShotWorkOrder is violated
ok    no-dedup: Invariant NoDuplicateTask is violated
...
~~~

## What is proved so far

**`specs/TaskLifecycle.tla`** — one requester, one performer, a network that
may replay any message forever, a performer daemon that may crash between any
two commit points. Ten invariants, including:

| Invariant | Protocol rule |
|---|---|
| `AtMostOnceEffect` | the worker really starts at most once, across every crash/replay (design §6.3 "effects are one-shot and crash-honest") |
| `DurableBeforeEffect` | the durable attempt record advances before any byte leaves (threat model T7) |
| `NoAuthorityWithoutApproval` | arrival is not execution: authority exists only after a local approval (§6.3) |
| `NoDuplicateTask` | a replayed proposal never creates or resets a task (§9.2 dedup tombstone) |
| `OneShotWorkOrder` | a work order is claimed at most once, ever (§12.3) |
| `AmbiguousNeverDone` | an attempt interrupted by a crash surfaces as `ambiguous`, never as done (§6.3) |
| `OutcomeIsGrounded` | an accepted outcome implies exactly one real execution, durably committed (§14.5) |

**`specs/ContractChain.tla`** — the contract revision chain's compare-and-swap
head, transcribed 1:1 from `apply_revision`/`accept_head` in
`akson-contract/src/chain.rs`, under adversarial delivery (replays, competing
siblings, skipped revisions, forged predecessors, stale acceptances):

| Invariant | Protocol rule |
|---|---|
| `LockIsFinal` | once a digest is locked, no later revision or sibling can displace it — no retroactive cancel (§9.3) |
| `AtMostOneLock` | exactly one acceptance can ever succeed per task |
| `ChainIntegrity` | the accepted history is one unbroken predecessor-digest chain from revision 0 (§10.2) |
| `LockedWasAdvanced` | an acceptance can never lock a digest that was never the head |

**`specs/ReceivePipeline.tla`** — the receive path's split commits (head
write before idempotency commit) under crashes and an adversarial sender:
one task per body digest, no lost receipt, immutable saved responses, and —
via probes — the machine-checked facts that a post-crash replay converges
and that one message id *can* leave two inert tasks in the crash window
(benign, and now documented by a counterexample rather than prose).

**`specs/Introduction.tla`** — first contact over identity tokens: an active
peer implies a live import under the exact committed epoch (so a handshake
held across remove + re-add can never resurrect), divergent material suspends
rather than forks, one identity per epoch.

**`specs/BrokerBudget.tla`** — brokered processor calls: the `max_operations`
budget bounds the wire (disclosure and cost) across crashes; each call
transmits at most once; `dispatching` is durable before the first byte.

**`specs/RollbackAdversary.tla`** — threat-model T13 checked both ways: with
a protected state-generation counter the one-shot-nonce invariant holds;
without one (interim key custody) TLC produces the snapshot-restore-reissue
attack trace.

**`specs/TaskLiveness.tla`** — the one honest liveness claim: every issued
work order terminates or expires within its TTL, assuming only that time
passes, crashed daemons restart, and deadlines are enforced — the worker
itself gets no fairness.

**`specs/PairingLedgerInd.tla`, `specs/RollbackAdversaryInd.tla`** —
Apalache inductive proofs that lift two models beyond TLC's bounds: every
pairing invariant, and the one-shot-nonce property for an *arbitrary*
generation bound, now hold for any run length (base + consecution +
implication, all discharged; vacuity and detection-dependence guarded in
`negative-checks.sh`).

**`conformance/`** — `cargo test` proves the Rust pure functions
(`attempt::next`, `subattempt::next`, `apply_revision`/`accept_head`) equal
the TLA+ transition relations on every (state, event) pair, so model and
code cannot silently drift.

`PROPERTIES.md` maps every invariant to its design section, its enforcing
code, and its model — and lists what remains.

## Layout

~~~text
specs/               one .tla model + one .cfg per protocol area
conformance/         cargo tests tying the Rust machines to the models
check.sh             run TLC on one spec:  ./check.sh TaskLifecycle
negative-checks.sh   mutations, probes and differentials for the harness itself
PROPERTIES.md        traceability: design § <-> code <-> invariant, + remaining
tools/               tla2tools.jar (fetched by make)
~~~

## Reading a counterexample

When an invariant breaks, TLC prints the shortest trace to the violation —
each numbered state shows every variable, and the action taken between
states. Read it bottom-up: the last state is the broken one, the steps above
it are the exact protocol scenario that got there.

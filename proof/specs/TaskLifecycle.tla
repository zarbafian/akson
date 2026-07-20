--------------------------- MODULE TaskLifecycle ---------------------------
(***************************************************************************)
(* Akson v1 task lifecycle: one requester, one performer, an at-least-once  *)
(* network that may replay any message forever, and a performer daemon     *)
(* that may crash at any commit point and recover.                         *)
(*                                                                         *)
(* Sources (in /home/vaein/agentic/axon):                                  *)
(*   design/2026-07-16-threads-enterprise-agent-communication.md           *)
(*     §6.3  normative invariants          §9.2  delivery semantics        *)
(*     §10.4 contract/attempt enums        §12.3 work-order machine        *)
(*     §14.1 completion atomicity          §14.5 outcomes                  *)
(*   design/2026-07-19-threat-model.md     T7 (durable-before-effect),     *)
(*                                         T10 (replay dedup)              *)
(*   crates/akson-authority/src/attempt.rs  implemented transition table    *)
(*   crates/akson-store/src/lib.rs          resolve_crashed_attempts        *)
(*                                                                         *)
(* Each proposal message m creates at most one task; we index all state    *)
(* by m.  "Durable" variables survive a crash; "volatile" ones do not;     *)
(* "history" variables record what really happened in the world (a crash   *)
(* cannot erase reality) and exist only so invariants can talk about it.   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Msgs           \* proposal message ids the requester may send

VARIABLES
  sent,       \* req durable : proposal m is in the outbox; the network may
              \*               redeliver it forever (at-least-once, §9.2)
  task,       \* perf durable: inert task exists for m (the dedup tombstone)
  created,    \* history     : number of tasks ever created for m
  contract,   \* perf durable: "none" | "proposed" | "accepted" | "rejected"
  attempt,    \* perf durable: work-order/attempt machine (§10.4, §12.3)
  claims,     \* history     : number of successful work-order claims for m
  spawned,    \* perf VOLATILE: worker launched during this uptime
  effects,    \* history     : real worker effect-starts for m
  committed,  \* perf durable: completion commit done (§14.1)
  wire,       \* perf-reported A2A task state (§10.1 matrix)
  outcome,    \* req durable : settlement for m (§14.5)
  up          \* performer daemon is up

vars == <<sent, task, created, contract, attempt, claims, spawned, effects,
          committed, wire, outcome, up>>

AttemptStates == {"none", "pending", "claimed", "running",
                  "succeeded", "failed", "ambiguous", "cancelled"}
WireStates    == {"none", "SUBMITTED", "WORKING",
                  "COMPLETED", "FAILED", "REJECTED", "CANCELED"}

TypeOK ==
  /\ sent      \in [Msgs -> BOOLEAN]
  /\ task      \in [Msgs -> BOOLEAN]
  /\ created   \in [Msgs -> Nat]
  /\ contract  \in [Msgs -> {"none", "proposed", "accepted", "rejected"}]
  /\ attempt   \in [Msgs -> AttemptStates]
  /\ claims    \in [Msgs -> Nat]
  /\ spawned   \in [Msgs -> BOOLEAN]
  /\ effects   \in [Msgs -> Nat]
  /\ committed \in [Msgs -> BOOLEAN]
  /\ wire      \in [Msgs -> WireStates]
  /\ outcome   \in [Msgs -> {"none", "accepted"}]
  /\ up        \in BOOLEAN

Init ==
  /\ sent      = [m \in Msgs |-> FALSE]
  /\ task      = [m \in Msgs |-> FALSE]
  /\ created   = [m \in Msgs |-> 0]
  /\ contract  = [m \in Msgs |-> "none"]
  /\ attempt   = [m \in Msgs |-> "none"]
  /\ claims    = [m \in Msgs |-> 0]
  /\ spawned   = [m \in Msgs |-> FALSE]
  /\ effects   = [m \in Msgs |-> 0]
  /\ committed = [m \in Msgs |-> FALSE]
  /\ wire      = [m \in Msgs |-> "none"]
  /\ outcome   = [m \in Msgs |-> "none"]
  /\ up        = TRUE

-----------------------------------------------------------------------------
(* Requester sends m.  sent[m] stays TRUE forever, so every later          *)
(* ReceiveNew enabling is a free replay/redelivery of the same bytes.      *)
Send(m) ==
  /\ ~sent[m]
  /\ sent' = [sent EXCEPT ![m] = TRUE]
  /\ UNCHANGED <<task, created, contract, attempt, claims, spawned, effects,
                 committed, wire, outcome, up>>

(* §6.3 arrival-is-not-execution + §9.2 dedup: a (re)delivered proposal    *)
(* may only durably create ONE inert task in SUBMITTED.  The tombstone     *)
(* task[m] turns every replay into a Duplicate response (a no-op here).    *)
ReceiveNew(m) ==
  /\ up /\ sent[m] /\ ~task[m]
  /\ task'     = [task     EXCEPT ![m] = TRUE]
  /\ created'  = [created  EXCEPT ![m] = @ + 1]
  /\ contract' = [contract EXCEPT ![m] = "proposed"]
  /\ wire'     = [wire     EXCEPT ![m] = "SUBMITTED"]
  /\ UNCHANGED <<sent, attempt, claims, spawned, effects, committed,
                 outcome, up>>

(* A LOCAL operator decision (§5.2) — never triggered by arrival.          *)
(* Acceptance mints the one-shot work order in "pending" (§12.3).          *)
Approve(m) ==
  /\ up /\ contract[m] = "proposed"
  /\ contract' = [contract EXCEPT ![m] = "accepted"]
  /\ attempt'  = [attempt  EXCEPT ![m] = "pending"]
  /\ UNCHANGED <<sent, task, created, claims, spawned, effects, committed,
                 wire, outcome, up>>

Deny(m) ==
  /\ up /\ contract[m] = "proposed"
  /\ contract' = [contract EXCEPT ![m] = "rejected"]
  /\ wire'     = [wire     EXCEPT ![m] = "REJECTED"]
  /\ UNCHANGED <<sent, task, created, attempt, claims, spawned, effects,
                 committed, outcome, up>>

(* Claim, budget reservation and nonce consumption are one atomic durable  *)
(* write (§12.3; attempt.rs Pending --Claim--> Claimed).                   *)
Claim(m) ==
  /\ up /\ attempt[m] = "pending"
  /\ attempt' = [attempt EXCEPT ![m] = "claimed"]
  /\ claims'  = [claims  EXCEPT ![m] = @ + 1]
  /\ UNCHANGED <<sent, task, created, contract, spawned, effects, committed,
                 wire, outcome, up>>

(* TM T7: the durable record advances to running BEFORE any effect.        *)
MarkRunning(m) ==
  /\ up /\ attempt[m] = "claimed"
  /\ attempt' = [attempt EXCEPT ![m] = "running"]
  /\ wire'    = [wire    EXCEPT ![m] = "WORKING"]
  /\ UNCHANGED <<sent, task, created, contract, claims, spawned, effects,
                 committed, outcome, up>>

(* The first real-world effect: the sandboxed worker starts.               *)
SpawnWorker(m) ==
  /\ up /\ attempt[m] = "running" /\ ~spawned[m]
  /\ spawned' = [spawned EXCEPT ![m] = TRUE]
  /\ effects' = [effects EXCEPT ![m] = @ + 1]
  /\ UNCHANGED <<sent, task, created, contract, attempt, claims, committed,
                 wire, outcome, up>>

WorkerSucceeds(m) ==
  /\ up /\ attempt[m] = "running" /\ spawned[m]
  /\ attempt' = [attempt EXCEPT ![m] = "succeeded"]
  /\ UNCHANGED <<sent, task, created, contract, claims, spawned, effects,
                 committed, wire, outcome, up>>

WorkerFails(m) ==
  /\ up /\ attempt[m] = "running" /\ spawned[m]
  /\ attempt' = [attempt EXCEPT ![m] = "failed"]
  /\ wire'    = [wire    EXCEPT ![m] = "FAILED"]
  /\ UNCHANGED <<sent, task, created, contract, claims, spawned, effects,
                 committed, outcome, up>>

(* attempt.rs: Pending|Claimed --Cancel--> Cancelled, legal only because   *)
(* provably no effect has started yet (effects need "running").            *)
CancelEarly(m) ==
  /\ up /\ attempt[m] \in {"pending", "claimed"}
  /\ attempt' = [attempt EXCEPT ![m] = "cancelled"]
  /\ wire'    = [wire    EXCEPT ![m] = "CANCELED"]
  /\ UNCHANGED <<sent, task, created, contract, claims, spawned, effects,
                 committed, outcome, up>>

(* attempt.rs: Running --Cancel--> Ambiguous — an effect may already have  *)
(* escaped, so cancellation must be honest about the uncertainty.          *)
CancelRunning(m) ==
  /\ up /\ attempt[m] = "running"
  /\ attempt' = [attempt EXCEPT ![m] = "ambiguous"]
  /\ wire'    = [wire    EXCEPT ![m] = "FAILED"]
  /\ UNCHANGED <<sent, task, created, contract, claims, spawned, effects,
                 committed, outcome, up>>

(* attempt.rs: Claimed|Running --MarkAmbiguous--> Ambiguous (operator).    *)
MarkAmbiguous(m) ==
  /\ up /\ attempt[m] \in {"claimed", "running"}
  /\ attempt' = [attempt EXCEPT ![m] = "ambiguous"]
  /\ wire'    = [wire    EXCEPT ![m] = "FAILED"]
  /\ UNCHANGED <<sent, task, created, contract, claims, spawned, effects,
                 committed, outcome, up>>

(* §14.1: outputs, manifest and evidence commit durably in one step, and   *)
(* only then is COMPLETED reported — never a partial completed result.     *)
Commit(m) ==
  /\ up /\ attempt[m] = "succeeded" /\ ~committed[m]
  /\ committed' = [committed EXCEPT ![m] = TRUE]
  /\ wire'      = [wire      EXCEPT ![m] = "COMPLETED"]
  /\ UNCHANGED <<sent, task, created, contract, attempt, claims, spawned,
                 effects, outcome, up>>

(* §14.5: the requester validates the delivered bundle against the digest  *)
(* the performer committed, then signs an outcome.                         *)
Settle(m) ==
  /\ committed[m] /\ wire[m] = "COMPLETED" /\ outcome[m] = "none"
  /\ outcome' = [outcome EXCEPT ![m] = "accepted"]
  /\ UNCHANGED <<sent, task, created, contract, attempt, claims, spawned,
                 effects, committed, wire, up>>

(* The performer daemon dies at an arbitrary point; volatile state is      *)
(* lost, durable state and world history survive.                          *)
Crash ==
  /\ up
  /\ up'      = FALSE
  /\ spawned' = [m \in Msgs |-> FALSE]
  /\ UNCHANGED <<sent, task, created, contract, attempt, claims, effects,
                 committed, wire, outcome>>

(* §6.3 "Effects are one-shot and crash-honest" / TM T7 /                  *)
(* store resolve_crashed_attempts: recovery marks anything mid-flight      *)
(* ambiguous — never retried, never reported done.  "pending" survives     *)
(* untouched (attempt.rs rejects Pending --RecoverAfterCrash): no claim,   *)
(* no effect, nothing to be uncertain about.  Ambiguous maps to FAILED     *)
(* on the wire (§10.1).                                                    *)
Recover ==
  /\ ~up
  /\ up' = TRUE
  /\ attempt' = [m \in Msgs |->
                   IF attempt[m] \in {"claimed", "running"}
                   THEN "ambiguous" ELSE attempt[m]]
  /\ wire'    = [m \in Msgs |->
                   IF attempt[m] \in {"claimed", "running"}
                   THEN "FAILED" ELSE wire[m]]
  /\ UNCHANGED <<sent, task, created, contract, claims, spawned, effects,
                 committed, outcome>>

Next ==
  \/ \E m \in Msgs :
       \/ Send(m) \/ ReceiveNew(m) \/ Approve(m) \/ Deny(m)
       \/ Claim(m) \/ MarkRunning(m) \/ SpawnWorker(m)
       \/ WorkerSucceeds(m) \/ WorkerFails(m)
       \/ CancelEarly(m) \/ CancelRunning(m) \/ MarkAmbiguous(m)
       \/ Commit(m) \/ Settle(m)
  \/ Crash \/ Recover

-----------------------------------------------------------------------------
(* Machine-checked invariants                                              *)

(* §6.3 "Effects are one-shot and crash-honest": across every crash and    *)
(* replay interleaving, a task's worker really starts at most once.        *)
AtMostOnceEffect ==
  \A m \in Msgs : effects[m] <= 1

(* TM T7: no byte leaves before the durable attempt record has advanced.   *)
DurableBeforeEffect ==
  \A m \in Msgs :
    effects[m] > 0 =>
      attempt[m] \in {"running", "succeeded", "failed", "ambiguous"}

(* §6.3 "Arrival is not execution" + "Authority is endpoint-local":        *)
(* authority (any attempt state) exists only after a LOCAL acceptance.     *)
NoAuthorityWithoutApproval ==
  \A m \in Msgs : attempt[m] # "none" => contract[m] = "accepted"

(* §9.2: a replayed proposal never creates a second task (or resets an     *)
(* existing one).                                                          *)
NoDuplicateTask ==
  \A m \in Msgs : created[m] <= 1

(* §12.3: the work order is one-shot — claimed at most once, ever.         *)
OneShotWorkOrder ==
  \A m \in Msgs : claims[m] <= 1

(* §14.1 + §6.3: COMPLETED is reported only after the durable completion   *)
(* commit of a genuinely succeeded attempt.                                *)
CompletedIsCommitted ==
  \A m \in Msgs :
    wire[m] = "COMPLETED" => committed[m] /\ attempt[m] = "succeeded"

(* §6.3 crash-honest: an interrupted attempt surfaces as ambiguous and is  *)
(* never presented — or settled — as done.                                 *)
AmbiguousNeverDone ==
  \A m \in Msgs :
    attempt[m] = "ambiguous" =>
      ~committed[m] /\ wire[m] # "COMPLETED" /\ outcome[m] = "none"

(* attempt.rs cancel semantics: "cancelled" is claimable only before the   *)
(* first effect; a cancellation that races a real effect must land in      *)
(* "ambiguous" instead.                                                    *)
CancelledMeansNoEffect ==
  \A m \in Msgs : attempt[m] = "cancelled" => effects[m] = 0

(* §14.5: an accepted outcome is grounded in exactly one real execution    *)
(* whose result was durably committed.                                     *)
OutcomeIsGrounded ==
  \A m \in Msgs :
    outcome[m] = "accepted" => committed[m] /\ effects[m] = 1

=============================================================================

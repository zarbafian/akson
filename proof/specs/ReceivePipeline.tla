-------------------------- MODULE ReceivePipeline --------------------------
(***************************************************************************)
(* The durable receive pipeline for contract proposals, with its split     *)
(* commits and crash windows.                                              *)
(*                                                                         *)
(* Sources (in /home/vaein/agentic/axon):                                  *)
(*   crates/aksond/src/receive.rs::dispatch_proposal — the pipeline order:  *)
(*     peek (idempotency) -> validate -> submit_revision (CAS head write)  *)
(*     -> persist_worker_inputs -> receive_request (idempotency commit,    *)
(*     durable-before-response).  A crash between head write and           *)
(*     idempotency commit makes the replay re-run the pipeline.            *)
(*   crates/akson-store/src/lib.rs::submit_revision — returns a Stale       *)
(*     verdict as Ok; receive.rs:104 DISCARDS the verdict, so a replayed   *)
(*     head write is a no-op, not an error.  Convergence depends on this.  *)
(*   receive.rs:99 — the task id is a pure function of the proposal        *)
(*     digest, so a replay recomputes the same task id and response.       *)
(*   design §9.2 (dedup covered values), §9.3 (CAS head), TM T10.          *)
(*                                                                         *)
(* Model shape: a proposal body is a Variant (its digest); the same body   *)
(* may be sent under any message id (Mids).  Tasks are content-addressed   *)
(* by Variant; idempotency records are keyed by message id.  The daemon    *)
(* processes one request at a time (SQLite serializes) and may crash       *)
(* between any two durable writes.                                         *)
(*                                                                         *)
(* Proved:  one task per body digest; a committed idempotency record       *)
(*   always points at a fully persisted task (no lost receipt); a record   *)
(*   is never rewritten (a Conflict or replay cannot change the saved      *)
(*   response); an accepted (locked) head is never reset by a replay.     *)
(* Disproved on purpose (negative-checks.sh): "one task per message id" — *)
(*   in the crash window before the idempotency commit, a sender reusing  *)
(*   a message id with a DIFFERENT body is not detectable as a Conflict,  *)
(*   so one message id can leave two (inert, expiring) tasks.  Benign but *)
(*   real; kept as a machine-checked fact rather than prose.              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Mids,        \* message ids a sender may use
  Variants,    \* distinct proposal bodies (a variant IS its digest)
  NoMid,       \* model value: "no message id recorded"
  NoVar        \* model value: "no record / no body"

VARIABLES
  head,        \* durable: per-body CAS head  "empty" | "open" | "locked"
  inputs,      \* durable: worker-visible input bytes persisted for body v
  rec,         \* durable: idempotency record per mid — the body variant it
               \*          committed for (NoVar = no record yet)
  proc,        \* VOLATILE: the one in-flight request and its pipeline stage
  up,          \* daemon is up
  created,     \* history: head advances (task creations) per body
  creators,    \* history: which mids' processing created body v's task
  recWrites,   \* history: idempotency-record writes per mid
  lockedEver,  \* history: body v's head was locked at some point
  crashedMid,  \* history: first mid whose in-flight request died after the
  crashedVar   \*          head write, and the body it carried (the probe
               \*          for replay convergence needs the exact pair)

vars == <<head, inputs, rec, proc, up, created, creators, recWrites,
          lockedEver, crashedMid, crashedVar>>

Stages == {"idle", "validated", "headDone", "inputsDone"}

TypeOK ==
  /\ head       \in [Variants -> {"empty", "open", "locked"}]
  /\ inputs     \in [Variants -> BOOLEAN]
  /\ rec        \in [Mids -> Variants \cup {NoVar}]
  /\ proc       \in [mid : Mids, v : Variants, stage : Stages]
  /\ up         \in BOOLEAN
  /\ created    \in [Variants -> Nat]
  /\ creators   \in [Variants -> SUBSET Mids]
  /\ recWrites  \in [Mids -> Nat]
  /\ lockedEver \in [Variants -> BOOLEAN]
  /\ crashedMid \in Mids \cup {NoMid}
  /\ crashedVar \in Variants \cup {NoVar}

Init ==
  /\ head       = [v \in Variants |-> "empty"]
  /\ inputs     = [v \in Variants |-> FALSE]
  /\ rec        = [m \in Mids |-> NoVar]
  /\ proc       \in {[mid |-> m, v |-> v, stage |-> "idle"]
                       : m \in Mids, v \in Variants}
  /\ up         = TRUE
  /\ created    = [v \in Variants |-> 0]
  /\ creators   = [v \in Variants |-> {}]
  /\ recWrites  = [m \in Mids |-> 0]
  /\ lockedEver = [v \in Variants |-> FALSE]
  /\ crashedMid = NoMid
  /\ crashedVar = NoVar

-----------------------------------------------------------------------------
(* A request (mid, v) arrives and passes peek + validation.  The sender is *)
(* adversarial: any body under any message id, any number of times.        *)
(* peek (receive.rs:68): an existing record for mid short-circuits to      *)
(* Duplicate (same body) or Conflict (different body) — both no-ops here,  *)
(* so only the Fresh path is an action.                                    *)
Begin(m, v) ==
  /\ up /\ proc.stage = "idle"
  /\ rec[m] = NoVar
  /\ proc' = [mid |-> m, v |-> v, stage |-> "validated"]
  /\ UNCHANGED <<head, inputs, rec, up, created, creators, recWrites,
                 lockedEver, crashedMid, crashedVar>>

(* submit_revision: revision 0 advances an Empty head; on an existing head *)
(* apply_revision yields Stale, which receive.rs:104 discards — the        *)
(* pipeline CONTINUES with the digest-derived task id.  (chain.rs already  *)
(* guarantees Stale writes nothing; the locked case is checked here too.)  *)
StepHead ==
  /\ up /\ proc.stage = "validated"
  /\ \/ /\ head[proc.v] = "empty"
        /\ head'     = [head     EXCEPT ![proc.v] = "open"]
        /\ created'  = [created  EXCEPT ![proc.v] = @ + 1]
        /\ creators' = [creators EXCEPT ![proc.v] = @ \cup {proc.mid}]
        /\ proc' = [proc EXCEPT !.stage = "headDone"]
     \/ /\ head[proc.v] # "empty"
        /\ UNCHANGED <<head, created, creators>>
        /\ proc' = [proc EXCEPT !.stage = "headDone"]  \* Stale is discarded
  /\ UNCHANGED <<inputs, rec, up, recWrites, lockedEver, crashedMid,
                 crashedVar>>

(* persist_worker_inputs: sealed input bytes, idempotent for one body.     *)
StepInputs ==
  /\ up /\ proc.stage = "headDone"
  /\ inputs' = [inputs EXCEPT ![proc.v] = TRUE]
  /\ proc'   = [proc EXCEPT !.stage = "inputsDone"]
  /\ UNCHANGED <<head, rec, up, created, creators, recWrites, lockedEver,
                 crashedMid, crashedVar>>

(* receive_request: the idempotency commit, durable before the response.   *)
(* The saved response embeds the digest-derived task id, so an exact       *)
(* replay later returns identical bytes.                                   *)
StepCommit ==
  /\ up /\ proc.stage = "inputsDone"
  /\ rec'       = [rec       EXCEPT ![proc.mid] = proc.v]
  /\ recWrites' = [recWrites EXCEPT ![proc.mid] = @ + 1]
  /\ proc'      = [proc EXCEPT !.stage = "idle"]
  /\ UNCHANGED <<head, inputs, up, created, creators, lockedEver,
                 crashedMid, crashedVar>>

(* A local operator accepts the proposal: the head locks (§9.3).  Replays  *)
(* arriving after this must not reopen it.                                 *)
Accept(v) ==
  /\ up /\ head[v] = "open"
  /\ head'       = [head       EXCEPT ![v] = "locked"]
  /\ lockedEver' = [lockedEver EXCEPT ![v] = TRUE]
  /\ UNCHANGED <<inputs, rec, proc, up, created, creators, recWrites,
                 crashedMid, crashedVar>>

(* The daemon dies; the in-flight request is lost, durable state stays.    *)
(* Record the first post-head-write casualty for the convergence probe.    *)
Crash ==
  /\ up
  /\ up' = FALSE
  /\ IF proc.stage \in {"headDone", "inputsDone"} /\ crashedMid = NoMid
     THEN crashedMid' = proc.mid /\ crashedVar' = proc.v
     ELSE UNCHANGED <<crashedMid, crashedVar>>
  /\ proc' = [proc EXCEPT !.stage = "idle"]
  /\ UNCHANGED <<head, inputs, rec, created, creators, recWrites,
                 lockedEver>>

Recover ==
  /\ ~up
  /\ up' = TRUE
  /\ UNCHANGED <<head, inputs, rec, proc, created, creators, recWrites,
                 lockedEver, crashedMid, crashedVar>>

Next ==
  \/ \E m \in Mids, v \in Variants : Begin(m, v)
  \/ StepHead \/ StepInputs \/ StepCommit
  \/ \E v \in Variants : Accept(v)
  \/ Crash \/ Recover

-----------------------------------------------------------------------------
(* Machine-checked invariants                                              *)

(* Tasks are content-addressed: one task per body digest, ever — across    *)
(* replays, message-id reuse, and crashes (§9.3 CAS + digest-derived id). *)
OneTaskPerBody ==
  \A v \in Variants : created[v] <= 1

(* No lost receipt (§9.2 durable-before-response): a committed             *)
(* idempotency record always points at a fully persisted task — head      *)
(* written AND worker inputs sealed.  The response never acks work the    *)
(* store lost.                                                             *)
RecordImpliesTask ==
  \A m \in Mids :
    rec[m] # NoVar => head[rec[m]] \in {"open", "locked"} /\ inputs[rec[m]]

(* A saved response is immutable: neither an exact replay (Duplicate) nor  *)
(* a changed-body retry (Conflict) ever rewrites it (§9.2).                *)
RecordIsFinal ==
  \A m \in Mids : recWrites[m] <= 1

(* An accepted contract stays accepted: no replay of the original          *)
(* proposal can reopen a locked head (§9.3 no retroactive change).         *)
LockedStaysLocked ==
  \A v \in Variants : lockedEver[v] => head[v] = "locked"

-----------------------------------------------------------------------------
(* Probes for negative-checks.sh — NOT invariants of the design.           *)

(* FALSE by design (TLC must find a counterexample): in the crash window   *)
(* before the idempotency commit, a message id reused with a different     *)
(* body escapes Conflict detection, so one mid can create two tasks.       *)
OneTaskPerMid ==
  \A m \in Mids :
    Cardinality({v \in Variants : m \in creators[v]}) <= 1

(* FALSE in the real design (TLC must find a counterexample): after a      *)
(* post-head-write crash, the exact replay CAN still commit its record —   *)
(* convergence.  In a mutant where a Stale head write aborts the pipeline  *)
(* (submit_revision's verdict treated as an error), this becomes TRUE:     *)
(* the crashed request can never complete, only its record stays absent.   *)
CrashReplayNeverCompletes ==
  ~(crashedMid # NoMid /\ rec[crashedMid] = crashedVar)

=============================================================================

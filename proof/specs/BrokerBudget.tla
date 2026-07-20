--------------------------- MODULE BrokerBudget ----------------------------
(***************************************************************************)
(* Brokered processor calls under one work order: the sub-attempt machine  *)
(* and the aggregate operation budget, across daemon crashes.              *)
(*                                                                         *)
(* Sources (in /home/vaein/agentic/axon):                                  *)
(*   crates/akson-broker/src/subattempt.rs — transition table:              *)
(*     Prepared --Dispatch--> Dispatching --Complete|Fail--> terminal;     *)
(*     Prepared --Cancel--> Cancelled; Dispatching --Cancel|MarkAmbiguous  *)
(*     |RecoverAfterCrash--> Ambiguous.  Ambiguous is terminal: never      *)
(*     auto-retried (§13.1 — a lost response may have disclosed data and   *)
(*     cost money; only an operator can authorize a new attempt).          *)
(*   crates/akson-store/src/lib.rs::prepare_call — counts this work         *)
(*     order's existing processor_calls rows INSIDE the same transaction   *)
(*     and returns BudgetExhausted at max_operations; terminal rows keep   *)
(*     counting (the budget is for the work order's lifetime).             *)
(*   crates/akson-store/src/lib.rs::resolve_crashed_calls — restart maps    *)
(*     'dispatching' to 'ambiguous'.                                       *)
(*   design §13.1 processor calls are effects; TM T7.                      *)
(*                                                                         *)
(* Calls is deliberately larger than MaxOps so TLC must prove the budget   *)
(* holds even when more calls are attempted than allowed.                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Calls,      \* processor-call slots the worker may ask for (|Calls| > MaxOps)
  MaxOps      \* the work order's max_operations budget

VARIABLES
  call,       \* durable : per-call sub-attempt state
  inflight,   \* VOLATILE: request bytes are on the wire this uptime
  sent,       \* history : real transmissions per call (crash-proof reality)
  totalSent,  \* history : total transmissions for the work order
  up          \* daemon is up

vars == <<call, inflight, sent, totalSent, up>>

CallStates == {"none", "prepared", "dispatching",
               "completed", "failed", "ambiguous", "cancelled"}

TypeOK ==
  /\ call      \in [Calls -> CallStates]
  /\ inflight  \in [Calls -> BOOLEAN]
  /\ sent      \in [Calls -> Nat]
  /\ totalSent \in Nat
  /\ up        \in BOOLEAN

Init ==
  /\ call      = [c \in Calls |-> "none"]
  /\ inflight  = [c \in Calls |-> FALSE]
  /\ sent      = [c \in Calls |-> 0]
  /\ totalSent = 0
  /\ up        = TRUE

Used == {c \in Calls : call[c] # "none"}

-----------------------------------------------------------------------------
(* store::prepare_call — the durable 'prepared' row, with the budget count *)
(* taken inside the same transaction: at max_operations the verdict is     *)
(* BudgetExhausted and nothing is written.                                 *)
Prepare(c) ==
  /\ up /\ call[c] = "none"
  /\ Cardinality(Used) < MaxOps
  /\ call' = [call EXCEPT ![c] = "prepared"]
  /\ UNCHANGED <<inflight, sent, totalSent, up>>

(* The durable record advances to 'dispatching' BEFORE any byte leaves     *)
(* (TM T7; §13.1).                                                         *)
MarkDispatching(c) ==
  /\ up /\ call[c] = "prepared"
  /\ call' = [call EXCEPT ![c] = "dispatching"]
  /\ UNCHANGED <<inflight, sent, totalSent, up>>

(* The real-world effect: the request leaves for the processor.            *)
Transmit(c) ==
  /\ up /\ call[c] = "dispatching" /\ ~inflight[c]
  /\ inflight'  = [inflight EXCEPT ![c] = TRUE]
  /\ sent'      = [sent     EXCEPT ![c] = @ + 1]
  /\ totalSent' = totalSent + 1
  /\ UNCHANGED <<call, up>>

Complete(c) ==
  /\ up /\ call[c] = "dispatching" /\ inflight[c]
  /\ call' = [call EXCEPT ![c] = "completed"]
  /\ UNCHANGED <<inflight, sent, totalSent, up>>

Fail(c) ==
  /\ up /\ call[c] = "dispatching" /\ inflight[c]
  /\ call' = [call EXCEPT ![c] = "failed"]
  /\ UNCHANGED <<inflight, sent, totalSent, up>>

(* subattempt.rs: Prepared --Cancel--> Cancelled (nothing left the host);  *)
(* Dispatching --Cancel--> Ambiguous (a byte may already be out).          *)
CancelPrepared(c) ==
  /\ up /\ call[c] = "prepared"
  /\ call' = [call EXCEPT ![c] = "cancelled"]
  /\ UNCHANGED <<inflight, sent, totalSent, up>>

CancelDispatching(c) ==
  /\ up /\ call[c] = "dispatching"
  /\ call' = [call EXCEPT ![c] = "ambiguous"]
  /\ UNCHANGED <<inflight, sent, totalSent, up>>

Crash ==
  /\ up
  /\ up'       = FALSE
  /\ inflight' = [c \in Calls |-> FALSE]
  /\ UNCHANGED <<call, sent, totalSent>>

(* store::resolve_crashed_calls at bootstrap: 'dispatching' becomes        *)
(* 'ambiguous' — never retried; 'prepared' survives (nothing left yet).    *)
Recover ==
  /\ ~up
  /\ up' = TRUE
  /\ call' = [c \in Calls |->
                IF call[c] = "dispatching" THEN "ambiguous" ELSE call[c]]
  /\ UNCHANGED <<inflight, sent, totalSent>>

Next ==
  \/ \E c \in Calls :
       \/ Prepare(c) \/ MarkDispatching(c) \/ Transmit(c)
       \/ Complete(c) \/ Fail(c)
       \/ CancelPrepared(c) \/ CancelDispatching(c)
  \/ Crash \/ Recover

-----------------------------------------------------------------------------
(* Machine-checked invariants                                              *)

(* §12.3/§13.1: the aggregate budget bounds the work order's lifetime      *)
(* call rows — terminal calls keep counting; crashes free nothing.         *)
BudgetBound ==
  Cardinality(Used) <= MaxOps

(* Each call's request leaves the host at most once, across every crash    *)
(* (ambiguous is terminal, never auto-retried).                            *)
AtMostOneTransmit ==
  \A c \in Calls : sent[c] <= 1

(* Therefore the wire — disclosure and cost — is bounded by the budget     *)
(* too, not just the database rows.                                        *)
WireBoundedByBudget ==
  totalSent <= MaxOps

(* TM T7: no byte leaves before the durable record reached 'dispatching'.  *)
DurableBeforeWire ==
  \A c \in Calls :
    sent[c] > 0 => call[c] \in {"dispatching", "completed", "failed",
                                "ambiguous"}

=============================================================================

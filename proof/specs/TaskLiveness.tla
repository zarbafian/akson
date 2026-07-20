--------------------------- MODULE TaskLiveness ----------------------------
(***************************************************************************)
(* The one honest liveness claim the design makes (§8.5): every issued    *)
(* work order reaches a terminal state or expires — authority never       *)
(* dangles forever.  The design is deliberately safety-biased everywhere  *)
(* else (ambiguous is never auto-retried, recovery waits for an           *)
(* operator), so this is TTL-shaped termination, not useful progress.     *)
(*                                                                         *)
(* Assumptions, stated as fairness/bounds (all necessary):                *)
(*   - wall-clock time advances                    (WF on Tick)           *)
(*   - a crashed daemon eventually restarts        (WF on Recover)        *)
(*   - the daemon enforces deadlines when up       (WF on Expire/Kill)    *)
(*   - crashes happen finitely often               (crashCount bound)     *)
(* The worker gets NO fairness: termination must hold even if it never    *)
(* claims, never starts, or hangs forever — the TTL is the backstop.      *)
(*                                                                         *)
(* Sources: design §8.5 (work-order 1h hard TTL; restart cannot extend an *)
(* already issued TTL — the clock here is world time, untouched by        *)
(* Crash), §12.3, attempt.rs (claimed kills to cancelled pre-effect,      *)
(* running kills to ambiguous).                                            *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
  Deadline,     \* ticks until the work order's TTL
  MaxCrashes    \* finite crash budget for the run

VARIABLES
  attempt,      \* durable : the work-order attempt state (+ "expired")
  clock,        \* world time: survives crashes by construction
  up,           \* daemon is up
  crashCount

vars == <<attempt, clock, up, crashCount>>

Terminal == {"succeeded", "failed", "ambiguous", "cancelled", "expired"}

TypeOK ==
  /\ attempt \in {"pending", "claimed", "running"} \cup Terminal
  /\ clock \in 0..Deadline
  /\ up \in BOOLEAN
  /\ crashCount \in 0..MaxCrashes

Init ==
  /\ attempt = "pending"     \* the work order has just been issued
  /\ clock = 0
  /\ up = TRUE
  /\ crashCount = 0

-----------------------------------------------------------------------------
Tick ==
  /\ clock < Deadline
  /\ clock' = clock + 1
  /\ UNCHANGED <<attempt, up, crashCount>>

Claim ==
  /\ up /\ attempt = "pending" /\ clock < Deadline
  /\ attempt' = "claimed"
  /\ UNCHANGED <<clock, up, crashCount>>

Start ==
  /\ up /\ attempt = "claimed" /\ clock < Deadline
  /\ attempt' = "running"
  /\ UNCHANGED <<clock, up, crashCount>>

Succeed ==
  /\ up /\ attempt = "running"
  /\ attempt' = "succeeded"
  /\ UNCHANGED <<clock, up, crashCount>>

Fail ==
  /\ up /\ attempt = "running"
  /\ attempt' = "failed"
  /\ UNCHANGED <<clock, up, crashCount>>

(* §8.5: an unclaimed work order past its deadline is expired — the       *)
(* claim path re-checks validity and refuses (issue.rs::validity).        *)
Expire ==
  /\ up /\ attempt = "pending" /\ clock = Deadline
  /\ attempt' = "expired"
  /\ UNCHANGED <<clock, up, crashCount>>

(* Deadline enforcement on in-flight work: claimed dies provably before   *)
(* any effect (-> cancelled); running may have effects out (-> ambiguous). *)
KillClaimed ==
  /\ up /\ attempt = "claimed" /\ clock = Deadline
  /\ attempt' = "cancelled"
  /\ UNCHANGED <<clock, up, crashCount>>

KillRunning ==
  /\ up /\ attempt = "running" /\ clock = Deadline
  /\ attempt' = "ambiguous"
  /\ UNCHANGED <<clock, up, crashCount>>

Crash ==
  /\ up /\ crashCount < MaxCrashes
  /\ up' = FALSE
  /\ crashCount' = crashCount + 1
  /\ UNCHANGED <<attempt, clock>>

(* resolve_crashed_attempts: mid-flight becomes ambiguous at bootstrap.    *)
Recover ==
  /\ ~up
  /\ up' = TRUE
  /\ attempt' = IF attempt \in {"claimed", "running"}
                THEN "ambiguous" ELSE attempt
  /\ UNCHANGED <<clock, crashCount>>

Next ==
  \/ Tick \/ Claim \/ Start \/ Succeed \/ Fail
  \/ Expire \/ KillClaimed \/ KillRunning
  \/ Crash \/ Recover

Spec ==
  /\ Init /\ [][Next]_vars
  /\ WF_vars(Tick)
  /\ WF_vars(Recover)
  /\ WF_vars(Expire)
  /\ WF_vars(KillClaimed)
  /\ WF_vars(KillRunning)

-----------------------------------------------------------------------------
(* Safety: expiry fires only at the deadline — never early.                *)
NoEarlyExpiry ==
  attempt = "expired" => clock = Deadline

(* Liveness: every issued work order eventually terminates or expires.     *)
(* Terminal states have no outgoing transitions, so this is stable.        *)
Termination ==
  <>(attempt \in Terminal)

=============================================================================

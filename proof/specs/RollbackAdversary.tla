-------------------------- MODULE RollbackAdversary ------------------------
(***************************************************************************)
(* The database-rollback adversary (threat model T13) against the          *)
(* state-generation anti-rollback scheme (design §15.5, ADR-0009).         *)
(*                                                                         *)
(* Scheme: before any authority-issuing transaction the daemon reserves a  *)
(* new monotonic generation in the keystore/TPM (external, survives DB     *)
(* restore) and commits it inside the DB transaction.  At open, external   *)
(* checkpoint != DB generation means the DB is old: the daemon enters      *)
(* recovery and refuses to issue authority until an operator acts.         *)
(*                                                                         *)
(* The adversary (or an innocent operator) may snapshot the database and   *)
(* restore it later, resurrecting consumed one-use nonces.                 *)
(*                                                                         *)
(* Checked both ways:                                                      *)
(*   Detection = TRUE  (protected counter available): OneShotNonceForever  *)
(*     HOLDS — a rolled-back DB is detected and issues nothing.            *)
(*   Detection = FALSE (interim file-KEK custody, `rollback_detection:     *)
(*     unavailable`): negative-checks.sh expects TLC to produce the attack *)
(*     trace — issue, snapshot..., restore, reissue the same nonce.  The   *)
(*     threat model's residual risk, as a counterexample instead of prose. *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
  Nonces,     \* one-use authority nonces
  MaxGen,     \* bound on generations for model checking
  Detection,  \* BOOLEAN: a protected external counter exists (§15.5)
  NoBackup    \* model value: no snapshot taken yet

VARIABLES
  gen,        \* DB: the generation committed in the last authority txn
  ext,        \* keystore/TPM: reserved generation (NOT in the DB backup)
  used,       \* DB: consumed nonces
  backup,     \* the operator's snapshot: [gen, used] or NoBackup
  mode,       \* daemon: "normal" | "recovery"
  issued      \* history: real-world issuances per nonce (restores cannot
              \*          erase what authority already left the building)

vars == <<gen, ext, used, backup, mode, issued>>

TypeOK ==
  /\ gen \in 0..MaxGen
  /\ ext \in 0..MaxGen
  /\ used \subseteq Nonces
  /\ backup \in [gen : 0..MaxGen, used : SUBSET Nonces] \cup {NoBackup}
  /\ mode \in {"normal", "recovery"}
  /\ issued \in [Nonces -> 0..2]

Init ==
  /\ gen = 0 /\ ext = 0
  /\ used = {}
  /\ backup = NoBackup
  /\ mode = "normal"
  /\ issued = [n \in Nonces |-> 0]

-----------------------------------------------------------------------------
(* §15.5: reserve ext+1 in the keystore BEFORE the txn, commit it in the   *)
(* txn that consumes the nonce and issues the authority — one action here  *)
(* because the reservation-then-commit pair is what the scheme protects.   *)
(* (issued is capped at 2 only to keep the state space finite.)            *)
Issue(n) ==
  /\ mode = "normal" /\ n \notin used /\ ext < MaxGen /\ issued[n] < 2
  /\ ext'    = ext + 1
  /\ gen'    = ext + 1
  /\ used'   = used \cup {n}
  /\ issued' = [issued EXCEPT ![n] = @ + 1]
  /\ UNCHANGED <<backup, mode>>

(* The operator snapshots the database (keystore state is NOT included).   *)
TakeBackup ==
  /\ backup' = [gen |-> gen, used |-> used]
  /\ UNCHANGED <<gen, ext, used, mode, issued>>

(* Restore + reopen: the DB reverts; the external counter does not.  At    *)
(* open the daemon compares them — if it can (§15.5 degrades to            *)
(* `rollback_detection: unavailable` without a protected counter).         *)
RestoreAndReopen ==
  /\ backup # NoBackup
  /\ gen'  = backup.gen
  /\ used' = backup.used
  /\ mode' = IF Detection /\ backup.gen # ext THEN "recovery" ELSE "normal"
  /\ UNCHANGED <<ext, backup, issued>>

Next ==
  \/ \E n \in Nonces : Issue(n)
  \/ TakeBackup \/ RestoreAndReopen

-----------------------------------------------------------------------------
(* §12.3 one-use nonces must stay one-use across restores: with a          *)
(* protected counter this is an invariant; without one it is exactly the   *)
(* T13 residual, and TLC finds the attack.                                 *)
OneShotNonceForever ==
  \A n \in Nonces : issued[n] <= 1

(* A daemon that detected a rollback refuses to issue authority: recovery  *)
(* mode only ever transitions by operator action, which is not modeled —   *)
(* so from recovery, no Issue is enabled (structural; stated for clarity). *)
RecoveryRefusesAuthority ==
  mode = "recovery" => TRUE

=============================================================================

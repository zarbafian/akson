--------------------------- MODULE PairingLedger ---------------------------
(***************************************************************************)
(* The bootstrap consume-once ledger for one invitation.                   *)
(*                                                                         *)
(* Sources (in /home/vaein/agentic/axon):                                  *)
(*   crates/akson-pairing/src/state_machine.rs::accept — transcribed:       *)
(*     consumed-record check first (same transcript => Replay, changed     *)
(*     => TranscriptConflict, both no-ops); then take_active; check_secret *)
(*     Ok => commit_consumed atomically (secret consumed in the same       *)
(*     commit that creates the pending peer); Expired/AttemptsExhausted    *)
(*     invitations are taken and NOT re-inserted (dead).                   *)
(*   design §8.2 — pairing is retry-safe, not exactly-once; the consumed   *)
(*     record is retained until invitation expiry.                         *)
(*                                                                         *)
(* The adversary replays and varies transcripts at will; expiry strikes    *)
(* nondeterministically.  Wrong secrets hash to a different verifier and   *)
(* are no-ops (BadSecret); a verifier collision with a wrong secret is a   *)
(* SHA-256 collision and is not modeled.  The attempt cap only matters     *)
(* under such collisions, so it is not modeled either.                     *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
  Transcripts,  \* distinct bootstrap transcripts an accepter may present
  NoT           \* model value: no consumed record

VARIABLES
  active,          \* durable: a live invitation exists for the verifier
  expired,         \* the invitation's not_after has passed
  dead,            \* durable: invitation taken by an expired attempt
  consumed,        \* durable: consumed record's transcript (NoT = none)
  peers,           \* history: pending peers ever created by this invitation
  everConsumed,    \* history: a fresh pairing succeeded at some point
  consumedWrites,  \* history: content writes to the consumed record
  pairedLate       \* history: a pairing succeeded after expiry (never, §8.5)

vars == <<active, expired, dead, consumed, peers, everConsumed,
          consumedWrites, pairedLate>>

TypeOK ==
  /\ active         \in BOOLEAN
  /\ expired        \in BOOLEAN
  /\ dead           \in BOOLEAN
  /\ consumed       \in Transcripts \cup {NoT}
  /\ peers          \in Nat
  /\ everConsumed   \in BOOLEAN
  /\ consumedWrites \in Nat
  /\ pairedLate     \in BOOLEAN

Init ==
  /\ active         = TRUE
  /\ expired        = FALSE
  /\ dead           = FALSE
  /\ consumed       = NoT
  /\ peers          = 0
  /\ everConsumed   = FALSE
  /\ consumedWrites = 0
  /\ pairedLate     = FALSE

-----------------------------------------------------------------------------
(* A valid, in-date bootstrap: take_active + check_secret Ok +             *)
(* commit_consumed, one atomic commit — the secret is consumed in the      *)
(* same transaction that records the pending peer (§8.2).                  *)
(* (Replay and TranscriptConflict verdicts are pure reads — no actions.)   *)
ConsumeFresh(t) ==
  /\ active /\ ~expired
  /\ active'         = FALSE
  /\ consumed'       = t
  /\ everConsumed'   = TRUE
  /\ consumedWrites' = consumedWrites + 1
  /\ peers'          = peers + 1
  /\ pairedLate'     = IF expired THEN TRUE ELSE pairedLate
  /\ UNCHANGED <<expired, dead>>

(* check_secret returns Expired: the taken invitation is dead — it is      *)
(* deliberately NOT re-inserted (state_machine.rs:189-191).                *)
TakeExpired ==
  /\ active /\ expired
  /\ active' = FALSE
  /\ dead'   = TRUE
  /\ UNCHANGED <<expired, consumed, peers, everConsumed, consumedWrites,
                 pairedLate>>

(* Wall-clock passes the invitation's not_after (15-minute hard max §8.5). *)
Expire ==
  /\ ~expired
  /\ expired' = TRUE
  /\ UNCHANGED <<active, dead, consumed, peers, everConsumed,
                 consumedWrites, pairedLate>>

(* The consumed record is retained only until invitation expiry (§8.2);    *)
(* after that it may be purged — later retries fail closed as BadSecret.   *)
Purge ==
  /\ expired /\ consumed # NoT
  /\ consumed' = NoT
  /\ UNCHANGED <<active, expired, dead, peers, everConsumed,
                 consumedWrites, pairedLate>>

Next ==
  \/ \E t \in Transcripts : ConsumeFresh(t)
  \/ TakeExpired \/ Expire \/ Purge

-----------------------------------------------------------------------------
(* Machine-checked invariants                                              *)

(* §8.2 "No second peer can be created": the invitation pairs at most      *)
(* once, under every ordering of retries, conflicts, expiry and purging.   *)
AtMostOnePeer ==
  peers <= 1

(* A consumed invitation never comes back to life.                         *)
NoRevival ==
  everConsumed => ~active

(* The consumed record is written once; replays serve exactly the stored   *)
(* response, and a TranscriptConflict changes nothing.                     *)
ConsumedRecordFinal ==
  consumedWrites <= 1

(* An invitation that died expired never produced a peer.                  *)
ExpiredNeverPairs ==
  dead => peers = 0

(* Retry safety (§8.2): while the invitation is unexpired, a completed     *)
(* pairing keeps its consumed record — the exact retry can always be       *)
(* answered with the identical response.                                   *)
RetentionUntilExpiry ==
  everConsumed /\ ~expired => consumed # NoT

(* §8.5 expiry is an authority boundary: no pairing ever succeeds after   *)
(* the invitation's not_after.                                             *)
NoLatePairing ==
  ~pairedLate

=============================================================================

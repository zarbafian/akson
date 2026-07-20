------------------------- MODULE PairingLedgerInd -------------------------
(***************************************************************************)
(* Apalache inductive-proof variant of PairingLedger.tla.                  *)
(*                                                                         *)
(* TLC checked the ledger exhaustively to its bounded depth; this module   *)
(* removes the run-length bound: Apalache proves IndInv is inductive       *)
(*   base:        Init  => IndInv                 (--length=0)             *)
(*   consecution: IndInit /\ Next => IndInv'      (--init=IndInit)         *)
(*   implication: IndInit => TargetInv            (--length=0)             *)
(* so every invariant of the TLC spec holds after ANY number of steps.     *)
(*                                                                         *)
(* The machine below is PairingLedger.tla transcribed unchanged, with      *)
(* Apalache type annotations and strings in place of TLC model values.     *)
(* A behavioral change to either module must be mirrored in the other —    *)
(* the transcription is checked by review, not tooling.                    *)
(***************************************************************************)
EXTENDS Integers

Transcripts == {"t1", "t2"}
NoT == "none"

VARIABLES
  \* @type: Bool;
  active,
  \* @type: Bool;
  expired,
  \* @type: Bool;
  dead,
  \* @type: Str;
  consumed,
  \* @type: Int;
  peers,
  \* @type: Bool;
  everConsumed,
  \* @type: Int;
  consumedWrites,
  \* @type: Bool;
  pairedLate

Init ==
  /\ active         = TRUE
  /\ expired        = FALSE
  /\ dead           = FALSE
  /\ consumed       = NoT
  /\ peers          = 0
  /\ everConsumed   = FALSE
  /\ consumedWrites = 0
  /\ pairedLate     = FALSE

ConsumeFresh(t) ==
  /\ active /\ ~expired
  /\ active'         = FALSE
  /\ consumed'       = t
  /\ everConsumed'   = TRUE
  /\ consumedWrites' = consumedWrites + 1
  /\ peers'          = peers + 1
  /\ pairedLate'     = IF expired THEN TRUE ELSE pairedLate
  /\ UNCHANGED <<expired, dead>>

TakeExpired ==
  /\ active /\ expired
  /\ active' = FALSE
  /\ dead'   = TRUE
  /\ UNCHANGED <<expired, consumed, peers, everConsumed, consumedWrites,
                 pairedLate>>

Expire ==
  /\ ~expired
  /\ expired' = TRUE
  /\ UNCHANGED <<active, dead, consumed, peers, everConsumed,
                 consumedWrites, pairedLate>>

Purge ==
  /\ expired /\ consumed # NoT
  /\ consumed' = NoT
  /\ UNCHANGED <<active, expired, dead, peers, everConsumed,
                 consumedWrites, pairedLate>>

Next ==
  \/ \E t \in Transcripts : ConsumeFresh(t)
  \/ TakeExpired \/ Expire \/ Purge

-----------------------------------------------------------------------------
(* The inductive strengthening: every conjunct is needed to push some      *)
(* other conjunct through some action.                                     *)
IndInv ==
  /\ consumed \in Transcripts \cup {NoT}
  /\ peers = (IF everConsumed THEN 1 ELSE 0)
  /\ consumedWrites = peers
  /\ active => ~everConsumed
  /\ dead => ~active
  /\ dead => ~everConsumed
  /\ consumed # NoT => everConsumed
  /\ (everConsumed /\ ~expired) => consumed # NoT
  /\ ~pairedLate

(* IndInv as a symbolic initial state: Apalache needs every variable       *)
(* assigned, so bind each to its type domain, then constrain with IndInv.  *)
IndInit ==
  /\ active         \in BOOLEAN
  /\ expired        \in BOOLEAN
  /\ dead           \in BOOLEAN
  /\ consumed       \in (Transcripts \union {NoT})
  /\ peers          \in Nat
  /\ everConsumed   \in BOOLEAN
  /\ consumedWrites \in Nat
  /\ pairedLate     \in BOOLEAN
  /\ IndInv

(* Vacuity probe for negative-checks.sh: a false invariant.  If IndInit   *)
(* is satisfiable, Apalache MUST refute this; a pass would mean the        *)
(* induction was checked over an empty state predicate.                    *)
ProbeFalse == FALSE

(* Exactly the six invariants the TLC spec checks.                         *)
TargetInv ==
  /\ peers <= 1                                    \* AtMostOnePeer
  /\ everConsumed => ~active                       \* NoRevival
  /\ consumedWrites <= 1                           \* ConsumedRecordFinal
  /\ dead => peers = 0                             \* ExpiredNeverPairs
  /\ (everConsumed /\ ~expired) => consumed # NoT  \* RetentionUntilExpiry
  /\ ~pairedLate                                   \* NoLatePairing

=============================================================================

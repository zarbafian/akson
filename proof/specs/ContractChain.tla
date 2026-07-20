--------------------------- MODULE ContractChain ---------------------------
(***************************************************************************)
(* The per-task contract revision chain and its compare-and-swap head.     *)
(*                                                                         *)
(* Sources (in /home/vaein/agentic/axon):                                  *)
(*   crates/akson-contract/src/chain.rs   apply_revision / accept_head,    *)
(*     transcribed 1:1 (HeadState Empty | Open | Locked)                   *)
(*   design §9.3 (single CAS head, no global order), §10.2 (predecessor    *)
(*     digest chaining, acceptance locks exactly one digest)               *)
(*                                                                         *)
(* The environment is adversarial delivery: proposals for any revision     *)
(* number, any sibling variant, any claimed predecessor — replayed, out    *)
(* of order, competing — plus acceptance attempts for arbitrary digests    *)
(* (stale acceptances included).  Only the exact chain.rs guards decide    *)
(* what advances or locks; TLC tries everything else and must find no      *)
(* state where the invariants break.                                       *)
(*                                                                         *)
(* A digest is modeled as the pair <<revision, variant>>: two proposals    *)
(* with the same revision but different variants are competing siblings    *)
(* with distinct digests.                                                  *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
  MaxRev,      \* highest revision number the environment may propose
  Variants,    \* sibling space: distinct proposal bodies per revision
  NoPred       \* model value: "carries no predecessor_digest"

Digests == {<<r, v>> : r \in 0..MaxRev, v \in Variants}

VARIABLES
  head,        \* the durable CAS head: mode "empty" | "open" | "locked"
  hist,        \* history: every head advance, in order (for invariants)
  lockCount,   \* history: number of successful accept_head locks
  firstLock    \* history: the first digest ever locked (NoPred = none yet)

vars == <<head, hist, lockCount, firstLock>>

TypeOK ==
  /\ head \in [mode : {"empty", "open", "locked"},
               rev  : 0..MaxRev,
               dig  : Digests \cup {NoPred}]
  /\ hist \in Seq([rev : 0..MaxRev, dig : Digests, pred : Digests \cup {NoPred}])
  /\ lockCount \in Nat
  /\ firstLock \in Digests \cup {NoPred}

Init ==
  /\ head      = [mode |-> "empty", rev |-> 0, dig |-> NoPred]
  /\ hist      = <<>>
  /\ lockCount = 0
  /\ firstLock = NoPred

-----------------------------------------------------------------------------
(* chain.rs apply_revision: revision 0 advances only an Empty head and     *)
(* must carry no predecessor; a follow-up must chain onto the Open head    *)
(* with revision = head.rev + 1 AND predecessor = head.digest; a Locked    *)
(* head refuses everything.  Every delivery failing this guard is a Stale  *)
(* verdict, i.e. no state change — so only the Advance case is an action.  *)
CanAdvance(r, p) ==
  \/ head.mode = "empty" /\ r = 0 /\ p = NoPred
  \/ head.mode = "open"  /\ r = head.rev + 1 /\ p = head.dig

Deliver(r, v, p) ==
  LET d == <<r, v>> IN
  /\ CanAdvance(r, p)
  /\ head' = [mode |-> "open", rev |-> r, dig |-> d]
  /\ hist' = Append(hist, [rev |-> r, dig |-> d, pred |-> p])
  /\ UNCHANGED <<lockCount, firstLock>>

(* chain.rs accept_head: a signed acceptance locks only an Open head       *)
(* whose digest equals the accepted digest; a stale acceptance (sibling    *)
(* or superseded digest) is DigestMismatch — no state change.              *)
Accept(d) ==
  /\ head.mode = "open" /\ head.dig = d
  /\ head'      = [head EXCEPT !.mode = "locked"]
  /\ lockCount' = lockCount + 1
  /\ firstLock' = IF firstLock = NoPred THEN d ELSE firstLock
  /\ UNCHANGED hist

Next ==
  \/ \E r \in 0..MaxRev, v \in Variants, p \in Digests \cup {NoPred} :
       Deliver(r, v, p)
  \/ \E d \in Digests : Accept(d)

-----------------------------------------------------------------------------
(* Machine-checked invariants                                              *)

(* §9.3/§10.2 "no retroactive cancel": once any digest is locked, the      *)
(* head is that digest, locked, forever — no later sibling or revision     *)
(* can displace authority already issued against it.                       *)
LockIsFinal ==
  firstLock # NoPred => head.mode = "locked" /\ head.dig = firstLock

(* Exactly one acceptance can ever succeed for a task.                     *)
AtMostOneLock ==
  lockCount <= 1

(* §10.2 digest chaining: the advance history is a single unbroken chain — *)
(* revision 0 opens it with no predecessor, and every later advance links  *)
(* to exactly the digest it replaced.                                      *)
ChainIntegrity ==
  /\ hist # <<>> => hist[1].rev = 0 /\ hist[1].pred = NoPred
  /\ \A i \in 2..Len(hist) :
       hist[i].rev = hist[i-1].rev + 1 /\ hist[i].pred = hist[i-1].dig

(* The head is always the most recent advance (or empty before any).       *)
HeadMatchesHistory ==
  IF head.mode = "empty"
  THEN hist = <<>>
  ELSE hist # <<>> /\ head.dig = hist[Len(hist)].dig
                   /\ head.rev = hist[Len(hist)].rev

(* A locked digest is one that genuinely advanced the head — an            *)
(* acceptance can never smuggle in a digest that was never the head.       *)
LockedWasAdvanced ==
  firstLock # NoPred => \E i \in 1..Len(hist) : hist[i].dig = firstLock

=============================================================================

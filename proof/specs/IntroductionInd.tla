------------------------- MODULE IntroductionInd -------------------------
(***************************************************************************)
(* Apalache inductive-proof variant of Introduction.tla.                   *)
(*                                                                         *)
(* What this buys over TLC: MaxEpoch is an ARBITRARY natural (ConstInit),  *)
(* and induction removes the run-length bound — no admission without       *)
(* import and one-material-per-epoch hold for ANY number of remove/re-add  *)
(* cycles and arbitrarily many handshakes held open across them, not just  *)
(* the states TLC enumerated at MaxEpoch = 4.                              *)
(*                                                                         *)
(*   base:        Init  => IndInv                  (--length=0)            *)
(*   consecution: IndInit /\ Next => IndInv'       (--init=IndInit)        *)
(*   implication: IndInit => TargetInv             (--length=0)            *)
(*                                                                         *)
(* Handshake sets in the symbolic initial state are generated with a       *)
(* size cap (Gen(4)) — the CONTENTS (which epochs, up to MaxEpoch) stay    *)
(* arbitrary, and handshakes never interact, so the cap bounds only how    *)
(* many can be held simultaneously in one induction step.                  *)
(*                                                                         *)
(* The TLC spec's per-epoch firstMat function collapses to one scalar      *)
(* here: `curFirst` is firstMat[epoch].  Sound because the epoch only      *)
(* grows and every invariant about material history refers to the          *)
(* CURRENT epoch (an active pin has pinnedEpoch = epoch by A) — past       *)
(* epochs' history is immutable by construction and never consulted.       *)
(*                                                                         *)
(* The IndInv chain, in words: an active pin sits under a live import at   *)
(* exactly the current epoch (A) with exactly the epoch's first-activated  *)
(* material (B); every in-flight handshake snapshot is from a past or      *)
(* current epoch (C); a pin holds material (D) under a real epoch (E);     *)
(* and current-epoch history implies a live pin (G) — G is what pushes B   *)
(* through activation after a remove-and-re-import.                        *)
(***************************************************************************)
EXTENDS Integers, Apalache

Materials == {"m1", "m2"}
NoM == "none-material"

CONSTANT
  \* @type: Int;
  MaxEpoch

ConstInit == MaxEpoch \in Nat \ {0}

VARIABLES
  \* @type: Str;
  import,
  \* @type: Int;
  epoch,
  \* @type: Set(Int);
  handshakes,
  \* @type: Str;
  pinned,
  \* @type: Str;
  pinnedMat,
  \* @type: Int;
  pinnedEpoch,
  \* @type: Str;
  curFirst

Init ==
  /\ import = "none"
  /\ epoch = 1
  /\ handshakes = {}
  /\ pinned = "none"
  /\ pinnedMat = NoM
  /\ pinnedEpoch = 0
  /\ curFirst = NoM

Import ==
  /\ import \in {"none", "tomb"}
  /\ import' = "live"
  /\ UNCHANGED <<epoch, handshakes, pinned, pinnedMat, pinnedEpoch, curFirst>>

(* Removal bumps the epoch: the new epoch has no material history yet. *)
Remove ==
  /\ import = "live"
  /\ epoch < MaxEpoch
  /\ import' = "tomb"
  /\ epoch' = epoch + 1
  /\ pinned' = "none"
  /\ pinnedMat' = NoM
  /\ pinnedEpoch' = 0
  /\ curFirst' = NoM
  /\ UNCHANGED handshakes

Hello ==
  /\ import = "live"
  /\ handshakes' = handshakes \union {epoch}
  /\ UNCHANGED <<import, epoch, pinned, pinnedMat, pinnedEpoch, curFirst>>

Complete(e, m) ==
  /\ e \in handshakes
  /\ handshakes' = handshakes \ {e}
  /\ IF import = "live" /\ epoch = e
     THEN IF pinned = "none"
          THEN /\ pinned' = "active"
               /\ pinnedMat' = m
               /\ pinnedEpoch' = e
               /\ curFirst' = IF curFirst = NoM THEN m ELSE curFirst
               /\ UNCHANGED <<import, epoch>>
          ELSE IF pinned = "active" /\ pinnedMat = m
          THEN UNCHANGED <<import, epoch, pinned, pinnedMat, pinnedEpoch,
                           curFirst>>
          ELSE /\ pinned' = "suspended"
               /\ UNCHANGED <<import, epoch, pinnedMat, pinnedEpoch, curFirst>>
     ELSE UNCHANGED <<import, epoch, pinned, pinnedMat, pinnedEpoch, curFirst>>

Next ==
  \/ Import \/ Remove \/ Hello
  \/ \E e \in 1..MaxEpoch, m \in Materials : Complete(e, m)

-----------------------------------------------------------------------------
TypeInv ==
  /\ import \in {"none", "live", "tomb"}
  /\ epoch >= 1 /\ epoch <= MaxEpoch
  /\ \A h \in handshakes : h >= 1 /\ h <= MaxEpoch
  /\ pinned \in {"none", "active", "suspended"}
  /\ pinnedMat \in Materials \union {NoM}
  /\ pinnedEpoch >= 0 /\ pinnedEpoch <= MaxEpoch
  /\ curFirst \in Materials \union {NoM}

IndInv ==
  /\ TypeInv
  \* A — no admission without import, no commit across an epoch bump:
  /\ pinned = "active" => (import = "live" /\ pinnedEpoch = epoch)
  \* B — one material per epoch:
  /\ pinned = "active" => curFirst = pinnedMat
  \* C — handshake snapshots never come from the future:
  /\ \A h \in handshakes : h <= epoch
  \* D — a pin (active or suspended) holds material:
  /\ pinned # "none" => pinnedMat # NoM
  \* E — the pin's epoch is real:
  /\ pinned # "none" => (pinnedEpoch >= 1 /\ pinnedEpoch <= epoch)
  \* G — current-epoch history implies a live pin:
  /\ curFirst # NoM => pinned # "none"

IndInit ==
  /\ import \in {"none", "live", "tomb"}
  /\ epoch \in Nat
  /\ handshakes = Gen(4)
  /\ pinned \in {"none", "active", "suspended"}
  /\ pinnedMat \in Materials \union {NoM}
  /\ pinnedEpoch \in Nat
  /\ curFirst \in Materials \union {NoM}
  /\ IndInv

TargetInv ==
  /\ pinned = "active" => (import = "live" /\ pinnedEpoch = epoch)
  /\ pinned = "active" => curFirst = pinnedMat

(* Vacuity probe: a false claim over IndInit must be refutable. *)
ProbeFalse ==
  pinned # "suspended"

=============================================================================

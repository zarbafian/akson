----------------------- MODULE RollbackAdversaryInd -----------------------
(***************************************************************************)
(* Apalache inductive-proof variant of RollbackAdversary.tla, for the      *)
(* protected configuration (Detection = TRUE baked in — the unprotected    *)
(* configuration is the documented attack, not a theorem).                 *)
(*                                                                         *)
(* What this buys over TLC: MaxGen is an ARBITRARY natural (ConstInit),    *)
(* and induction removes the run-length bound — the one-shot-nonce         *)
(* property holds for any number of generations, backups and restores,     *)
(* not just the 18 states TLC enumerated at MaxGen = 4.                    *)
(*                                                                         *)
(*   base:        Init  => IndInv                  (--length=0)            *)
(*   consecution: IndInit /\ Next => IndInv'       (--init=IndInit)        *)
(*   implication: IndInit => TargetInv             (--length=0)            *)
(*                                                                         *)
(* The IndInv chain, in words: in normal mode the DB generation equals     *)
(* the protected external counter (A); at the newest generation every      *)
(* issued nonce is in the used set (D); a backup taken at the newest       *)
(* generation contains them all too (E, needed to push D through a         *)
(* restore); and backups never come from the future (gen <= ext).  From    *)
(* A+D the Issue guard n \notin used forces issued[n] = 0 — so the         *)
(* issued[n] < 2 state-space cap in the TLC spec provably never binds.     *)
(*                                                                         *)
(* The TLC spec's backup record is split into three scalar variables      *)
(* here (backupSome/backupGen/backupUsed) so the symbolic initial state    *)
(* can bind each to a type domain.                                         *)
(***************************************************************************)
EXTENDS Integers

Nonces == {"n1", "n2"}

CONSTANT
  \* @type: Int;
  MaxGen

ConstInit == MaxGen \in Nat

VARIABLES
  \* @type: Int;
  gen,
  \* @type: Int;
  ext,
  \* @type: Set(Str);
  used,
  \* @type: Bool;
  backupSome,
  \* @type: Int;
  backupGen,
  \* @type: Set(Str);
  backupUsed,
  \* @type: Str;
  mode,
  \* @type: Str -> Int;
  issued

Init ==
  /\ gen = 0 /\ ext = 0
  /\ used = {}
  /\ backupSome = FALSE /\ backupGen = 0 /\ backupUsed = {}
  /\ mode = "normal"
  /\ issued = [n \in Nonces |-> 0]

Issue(n) ==
  /\ mode = "normal" /\ n \notin used /\ ext < MaxGen /\ issued[n] < 2
  /\ ext'    = ext + 1
  /\ gen'    = ext + 1
  /\ used'   = used \union {n}
  /\ issued' = [issued EXCEPT ![n] = @ + 1]
  /\ UNCHANGED <<backupSome, backupGen, backupUsed, mode>>

TakeBackup ==
  /\ backupSome' = TRUE
  /\ backupGen'  = gen
  /\ backupUsed' = used
  /\ UNCHANGED <<gen, ext, used, mode, issued>>

RestoreAndReopen ==
  /\ backupSome
  /\ gen'  = backupGen
  /\ used' = backupUsed
  /\ mode' = IF backupGen /= ext THEN "recovery" ELSE "normal"
  /\ UNCHANGED <<ext, backupSome, backupGen, backupUsed, issued>>

Next ==
  \/ \E n \in Nonces : Issue(n)
  \/ TakeBackup \/ RestoreAndReopen

-----------------------------------------------------------------------------
IndInv ==
  /\ mode \in {"normal", "recovery"}
  /\ used \subseteq Nonces
  /\ backupUsed \subseteq Nonces
  /\ 0 <= gen /\ gen <= ext
  /\ backupSome => (0 <= backupGen /\ backupGen <= ext)
  /\ \A n \in Nonces : 0 <= issued[n] /\ issued[n] <= 1
  /\ mode = "normal" => gen = ext                                   \* A
  /\ gen = ext =>                                                   \* D
       \A n \in Nonces : issued[n] >= 1 => n \in used
  /\ (backupSome /\ backupGen = ext) =>                             \* E
       \A n \in Nonces : issued[n] >= 1 => n \in backupUsed

(* IndInv as a symbolic initial state: every variable bound to its type    *)
(* domain, then constrained by IndInv.                                     *)
IndInit ==
  /\ gen \in Nat
  /\ ext \in Nat
  /\ used \in SUBSET Nonces
  /\ backupSome \in BOOLEAN
  /\ backupGen \in Nat
  /\ backupUsed \in SUBSET Nonces
  /\ mode \in {"normal", "recovery"}
  /\ issued \in [Nonces -> 0..2]
  /\ IndInv

(* Vacuity probe for negative-checks.sh: a false invariant.  If IndInit   *)
(* is satisfiable, Apalache MUST refute this; a pass would mean the        *)
(* induction was checked over an empty state predicate.                    *)
ProbeFalse == FALSE

(* §12.3 / TM T13: one-use nonces stay one-use across any number of        *)
(* snapshot/restore cycles, for any MaxGen.                                *)
TargetInv ==
  \A n \in Nonces : issued[n] <= 1

=============================================================================

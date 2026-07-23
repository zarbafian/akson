--------------------------- MODULE Introduction ---------------------------
(***************************************************************************)
(* First contact over identity tokens, for one relationship (one peer      *)
(* root): the import / introduction / epoch machine (design §8.2,          *)
(* ADR-0015).                                                              *)
(*                                                                         *)
(* Sources (in /home/vaein/agentic/axon):                                  *)
(*   crates/akson-store/src/lib.rs::add_peer_import / remove_peer_import — *)
(*     removal tombstones AND advances the epoch in one statement; a       *)
(*     re-add revives under the already-advanced epoch.                    *)
(*   crates/aksond/src/introduce.rs::respond_introduction — the hello      *)
(*     admission gate snapshots the live import's epoch into the           *)
(*     per-connection state; the commit CAS runs against THAT epoch.       *)
(*   crates/akson-store/src/lib.rs::commit_introduced_peer — the CAS:      *)
(*     refused unless the import is live under the snapshotted epoch;      *)
(*     identical material is idempotent; changed material for a pinned     *)
(*     peer suspends (§8.4) and a suspended peer never silently            *)
(*     reactivates. Removal (dispatch) also drops the pinned peer.        *)
(*                                                                         *)
(* The adversary dials at will and may hold a completed hello open for     *)
(* arbitrarily long (the slice-2 review's ABA case: remove + re-add        *)
(* between the flights), and may present divergent identity material on    *)
(* any complete.                                                           *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
  Materials,  \* distinct identity material a dialer may present
  MaxEpoch,   \* TLC bound on relationship epochs
  NoM         \* model value: nothing pinned / no material recorded

VARIABLES
  import,      \* "none" | "live" | "tomb" — the operator's trust state
  epoch,       \* the relationship epoch (advanced by removal)
  handshakes,  \* epochs snapshotted by admitted hellos, still in flight
  pinned,      \* "none" | "active" | "suspended"
  pinnedMat,   \* the material pinned when active/suspended (NoM = none)
  pinnedEpoch, \* the epoch the pinned peer committed under
  firstMat     \* history: the first material ever activated, per epoch

vars == <<import, epoch, handshakes, pinned, pinnedMat, pinnedEpoch, firstMat>>

TypeOK ==
  /\ import      \in {"none", "live", "tomb"}
  /\ epoch       \in 1..MaxEpoch
  /\ handshakes  \subseteq 1..MaxEpoch
  /\ pinned      \in {"none", "active", "suspended"}
  /\ pinnedMat   \in Materials \cup {NoM}
  /\ pinnedEpoch \in 0..MaxEpoch
  /\ firstMat    \in [1..MaxEpoch -> Materials \cup {NoM}]

Init ==
  /\ import      = "none"
  /\ epoch       = 1
  /\ handshakes  = {}
  /\ pinned      = "none"
  /\ pinnedMat   = NoM
  /\ pinnedEpoch = 0
  /\ firstMat    = [e \in 1..MaxEpoch |-> NoM]

-----------------------------------------------------------------------------
(* The operator imports the token — the one trust act (§8.2 step 3). A    *)
(* tombstoned root revives under its already-advanced epoch.               *)
Import ==
  /\ import \in {"none", "tomb"}
  /\ import' = "live"
  /\ UNCHANGED <<epoch, handshakes, pinned, pinnedMat, pinnedEpoch, firstMat>>

(* Removal: tombstone + epoch bump in ONE transaction, and the pinned      *)
(* peer state drops with it (the PeerImportRemove cascade).                *)
Remove ==
  /\ import = "live"
  /\ epoch < MaxEpoch
  /\ import'      = "tomb"
  /\ epoch'       = epoch + 1
  /\ pinned'      = "none"
  /\ pinnedMat'   = NoM
  /\ pinnedEpoch' = 0
  /\ UNCHANGED <<handshakes, firstMat>>

(* The hello admission gate: only a live import admits, and the epoch is   *)
(* snapshotted into the connection state (introduce.rs). An unimported     *)
(* dialer is refused before any signature work — no action exists for it.  *)
Hello ==
  /\ import = "live"  \* the admission gate
  /\ handshakes' = handshakes \cup {epoch}
  /\ UNCHANGED <<import, epoch, pinned, pinnedMat, pinnedEpoch, firstMat>>

(* A complete for an admitted hello, presenting material m. The commit CAS *)
(* runs against the SNAPSHOTTED epoch e — a removal (even remove+re-add)   *)
(* between the flights refuses the stale handshake.                        *)
Complete(e, m) ==
  /\ e \in handshakes
  /\ handshakes' = handshakes \ {e}
  /\ IF import = "live" /\ epoch = e
     THEN IF pinned = "none"
          THEN /\ pinned'      = "active"
               /\ pinnedMat'   = m
               /\ pinnedEpoch' = e
               /\ firstMat'    = [firstMat EXCEPT
                                    ![e] = IF @ = NoM THEN m ELSE @]
               /\ UNCHANGED <<import, epoch>>
          ELSE IF pinned = "active" /\ pinnedMat = m
          THEN \* idempotent re-introduction (AlreadyActive)
               UNCHANGED <<import, epoch, pinned, pinnedMat, pinnedEpoch,
                           firstMat>>
          ELSE \* divergent material, or an already-suspended peer: suspend
               \* for review — never re-pin, never a second active identity
               /\ pinned' = "suspended"
               /\ UNCHANGED <<import, epoch, pinnedMat, pinnedEpoch, firstMat>>
     ELSE \* refused: the epoch moved or the import is gone — nothing written
          UNCHANGED <<import, epoch, pinned, pinnedMat, pinnedEpoch, firstMat>>

Next ==
  \/ Import \/ Remove \/ Hello
  \/ \E e \in 1..MaxEpoch, m \in Materials : Complete(e, m)

-----------------------------------------------------------------------------
(* Machine-checked invariants                                              *)

(* No admission without import + no commit across an epoch bump: an        *)
(* active peer implies the operator's import is live NOW, under exactly    *)
(* the epoch the introduction committed with. Removal (which bumps the     *)
(* epoch) drops the pin in the same step, so a stale handshake — held      *)
(* across remove, or remove + re-add — can never leave an active peer.     *)
ActiveImpliesLiveImport ==
  pinned = "active" => (import = "live" /\ pinnedEpoch = epoch)

(* One epoch, one identity: whatever material activates first under an     *)
(* epoch is the only material ever active under it — divergent material    *)
(* suspends the relationship rather than replacing or forking it.          *)
OneMaterialPerEpoch ==
  pinned = "active" => firstMat[pinnedEpoch] = pinnedMat

(* An active pin always exists under the epoch that admitted it.           *)
ActiveEpochIsReal ==
  pinned = "active" => pinnedEpoch >= 1 /\ pinnedEpoch <= epoch

(* Suspension holds the disputed material for operator review; only a      *)
(* removal clears it.                                                      *)
SuspensionHoldsMaterial ==
  pinned = "suspended" => pinnedMat # NoM

=============================================================================

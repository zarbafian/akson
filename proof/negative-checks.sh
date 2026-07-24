#!/usr/bin/env sh
# A green model check is only evidence if the check can fail.  This script
# proves it can, three ways:
#   - mutations: each breaks one protocol rule in a copy of a spec; TLC MUST
#     report a counterexample;
#   - probes: claims that are deliberately false in the healthy design; TLC
#     MUST refute them (proves the interesting scenarios are reachable);
#   - differentials: a mutant that must make a refutable probe hold, showing
#     exactly which code behavior a property depends on.
# Any unexpected "No error" from a mutant is a bug in the harness itself.
set -u
cd "$(dirname "$0")"
ROOT=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

tlc() { # tlc <dir> <spec>
  (cd "$1" && java -cp "$ROOT/tools/tla2tools.jar" tlc2.TLC \
     -deadlock -workers auto "$2" 2>&1)
}

expect_violation() { # expect_violation <name> <spec> <sed-expr> <invariant-alternation>
  # <invariant-alternation> lists every invariant the mutation legitimately
  # breaks ("A|B"): parallel TLC workers race, so any of them may be the
  # first one reported.
  name=$1 spec=$2 expr=$3 want=$4
  mkdir -p "$tmp/$name"
  sed "$expr" "specs/$spec.tla" > "$tmp/$name/$spec.tla"
  if cmp -s "specs/$spec.tla" "$tmp/$name/$spec.tla"; then
    echo "FAIL  $name: mutation did not change the spec (sed pattern rotted?)"
    fail=1; return
  fi
  cp "specs/$spec.cfg" "$tmp/$name/"
  caught=$(tlc "$tmp/$name" "$spec" \
             | grep -Eo "Invariant ($want) is violated" | head -1)
  if [ -n "$caught" ]; then
    echo "ok    $name: $caught"
  else
    echo "FAIL  $name: expected a counterexample violating $want, got none"
    fail=1
  fi
}

probe_violated() { # probe_violated <name> <spec> <invariant-defined-in-spec>
  # The healthy spec plus a deliberately-false claim: TLC must refute it,
  # proving the scenario it denies is genuinely reachable.
  name=$1 spec=$2 inv=$3
  mkdir -p "$tmp/$name"
  cp "specs/$spec.tla" "$tmp/$name/"
  { cat "specs/$spec.cfg"; echo "INVARIANT $inv"; } > "$tmp/$name/$spec.cfg"
  if tlc "$tmp/$name" "$spec" | grep -q "Invariant $inv is violated"; then
    echo "ok    $name: $inv refuted (scenario reachable)"
  else
    echo "FAIL  $name: $inv unexpectedly holds - scenario unreachable"
    fail=1
  fi
}

# ========== TaskLifecycle ==================================================
# Probe: the full happy path (send..settle) must be reachable.
mkdir -p "$tmp/probe-settle"
head -n -1 specs/TaskLifecycle.tla > "$tmp/probe-settle/TaskLifecycle.tla"
cat >> "$tmp/probe-settle/TaskLifecycle.tla" <<'EOF'
NeverSettles == \A m \in Msgs : outcome[m] # "accepted"
=============================================================================
EOF
cp specs/TaskLifecycle.cfg "$tmp/probe-settle/"
echo "INVARIANT NeverSettles" >> "$tmp/probe-settle/TaskLifecycle.cfg"
if tlc "$tmp/probe-settle" TaskLifecycle | grep -q "Invariant NeverSettles is violated"; then
  echo "ok    probe-settle: settlement is reachable"
else
  echo "FAIL  probe-settle: settlement unreachable - the model is vacuous"
  fail=1
fi

# Recovery retries mid-flight work instead of marking it ambiguous (§6.3).
expect_violation retry-after-crash TaskLifecycle \
  's/THEN "ambiguous" ELSE attempt\[m\]\]/THEN "pending" ELSE attempt[m]]/' \
  'DurableBeforeEffect|OneShotWorkOrder|AtMostOnceEffect'
# The receive path loses its dedup tombstone (§9.2): replays create tasks.
expect_violation no-dedup TaskLifecycle \
  's|/\\ up /\\ sent\[m\] /\\ ~task\[m\]|/\\ up /\\ sent[m]|' \
  'NoDuplicateTask|NoAuthorityWithoutApproval'

# ========== ContractChain ==================================================
# apply_revision forgets the predecessor-digest check (§10.2).
expect_violation no-predecessor-check ContractChain \
  's|/\\ r = head.rev + 1 /\\ p = head.dig|/\\ r = head.rev + 1|' \
  ChainIntegrity
# accept_head locks whatever digest the acceptance names (stale acceptance).
expect_violation accept-any-digest ContractChain \
  's|/\\ head.mode = "open" /\\ head.dig = d|/\\ head.mode = "open"|' \
  LockIsFinal
# A locked head stops refusing revisions: retroactive cancel (§9.3).
expect_violation locked-not-final ContractChain \
  's|head.mode = "open"  /\\ r = head.rev + 1|head.mode \\in {"open", "locked"}  /\\ r = head.rev + 1|' \
  LockIsFinal

# ========== ReceivePipeline ================================================
# Probe: one message id CAN create two tasks in the pre-commit crash window
# (benign - both tasks are inert and expire; the honest invariant is
# one-task-per-BODY, which the main run proves).
probe_violated crash-window-two-tasks ReceivePipeline OneTaskPerMid
# Probe: a post-crash exact replay CAN converge and commit its record.
probe_violated replay-converges ReceivePipeline CrashReplayNeverCompletes
# Differential: convergence depends on receive.rs DISCARDING submit_revision's
# Stale verdict.  If a Stale head write aborted the pipeline instead, the
# crashed request could never complete - the probe would hold.
mkdir -p "$tmp/stale-aborts"
sed 's|/\\ proc'"'"' = \[proc EXCEPT !.stage = "headDone"\]  \\\* Stale is discarded|/\\ proc'"'"' = [proc EXCEPT !.stage = "idle"]|' \
  specs/ReceivePipeline.tla > "$tmp/stale-aborts/ReceivePipeline.tla"
if cmp -s specs/ReceivePipeline.tla "$tmp/stale-aborts/ReceivePipeline.tla"; then
  echo "FAIL  stale-aborts: mutation did not change the spec"; fail=1
else
  { cat specs/ReceivePipeline.cfg; echo "INVARIANT CrashReplayNeverCompletes"; } \
    > "$tmp/stale-aborts/ReceivePipeline.cfg"
  if tlc "$tmp/stale-aborts" ReceivePipeline | grep -q "No error"; then
    echo "ok    stale-aborts: with Stale-as-error, the crashed replay can never converge"
  else
    echo "FAIL  stale-aborts: expected convergence to become impossible"; fail=1
  fi
fi

# ========== Introduction ===================================================
# The commit CAS runs against the CURRENT epoch instead of the hello-time
# snapshot: the slice-2 ABA attack (remove + re-add between the flights)
# resurrects the stale handshake.
expect_violation stale-handshake-commits Introduction \
  's|IF import = "live" /\\ epoch = e|IF import = "live"|' \
  ActiveImpliesLiveImport
# Removal stops dropping the pinned peer (the cascade forgotten): a removed
# relationship keeps an active peer behind.
expect_violation remove-keeps-pin Introduction \
  's|/\\ pinned'"'"'      = "none"|/\\ pinned'"'"'      = pinned|' \
  ActiveImpliesLiveImport
# Divergent material re-pins (with ITS material) instead of suspending:
# the relationship forks (§8.4 forgotten).
expect_violation divergent-repins Introduction \
  's|/\\ pinned'"'"' = "suspended"|/\\ pinned'"'"' = "active" /\\ pinnedMat'"'"' = m|; s|UNCHANGED <<import, epoch, pinnedMat, pinnedEpoch, firstMat>>|UNCHANGED <<import, epoch, pinnedEpoch, firstMat>>|' \
  OneMaterialPerEpoch
# Differential: the hello ADMISSION gate alone is defense in depth, not the
# safety boundary — with it removed, the commit CAS still refuses to pin
# (safety holds; the gate's real job is refusing unknown callers before any
# signature work, an availability property outside this model).
mkdir -p "$tmp/admit-without-import"
sed 's|/\\ import = "live"  .. the admission gate|/\\ TRUE|' \
  specs/Introduction.tla > "$tmp/admit-without-import/Introduction.tla"
if cmp -s specs/Introduction.tla "$tmp/admit-without-import/Introduction.tla"; then
  echo "FAIL  admit-without-import: mutation did not change the spec"; fail=1
else
  cp specs/Introduction.cfg "$tmp/admit-without-import/"
  if tlc "$tmp/admit-without-import" Introduction | grep -q "No error"; then
    echo "ok    admit-without-import: commit CAS alone still holds safety (defense in depth)"
  else
    echo "FAIL  admit-without-import: expected safety to hold on the commit CAS alone"; fail=1
  fi
fi

# ========== BrokerBudget ===================================================
# prepare_call stops counting rows in-transaction: unbounded calls.
expect_violation budget-uncounted BrokerBudget \
  's|/\\ Cardinality(Used) < MaxOps|/\\ TRUE|' \
  'BudgetBound|WireBoundedByBudget'
# Crash recovery retries a dispatching call instead of marking it ambiguous.
expect_violation call-retry-after-crash BrokerBudget \
  's|IF call\[c\] = "dispatching" THEN "ambiguous"|IF call[c] = "dispatching" THEN "prepared"|' \
  'AtMostOneTransmit|DurableBeforeWire|WireBoundedByBudget'

# ========== RollbackAdversary ==============================================
# Without a protected counter (interim file-KEK custody), TLC must produce
# the TM T13 attack: snapshot, consume a nonce, restore, reissue it.
mkdir -p "$tmp/rollback-undetected"
cp specs/RollbackAdversary.tla "$tmp/rollback-undetected/"
sed 's/CONSTANT Detection = TRUE/CONSTANT Detection = FALSE/' \
  specs/RollbackAdversary.cfg > "$tmp/rollback-undetected/RollbackAdversary.cfg"
if tlc "$tmp/rollback-undetected" RollbackAdversary \
     | grep -q "Invariant OneShotNonceForever is violated"; then
  echo "ok    rollback-undetected: T13 attack trace found without detection"
else
  echo "FAIL  rollback-undetected: expected the rollback attack to be found"
  fail=1
fi

# ========== Inductive proofs (Apalache) ====================================
if [ -x "$ROOT/tools/apalache/bin/apalache-mc" ]; then
  apa() { "$ROOT/tools/apalache/bin/apalache-mc" check "$@" 2>&1; }

  # Vacuity guards: IndInit must be satisfiable, or the consecution and
  # implication obligations were checked over an empty state predicate.
  # A false invariant over a satisfiable init MUST be refuted.
  if apa --cinit=ConstInit --init=IndInit --inv=ProbeFalse --length=0 \
       specs/IntroductionInd.tla | grep -q 'The outcome is: Error'; then
    echo "ok    ind-sat-introduction: IndInit is satisfiable"
  else
    echo "FAIL  ind-sat-introduction: IndInit unsatisfiable - induction was vacuous"; fail=1
  fi
  if apa --cinit=ConstInit --init=IndInit --inv=ProbeFalse --length=0 \
       specs/RollbackAdversaryInd.tla | grep -q 'The outcome is: Error'; then
    echo "ok    ind-sat-rollback: IndInit is satisfiable"
  else
    echo "FAIL  ind-sat-rollback: IndInit unsatisfiable - induction was vacuous"; fail=1
  fi

  # The induction must genuinely need rollback detection: a mutant whose
  # restore always reopens in normal mode (Detection = FALSE, TM T13's
  # residual) must break consecution.
  mkdir -p "$tmp/ind-no-detection"
  sed 's|IF backupGen /= ext THEN "recovery" ELSE "normal"|"normal"|' \
    specs/RollbackAdversaryInd.tla > "$tmp/ind-no-detection/RollbackAdversaryInd.tla"
  if cmp -s specs/RollbackAdversaryInd.tla "$tmp/ind-no-detection/RollbackAdversaryInd.tla"; then
    echo "FAIL  ind-no-detection: mutation did not change the spec"; fail=1
  elif apa --cinit=ConstInit --init=IndInit --inv=IndInv --length=1 \
         "$tmp/ind-no-detection/RollbackAdversaryInd.tla" \
       | grep -q 'The outcome is: Error'; then
    echo "ok    ind-no-detection: consecution collapses without detection"
  else
    echo "FAIL  ind-no-detection: induction survived removing detection"; fail=1
  fi
else
  echo "skip  inductive negative checks (tools/apalache missing; run 'make inductive' first)"
fi

# ========== TaskLiveness ===================================================
# Termination genuinely depends on deadline enforcement: dropping the
# fairness on Expire must break the temporal property.
mkdir -p "$tmp/no-expiry-fairness"
sed '/WF_vars(Expire)/d' specs/TaskLiveness.tla > "$tmp/no-expiry-fairness/TaskLiveness.tla"
cp specs/TaskLiveness.cfg "$tmp/no-expiry-fairness/"
if tlc "$tmp/no-expiry-fairness" TaskLiveness | grep -q "Temporal properties were violated"; then
  echo "ok    no-expiry-fairness: Termination fails without deadline enforcement"
else
  echo "FAIL  no-expiry-fairness: Termination held without fairness on Expire"
  fail=1
fi

exit $fail

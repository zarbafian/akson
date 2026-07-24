#!/usr/bin/env sh
# Inductive proofs with Apalache: for each *Ind module, discharge
#   base:        Init    => IndInv     (--length=0)
#   consecution: IndInit /\ Next => IndInv'   (--init=IndInit --length=1)
#   implication: IndInit => TargetInv  (--length=0)
# Together these prove the TLC spec's invariants for ANY run length —
# and, where ConstInit is used, arbitrary integer parameters.
set -eu
cd "$(dirname "$0")"
A=tools/apalache/bin/apalache-mc
fail=0

run() { # run <label> <apalache-args...>
  label=$1; shift
  if "$A" check "$@" 2>&1 | grep -q 'The outcome is: NoError'; then
    echo "ok    $label"
  else
    echo "FAIL  $label"; fail=1
  fi
}


run "IntroductionInd     base       " --cinit=ConstInit --init=Init    --inv=IndInv    --length=0 specs/IntroductionInd.tla
run "IntroductionInd     consecution" --cinit=ConstInit --init=IndInit --inv=IndInv    --length=1 specs/IntroductionInd.tla
run "IntroductionInd     implication" --cinit=ConstInit --init=IndInit --inv=TargetInv --length=0 specs/IntroductionInd.tla
run "RollbackAdversaryInd base       " --cinit=ConstInit --init=Init    --inv=IndInv    --length=0 specs/RollbackAdversaryInd.tla
run "RollbackAdversaryInd consecution" --cinit=ConstInit --init=IndInit --inv=IndInv    --length=1 specs/RollbackAdversaryInd.tla
run "RollbackAdversaryInd implication" --cinit=ConstInit --init=IndInit --inv=TargetInv --length=0 specs/RollbackAdversaryInd.tla

exit $fail

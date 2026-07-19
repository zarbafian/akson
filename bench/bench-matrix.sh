#!/usr/bin/env bash
# Distributed matrix bench: for each model back-end × scenario, time N iterations of
# the full round trip. Runs ON alice (co-located); switches the performer's worker
# per provider over the VPC (processors persist on bob, so no key ever leaves it).
#
#   BOB_PRIV=10.108.0.2 PROVIDERS="openai anthropic gemini" ITERS=10 ./bench-matrix.sh
#
# Prereq: both daemons up and paired; bob's serve.sh already ran once WITH the keys
# (so every processor is configured). This driver only switches the active worker.
set -uo pipefail
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export PATH="$HOME/axon/target/release:$PATH"
BOB_PRIV="${BOB_PRIV:?}"; PROVIDERS="${PROVIDERS:-openai anthropic gemini}"; ITERS="${ITERS:-10}"
KEY="$HOME/.ssh/bench_key"
SSH=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile="$HOME/.ssh/bench_known"
     -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-%h" -o ControlPersist=300 -o BatchMode=yes)
RENV='export XDG_RUNTIME_DIR=/run/user/$(id -u); export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus; export PATH=$HOME/axon/target/release:$PATH'
bobsh() { ssh "${SSH[@]}" "bench@$BOB_PRIV" "$RENV; $*"; }
bob()   { bobsh "axon $*"; }

SCEN_DIR="$HOME/axon/bench/scenarios"
SCENARIOS=$(ls "$SCEN_DIR"/*.json | xargs -n1 basename | sed 's/\.json$//')
now(){ date +%s.%N; }; el(){ awk -v a="$1" -v b="$2" 'BEGIN{printf "%.4f",b-a}'; }
TMP=$(mktemp -d)
bob whoami >/dev/null   # warm the control connection

for prov in $PROVIDERS; do
  echo "== provider: $prov =="
  bobsh "ROLE=performer SELF_IP=$BOB_PRIV PROVIDER=$prov bash \$HOME/axon/bench/serve.sh" >/dev/null 2>&1
  # wait for the restarted daemon
  for _ in $(seq 1 40); do bob whoami >/dev/null 2>&1 && break; sleep 0.25; done
  for scen in $SCENARIOS; do
    cell="$prov.$scen"; : > "$TMP/$cell"; ok=0
    for i in $(seq 1 "$ITERS"); do
      L0=$(now); good=1
      for k in 1 2 3 4 5; do if OUT=$(axon task send "$SCEN_DIR/$scen.json" 2>&1); then break; fi; sleep 0.5; done
      ID=$(printf '%s' "$OUT" | grep -oE 'task-[0-9A-Za-z_-]+' | head -1)
      [ -n "$ID" ] || { good=0; }
      if [ "$good" = 1 ]; then bob task approve "$ID" --processor "$prov" >/dev/null 2>&1 || good=0; fi
      if [ "$good" = 1 ]; then bob task run "$ID" >/dev/null 2>&1 || good=0; fi
      if [ "$good" = 1 ]; then for k in 1 2 3 4 5; do bob task deliver "$ID" >/dev/null 2>&1 && break; sleep 0.5; done; fi
      if [ "$good" = 1 ]; then echo "$(el "$L0" "$(now)")" >> "$TMP/$cell"; ok=$((ok+1)); fi
      printf '\r  %-22s %d/%d (ok %d)' "$cell" "$i" "$ITERS" "$ok"
    done
    echo "$ok" > "$TMP/$cell.ok"
    echo
  done
done

echo
printf '%-11s %-14s %5s %5s %8s %8s\n' provider scenario n ok p50 p95
for prov in $PROVIDERS; do for scen in $SCENARIOS; do
  cell="$prov.$scen"; ok=$(cat "$TMP/$cell.ok" 2>/dev/null || echo 0)
  read -r p50 p95 <<<"$(sort -n "$TMP/$cell" 2>/dev/null | awk '{a[NR]=$1} END{if(NR){printf "%.2f %.2f", a[int((NR-1)*0.5)+1], a[int((NR-1)*0.95)+1]} else printf "- -"}')"
  printf '%-11s %-14s %5s %5s %8s %8s\n' "$prov" "$scen" "$ITERS" "$ok" "$p50" "$p95"
done; done
echo "(loop seconds incl. the model call; ok = successful full round trips of $ITERS)"
rm -rf "$TMP"

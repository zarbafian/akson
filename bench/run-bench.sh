#!/usr/bin/env bash
# Drive the two-machine round trip from your laptop and time it. Pairs the two
# endpoints once, then runs send → approve → run → deliver for ITERS iterations and
# reports per-phase p50/p95/max plus the whole-loop total.
#
#   REQUESTER_SSH=alice PERFORMER_SSH=bob ALICE_IP=10.0.0.1 BOB_IP=10.0.0.2 \
#     ITERS=20 ./run-bench.sh
set -euo pipefail

REQUESTER_SSH="${REQUESTER_SSH:?ssh target for alice, e.g. user@1.2.3.4}"
PERFORMER_SSH="${PERFORMER_SSH:?ssh target for bob}"
ITERS="${ITERS:-20}"

# Persistent ssh connections so per-call channel overhead is ~ms, not a full
# handshake. (The fast phases still include a little ssh cost — for exact protocol
# timing, run this driver ON alice and ssh only to bob.)
SSHOPTS=(-o ControlMaster=auto -o ControlPath="$HOME/.ssh/akson-bench-%r@%h:%p" -o ControlPersist=120)
# Remote preamble: find the release binaries and this host's runtime dir.
PRE='export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}; export PATH=$HOME/.cargo/bin:$HOME/akson/target/release:$PATH'

ra() { ssh "${SSHOPTS[@]}" "$REQUESTER_SSH" "$PRE; akson $*"; }
pf() { ssh "${SSHOPTS[@]}" "$PERFORMER_SSH" "$PRE; akson $*"; }

echo "==> Warming ssh control connections…"
ra whoami >/dev/null; pf whoami >/dev/null

echo "==> Copying the task spec to alice…"
scp "${SSHOPTS[@]}" "$(dirname "$0")/task.json" "$REQUESTER_SSH:/tmp/akson-task.json" >/dev/null

echo "==> Pairing (once)…"
ra pair invite /tmp/inv.json >/dev/null
# Move alice's invitation to bob (out of band).
ssh "${SSHOPTS[@]}" "$REQUESTER_SSH" 'cat /tmp/inv.json' | \
  ssh "${SSHOPTS[@]}" "$PERFORMER_SSH" 'cat > /tmp/inv.json'
pf pair accept /tmp/inv.json >/dev/null
ra peer confirm bob   >/dev/null
pf peer confirm alice >/dev/null
echo "    paired: $(ra peer list | tr -d '\n')"

now() { date +%s.%N; }
dur() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", b-a}'; }
TMP="$(mktemp -d)"; : >"$TMP/send" >"$TMP/approve" >"$TMP/run" >"$TMP/deliver" >"$TMP/loop"

echo "==> $ITERS iterations…"
for i in $(seq 1 "$ITERS"); do
  L0=$(now)

  t=$(now); OUT=$(ra task send /tmp/akson-task.json); dur "$t" "$(now)" >>"$TMP/send"
  ID=$(printf '%s' "$OUT" | grep -oE 'task-[0-9A-Za-z_-]+' | head -1)
  [ -n "$ID" ] || { echo "could not parse task id from: $OUT" >&2; exit 1; }

  t=$(now); pf task approve "$ID" --processor gpt >/dev/null; dur "$t" "$(now)" >>"$TMP/approve"
  t=$(now); pf task run     "$ID"                >/dev/null; dur "$t" "$(now)" >>"$TMP/run"
  t=$(now); pf task deliver "$ID"                >/dev/null; dur "$t" "$(now)" >>"$TMP/deliver"

  dur "$L0" "$(now)" >>"$TMP/loop"
  printf '\r    %d/%d  (%s)' "$i" "$ITERS" "$ID"
done
echo

echo
printf '%-9s %8s %8s %8s %8s\n' phase p50 p95 max mean
stat() { # p50 p95 max mean of a column of seconds
  sort -n "$1" | awk '
    {a[NR]=$1; s+=$1}
    END{ n=NR; p50=a[int((n-1)*0.50)+1]; p95=a[int((n-1)*0.95)+1];
         printf "%8.3f %8.3f %8.3f %8.3f\n", p50, p95, a[n], s/n }'
}
for ph in send approve run deliver loop; do
  printf '%-9s ' "$ph"; stat "$TMP/$ph"
done
echo
echo "seconds. 'run' includes the model call; see bench/README.md to isolate it."
echo "delivered outcomes on alice: $(ra task outcomes | grep -c task- || true)"
rm -rf "$TMP"

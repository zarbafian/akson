#!/usr/bin/env bash
# Two agents, two components, many rounds — against REAL models.
#
# The hermetic version of this scenario lives in
# crates/aksond/tests/cooperation_e2e.rs, where both "agents" are pure functions.
# This is the same six-round loop with a model behind each side's worker:
#
#   alice owns the web UI          bob owns the API server
#     1. alice → bob   feature  "add GET /stats"
#     2. bob   → alice feature  "it's live, here's the shape — render it"
#     3. alice → bob   defect   "uptime arrives in ms, the shape says seconds"
#     4. bob   → alice feature  "added error_rate, render that too"
#     5. alice → bob   defect   "/stats 500s when users = 0"
#     6. bob   → alice confirm  "fixed — re-check against the shape"
#
# Round N+1's task inputs are the bytes round N delivered, read back with
# `akson task output`. Nothing else crosses: neither side ever sees the other's
# source, only the signed result of a delegated task.
#
# Unlike run-bench.sh this needs BOTH hosts to be performers — each must have a
# worker and a processor with a key, and each must pin the other's task-result
# key. serve.sh with ROLE=peer does that.
#
#   REQUESTER_SSH=bench@1.2.3.4 PERFORMER_SSH=bench@5.6.7.8 \
#     ALICE_IP=10.0.0.1 BOB_IP=10.0.0.2 ./cooperate.sh
set -euo pipefail

ALICE_SSH="${ALICE_SSH:?ssh target for alice (the web-UI agent)}"
BOB_SSH="${BOB_SSH:?ssh target for bob (the API agent)}"
PROCESSOR="${PROCESSOR:-openai}"

SSHOPTS=(-o ControlMaster=auto -o ControlPath="$HOME/.ssh/akson-coop-%r@%h:%p" -o ControlPersist=180)
PRE='export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}; export PATH=$HOME/.cargo/bin:$HOME/akson/target/release:$PATH'
alice() { ssh "${SSHOPTS[@]}" "$ALICE_SSH" "$PRE; akson $*"; }
bob()   { ssh "${SSHOPTS[@]}" "$BOB_SSH"   "$PRE; akson $*"; }
ssh_of() { case "$1" in alice) echo "$ALICE_SSH" ;; bob) echo "$BOB_SSH" ;; esac; }

# One full exchange. Echoes the response bytes the requester ends up holding —
# which is what the next round sends as its input.
round() { # round <n> <requester> <performer> <objective> <input-json>
  local n="$1" req="$2" perf="$3" objective="$4" input="$5"
  echo "== round $n: $req → $perf" >&2
  # The task spec is written on the requester's host, then signed and posted
  # from there — the private key never leaves it.
  jq -nc --arg p "$perf" --arg o "$objective" --arg i "$input" '{
    performer: $p,
    task_type: "https://akson.invalid/task/component-change/v1",
    objective: $o,
    inputs: [{ id: "context", media_type: "application/json", text: $i }],
    deliverables: [{ role: "response", media_type: "application/json" }],
    capabilities: ["respond", "read_supplied_inputs", "processor_use"],
    deadline: "2030-01-01T00:00:00Z",
    max_response_bytes: 8192
  }' | ssh "${SSHOPTS[@]}" "$(ssh_of "$req")" "cat > /tmp/akson-coop-task.json"

  local id
  id=$("$req" task send /tmp/akson-coop-task.json | grep -oE 'task-[0-9A-Za-z_-]+' | head -1)
  [ -n "$id" ] || { echo "round $n: no task id" >&2; exit 1; }

  # The performing side's operator approves, granting processor_use for this one
  # attempt; the confined worker then calls the model through the broker.
  "$perf" task approve "$id" --processor "$PROCESSOR" >/dev/null
  "$perf" task run     "$id" >/dev/null
  "$perf" task deliver "$id" >/dev/null
  # The requester reads back exactly the bytes the performer signed for.
  "$req" task output "$id" --role response
}

echo "==> Confirming both endpoints are paired both ways…"
alice peer list
bob peer list

OUT=$(round 1 alice bob \
  "Add GET /stats returning users and uptime_seconds. Reply ONLY with a JSON object: {\"endpoint\",\"fields\",\"uptime_unit_actually_sent\",\"safe_when_no_users\"}." \
  '{"component":"web-ui","needs":"a stats panel"}')

OUT=$(round 2 bob alice \
  "/stats is live. Wire the panel to these fields. Reply ONLY with JSON: {\"renders\",\"uptime_unit_received\",\"blank_when_no_users\"}." \
  "$OUT")

OUT=$(round 3 alice bob \
  "Defect: uptime arrives in milliseconds but the shape promises uptime_seconds. Fix it and re-publish the same JSON shape." \
  "$OUT")

OUT=$(round 4 bob alice \
  "The API also returns error_rate now. Render it too and report the same JSON shape." \
  "$OUT")

OUT=$(round 5 alice bob \
  "Defect: /stats returns 500 when users is 0 and the panel goes blank. Fix it and re-publish the same JSON shape." \
  "$OUT")

OUT=$(round 6 bob alice \
  "Both defects are fixed. Re-check the panel against the shape and report the same JSON." \
  "$OUT")

echo
echo "==> Final UI state:"
echo "$OUT" | jq . 2>/dev/null || echo "$OUT"
echo
echo "==> Signed outcomes recorded:"
echo "    alice: $(alice task outcomes | grep -c 'task-' || true) (rounds 1, 3, 5)"
echo "    bob:   $(bob   task outcomes | grep -c 'task-' || true) (rounds 2, 4, 6)"

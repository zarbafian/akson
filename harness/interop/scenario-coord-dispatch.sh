#!/usr/bin/env bash
# Interop scenario 2 — the coordination carrier (ADR-0016 §2, C4 slice 3).
#
# Two Akson endpoints in **separate processes**, over real TLS 1.3 mutual
# authentication: endpoint-a serves; endpoint-b imports a's token, introduces,
# then runs the whole coordination surface for real — `stage` (inert, on coord),
# `stage consent` (the operator's one-shot yes, on admin), `dispatch` (spend the
# receipt, commit, and CARRY the staged bytes to a in a coordination envelope).
#
# What the scenario proves that an in-process test cannot: the bytes crossed a
# process boundary and a socket, a's receive server verified the envelope's
# digests against the payload it actually read and the sender against the
# certificate it pinned at introduction, and b learned `sent` from a's
# acknowledgement rather than from its own optimism. The replay check at the end
# is the one-shot property over a real relationship.
#
# Runs locally with no containers (two processes) — the containerised form is
# harness/interop/compose.yaml. FOSS only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill "${SERVE_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "building akson-harness..."
cargo build -q -p akson-harness --manifest-path "$ROOT/Cargo.toml"

# Ask cargo where the binary went; `.cargo/config.toml`'s build.target-dir is
# one of several ways this repo redirects it (see scenario-pairing.sh).
cargo_target_dir() {
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then printf '%s\n' "$CARGO_TARGET_DIR"; return 0; fi
  cargo metadata --format-version 1 --no-deps --manifest-path "$ROOT/Cargo.toml" 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null &&
    return 0
  printf '%s\n' "$ROOT/target"
}
BIN="$(cargo_target_dir)/debug/akson-harness"
[ -x "$BIN" ] || { echo "scenario-coord-dispatch: no akson-harness binary at $BIN" >&2; exit 2; }

echo "endpoint-b: writing its identity token (the out-of-band exchange)"
"$BIN" token --seed 4 --token-out "$WORK/b.token"

echo "endpoint-a: importing endpoint-b's token + serving"
"$BIN" serve \
  --state "$WORK/a.db" --seed 3 \
  --host 127.0.0.1 --port 0 \
  --token-out "$WORK/a.token" --agent endpoint-a \
  --import "$WORK/b.token" --label endpoint-b \
  > "$WORK/a.log" 2>&1 &
SERVE_PID=$!

for _ in $(seq 1 50); do [ -s "$WORK/a.token" ] && break; sleep 0.1; done
sleep 0.3
cat "$WORK/a.log"

echo "endpoint-b: introducing, then staging + consenting + dispatching"
if "$BIN" coord-dispatch \
     --state "$WORK/b.db" --seed 4 \
     --token "$WORK/a.token" --agent endpoint-b --label endpoint-a \
     --payload "the coordination payload the operator consented to" \
     > "$WORK/b.log" 2>&1; then
  cat "$WORK/b.log"
else
  echo "SCENARIO FAILED" >&2
  cat "$WORK/b.log" >&2
  exit 1
fi

# The sender says `sent` only when the recipient echoed the exact staged digest,
# and a second execution key on the spent receipt must have been refused.
grep -q '^DISPATCHED sent ' "$WORK/b.log" || {
  echo "SCENARIO FAILED — the payload was not acknowledged by the peer" >&2; exit 1; }
grep -q '^REPLAY REFUSED urn:akson:error:consent-spent$' "$WORK/b.log" || {
  echo "SCENARIO FAILED — a spent consent receipt was not refused" >&2; exit 1; }

echo "SCENARIO OK — a consented coordination payload crossed two processes over mTLS,"
echo "  was digest- and sender-verified by the recipient, and the receipt is spent once"

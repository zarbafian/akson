#!/usr/bin/env bash
# Interop scenario 1 — first contact over identity tokens (design §8.2,
# ADR-0013/0015; the Layer-1 interop checkpoint). Two Akson endpoints run as
# separate processes: each writes its public identity token; endpoint-a imports
# endpoint-b's and serves its receive listener; endpoint-b imports endpoint-a's
# and dials the introduction — mutual verification against the imported roots,
# bound to the live TLS session, over real TLS 1.3.
#
# Runs locally with no containers (two processes) — the containerised form is
# harness/interop/compose.yaml. FOSS only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill "${SERVE_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "building akson-harness..."
cargo build -q -p akson-harness --manifest-path "$ROOT/Cargo.toml"
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/akson-harness"

echo "endpoint-b: writing its identity token (the out-of-band exchange)"
"$BIN" token --seed 2 --token-out "$WORK/b.token"

echo "endpoint-a: importing endpoint-b's token + serving"
"$BIN" serve \
  --state "$WORK/a.db" --seed 1 \
  --host 127.0.0.1 --port 0 \
  --token-out "$WORK/a.token" --agent endpoint-a \
  --import "$WORK/b.token" --label endpoint-b \
  > "$WORK/a.log" 2>&1 &
SERVE_PID=$!

# Wait for the token to be written with the live port.
for _ in $(seq 1 50); do [ -s "$WORK/a.token" ] && break; sleep 0.1; done
sleep 0.3
cat "$WORK/a.log"

echo "endpoint-b: introducing"
if "$BIN" introduce --state "$WORK/b.db" --seed 2 --token "$WORK/a.token" --agent endpoint-b --label endpoint-a; then
  echo "SCENARIO OK — two endpoints introduced over mTLS"
else
  echo "SCENARIO FAILED" >&2
  exit 1
fi

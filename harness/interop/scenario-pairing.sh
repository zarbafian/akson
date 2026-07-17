#!/usr/bin/env bash
# Interop scenario 1 — pairing over mTLS (design §8.2, the Layer-1 interop
# checkpoint). Two Axon endpoints run as separate processes: endpoint-a mints an
# invitation and serves the bootstrap endpoint; endpoint-b reads the invitation
# and pairs, pinning endpoint-a over real TLS 1.3 with certificate pinning.
#
# Runs locally with no containers (two processes) — the containerised form is
# harness/interop/compose.yaml. FOSS only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill "${SERVE_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "building axon-harness..."
cargo build -q -p axon-harness --manifest-path "$ROOT/Cargo.toml"
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/axon-harness"

echo "endpoint-a: serving + minting invitation"
"$BIN" serve \
  --state "$WORK/a.db" --seed 1 \
  --host 127.0.0.1 --port 0 \
  --invitation-out "$WORK/invitation.json" --agent endpoint-a \
  > "$WORK/a.log" 2>&1 &
SERVE_PID=$!

# Wait for the invitation to be written and the endpoint to be listening.
for _ in $(seq 1 50); do [ -s "$WORK/invitation.json" ] && break; sleep 0.1; done
sleep 0.3
cat "$WORK/a.log"

echo "endpoint-b: pairing"
if "$BIN" pair --state "$WORK/b.db" --seed 2 --invitation "$WORK/invitation.json" --agent endpoint-b; then
  echo "SCENARIO OK — two endpoints paired over mTLS"
else
  echo "SCENARIO FAILED" >&2
  exit 1
fi

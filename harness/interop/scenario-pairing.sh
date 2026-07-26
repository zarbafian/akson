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

# Where cargo actually put it. CARGO_TARGET_DIR is only one of the ways a build
# gets redirected — `.cargo/config.toml`'s `build.target-dir` is another, and
# this repo uses it to keep targets off the root filesystem. Guessing
# "$ROOT/target" made this script fail looking for a binary cargo never wrote
# there, so ask cargo instead of assuming.
cargo_target_dir() {
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then printf '%s\n' "$CARGO_TARGET_DIR"; return 0; fi
  cargo metadata --format-version 1 --no-deps --manifest-path "$ROOT/Cargo.toml" 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null &&
    return 0
  printf '%s\n' "$ROOT/target"
}
BIN="$(cargo_target_dir)/debug/akson-harness"
[ -x "$BIN" ] || { echo "scenario-pairing: no akson-harness binary at $BIN" >&2; exit 2; }

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

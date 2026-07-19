#!/usr/bin/env bash
# Start an axon endpoint for the bench under a delegated cgroup, and (for the
# performer) configure the OpenAI processor + credential.
#
#   ROLE=performer SELF_IP=10.0.0.2 OPENAI_API_KEY=sk-... MODEL=gpt-4o-mini ./serve.sh
#   ROLE=requester SELF_IP=10.0.0.1 ./serve.sh
#
# The key is stored ONLY here (sealed) and injected by the daemon at call time; the
# confined adapter never sees it.
set -euo pipefail

ROLE="${ROLE:?set ROLE=requester|performer}"
SELF_IP="${SELF_IP:?set SELF_IP to the reachable VPC IP of this host}"
MODEL="${MODEL:-gpt-4o-mini}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release"
export PATH="$HOME/.cargo/bin:$BIN:$PATH"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
# systemd-run --user over a non-interactive ssh needs the user bus address.
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"

case "$ROLE" in
  requester) AGENT=alice; ISSUER=orgA; RECV=18443; PAIRP=19443 ;;
  performer) AGENT=bob;   ISSUER=orgB; RECV=18444; PAIRP=19444 ;;
  *) echo "ROLE must be requester|performer" >&2; exit 2 ;;
esac

DATA="$HOME/.axon-bench-$ROLE"
UNIT="axon-$ROLE"

# Env the daemon reads at startup (DaemonConfig::from_env). Bind + advertise the
# reachable (VPC) IP — AXON_PAIR_ADDR is both the bind address and the endpoint the
# invitation tells the peer to dial, so it must not be 0.0.0.0. (mTLS pins the cert
# fingerprint, not the hostname, so a raw IP is fine.)
ENV=(
  "--setenv=AXON_DATA_DIR=$DATA"
  "--setenv=AXON_ISSUER=$ISSUER"
  "--setenv=AXON_AGENT=$AGENT"
  "--setenv=AXON_INTERFACE_URL=https://$SELF_IP:$RECV/a2a"
  "--setenv=AXON_RECEIVE_ADDR=$SELF_IP:$RECV"
  "--setenv=AXON_PAIR_ADDR=$SELF_IP:$PAIRP"
)
if [ "$ROLE" = performer ]; then
  # Run the adapter DIRECTLY (no shell) under the strict adapter seccomp profile.
  ENV+=("--setenv=AXON_WORKER_EXEC=$BIN/axon-adapter-openai --processor gpt --model $MODEL")
fi

echo "==> Starting $UNIT (delegated cgroup) as $ISSUER/$AGENT on $SELF_IP:$RECV…"
# Replace any previous instance (idempotent restart) before claiming the unit name.
systemctl --user stop "$UNIT" 2>/dev/null || true
systemctl --user reset-failed "$UNIT" 2>/dev/null || true
# A transient user service with Delegate=yes gives axond the cgroup v2 subtree that
# `task run` needs; without it the daemon fails closed (503) rather than run unconfined.
if ! systemd-run --user --unit="$UNIT" -p Delegate=yes --collect \
      "${ENV[@]}" "$BIN/axond" serve; then
  echo "!! systemd-run --user failed (no user manager / linger?)." >&2
  echo "   Enable it: sudo loginctl enable-linger $USER ; then re-run." >&2
  echo "   (Running without delegation would make 'task run' 503 on the performer.)" >&2
  exit 1
fi

# Wait for the admin control socket so the CLI can talk to the daemon.
SOCK="$XDG_RUNTIME_DIR/axon/admin.sock"
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket did not appear: $SOCK" >&2; exit 1; }

if [ "$ROLE" = performer ]; then
  : "${OPENAI_API_KEY:?set OPENAI_API_KEY for the performer}"
  echo "==> Configuring the OpenAI processor 'gpt' ($MODEL)…"
  # `ca` = validate api.openai.com against the CA roots (no pin, real egress).
  axon processor add gpt openai api.openai.com 443 ca \
    --path /v1/chat/completions --auth bearer
  axon processor credential gpt "$OPENAI_API_KEY"
fi

echo "==> Up:"
axon whoami
echo "   logs: journalctl --user -u $UNIT -f"

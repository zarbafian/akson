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

case "$ROLE" in
  requester) AGENT=alice; ISSUER=orgA; RECV=18443; PAIRP=19443 ;;
  performer) AGENT=bob;   ISSUER=orgB; RECV=18444; PAIRP=19444 ;;
  *) echo "ROLE must be requester|performer" >&2; exit 2 ;;
esac

DATA="$HOME/.axon-bench-$ROLE"
UNIT="axon-$ROLE"

# Env the daemon reads at startup (DaemonConfig::from_env). Bind on all interfaces;
# advertise the reachable IP (mTLS pins the cert fingerprint, not the hostname).
ENV=(
  "-E" "AXON_DATA_DIR=$DATA"
  "-E" "AXON_ISSUER=$ISSUER"
  "-E" "AXON_AGENT=$AGENT"
  "-E" "AXON_INTERFACE_URL=https://$SELF_IP:$RECV/a2a"
  "-E" "AXON_RECEIVE_ADDR=0.0.0.0:$RECV"
  "-E" "AXON_PAIR_ADDR=0.0.0.0:$PAIRP"
)
if [ "$ROLE" = performer ]; then
  # Run the adapter DIRECTLY (no shell) under the strict adapter seccomp profile.
  ENV+=("-E" "AXON_WORKER_EXEC=$BIN/axon-adapter-openai --processor gpt --model $MODEL")
fi

echo "==> Starting $UNIT (delegated cgroup) as $ISSUER/$AGENT on $SELF_IP:$RECV…"
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

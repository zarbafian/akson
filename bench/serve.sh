#!/usr/bin/env bash
# Start an akson endpoint for the bench under a delegated cgroup. For the performer,
# configure a processor for every model back-end whose API key is present, and run
# the adapter selected by PROVIDER.
#
#   # requester (no keys):
#   ROLE=requester SELF_IP=10.0.0.1 ./serve.sh
#   # performer, run the OpenAI adapter, with all keys that are set configured:
#   ROLE=performer SELF_IP=10.0.0.2 PROVIDER=openai \
#     OPENAI_API_KEY=sk-… ANTHROPIC_API_KEY=sk-ant-… GEMINI_API_KEY=… ./serve.sh
#   # switch the performer's worker to Claude (re-run; processors persist):
#   ROLE=performer SELF_IP=10.0.0.2 PROVIDER=anthropic ANTHROPIC_API_KEY=… ./serve.sh
#
# Each key is stored ONLY on the performer (sealed) and injected by the daemon at
# call time; the confined adapter never sees it.
set -uo pipefail

ROLE="${ROLE:?set ROLE=requester|performer}"
SELF_IP="${SELF_IP:?set SELF_IP to the reachable VPC IP of this host}"
PROVIDER="${PROVIDER:-openai}"
OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o-mini}"
ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-claude-haiku-4-5-20251001}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-3.5-flash}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release"
export PATH="$HOME/.cargo/bin:$BIN:$PATH"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"

# requester/performer are the one-way bench roles. alice/bob are the two-way
# cooperation roles (cooperate.sh): same identities and ports, but BOTH get a
# worker, because each side takes its turn performing.
case "$ROLE" in
  requester) AGENT=alice; ISSUER=orgA; RECV=18443; WORKER=0 ;;
  performer) AGENT=bob;   ISSUER=orgB; RECV=18444; WORKER=1 ;;
  alice)     AGENT=alice; ISSUER=orgA; RECV=18443; WORKER=1 ;;
  bob)       AGENT=bob;   ISSUER=orgB; RECV=18444; WORKER=1 ;;
  *) echo "ROLE must be requester|performer|alice|bob" >&2; exit 2 ;;
esac
DATA="$HOME/.akson-bench-$ROLE"
UNIT="akson-$ROLE"

# The worker command for the selected provider (runs directly, no shell, under the
# strict adapter seccomp profile). The processor id == the provider name.
worker_exec() {
  case "$1" in
    openai)    echo "$BIN/akson-adapter-openai --processor openai --model $OPENAI_MODEL" ;;
    anthropic) echo "$BIN/akson-adapter-anthropic --processor anthropic --model $ANTHROPIC_MODEL" ;;
    gemini)    echo "$BIN/akson-adapter-gemini --processor gemini" ;;
    *) echo "unknown PROVIDER '$1' (openai|anthropic|gemini)" >&2; exit 2 ;;
  esac
}

ENV=(
  "--setenv=AKSON_DATA_DIR=$DATA"
  "--setenv=AKSON_ISSUER=$ISSUER"
  "--setenv=AKSON_AGENT=$AGENT"
  "--setenv=AKSON_INTERFACE_URL=https://$SELF_IP:$RECV/a2a"
  "--setenv=AKSON_RECEIVE_ADDR=$SELF_IP:$RECV"
)
[ "$WORKER" = 1 ] && ENV+=("--setenv=AKSON_WORKER_EXEC=$(worker_exec "$PROVIDER")")

echo "==> Starting $UNIT (delegated cgroup) as $ISSUER/$AGENT on $SELF_IP:$RECV${ROLE:+ [provider=$PROVIDER]}…"
systemctl --user stop "$UNIT" 2>/dev/null || true
systemctl --user reset-failed "$UNIT" 2>/dev/null || true
if ! systemd-run --user --unit="$UNIT" -p Delegate=yes --collect "${ENV[@]}" "$BIN/aksond" serve; then
  echo "!! systemd-run --user failed (no user manager / linger?). Try: sudo loginctl enable-linger $USER" >&2
  exit 1
fi

SOCK="$XDG_RUNTIME_DIR/akson/admin.sock"
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket did not appear: $SOCK" >&2; exit 1; }

if [ "$WORKER" = 1 ]; then
  # Configure a processor for every back-end whose key is present (`ca` = validate
  # the public endpoint against the CA roots). Re-adding is idempotent.
  if [ -n "${OPENAI_API_KEY:-}" ]; then
    akson processor add openai openai api.openai.com 443 ca --path /v1/chat/completions --auth bearer
    akson processor credential openai "$OPENAI_API_KEY"; echo "   + openai ($OPENAI_MODEL)"
  fi
  if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    akson processor add anthropic anthropic api.anthropic.com 443 ca \
      --path /v1/messages --auth x-api-key --header anthropic-version:2023-06-01
    akson processor credential anthropic "$ANTHROPIC_API_KEY"; echo "   + anthropic ($ANTHROPIC_MODEL)"
  fi
  if [ -n "${GEMINI_API_KEY:-}" ]; then
    akson processor add gemini google generativelanguage.googleapis.com 443 ca \
      --path "/v1beta/models/$GEMINI_MODEL:generateContent" --auth x-goog-api-key
    akson processor credential gemini "$GEMINI_API_KEY"; echo "   + gemini ($GEMINI_MODEL)"
  fi
  # Guard: the selected worker's processor must have a key.
  case "$PROVIDER" in
    openai)    [ -n "${OPENAI_API_KEY:-}" ]    || echo "!! PROVIDER=openai but OPENAI_API_KEY unset" >&2 ;;
    anthropic) [ -n "${ANTHROPIC_API_KEY:-}" ] || echo "!! PROVIDER=anthropic but ANTHROPIC_API_KEY unset" >&2 ;;
    gemini)    [ -n "${GEMINI_API_KEY:-}" ]    || echo "!! PROVIDER=gemini but GEMINI_API_KEY unset" >&2 ;;
  esac
fi

echo "==> Up:"; akson whoami | grep -E 'agent:|interface:'
echo "   logs: journalctl --user -u $UNIT -f"

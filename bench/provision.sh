#!/usr/bin/env bash
# Prepare a droplet to run an axon endpoint: install deps, build the binaries, and
# report whether the host can run the confined-worker sandbox. Idempotent.
#
# Run from the repo's bench/ directory on the droplet (the repo rsync'd to ~/axon):
#   cd ~/axon/bench && ./provision.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

echo "==> Installing OS packages (bwrap, build tools)…"
if command -v apt-get >/dev/null; then
  sudo apt-get update -qq
  # bubblewrap = the sandbox launcher; the rest build the Rust workspace.
  sudo apt-get install -y -qq bubblewrap build-essential pkg-config libssl-dev git curl
fi

if ! command -v cargo >/dev/null; then
  echo "==> Installing Rust toolchain…"
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> Building axond, axon CLI, and the OpenAI adapter (release)…"
# Release build: this is a latency bench, so don't measure debug overhead.
CARGO_INCREMENTAL=0 cargo build --release -p axond -p axon-cli -p axon-adapter-openai

BIN="$REPO/target/release"
echo "    built: $BIN/{axond,axon,axon-adapter-openai}"

echo
echo "==> Sandbox readiness (axon doctor):"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" "$BIN/axon" doctor || true
echo
echo "If doctor reports userns/cgroup problems on the PERFORMER host, see bench/README.md"
echo "(Ubuntu 24.04: sysctl kernel.apparmor_restrict_unprivileged_userns=0; enable-linger)."

#!/usr/bin/env bash
# On-demand local validation — the CI replacement. Runs everything that can be
# checked without special privileges, then the live namespace-isolation checks
# when unprivileged user namespaces are available (and prints exactly how to
# enable them, for one run, when they are not).
#
# Usage:  ./harness/run-checks.sh            # everything runnable now
#         FAST=1 ./harness/run-checks.sh     # skip clippy for a quicker loop
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0
step() { printf '\n=== %s ===\n' "$*"; }
run()  { "$@" || fail=1; }

step "format"
run cargo fmt --all --check

if [ "${FAST:-0}" != "1" ]; then
  step "clippy (deny warnings)"
  run cargo clippy --workspace --all-targets -- -D warnings
fi

step "unit + integration tests (incl. seccomp + Landlock enforcement)"
run cargo test --workspace

step "golden-vector cross-check (Rust vs Python)"
if [ -x xcheck/.venv/bin/python ]; then
  run xcheck/.venv/bin/python xcheck/run.py spec/vectors
else
  run python3 xcheck/run.py spec/vectors
fi

step "interop: pairing over mTLS (two processes, no containers)"
run bash harness/interop/scenario-pairing.sh

step "public-processor CA path (needs outbound TCP 443)"
if timeout 8 bash -c 'exec 3<>/dev/tcp/example.com/443' 2>/dev/null; then
  echo "outbound TLS reachable — validating the CA-validated broker transport"
  # Network-gated (#[ignore]): the pure-Rust provider must accept a real CA chain
  # and reject an untrusted self-signed server.
  run cargo test -p axon-transport --test ca_tls -- --ignored
else
  echo "SKIPPED — no outbound TCP 443 (the pinned-processor path is covered by the"
  echo "  default gate; the CA path validates in CI, which has network)."
fi

step "live namespace isolation (needs unprivileged user namespaces)"
if unshare --user --map-root-user true 2>/dev/null; then
  echo "user namespaces available — running the live sandbox checklist"
  # Live namespace/mount/exec tests are marked #[ignore]; run them explicitly.
  run cargo test -p axon-sandbox -- --ignored
  # The clean-worker end-to-end demo (work order → sandbox → gate) also needs a
  # delegated cgroup; it skips its cgroup step gracefully if none is present.
  run cargo test -p axon-harness --test clean_worker_e2e -- --ignored --nocapture
  # The daemon-level worker run (receive → approve → run in sandbox → manifest)
  # also skips gracefully without a delegated cgroup.
  run cargo test -p axond --test receive_e2e the_daemon_runs_the_approved -- --ignored --nocapture
  # The full gated-via-broker chain: the real OpenAI adapter binary, confined,
  # reviewing via a mock model reached only through the broker.
  run cargo build -p axon-adapter-openai
  run cargo test -p axond --test receive_e2e the_openai_adapter -- --ignored --nocapture
else
  restrict="$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo '?')"
  cat <<EOF
SKIPPED — unprivileged user namespaces are blocked on this host
  (kernel.apparmor_restrict_unprivileged_userns=$restrict).
  seccomp and Landlock were still validated above (they need no user namespace).
  To validate the namespace/mount path too, enable userns for one run and restore:

    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
    ./harness/run-checks.sh
    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
EOF
fi

printf '\n'
if [ "$fail" -eq 0 ]; then
  echo "ALL ON-DEMAND CHECKS PASSED"
else
  echo "SOME CHECKS FAILED"
  exit 1
fi

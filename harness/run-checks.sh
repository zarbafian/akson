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
skipped=0
step() { printf '\n=== %s ===\n' "$*"; }
run()  { "$@" || fail=1; }

step "format"
run cargo fmt --all --check

step "docs: the site's claims vs. the code and the specs"
# docs/ hand-copies operation names, counts, envelope members, timeouts and the
# version out of the sources. That is how a false claim survives a change: the
# source moves, the prose does not, and nothing fails. This regenerates every
# mechanically-derivable claim from crates/ and spec/ and compares, then resolves
# every internal link and checks each page's tags balance.
# Pure stdlib, so a missing interpreter is the only way it cannot run.
if command -v python3 >/dev/null 2>&1; then
  run python3 harness/check-docs.py
else
  skipped=$((skipped + 1))
  cat <<'EOF'
SKIPPED — python3 is not on this host, so the site cannot be held to the code.
  The claims on docs/ are hand-written prose next to generated blocks; without
  this check a source change that the pages did not follow ships silently.
  It needs no packages at all — any python3 will do:

    sudo apt install -y python3
EOF
fi

if [ "${FAST:-0}" != "1" ]; then
  step "clippy (deny warnings)"
  run cargo clippy --workspace --all-targets -- -D warnings
fi

step "unit + integration tests (incl. seccomp + Landlock enforcement)"
run cargo test --workspace

step "golden-vector cross-check (Rust vs Python)"
# The point of xcheck is an INDEPENDENT rederivation, so it uses the third-party
# rfc8785 canonicalizer rather than anything in this repo. That makes it a real
# dependency: without it there is no independent check to run, and pretending
# otherwise by substituting our own canonicalizer would defeat the exercise.
# A missing dev dependency is an environment gap, not a failed check — say so
# loudly and keep the distinction, but still fail if it runs and disagrees.
if [ -x xcheck/.venv/bin/python ]; then
  run xcheck/.venv/bin/python xcheck/run.py spec/vectors
elif python3 -c 'import rfc8785' 2>/dev/null; then
  run python3 xcheck/run.py spec/vectors
else
  skipped=$((skipped + 1))
  cat <<'EOF'
SKIPPED — the rfc8785 canonicalizer is not installed, so the independent
  rederivation cannot run on this host. The vectors are still enforced by the
  Rust side above; what is missing is the second, independent opinion.
  CI installs it. To run it here:

    sudo apt install -y python3-venv        # this host has no ensurepip
    python3 -m venv xcheck/.venv
    xcheck/.venv/bin/pip install rfc8785 cryptography
EOF
fi

step "interop: pairing over mTLS (two processes, no containers)"
run bash harness/interop/scenario-pairing.sh

step "interop: coordination dispatch over mTLS (two processes)"
run bash harness/interop/scenario-coord-dispatch.sh

step "public-processor CA path (needs outbound TCP 443)"
if timeout 8 bash -c 'exec 3<>/dev/tcp/example.com/443' 2>/dev/null; then
  echo "outbound TLS reachable — validating the CA-validated broker transport"
  # Network-gated (#[ignore]): the pure-Rust provider must accept a real CA chain
  # and reject an untrusted self-signed server.
  run cargo test -p akson-transport --test ca_tls -- --ignored
else
  skipped=$((skipped + 1))
  echo "SKIPPED — no outbound TCP 443 (the pinned-processor path is covered by the"
  echo "  default gate; the CA path validates in CI, which has network)."
fi

step "live namespace isolation (needs unprivileged user namespaces)"
if unshare --user --map-root-user true 2>/dev/null; then
  echo "user namespaces available — running the live sandbox checklist"
  # Live namespace/mount/exec tests are marked #[ignore]; run them explicitly.
  run cargo test -p akson-sandbox -- --ignored
  # The clean-worker end-to-end demo (work order → sandbox → gate) also needs a
  # delegated cgroup; it skips its cgroup step gracefully if none is present.
  run cargo test -p akson-harness --test clean_worker_e2e -- --ignored --nocapture
  # The daemon-level worker run (receive → approve → run in sandbox → manifest)
  # also skips gracefully without a delegated cgroup.
  run cargo test -p aksond --test receive_e2e the_daemon_runs_the_approved -- --ignored --nocapture
  # The full gated-via-broker chain: the real OpenAI adapter binary, confined,
  # reviewing via a mock model reached only through the broker.
  run cargo build -p akson-adapter-openai
  run cargo test -p aksond --test receive_e2e the_openai_adapter -- --ignored --nocapture
else
  skipped=$((skipped + 1))
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
  if [ "$skipped" -eq 0 ]; then
    echo "ALL ON-DEMAND CHECKS PASSED"
  else
    # Deliberately not the same sentence as a clean run: a green line that hides
    # a skipped check teaches people to stop reading the output.
    echo "CHECKS PASSED, WITH $skipped SKIPPED — see the SKIPPED block(s) above"
  fi
else
  echo "SOME CHECKS FAILED"
  exit 1
fi

#!/usr/bin/env bash
# Run a command from inside the delegated cgroup subtree, when there is one.
#
# harness/ci/delegate-cgroup.sh creates the subtree; it persists on cgroupfs for
# the rest of the job, but cgroup *membership* does not — each workflow step is a
# fresh process forked by the runner, inside the runner's own cgroup. So each
# step that needs cgroup confinement joins the subtree itself, here, and the test
# binary it then spawns inherits that membership.
#
# No subtree (or no way into it) means the command still runs: the tests that
# need one are skipped by name via delegate-cgroup.sh's `test_skip_args`, and the
# e2e demos self-skip their confined half. This script never decides that.
#
# Usage: harness/ci/in-cgroup.sh cargo test -p akson-sandbox --locked -- --ignored
set -uo pipefail

subtree="${AKSON_CGROUP_SUBTREE:-${AKSON_CGROUP_ROOT:-/sys/fs/cgroup}/akson-ci}"
job="$subtree/job"

if [ -d "$job" ]; then
	# Moving *this shell* is what matters: `exec` below keeps this pid, and the
	# test binary it becomes inherits the membership.
	if [ "$(id -u)" = 0 ] || [ -w "$job/cgroup.procs" ]; then
		echo $$ >"$job/cgroup.procs"
	else
		sudo -n sh -c "echo $$ > '$job/cgroup.procs'"
	fi || {
		# The subtree exists, so delegate-cgroup.sh proved this works and the
		# cgroup-dependent tests are about to run for real. Failing here names
		# the cause; failing later would surface as NoDelegatedSubtree.
		echo "::error::cannot join $job — the delegated subtree exists but this step could not enter it" >&2
		exit 1
	}
	echo "cgroup: $(grep -m1 '^0::' /proc/self/cgroup || echo unknown)"
else
	echo "cgroup: no delegated subtree at $subtree — running without it"
fi

exec "$@"

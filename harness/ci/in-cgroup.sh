#!/usr/bin/env bash
# Run a command from inside the delegated cgroup subtree, when this step can get
# into one.
#
# harness/ci/delegate-cgroup.sh creates the subtree; it persists on cgroupfs for
# the rest of the job, but cgroup *membership* does not — each workflow step is a
# fresh process forked by the runner, inside the runner's own cgroup. So each
# step joins the subtree itself, here; `exec` keeps this pid, so the test binary
# inherits both the membership and the uid.
#
# Joining can need sudo even when the destination is ours. cgroup v2 delegation
# containment requires write access to the cgroup.procs of the **common
# ancestor** of source and destination; on a runner the step starts inside the
# runner service's own cgroup, so that ancestor is at or near the hierarchy root
# and stays root-owned however much we chown beneath it. `[ -w ... ]` cannot see
# this — access(2) reads permission bits, not the kernel's containment rule —
# which is exactly how the first version of this script failed: it saw a writable
# cgroup.procs, wrote to it unprivileged, and got EACCES.
#
# Moving the pid is the ONLY privileged act. Everything the tests then do —
# create leaf cgroups, set memory.max/pids.max, confine a process — happens as
# the job user, which is the property they exist to demonstrate.
#
# If it cannot be joined at all, that is an environment gap, not a failure: the
# cgroup-dependent tests are skipped by name (loudly, via isolation-env.sh) and
# the command still runs for everything else.
#
# Usage: harness/ci/in-cgroup.sh cargo test -p akson-sandbox --locked -- --ignored
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=harness/ci/isolation-env.sh
. "$here/isolation-env.sh"

subtree="${AKSON_CGROUP_SUBTREE:-${AKSON_CGROUP_ROOT:-/sys/fs/cgroup}/akson-ci}"
job="$subtree/job"
joined=no

# A pass must mean *unprivileged* confinement. Root can create cgroups and set
# ceilings whatever the delegation says, so a green tick as root establishes
# nothing — the tests assert this too (akson-sandbox), and this keeps the job
# from reaching them in the first place.
if [ "$(id -u)" = 0 ]; then
	isolation_report_skip cgroup "this step runs as root, so a pass would not demonstrate unprivileged confinement"
elif [ -d "$job" ]; then
	# Unprivileged first (a systemd user session owns the common ancestor, so a
	# developer's machine needs no sudo), then sudo, which a runner grants.
	if (echo $$ >"$job/cgroup.procs") 2>/dev/null; then
		joined=unprivileged
	elif sudo -n sh -c "echo $$ > '$job/cgroup.procs'" 2>/dev/null; then
		joined=sudo
	fi

	if [ "$joined" = no ]; then
		echo "could not enter $job; the delegated subtree exists but this step cannot join it:"
		isolation_cgroup_layout "$job"
		# Report once per job, not once per wrapped step.
		marker="${RUNNER_TEMP:-/tmp}/akson-cgroup-join-skip"
		if [ ! -e "$marker" ]; then
			isolation_report_skip cgroup "the delegated subtree exists but no step can enter it (cgroup v2 delegation containment: the common ancestor's cgroup.procs is not writable, and sudo did not work either)"
			: >"$marker"
		fi
	else
		echo "cgroup: joined via $joined — $(grep -m1 '^0::' /proc/self/cgroup || echo unknown)"
	fi
else
	# delegate-cgroup.sh already reported this one; do not repeat the block.
	echo "cgroup: no delegated subtree at $subtree — running without it"
fi

# Not in a delegated cgroup: leave the tests that need one visibly unrun. The
# caller supplies the flags (they come from isolation-env.sh via the delegation
# step's output), so the test names live in exactly one place.
if [ "$joined" = no ]; then
	# shellcheck disable=SC2086  # a flag list, deliberately word-split
	set -- "$@" ${AKSON_CGROUP_SKIP_ARGS:-}
fi

echo "+ $*"
exec "$@"

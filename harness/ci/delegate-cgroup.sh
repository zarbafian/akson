#!/usr/bin/env bash
# Hand this job a cgroup v2 subtree it owns — or say, loudly, that it has none.
#
# What §13.1 needs. `CgroupScope::create()` looks *upward* from the calling
# process's own cgroup for the nearest ancestor that both lists `memory` and
# `pids` in `cgroup.subtree_control` and is writable by this user. That is a
# delegated subtree — the shape `systemd Delegate=yes` produces, and the reason
# the cgroup tests already pass in a developer's systemd user session.
#
# A GitHub runner has none: every step runs inside the runner service's
# root-owned cgroup, so the search walks to the hierarchy root and stops
# (`CgroupError::NoDelegatedSubtree` — the failure this script exists to fix).
# Runners do grant passwordless sudo, so carve a subtree out and chown it to the
# job user: delegation, done by hand instead of by systemd.
#
# This never fails the job. A missing kernel capability is an environment gap,
# not a failed check — the same rule harness/run-checks.sh follows, routed here
# through isolation-env.sh so every gap in this job produces the same visible
# skip whenever it is found. It reports:
#
#   delegated=true|false   did we get one?
#   skip_args=...          the libtest `--skip` flags for the tests that need a
#                          subtree. ALWAYS the same string, even on success:
#                          whether they get used is decided at the moment of
#                          truth by harness/ci/in-cgroup.sh, because a subtree
#                          that builds cleanly here can still refuse to be
#                          entered there, and that discovery must be able to
#                          reach the skip path too.
#
# Local dry run — no sudo, borrowing the systemd user session's own delegated
# subtree as the stand-in hierarchy root:
#
#   AKSON_CGROUP_ROOT=/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice \
#     harness/ci/delegate-cgroup.sh
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=harness/ci/isolation-env.sh
. "$here/isolation-env.sh"

# The hierarchy root to carve the subtree out of, and the subtree itself. Both
# are overridable so the whole script can be exercised without root (above).
root="${AKSON_CGROUP_ROOT:-/sys/fs/cgroup}"
subtree="${AKSON_CGROUP_SUBTREE:-$root/akson-ci}"
job="$subtree/job"

give_up() {
	isolation_emit delegated false
	isolation_emit skip_args "$(isolation_skip_args cgroup)"
	isolation_report_skip cgroup "$1"
	exit 0
}

# A privileged step: try as ourselves first — a subtree we already own needs no
# sudo, which is what a systemd user session hands a developer — then fall back
# to the passwordless sudo a GitHub runner hands the job.
maybe_root() {
	"$@" 2>/dev/null && return 0
	[ "$(id -u)" = 0 ] && return 1
	sudo -n "$@" 2>/dev/null
}

[ -e "$root/cgroup.controllers" ] || give_up "no cgroup v2 unified hierarchy at $root"

# 1. The hierarchy root must be willing to hand memory+pids down to a child.
#    (The root cgroup is exempt from the no-internal-process rule, so this is
#    legal even though it holds every process on the machine.)
maybe_root sh -c "echo '+memory +pids' > '$root/cgroup.subtree_control'"
for c in memory pids; do
	grep -qw "$c" "$root/cgroup.subtree_control" ||
		give_up "$root does not delegate the $c controller"
done

# 2. The subtree. Enable its controllers while it is still processless — cgroup
#    v2 forbids that write once a cgroup holds processes, which is why the job's
#    processes live in the `job` leaf below it and never in the subtree itself.
maybe_root mkdir -p "$subtree" || give_up "cannot create $subtree"
maybe_root sh -c "echo '+memory +pids' > '$subtree/cgroup.subtree_control'" ||
	give_up "cannot enable controllers on $subtree"
maybe_root sh -c "echo '+cpu' > '$subtree/cgroup.subtree_control'" || true
maybe_root mkdir -p "$job" || give_up "cannot create $job"
maybe_root chown -R "$(id -u):$(id -g)" "$subtree" || give_up "cannot chown $subtree"

# 3. Prove it, as the job user, by doing exactly what CgroupScope::create does:
#    a leaf, its memory and pids ceilings, a process inside it, and removal.
probe="$subtree/probe-$$"
mkdir "$probe" || give_up "cannot create a leaf cgroup as $(id -un)"
echo $((64 * 1024 * 1024)) >"$probe/memory.max" || give_up "cannot set memory.max as $(id -un)"
echo 16 >"$probe/pids.max" || give_up "cannot set pids.max as $(id -un)"
sleep 30 &
probe_pid=$!
echo "$probe_pid" >"$probe/cgroup.procs" || {
	kill "$probe_pid" 2>/dev/null
	give_up "cannot place a process in a leaf cgroup as $(id -un)"
}
grep -qx "$probe_pid" "$probe/cgroup.procs" || {
	kill "$probe_pid" 2>/dev/null
	give_up "a placed process did not appear in cgroup.procs"
}
kill "$probe_pid" 2>/dev/null
wait "$probe_pid" 2>/dev/null
rmdir "$probe" 2>/dev/null || true

# 4. And prove the join the test steps actually perform — the same way, in the
#    same order in-cgroup.sh does it. The first version of this script probed
#    the migration with a helper that fell back to sudo, while in-cgroup.sh
#    decided on `[ -w ]` and never tried sudo at all: the probe passed and every
#    step then failed to enter the subtree it had just declared ready. The
#    layout printed here is the evidence for why (delegation containment cares
#    about the common ancestor, which chowning below $subtree cannot change).
echo "cgroup v2 delegation facts for the join:"
isolation_cgroup_layout "$job"
sleep 30 &
move_pid=$!
if (echo "$move_pid" >"$job/cgroup.procs") 2>/dev/null; then
	how=unprivileged
elif sudo -n sh -c "echo $move_pid > '$job/cgroup.procs'" 2>/dev/null; then
	how=sudo
else
	kill "$move_pid" 2>/dev/null
	give_up "a process cannot be migrated into $job with or without sudo (cgroup v2 delegation containment)"
fi
grep -qx "$move_pid" "$job/cgroup.procs" || {
	kill "$move_pid" 2>/dev/null
	give_up "a migrated process did not appear in $job/cgroup.procs"
}
kill "$move_pid" 2>/dev/null
wait "$move_pid" 2>/dev/null

isolation_emit delegated true
isolation_emit skip_args "$(isolation_skip_args cgroup)"
echo "delegated cgroup v2 subtree ready: $subtree"
echo "  controllers: $(cat "$subtree/cgroup.subtree_control")"
echo "  owner:       $(stat -c '%U:%G' "$subtree")"
echo "  join:        $how (steps enter $job via harness/ci/in-cgroup.sh)"

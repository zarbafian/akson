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
# not a failed check — the same rule harness/run-checks.sh follows. It reports:
#
#   delegated=true|false   did we get one?
#   test_skip_args=...     libtest `--skip` flags the caller MUST pass when we
#                          did not, so the cgroup-dependent tests are visibly
#                          NOT RUN rather than silently reported green.
#
# Local dry run — no sudo, borrowing the systemd user session's own delegated
# subtree as the stand-in hierarchy root:
#
#   AKSON_CGROUP_ROOT=/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice \
#     harness/ci/delegate-cgroup.sh
set -uo pipefail

# The hierarchy root to carve the subtree out of, and the subtree itself. Both
# are overridable so the whole script can be exercised without root (above).
root="${AKSON_CGROUP_ROOT:-/sys/fs/cgroup}"
subtree="${AKSON_CGROUP_SUBTREE:-$root/akson-ci}"
job="$subtree/job"

# The two #[ignore] tests that cannot run without a delegated subtree. Named
# here, once: the caller passes them to libtest verbatim.
skips="--skip cgroup_scope_applies_limits_and_confines_a_process"
skips="$skips --skip live_confined_launch_composes_all_isolation"

emit() { # emit <delegated> <skip-args>
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		printf 'delegated=%s\n' "$1" >>"$GITHUB_OUTPUT"
		printf 'test_skip_args=%s\n' "$2" >>"$GITHUB_OUTPUT"
	fi
}

# A skip is not a pass. Say why, name what will not run, and put it where a
# reader of the run summary sees it without opening the log.
give_up() {
	emit false "$skips"
	cat <<EOF

SKIPPED — no delegated cgroup v2 subtree on this runner ($1).
  cgroup enforcement (§13.1) cannot be exercised here, so these two live tests
  will NOT run and must not be read as passing:

    akson-sandbox  cgroup_scope_applies_limits_and_confines_a_process
    akson-sandbox  live_confined_launch_composes_all_isolation

  The end-to-end demos (clean_worker_e2e, receive_e2e) will run their non-cgroup
  half and print "[skip] no delegated cgroup subtree" for the confined launch.
  Everything else in this job — seccomp, Landlock, namespaces, mount, bwrap —
  is unaffected and still enforced.
EOF
	echo "::warning title=cgroup confinement not exercised::$1 — 2 live cgroup tests skipped, not passed"
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		{
			echo "### sandbox isolation: cgroup confinement SKIPPED"
			echo
			echo "No delegated cgroup v2 subtree on this runner ($1)."
			echo "\`cgroup_scope_applies_limits_and_confines_a_process\` and"
			echo "\`live_confined_launch_composes_all_isolation\` did **not** run."
		} >>"$GITHUB_STEP_SUMMARY"
	fi
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

# 4. And prove the one thing the *test steps* still need root for: moving their
#    own shell into $job. (A plain user cannot: cgroup v2 delegation requires
#    write access to cgroup.procs of the common ancestor of source and
#    destination, which here is the hierarchy root.)
sleep 30 &
move_pid=$!
maybe_root sh -c "echo $move_pid > '$job/cgroup.procs'" || {
	kill "$move_pid" 2>/dev/null
	give_up "cannot migrate a process into $job"
}
kill "$move_pid" 2>/dev/null
wait "$move_pid" 2>/dev/null

emit true ""
echo "delegated cgroup v2 subtree ready: $subtree"
echo "  controllers: $(cat "$subtree/cgroup.subtree_control")"
echo "  owner:       $(stat -c '%U:%G' "$subtree")"
echo "  job leaf:    $job (steps join it via harness/ci/in-cgroup.sh)"

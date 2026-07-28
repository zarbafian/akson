#!/usr/bin/env bash
# Sourced by the isolation job's steps. It owns two things, in one place:
#
#   - which live #[ignore] tests depend on which environment capability, and
#   - what a skip looks like when a capability turns out to be absent.
#
# The rule the job follows: **the isolation job goes red when an isolation check
# fails, and only then.** A capability the runner does not grant is an
# environment gap. A gap makes named checks NOT RUN — loudly, on the run summary
# and as an annotation — rather than pass quietly or fail the job. That is
# harness/run-checks.sh's rule, applied to CI.
#
# The gap can be discovered late: `harness/ci/delegate-cgroup.sh` can build a
# subtree whose unprivileged probes all pass and a later step can still be unable
# to *enter* it. Every such discovery routes here, not to an error.

# Which live tests cannot run without <capability>. One name per line.
isolation_tests_needing() {
	case "$1" in
	bwrap)
		echo "live_bwrap_installs_the_seccomp_filter"
		echo "live_bwrap_isolates_the_worker"
		echo "live_bwrap_worker_has_no_network"
		echo "live_confined_launch_composes_all_isolation"
		;;
	cgroup)
		echo "cgroup_scope_applies_limits_and_confines_a_process"
		echo "live_confined_launch_composes_all_isolation"
		;;
	*)
		echo "isolation-env.sh: unknown capability '$1'" >&2
		return 1
		;;
	esac
}

# The libtest flags that leave those tests unrun. Passing them is what makes a
# skip visible in the test output ("N filtered out") instead of invisible.
isolation_skip_args() {
	isolation_tests_needing "$1" | awk '{ printf "--skip %s ", $0 }'
}

# A skip is not a pass. Say it in the log, name every check that will not
# happen, raise a warning annotation, and put it on the run summary so it is
# visible without opening the log.
isolation_report_skip() { # <capability> <reason>
	local cap=$1 reason=$2 n
	n=$(isolation_tests_needing "$cap" | wc -l)
	cat <<EOF

SKIPPED — $cap is unavailable on this runner ($reason).
  These $n live checks will NOT run, and a green job must not be read as
  having established them:

$(isolation_tests_needing "$cap" | sed 's/^/    akson-sandbox  /')

  Everything that does not need $cap is unaffected and still enforced.
EOF
	if [ "$cap" = cgroup ]; then
		cat <<'EOF'
  The end-to-end demos (clean_worker_e2e, receive_e2e) run their non-cgroup
  half and print "[skip] no delegated cgroup subtree" for the confined launch.
EOF
	fi
	echo "::warning title=isolation: $cap unavailable::$reason — $n live tests skipped, not passed"
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		{
			echo "### sandbox isolation: $cap SKIPPED"
			echo
			echo "$reason"
			echo
			# shellcheck disable=SC2016  # `$/` is sed's end-of-line anchor
			isolation_tests_needing "$cap" | sed 's/^/- `/; s/$/` did **not** run/'
		} >>"$GITHUB_STEP_SUMMARY"
	fi
}

isolation_emit() { # <key> <value>
	[ -n "${GITHUB_OUTPUT:-}" ] && printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
	return 0
}

# Print the facts that decide whether a cgroup join can work, so the next run
# *records* them rather than leaving the diagnosis to inference. cgroup v2
# delegation containment (kernel docs, "Delegation Containment") lets an
# unprivileged process migrate a process only if it can write BOTH the
# destination's cgroup.procs and the cgroup.procs of the **common ancestor** of
# source and destination. chowning below akson-ci cannot change the ancestor.
isolation_cgroup_layout() { # <destination cgroup dir>
	local dest=$1 src rel common
	rel=$(grep -m1 '^0::' /proc/self/cgroup 2>/dev/null | cut -d: -f3-)
	src="/sys/fs/cgroup${rel}"
	src="${src%/}"
	[ -n "$src" ] || src=/sys/fs/cgroup
	common=$src
	while [ "$common" != "/" ] && [ "$dest" != "$common" ] && [ "${dest#"$common"/}" = "$dest" ]; do
		common=$(dirname "$common")
	done
	echo "  running in:      $src"
	echo "  destination:     $dest"
	printf '  common ancestor: %s [%s] — its cgroup.procs is %s by %s\n' \
		"$common" "$(stat -c '%U:%G %A' "$common" 2>/dev/null || echo '?')" \
		"$([ -w "$common/cgroup.procs" ] && echo writable || echo 'NOT writable')" \
		"$(id -un)"
}

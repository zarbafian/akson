#!/usr/bin/env sh
# Machine-check one spec:  ./check.sh TaskLifecycle
# Runs TLC on specs/<Name>.tla with its side-by-side specs/<Name>.cfg.
# Extra args go straight to TLC, e.g.  ./check.sh TaskLifecycle -simulate
set -eu
spec=${1:?usage: ./check.sh SpecName [tlc args...]}
shift 2>/dev/null || true
cd "$(dirname "$0")"
mkdir -p states
exec java -XX:+UseParallelGC -cp tools/tla2tools.jar tlc2.TLC \
  -metadir states -workers auto -deadlock -cleanup \
  -config "specs/$spec.cfg" "specs/$spec.tla" "$@"

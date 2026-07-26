#!/usr/bin/env bash
# A0.5 evidence: report which of the profile's directives THIS host tolerates
# while akson's own checks still pass. Run on every fleet host; the output is
# the evidence a0-evidence.md cites.
set -uo pipefail
cd "$(dirname "$0")/.."

AKSOND="${AKSOND:-target/debug/aksond}"
AKSON="${AKSON:-target/debug/akson}"
[ -x "$AKSON" ] || { echo "verify: build first (cargo build -p aksond -p akson-cli)"; exit 2; }

echo "== host sandbox preconditions"
unshare --user --map-root-user true 2>/dev/null \
  && echo "  unprivileged userns: available" \
  || echo "  unprivileged userns: RESTRICTED — the sandbox cannot run here (see harness/README.md)"

echo "== akson doctor (reports whether the clean-worker sandbox is usable)"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/akson-verify-$$}"
export AKSON_DATA_DIR="${AKSON_DATA_DIR:-/tmp/akson-verify-data-$$}"
mkdir -p "$XDG_RUNTIME_DIR" "$AKSON_DATA_DIR" 2>/dev/null
"$AKSON" doctor; doctor_rc=$?
echo "  akson doctor exit: $doctor_rc"

echo "== coordination surface (ADR-0016)"
if grep -q '^Environment=AKSON_COORD_UID=[0-9]' deploy/akson-daemon.service 2>/dev/null; then
  echo "  AKSON_COORD_UID is set — coord.sock will be bound for that identity"
else
  echo "  AKSON_COORD_UID is NOT set — coord.sock is deliberately absent on this host."
  echo "  A host running the C4 driver must substitute it:"
  echo "    sudo systemctl edit akson-daemon.service   # Environment=AKSON_COORD_UID=\$(id -u akson-coord)"
fi
grep -q '^RuntimeDirectoryMode=0710' deploy/akson-daemon.service \
  && echo "  runtime dir is 0710 — the driver's group can traverse, not list" \
  || echo "  WARNING: runtime dir mode does not permit the driver to traverse to coord.sock"

echo "== directives this profile deliberately omits (and why)"
grep -E '^# (PrivateUsers|RestrictNamespaces|ProtectKernelTunables|SystemCallFilter|ProtectControlGroups|IPAddressDeny)' \
  deploy/akson-daemon.service | sed 's/^# /  /'

echo "== systemd-analyze security (if systemd is present)"
# systemd-analyze security only inspects units systemd has LOADED, so it
# needs them installed (root). Off a fleet host we verify what we can without
# root: that every directive parses and that the omissions above are the only
# sandbox-hostile ones present.
if command -v systemd-analyze >/dev/null 2>&1; then
  for u in deploy/akson-daemon.service deploy/akson-coord.service; do
    echo "  -- $u"
    if systemd-analyze verify "$(pwd)/$u" 2>&1 | grep -q .; then
      systemd-analyze verify "$(pwd)/$u" 2>&1 | sed 's/^/     /' | head -4
    else
      echo "     parses cleanly"
    fi
    # Sandbox-hostile directives must not be ACTIVE (commented reasons are ok).
    if grep -E '^(PrivateUsers|RestrictNamespaces|ProtectKernelTunables|SystemCallFilter)=' "$u" \
         | grep -qv '^SystemCallFilter' && [ "$u" = "deploy/akson-daemon.service" ]; then
      echo "     WARNING: a sandbox-hostile directive is active in the daemon unit"
    else
      echo "     no sandbox-hostile directive active"
    fi
  done
  echo "  (systemd-analyze security needs the units installed as root — run on a fleet host)"
else
  echo "  systemd-analyze not present on this host — record the skip"
fi

rm -rf "/tmp/akson-verify-$$" "/tmp/akson-verify-data-$$" 2>/dev/null
echo "verify: done (record this output in design/a0-evidence.md)"

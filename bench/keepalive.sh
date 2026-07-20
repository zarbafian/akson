#!/usr/bin/env bash
# Distributed keep-alive: many A2A exchanges over ONE mutual-TLS connection between
# two live endpoints on separate hosts.
#
# The round-trip bench (run-bench.sh) opens a fresh connection per task, so it never
# exercises connection reuse. This one drives N *distinct* signed contracts down a
# single connection, then one more after an idle gap — proving the receive server's
# per-request read deadlines (§9.1) bound each exchange without capping an active
# session, over a real network link.
#
# It runs the test ON the requester host (so the timings are protocol latency, not
# ssh overhead) against the performer's receive endpoint.
#
#   REQUESTER_SSH=bench@1.2.3.4 PERFORMER_SSH=bench@5.6.7.8 \
#     PERFORMER_IP=10.0.0.2 EXCHANGES=25 ./keepalive.sh
#
# Assumes both hosts are already provisioned, serving, and PAIRED (see README.md:
# provision.sh, serve.sh, then the pairing steps in run-bench.sh).
set -euo pipefail

REQUESTER_SSH="${REQUESTER_SSH:?ssh target for the requester (alice)}"
PERFORMER_SSH="${PERFORMER_SSH:?ssh target for the performer (bob)}"
PERFORMER_IP="${PERFORMER_IP:?the reachable VPC IP of the performer}"
EXCHANGES="${EXCHANGES:-25}"
PERFORMER_RECV="${PERFORMER_RECV:-18444}"

SSHOPTS=(-o ControlMaster=auto -o ControlPath="$HOME/.ssh/axon-ka-%r@%h:%p" -o ControlPersist=120)
ra() { ssh "${SSHOPTS[@]}" "$REQUESTER_SSH" "$@"; }
pf() { ssh "${SSHOPTS[@]}" "$PERFORMER_SSH" "$@"; }

echo "==> Reading the performer's endpoint certificate fingerprint…"
# What the requester must pin. It is exactly the SHA-256 over the persisted DER.
PEER_CERT=$(pf "sha256sum \$HOME/.axon-bench-performer/endpoint.der | cut -d' ' -f1")
[ -n "$PEER_CERT" ] || { echo "could not read the performer's endpoint.der" >&2; exit 1; }
echo "    $PEER_CERT"

echo "==> Driving $EXCHANGES exchanges over ONE connection, from the requester…"
ra "export PATH=\$HOME/.cargo/bin:\$PATH; cd \$HOME/axon && \
    AXON_WAN_DATA_DIR=\$HOME/.axon-bench-requester \
    AXON_WAN_PEER_ADDR=$PERFORMER_IP:$PERFORMER_RECV \
    AXON_WAN_PEER_CERT=$PEER_CERT \
    AXON_WAN_REQUESTER=orgA/alice \
    AXON_WAN_PERFORMER=orgB/bob \
    AXON_WAN_EXCHANGES=$EXCHANGES \
    CARGO_INCREMENTAL=0 cargo test --release -p axond --test wan_keepalive -- --ignored --nocapture"

echo
echo "==> Submitted tasks now queued on the performer:"
pf "export PATH=\$HOME/.cargo/bin:\$HOME/axon/target/release:\$PATH; \
    export XDG_RUNTIME_DIR=\${XDG_RUNTIME_DIR:-/run/user/\$(id -u)}; \
    axon inbox | tail -5"

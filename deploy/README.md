# Hardened deployment profile (A0.5)

The units `akson service install` writes are deliberately minimal: one
operator identity, `Delegate=yes`, and nothing else. That is right for a
laptop and wrong for a fleet host, where the kovee/byom program's I2 gate
runs three daemons side by side and a coordination driver reaches akson over
a socket.

This directory holds the fleet profile: **one Unix identity per role**, unit
directives that are hardened *only as far as akson's own sandbox can
tolerate*, and an explicit per-role egress policy.

## Why hardening has a ceiling here

Akson's clean worker (`akson-sandbox`, ADR-0006) is itself a sandbox. It
needs **unprivileged user namespaces, `mount`, and `pivot_root`** — exactly
the operations a reflexively-hardened unit removes. So the usual
copy-paste block is wrong: `PrivateUsers=yes`, `ProtectKernelTunables=yes`,
`RestrictNamespaces=yes` and a restrictive `SystemCallFilter=` each break the
inner sandbox, and the failure looks like "the sandbox is broken" when it is
the outer unit refusing.

The rule for this profile: **harden everything the daemon does not need, and
leave the sandbox's syscall surface alone.** `harness/run-checks.sh`'s
sandbox section and `akson doctor` are the arbiters — a directive that makes
either fail is not in the profile.

## The identity graph

| Role | Unit | Identity | Reaches |
|---|---|---|---|
| daemon | `akson-daemon.service` | `akson` | its store + runtime dir; the RECEIVE listener; the broker's egress allowlist |
| coordination driver (C4) | `akson-coord.service` | `akson-coord` | **only** `coord.sock` — never `admin.sock` |
| operator | (interactive) | the human's own login | `admin.sock` via `SO_PEERCRED` same-UID |

The coordination socket's admission rule (`AKSON_COORD_UID`) names
`akson-coord` and nothing else, so the C4 surface is bounded by an OS access
domain rather than by a token alone — the property `2026-07-25-byom-exchange-coordination-surface.md`
requires and the R0 review insisted on.

## Egress, per role

| Role | Egress |
|---|---|
| daemon | outbound 443 to the processor allowlist only (the broker resolves and refuses a non-globally-routable address); inbound only the RECEIVE port |
| coordination driver | none — it speaks a Unix socket |
| operator | none granted by a unit |

The daemon's allowlist is data, not a unit directive: `akson processor add`
pins host + port + certificate, and `akson-broker` refuses anything else.
`IPAddressDeny=`/`IPAddressAllow=` are deliberately **not** used, because the
broker's own check is the authority and a second, coarser copy in the unit
would drift from it.

## Files

- `akson-daemon.service` — the daemon, hardened to the ceiling above
- `akson-coord.service` — the C4 driver, hardened further (it needs no
  namespaces of its own)
- `sysusers.d/akson.conf` — the two system identities
- `verify.sh` — runs `akson doctor` and the sandbox self-check under the
  profile's directives and reports which ones a host actually tolerates

## Status

The units are the profile A0.5 asks for and `verify.sh` is the evidence
mechanism. Recorded honestly in `design/a0-evidence.md`: they are verified on
this development host, not yet on a fleet host — that happens when I2
provisions droplets and runs `verify.sh` there.

**No hardening score is claimed for either unit.** `systemd-analyze security`
only inspects units systemd has *loaded*, so it needs them installed as root,
which has not happened anywhere yet — it has never produced a number for
`akson-daemon.service` or `akson-coord.service`, and none is quoted here or in
`design/a0-evidence.md`. What has been verified off a fleet host is narrower and
should be read as exactly that: both units parse under `systemd-analyze verify`,
no sandbox-hostile directive is active in the daemon unit, and `akson doctor`
still reports its usual verdict. `verify.sh` prints that distinction rather than
hiding it.

**And the profile is opt-in.** Nothing here is the default: a plain
`aksond serve` runs everything under one UID, and `coord.sock` is not created at
all unless `AKSON_COORD_UID` is set. The separate identities below are the fleet
arrangement, not what a laptop gets. Admission on every socket is `SO_PEERCRED`
— which *user* connected, never which program — so this profile buys an OS access
domain per role, not an attested process identity.

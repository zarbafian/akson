# Akson interop test harness

Runnable Akson endpoints for **multi-endpoint scenarios** — first contact, contract
exchange, work-order flow, and (later) `codex ↔ claude`-style adapter runs — over
real sockets, real mTLS, and real on-disk state. The harness exercises the shipped
crates end to end; it is **not** the daemon (that is M12).

## Validation: local on demand + CI

Two complementary paths:

- **Local, on demand** — `./harness/run-checks.sh` runs the whole suite: format,
  clippy, unit + integration tests (including the seccomp and Landlock enforcement
  tests), the golden-vector cross-check, and the introduction interop scenario. The
  namespace-isolation checks are gated on **unprivileged user namespaces**; when a
  host restricts them (e.g. Ubuntu's `apparmor_restrict_unprivileged_userns`), the
  script skips that section and prints the exact one-run enable/restore commands.
  `FAST=1` skips clippy for a quicker loop.
- **CI** (`.github/workflows/ci.yml`) — the `isolation` job runs on a GitHub
  `ubuntu-latest` runner, which has passwordless sudo, so it **enables unprivileged
  user namespaces itself** and runs the live namespace/mount checklist that a
  restricted local host cannot. This is the home for validating the namespace path
  on every push.

**Open-source tools only.** Container scenarios use **Podman** (Apache-2.0,
daemonless, rootless) as the reference runtime; the compose file and scripts are
runtime-agnostic and also run under `docker compose`. The eventual model
scenarios use the FOSS/local-model adapter path the design mandates (§4.4 —
OpenCode + a local model, no vendor account); until the adapters land (M13) the
scenarios use the built-in endpoints with no model.

## Runner

`harness/runner` builds the `akson-harness` binary — a thin wiring of the shipped
crates into a runnable endpoint (keys and the store KEK are derived from a
`--seed`, so it is **test-only**):

- `akson-harness token --seed <n> [--advertise host:port] --token-out <f>`
- `akson-harness serve --state <db> --seed <n> [--host H] [--advertise A] [--port P] --token-out <f> [--import <token-file> --label <l>] [--agent NAME]`
- `akson-harness introduce --state <db> --seed <n> --token <token-file> [--agent NAME]`

## Scenarios

| # | Scenario | Status | Maps to |
|---|----------|--------|---------|
| 1 | First contact over identity tokens | **runnable** (`scenario-pairing.sh`) | Layer-1 interop checkpoint, §8.2 / ADR-0015 |
| 2 | Signed contract → accept → work order | pending receive-path assembly (M12-ish) | Layer-2, §10.2 |
| 3 | Crash injection at each commit point | planned | §19 crash matrix (M15) |
| 4 | `codex ↔ claude` adapter round trip | planned | G0 adapter gate (M13) |

### Run scenario 1 locally (no containers)

```sh
./harness/interop/scenario-pairing.sh
```

Two processes: each writes its public identity token (the out-of-band
exchange as a file drop); endpoint-a imports endpoint-b's and serves;
endpoint-b imports endpoint-a's and dials the introduction. Prints
`INTRODUCED with endpoint-a` on success.

### Run scenario 1 in containers

```sh
podman build -f harness/interop/Containerfile -t akson-harness .
podman compose -f harness/interop/compose.yaml up --abort-on-container-exit
```

## Running the sandbox (§13.1) in a container — read this first

The clean-worker sandbox (`akson-sandbox`, ADR-0006) needs **unprivileged user
namespaces, mount, and `pivot_root`** — exactly the operations a **stock**
container's default seccomp/AppArmor/no-userns profile *blocks*. A naive
`podman run akson-tests` will fail the sandbox checklist the same way a restricted
host does, and it will look like the sandbox is broken when it is not
(sandbox-inside-sandbox: the outer runtime must be permissive enough for the inner
one). Run sandbox-validation scenarios with a deliberately permissive runtime —
`--privileged`, or targeted `--cap-add`/`--security-opt seccomp=unconfined
--security-opt apparmor=unconfined` plus userns config.

For **local, on-demand** validation without containers, the simplest path is to
enable unprivileged user namespaces for a single run and let `run-checks.sh`
execute the namespace checklist directly:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
./harness/run-checks.sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1   # restore hardening
```

(seccomp and Landlock need no user namespace and are validated directly, even on
a restricted host.)

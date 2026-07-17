# Axon interop test harness

Runnable Axon endpoints for **multi-endpoint scenarios** — pairing, contract
exchange, work-order flow, and (later) `codex ↔ claude`-style adapter runs — over
real sockets, real mTLS, and real on-disk state. The harness exercises the shipped
crates end to end; it is **not** the daemon (that is M12).

## On-demand validation (no CI service required)

`./harness/run-checks.sh` runs the whole local validation suite on demand — format,
clippy, unit + integration tests (including the seccomp and Landlock enforcement
tests), the golden-vector cross-check, and the pairing interop scenario. The
namespace-isolation checks are gated on **unprivileged user namespaces**; when a
host restricts them (e.g. Ubuntu's `apparmor_restrict_unprivileged_userns`), the
script skips that section and prints the exact one-run enable/restore commands.
`FAST=1` skips clippy for a quicker loop.

**Open-source tools only.** Container scenarios use **Podman** (Apache-2.0,
daemonless, rootless) as the reference runtime; the compose file and scripts are
runtime-agnostic and also run under `docker compose`. The eventual model
scenarios use the FOSS/local-model adapter path the design mandates (§4.4 —
OpenCode + a local model, no vendor account); until the adapters land (M13) the
scenarios use the built-in endpoints with no model.

## Runner

`harness/runner` builds the `axon-harness` binary — a thin wiring of the shipped
crates into a runnable endpoint (keys and the store KEK are derived from a
`--seed`, so it is **test-only**):

- `axon-harness serve --state <db> --seed <n> [--host H] [--advertise A] [--port P] --invitation-out <f> [--agent NAME]`
- `axon-harness pair  --state <db> --seed <n> --invitation <f> [--agent NAME]`

## Scenarios

| # | Scenario | Status | Maps to |
|---|----------|--------|---------|
| 1 | Pairing over mTLS | **runnable** (`scenario-pairing.sh`) | Layer-1 interop checkpoint, §8.2 |
| 2 | Signed contract → accept → work order | pending receive-path assembly (M12-ish) | Layer-2, §10.2 |
| 3 | Crash injection at each commit point | planned | §19 crash matrix (M15) |
| 4 | `codex ↔ claude` adapter round trip | planned | G0 adapter gate (M13) |

### Run scenario 1 locally (no containers)

```sh
./harness/interop/scenario-pairing.sh
```

Two processes: endpoint-a mints an invitation and serves the bootstrap endpoint;
endpoint-b reads the invitation and pairs, pinning endpoint-a. Prints
`PAIRED with endpoint-a` on success.

### Run scenario 1 in containers

```sh
podman build -f harness/interop/Containerfile -t axon-harness .
podman compose -f harness/interop/compose.yaml up --abort-on-container-exit
```

## Running the sandbox (§13.1) in a container — read this first

The clean-worker sandbox (`axon-sandbox`, ADR-0006) needs **unprivileged user
namespaces, mount, and `pivot_root`** — exactly the operations a **stock**
container's default seccomp/AppArmor/no-userns profile *blocks*. A naive
`podman run axon-tests` will fail the sandbox checklist the same way a restricted
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

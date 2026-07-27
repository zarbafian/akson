# Two-machine bench (design §20.8)

Measures the full code-review round trip between two **separate** hosts over a
routable network, with a real model behind the performer's broker:

```
alice (requester)                         bob (performer)
  peer add ◀────── identity tokens ──────▶ peer add   (out of band, once)
  send  ─── introduction, then proposal ────▶ submitted task
                                             approve → run (confined adapter
                                                       ─▶ broker ─▶ OpenAI)
  outcome ◀──────── signed result ────────── deliver
```

The OpenAI key lives **only on bob**, sealed in its store; the daemon injects it
into the model call. The confined adapter never sees the key and has no network of
its own — so this exercises the real credential-injection + egress path, not just
the happy loop.

## Layout

| Host | Role | Needs |
|---|---|---|
| **bob** | performer | bwrap + unprivileged userns + a delegated cgroup v2; the OpenAI key; outbound 443 to `api.openai.com` |
| **alice** | requester | just `aksond` |

Run the driver (`run-bench.sh`) from your **laptop**, which `ssh`es into both.

## One-time

On each droplet (as a non-root sudo user — unprivileged userns is happiest not as
root; `enable-linger` so the user's systemd + `/run/user/$UID` exist even when you
are not logged in):

```
sudo loginctl enable-linger "$USER"
rsync -a --exclude target/ ./akson/ bob:~/akson/     # and → alice
ssh bob  'cd ~/akson/bench && ./provision.sh'        # installs deps, builds, runs akson doctor
ssh alice 'cd ~/akson/bench && ./provision.sh'
```

`provision.sh` ends by printing `akson doctor`. On **bob** it must report the sandbox
is usable. The usual blocker on a fresh Ubuntu 24.04 droplet is AppArmor gating
unprivileged userns — fix with:

```
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # or use a 22.04 image
```

## Start the daemons

The performer configures a processor for **every model back-end whose key is
present** (openai / anthropic / gemini) and runs the adapter named by `PROVIDER`.
The keys are stored sealed on bob and never leave it.

```
# bob (performer): pass whichever keys you have; PROVIDER picks the initial worker.
ssh bob 'cd ~/akson/bench && ROLE=performer SELF_IP=10.0.0.2 PROVIDER=openai \
         OPENAI_API_KEY=sk-... ANTHROPIC_API_KEY=sk-ant-... GEMINI_API_KEY=... ./serve.sh'

# alice (requester): SELF_IP is alice's IP.
ssh alice 'cd ~/akson/bench && ROLE=requester SELF_IP=10.0.0.1 ./serve.sh'
```

Open one port per host between the droplets (a DO firewall / VPC rule): each
host's RECEIVE port (alice 18443, bob 18444 by default). There is no separate
pairing listener — first contact is a mutual introduction on the RECEIVE
surface (ADR-0015).

Pairing is one identity-token import per side; `run-bench.sh` does it for you
on its first run. The manual equivalent (with `target/release` on `PATH`):

```
# on each host: print this endpoint's token, hand it to the other operator
akson token                         # → akson1…@<ip>:<port>

# on alice:                         # on bob:
akson peer add <bob-token> bob      akson peer add <alice-token> alice

# on alice — dial the introduction now (optional; the first task send
# triggers the same handshake):
akson peer ping bob
```

## Run the bench

Single-provider, per-phase timing:

```
REQUESTER_SSH=alice PERFORMER_SSH=bob ITERS=20 ./run-bench.sh
```

Those three are the only variables `run-bench.sh` reads — the addresses are
already baked into each daemon by `serve.sh`'s `SELF_IP`, so there is no
`ALICE_IP`/`BOB_IP` here.

Times `send → approve → run → deliver` for `ITERS` iterations and prints one row
per phase with `p50 p95 max mean`, plus a `loop` row — the same four statistics
over each iteration's *whole* round trip, not a sum.

**Matrix** — every back-end × every scenario in `scenarios/`, run *on alice*:

```
scp -i <key> bench/bench-matrix.sh bench/scenarios alice:~/akson/bench/   # if not already synced
ssh alice 'cd ~/akson/bench && BOB_PRIV=10.0.0.2 PROVIDERS="openai anthropic gemini" ITERS=10 ./bench-matrix.sh'
```

For each provider it switches bob's active worker (processors persist, so no key
re-enters), then times the full round trip for every scenario, and prints a
`provider × scenario` table of `n / ok / p50 / p95` (loop seconds). Add or edit
`scenarios/*.json` to extend the matrix.

Two more drivers share the same provisioned pair: `keepalive.sh` (many
exchanges over ONE mutual-TLS connection, exercising connection reuse) and
`cooperate.sh` (six alternating rounds where each side takes its turn
performing — start both with `ROLE=alice` / `ROLE=bob` so each gets a worker;
`serve.sh`'s `alice`/`bob` role arms exist precisely for this, and are the only
two that give *both* hosts a worker). Each script's header lists most of its
variables, but not all: `keepalive.sh` also reads `PERFORMER_RECV` (default
`18444`), `cooperate.sh` also reads `PROCESSOR` (default `openai`), and
`bench-matrix.sh` hard-codes the ssh key `$HOME/.ssh/bench_key` and the remote
user `bench@`. Read the body, not only the header.

## Reading the numbers

`run` includes the OpenAI call (~1–2 s), which dominates. To separate akson's own
overhead from model latency, run a second pass against a **local** model on bob
(same adapter, different processor):

```
# on bob, in another shell: ollama serve && ollama pull qwen2.5-coder:7b
# Pass the TLS terminator's cert SHA-256, NOT `ca`: `ca` marks the processor remote,
# and the egress policy only permits a loopback address for a *local* processor
# (broker.rs `if config.is_local() { policy.allow_local() }`). The broker always
# dials TLS, so front the plain-HTTP Ollama port with a TLS terminator.
ssh bob 'akson processor add local openai 127.0.0.1 11434 <cert-sha256> --path /v1/chat/completions --auth none'
# point AKSON_WORKER_EXEC at --processor local --model qwen2.5-coder:7b and re-run.
```

The delta between the OpenAI pass and the local pass is roughly the model latency;
what remains is akson's protocol + sandbox + signing overhead. Add `tc netem` on one
NIC (or put the droplets in different regions) to see how the loop behaves under WAN
latency/loss.

Two practical notes on that local pass: a bare `ssh bob 'akson …'` gets a
non-interactive shell with neither the release binaries on `PATH` nor
`XDG_RUNTIME_DIR` set, so prefix it the way the drivers do
(`export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}; export PATH=$HOME/.cargo/bin:$HOME/akson/target/release:$PATH`).
And `serve.sh` builds `AKSON_WORKER_EXEC` itself, hard-coding the processor id to
the provider name — `OPENAI_MODEL`/`ANTHROPIC_MODEL`/`GEMINI_MODEL` override the
model, but pointing the adapter at a processor called `local` means editing
`serve.sh`'s `worker_exec()`.

## Known mismatches in these scripts

Recorded rather than papered over — each is a line in a bench script that does
not agree with what it drives. None is exercised by `cargo test` or
`harness/run-checks.sh`, which is why they survived:

- **`run-bench.sh` approves with `--processor gpt`** (line 52), but `serve.sh`
  only ever registers processors named `openai`, `anthropic` and `gemini`, and
  the adapter it launches asks for the provider-named one. The broker requires an
  exact match, so the `run` phase this script is timing answers `403
  processor-mismatch`. `bench-matrix.sh` gets it right (`--processor "$prov"`).
- **`keepalive.sh`'s last step runs `akson inbox`** (line 51). That verb does not
  exist — it is `akson task inbox` — so the CLI prints its usage banner and exits
  2, and `set -euo pipefail` takes the script down with it *after* the measured
  run has finished.
- **`provision.sh` does not install `jq`**, which `cooperate.sh` needs to build
  each round's task spec.
- **`run-bench.sh`'s header** still shows `ALICE_IP=… BOB_IP=…` in its usage
  example; the body never reads either. (`cooperate.sh` had the same pair and its
  header was corrected on 2026-07-28.)

## What is not here

There is no coordination-surface (ADR-0016) scenario in `bench/`. Everything in
this directory drives the *contract* path — `task send`/`approve`/`run`/`deliver`
— and nothing exercises `stage`, `stage consent` or `dispatch`. The coordination
carrier's end-to-end evidence is
`harness/interop/scenario-coord-dispatch.sh` (two processes, one host, real
mutual TLS) plus `crates/aksond/tests/coord_egress_e2e.rs`; a two-machine
equivalent does not exist.

# Two-machine bench (design §20.8)

Measures the full code-review round trip between two **separate** hosts over a
routable network, with a real model behind the performer's broker:

```
alice (requester)                         bob (performer)
  pair  ───────────── invitation ──────────▶ accept
  send  ───────── signed proposal ─────────▶ submitted task
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
| **alice** | requester | just `axond` |

Run the driver (`run-bench.sh`) from your **laptop**, which `ssh`es into both.

## One-time

On each droplet (as a non-root sudo user — unprivileged userns is happiest not as
root; `enable-linger` so the user's systemd + `/run/user/$UID` exist even when you
are not logged in):

```
sudo loginctl enable-linger "$USER"
rsync -a --exclude target/ ./axon/ bob:~/axon/     # and → alice
ssh bob  'cd ~/axon/bench && ./provision.sh'        # installs deps, builds, runs axon doctor
ssh alice 'cd ~/axon/bench && ./provision.sh'
```

`provision.sh` ends by printing `axon doctor`. On **bob** it must report the sandbox
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
ssh bob 'cd ~/axon/bench && ROLE=performer SELF_IP=10.0.0.2 PROVIDER=openai \
         OPENAI_API_KEY=sk-... ANTHROPIC_API_KEY=sk-ant-... GEMINI_API_KEY=... ./serve.sh'

# alice (requester): SELF_IP is alice's IP.
ssh alice 'cd ~/axon/bench && ROLE=requester SELF_IP=10.0.0.1 ./serve.sh'
```

Open the two ports between the droplets (a DO firewall / VPC rule): each host's
RECEIVE and PAIR ports (alice 18443/19443, bob 18444/19444 by default). Then pair
them once (invite on alice → copy to bob → accept → both `peer confirm`).

## Run the bench

Single-provider, per-phase timing:

```
REQUESTER_SSH=alice PERFORMER_SSH=bob \
  ALICE_IP=10.0.0.1 BOB_IP=10.0.0.2 ITERS=20 ./run-bench.sh
```

Times `send → approve → run → deliver` for `ITERS` iterations and prints per-phase
p50/p95/max plus the whole-loop total.

**Matrix** — every back-end × every scenario in `scenarios/`, run *on alice*:

```
scp -i <key> bench/bench-matrix.sh bench/scenarios alice:~/axon/bench/   # if not already synced
ssh alice 'cd ~/axon/bench && BOB_PRIV=10.0.0.2 PROVIDERS="openai anthropic gemini" ITERS=10 ./bench-matrix.sh'
```

For each provider it switches bob's active worker (processors persist, so no key
re-enters), then times the full round trip for every scenario, and prints a
`provider × scenario` table of `n / ok / p50 / p95` (loop seconds). Add or edit
`scenarios/*.json` to extend the matrix.

## Reading the numbers

`run` includes the OpenAI call (~1–2 s), which dominates. To separate axon's own
overhead from model latency, run a second pass against a **local** model on bob
(same adapter, different processor):

```
# on bob, in another shell: ollama serve && ollama pull qwen2.5-coder:7b
ssh bob 'axon processor add local openai 127.0.0.1 11434 ca --path /v1/chat/completions --auth none'
# point AXON_WORKER_EXEC at --processor local --model qwen2.5-coder:7b and re-run.
```

The delta between the OpenAI pass and the local pass is roughly the model latency;
what remains is axon's protocol + sandbox + signing overhead. Add `tc netem` on one
NIC (or put the droplets in different regions) to see how the loop behaves under WAN
latency/loss.

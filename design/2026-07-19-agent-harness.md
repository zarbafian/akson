# Agent-tool harnesses (Codex, herdr, …) — design note

Model back-ends (openai/anthropic/gemini) are done: the confined worker makes **one
brokered model call**. The next layer is running a real **agent tool** — Codex,
herdr.dev, OpenCode — as a peer. Two sides, very different difficulty.

## What we want (concrete)

Node A runs Codex; node B runs a Codex *worker*. A delegates a review to B:

```text
# node A (requester): a Codex session delegates — nothing sandboxed here
axon task send review.json           # -> task-<id>, then: axon task outcomes

# node B (performer): the approved worker IS codex, run confined
AXON_WORKER_CMD='axon-adapter-codex --input diff'   # wraps `codex exec`
```

`axon-adapter-codex` reads the approved diff from `/inputs`, runs `codex exec`
non-interactively to review it, and writes the review to `/output/response` — the
same contract every adapter meets (§16.3), but the "worker" is a full agent instead
of a single model call.

## Feasibility (confirmed)

- `codex exec [PROMPT]` runs non-interactively; `codex exec review` reviews a repo.
- `codex -c model_providers.<name>.base_url=…` (and `--oss --local-provider`) point
  Codex at an arbitrary **OpenAI-compatible endpoint**. This is the hinge: a confined
  Codex can be told to call a *local* endpoint instead of `api.openai.com`.

## The one hard part: model access under the seal

Peer work runs network-sealed — a fresh net namespace with no route out, and
`socket()`/`connect()` off the seccomp allowlist (belt **and** suspenders). Our own
adapters sidestep this: they speak the broker protocol over an **inherited fd**. A
real agent CLI can't — it opens its own HTTP connection to its model.

**Approach — loopback model proxy.** Inside the sandbox, the adapter runs a tiny
OpenAI-compatible HTTP server on `127.0.0.1:<port>` and points Codex at it
(`base_url=http://127.0.0.1:<port>/v1`). Each request the proxy receives it forwards
**over the broker fd** to the daemon, which makes the real, credential-injected,
budgeted, egress-checked call. The model credential still never enters the sandbox;
the egress allowlist and budget still bind.

The seal still holds — but now at the **network-namespace** layer, not seccomp:
- Keep the fresh net namespace with **loopback only** and no external route, so even
  with `socket()`/`connect()` allowed the worker can reach *nothing but* `127.0.0.1`.
- Relax the strict adapter profile to permit `socket`/`connect`/`bind`/`listen`
  **for a Codex-class worker only** (a new `agent_worker_baseline`), since it must
  bind the loopback proxy and Codex must dial it.

Net effect: the worker can reach exactly one thing — the local proxy — and the proxy
enforces the same gates as the broker. This trades one defense-in-depth layer
(seccomp net-deny) for the ability to host arbitrary agent CLIs, while the
namespace-level seal and all broker gates remain. **This is the decision to make.**

## Complications to handle in the Codex adapter

- **HOME / session state.** Codex writes `~/.codex` (auth, session, logs). Give it a
  writable throwaway HOME under `/output` or a tmpfs; never the host's.
- **Codex's own sandbox + tools.** Codex runs an agent loop that executes tools
  (shell, file edits). Confined, there is no repo and no host tools, so run it in a
  read-only / no-exec posture (`-c sandbox_permissions=[]`, review-from-prompt) and
  feed the diff as the prompt — not `codex exec review` (which wants a git repo).
- **Auth.** Point Codex at the loopback proxy with a dummy key; the real key is
  injected daemon-side. Disable Codex's own login/telemetry egress.
- **Bounded output.** Cap Codex's response and run time (the work order's limits).

## Increments

1. **Requester harness (works today, no decision needed).** A Codex/herdr session
   delegates a review via `axon task send`; the performer uses an existing model
   adapter. This is exactly "Codex on A sends a task to Claude on B" and needs only a
   thin `delegate` helper + an `AGENTS.md` recipe. Good first, low-risk deliverable.
2. **Codex performer adapter (needs the decision above).** `agent_worker_baseline`
   seccomp profile + loopback model proxy + `axon-adapter-codex` wrapping `codex
   exec`. The real payoff; where the hard parts live.
3. **herdr / OpenCode** reuse the same proxy + profile; each is an adapter that
   launches its own CLI against the loopback endpoint.

## Open decision

Do we accept the **loopback-proxy model** (net-namespace-enforced seal + a relaxed
`agent_worker_baseline` that allows loopback sockets) as the way to host real agent
CLIs? If yes, increment 2 proceeds. If we want to keep seccomp's hard net-deny for
*every* worker, then agent CLIs can only run against a model over an inherited fd —
which today means a shim, not a stock Codex.

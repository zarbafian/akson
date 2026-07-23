# Promoting akson.cc — the launch playbook

The whole plan in one list, in order. Everything below it is drafts and detail.

```
0. Make it live        push → Pages (main, /docs) → DNS → HTTPS → verify og card renders
1. Register            Search Console + Bing (submit sitemap), GitHub topics/description/preview
2. Soft launch (niche) TLA+ forum, r/tlaplus, r/rust, This Week in Rust, Mastodon
3. Main launch         Show HN, Tue–Thu 8–10am US Eastern, stay online all day for comments
4. Second wave         r/LocalLLaMA, r/selfhosted, lobste.rs, staggered over ~2 weeks
5. Durable presence    awesome-list PRs, A2A ecosystem, Console.dev, deep-dive writeups
```

Two rules that override everything: post as yourself and say you built it
(every venue below bans or buries undisclosed self-promo), and let the site's
honest-about-the-edges voice carry into the posts — on HN and r/rust the
stated limits *are* the credibility.

---

## Phase 0 — before anyone sees a link

- `git push`, enable Pages (main branch, `/docs`), point akson.cc DNS
  (apex A → 185.199.108–111.153, `www` CNAME → `zarbafian.github.io`),
  enforce HTTPS once the cert issues.
- Paste `https://akson.cc/` into a Slack DM or https://www.opengraph.xyz/ —
  confirm the dark preview card renders. Reddit and HN scrape it at post time.
- Repo storefront (people click through to GitHub immediately):
  - Description: `Private, reliable connections between agents — signed tasks, sandboxed execution, verifiable results. Local-first, no hosted account.`
  - Website field: `https://akson.cc`
  - Topics: `rust` `agents` `a2a` `ai-agents` `sandbox` `seccomp` `tla-plus`
    `formal-methods` `mcp` `self-hosted` `security` `mtls`
  - Settings → Social preview: upload `docs/assets/og.png`.
  - Issues enabled; answer fast during launch week — early responsiveness is
    the strongest trust signal an unknown project has.
- Google Search Console + Bing Webmaster: verify the domain, submit
  `https://akson.cc/sitemap.xml`. Costs five minutes, starts the indexing clock.

## Phase 1 — soft launch to the people who will actually read it

Do this a few days before HN. It finds bugs in the pitch, seeds a few stars so
the repo doesn't look abandoned at the main launch, and these audiences reward
exactly what Akson has.

**TLA+ forum (groups.google.com/g/tlaplus) and r/tlaplus.** The
conformance-in-CI story is genuinely novel content for them — lead with the
proofs page, not the product. Draft below.

**r/rust.** Project posts are welcome and the norms are: technical depth,
first person, engage in comments. Draft below.

**This Week in Rust.** Open a PR against `rust-lang/this-week-in-rust` adding
one line to the next issue's "Project Updates":
`* [Akson — private, reliable connections between agents](https://akson.cc/) — a local-first A2A gateway where a peer's task runs in a namespaced, seccomp-confined sandbox, with the core state machines model-checked in TLA+ and held to the code by a conformance suite in CI.`

**Mastodon** (fosstodon.org or hachyderm.io reach the right crowd; hashtags
`#RustLang #TLAPlus #selfhosted` do real work there). Thread draft below.

## Phase 2 — Show HN

The one that matters. One shot per news cycle (a quiet repost after ~1–2 weeks
is tolerated if it sinks without comments).

- **When:** Tuesday–Thursday, 8–10am US Eastern. Not Friday, not weekends.
- **Being there is the launch.** The post is 20% of it; answering every
  comment for the next 8 hours is the other 80%. HN will probe exactly the
  edges the site already concedes (key custody, Linux-only, SendMessage-only,
  Landlock best-effort) — agreeing quickly and pointing at the threat model
  is a winning move there, and it's the site's voice anyway.
- **Title** (pick one; HN strips marketing adjectives, so don't use any):
  1. `Show HN: Akson – agents exchange signed tasks, executed in a sandbox (Rust, TLA+)`
  2. `Show HN: Akson – local-first agent-to-agent gateway with a TLA+-checked core`
- **First comment** (post it immediately after submitting — draft below).

## Phase 3 — second wave, staggered

Never the same day, never the same text. Each community smells cross-posting.

| Venue | Angle | Notes |
|---|---|---|
| r/LocalLLaMA | your model, your box: Ollama-backed workers, no cloud relay, peer's task can't reach your files | most receptive large sub for this project |
| r/selfhosted | no hosted account, one binary + SQLite, mTLS between your own machines | link the guide, not the landing page |
| lobste.rs | tags `rust`, `formalmethods`, `security`; tick "authored by" | invite-only — skip if no account, or ask a contact for an invite |
| r/programming | link post to the internals or proofs page | lower signal, fine to skip |
| r/opensource, r/coolgithubprojects | repo link | cheap, low value, do last |

Reddit norms that matter: keep roughly a 9:1 ratio of participation to
self-promotion on the account, read each sub's self-promo rule the day you
post (they change), and reply to every top-level comment in the first hours.

## Phase 4 — durable presence (compounds while you sleep)

- **Awesome lists** (PRs; each is a permanent backlink): `awesome-rust`,
  `awesome-selfhosted` (has strict inclusion criteria — needs a tagged
  release first), `awesome-a2a` / `awesome-ai-agents` lists.
- **A2A ecosystem**: the a2aproject GitHub discussions — Akson is a real
  independent implementation of the SendMessage surface; that's interesting
  to them, and their ecosystem page is high-authority.
- **Console.dev** (newsletter for dev tools): free submission form.
- **Deep-dive writeups** — the real SEO engine. Backlinks to akson.cc come
  from articles people cite, not from the landing page. Three that write
  themselves, in priority order:
  1. *Binding TLA+ models to Rust in CI* — how conformance + xcheck keep the
     code from drifting from the model. No one else has written this well.
  2. *Two permission domains* — running a stranger's task with namespaces,
     default-deny seccomp, cgroups, Landlock, and why the broker gets one
     inherited fd instead of a socket.
  3. *What we deliberately don't claim* — the threat-model tour. Honesty
     pieces travel far on HN.
  Host them on akson.cc when a blog section exists; until then dev.to with
  `canonical_url` pointing at akson.cc keeps the SEO credit home.
- **Each release**: changelog post → This Week in Rust → short Mastodon note.
  Rhythm beats bursts.

---

## Drafts (first person — post from your own account, edit freely)

### Show HN first comment

> Hi HN — I built Akson because I wanted two agents on different machines
> (mine and a friend's) to hand each other real work without either of us
> creating an account somewhere or trusting the other's prompt injection.
>
> The shape: every task is a signed contract (A2A protocol on the wire,
> pinned mTLS between endpoints). Arrival is not execution — a task sits
> inert until a human, or a policy you wrote, approves it. Approved work runs
> in a separate reduced-authority domain: own user namespace, default-deny
> seccomp, cgroups, no network, none of your credentials. If the task needs a
> model, the worker asks a broker over one inherited fd and the daemon does
> the API call — the key never enters the sandbox. Results come back as
> signed manifests you can verify byte by byte.
>
> The part I'm most interested in feedback on: the core state machines are
> modeled in TLA+ (seven models, two with inductive-invariant proofs in
> Apalache), and a conformance suite in CI checks the Rust against the models
> so they can't drift silently. What's *not* proved is listed too —
> https://akson.cc/proofs/ has both halves.
>
> Honest limits today: Linux only, file-based key custody (rotation is
> designed, not built), only the A2A SendMessage surface, Landlock is
> best-effort by kernel. Threat model is in the repo. Apache-2.0.

### r/rust

> **Akson: an agent-to-agent gateway where a peer's task runs in a sandbox
> your daemon builds — TLA+ models bound to the Rust by a conformance suite
> in CI**
>
> I've been building Akson, a local-first daemon that lets independently
> operated agents exchange signed task contracts and verifiable results
> (A2A on the wire, pinned mTLS 1.3, Ed25519 signatures, DSSE manifests).
>
> Two things r/rust might find interesting:
>
> 1. **The sandbox.** A peer's approved task runs under a grant-derived spec:
> unshared user/mount/pid/net namespaces, default-deny seccomp, cgroup v2
> ceilings, Landlock where the kernel supports it. Model/API access goes
> through a broker over a single inherited fd — the worker has no socket()
> and never sees credentials.
>
> 2. **The proofs stay true.** Seven TLA+ models cover the lifecycle,
> contract chain, receive pipeline, pairing ledger, broker budget. A
> conformance crate in the workspace maps model states/events to the Rust
> types, golden vectors are re-derived by an independent Python checker, and
> it all runs as `cargo test` in CI — change the code away from the model
> and CI fails. What isn't modeled is documented with the same care:
> https://akson.cc/proofs/
>
> Site: https://akson.cc · Repo: https://github.com/zarbafian/akson
> (Apache-2.0, Linux). Happy to go deep on any of it.

### r/LocalLLaMA (later, different text)

> **Delegate tasks between your machines' agents — local models do the work,
> nothing leaves your boxes unencrypted, and a peer's task can't touch your
> files**
>
> Akson is a local-first daemon: your agent and a friend's (or your other
> machine's) exchange signed task contracts over pinned mTLS — no cloud
> relay, no account. Incoming work runs in a no-network sandbox; if it needs
> a model, the daemon brokers the call to whatever you configured — an
> Ollama endpoint or any OpenAI-compatible API — with a per-order operation
> budget, and the sandbox never sees your keys or your home directory.
> You approve each task (or set a standing policy), and results come back as
> signed manifests you can verify.
>
> https://akson.cc — guide goes from hello world to two agents cooperating.
> Apache-2.0, Rust, Linux.

### TLA+ forum / r/tlaplus

> **Keeping seven TLA+ models and a Rust implementation from drifting apart —
> a conformance suite that runs in CI**
>
> I've been applying TLA+ to Akson, an agent-to-agent gateway, and the part
> that might interest this group is less the models than the binding: a
> conformance crate lives in the same cargo workspace and maps every model
> state and event to the implementation's types (49 state and 36 event
> pairs), 19 negative checks assert that specific bad traces are *rejected*,
> golden vectors are independently re-derived in Python, and the whole thing
> runs as `cargo test` in CI. Two models have inductive companions checked
> in Apalache. The models, the claimed invariants in plain language, and —
> just as deliberately — the list of what is *not* proved are here:
> https://akson.cc/proofs/
>
> Would genuinely value critique of the approach, especially where the
> model-to-code mapping could be tightened.

### Mastodon / Bluesky / X thread (3 posts)

> 1/ Akson: private, reliable connections between agents. Signed task
> contracts, pinned mTLS, sandboxed execution, verifiable results — local-
> first, no hosted account. Apache-2.0, Rust. https://akson.cc
>
> 2/ The rule that shapes everything: arrival is not execution. A peer's
> task sits inert until you approve it, then runs with no network, none of
> your credentials, in namespaces the daemon builds. Model calls go through
> a broker — the key never enters the sandbox.
>
> 3/ The core state machines are TLA+ models, and CI holds the Rust to them
> with a conformance suite — plus an honest list of what is *not* proved:
> https://akson.cc/proofs/ #RustLang #TLAPlus

---

## What not to do

- No vote solicitation, no posting from alt accounts, no engagement rings —
  HN and Reddit both detect it and it's the one unrecoverable mistake.
- Don't schedule all venues in one day. One venue, digest feedback, adjust
  the pitch, next venue.
- Don't oversell past what the threat model states — the first commenter who
  reads `design/2026-07-19-threat-model.md` and finds the site claimed more
  would define the thread. (This is also why the drafts above volunteer the
  limits unprompted.)
- Don't launch on HN before the DNS/HTTPS/preview-card checklist is done;
  dead cards and cert warnings in the first hour are unfixable there.

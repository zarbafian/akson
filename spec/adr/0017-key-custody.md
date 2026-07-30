# ADR-0017: Key custody — sealed keystore, key agent, rollback checkpoint

Status: proposed
Date: 2026-07-31 (v4. The review records, dispositions, and confirmation
reviews are **external artifacts** — they live in the private program
repository `akb-program` (`reviews/2026-07-30-adr0017-codex-review.md`,
`reviews/2026-07-30-adr0017-dispositions.md`,
`reviews/2026-07-31-adr0017-confirmation.md`,
`reviews/2026-07-31-adr0017-confirmation-r2.md`), not in this repository,
and reviewers of this repository cannot resolve them; they are cited as
context, and nothing normative below depends on reading them. v2 revised
after the independent adversarial review: v1's checkpoint and eviction
claims overreached, its socket registry could not boot a daemon, and its
migration state machine omitted reachable states. v3, after the
confirmation round, completed the agent-mode lifecycle the round proved
missing: executable lineage/checkpoint provisioning, a crash-total
root-proven `provision`, an offline quiescent `to-agent`, certificate
renewal, exact-manifest signing, a bounded reservation ledger, and an
operator exit from Recovery. v4, after confirmation round 2, makes the
transitions honest under concurrency, crashes, and retries: keyd's journal
gains a serialized writer, a complete fsync sequence, and corrupt-image
refusal; lineage adoption seals at the first successful open, not the
first reserve; certificate renewal becomes two-phase across its two files;
`recover ack` commits generation and audit in one transaction with
reserve-at-least; the exact-set signing rule ships as `key-binding.v2`
instead of mutating frozen v1; and consumed reservations return no
generation while the database's generation setter becomes a monotonic
compare-and-set.)

## Context

Custody today is two 32-byte owner-only files under the data dir
(`bootstrap.rs::load_or_init_secret`): `identity.seed` — the master seed from
which **every** purpose key and the work-order MAC derive (`aksond/keys.rs`)
— and `kek`, which wraps the store's DEK (ADR-0005). ADR-0009 built a
`KeyStore` trait and the degrade rule and *anticipated* `os-keystore`/`tpm`
adapters — but the daemon never adopted the trait: `DaemonState` owns
concrete `IdentityKeys`, bootstrap loads the two files directly, and the
external checkpoint is hardcoded `rollback_detectable: false`. The threat
model carries the residuals plainly: a local attacker with the user's uid
reads the master and KEK; rollback is undetectable (T13); the root's private
half alone is the identity (T14).

**The current bootstrap defect, stated precisely** (there is no deny-by-
absence today — `load_or_init_secret` regenerates any *individually* missing
file, so the failure shape depends on which file is missing):

- delete `identity.seed`, keep `kek`: a fresh master — and with it a fresh
  root and all purpose keys — is minted beside the existing database. A
  surviving `endpoint.der` is loaded without any check that its SPKI matches
  the new TLS key, so the failure surfaces later and confusingly at TLS
  setup, not at bootstrap.
- delete `identity.seed` **and** `endpoint.der`, keep `kek`: a coherent
  fresh identity and certificate are silently created beside the existing
  database — full silent identity replacement, the worst case.
- delete `kek` (with or without the seed): a fresh `kek` file is written,
  then the store's authenticated DEK unwrap fails. Noisy failure — but only
  *after* replacement key material was already generated on disk.

The program plan — `AKB-SOTA-PLAN.md` at the root of the private program
repository `akb-program`, an **external artifact** reviewers of this
repository cannot resolve — requires, under Phase 1 "Trust track (primary)":
"Replace interim key custody (ADR-0009) with real custody; make per-role UID
separation the documented recommended profile, not a footnote." This repo's own
implementation plan names the sandbox launcher (M9) its hardest milestone;
no priority superlative is claimed here. `deploy/` already has the
two-identity fleet arrangement this ADR extends.

One derivation fact governs the whole decision: a single master derives all
eight purpose keys and the work-order MAC (a keyed, domain-separated
SHA-256; deterministic, so identical bytes in mean identical keys out).
One-key-one-role holds at the **usage** layer; custody concentrates at the
master. The derivation currently lives inside `aksond` — private to the
daemon — which this ADR fixes by moving it to a shared normative module,
because a second implementation (the key agent) must produce the same bytes.

Continuity is more than the two secret files. Peers pin the TLS certificate
by SHA-256 over the **complete DER** (`cert.rs`), whose validity is minted
from the clock at generation time — so regenerating `endpoint.der` moves the
pinned fingerprint even when the key is unchanged. Tokens embed the raw root
public key (`token.rs`); peer records carry card, key-binding, and
security-projection digests (`identity.rs`). `endpoint.der` is therefore
**continuity state**, public or not, and this ADR treats it as such.

Evaluated:

- **(a) passphrase-sealed keystore** (KDF + AEAD, unlock ceremony) — closes
  at-rest/offline theft of *future logical copies* only (see the sealed
  section for the exact qualification).
- **(b) OS keyring** — **rejected as an assurance tier, on scoped grounds**:
  on the deployment this project supports (Linux, frequently unattended or
  headless), the named implementations (GNOME Keyring / Secret Service over
  D-Bus) provide no *portable, mandatory* per-client isolation — an unlocked
  collection is readable by any same-UID client, and per-client unlocking is
  permitted by the spec but not required of implementations — and headless
  availability is unreliable. What a keyring *does* provide (protection of
  the powered-off disk, inactive keyrings, swap) overlaps mode (a); it adds
  no process-boundary assurance over it. A keyring may later serve as a
  passphrase *source* or an at-rest backend where present — never as a
  silent fallback — and that is ergonomics, not this ADR.
- **(c) TPM2** — machine-binding for the sealed material and a real NV
  monotonic counter. **Deferred, not selected**: this ADR reserves the axis
  values and defers the entire composition to its own future ADR; nothing in
  this ADR's implementation plan builds or ships it (its section below).
- **(d) a key-agent process under its own UID** (the ssh-agent model) — the
  daemon never holds long-term private keys; typed operations over a narrow
  socket.
- **(e) tiers of the above** — chosen.
- **(f) a root-only split** — *possible*, contrary to v1 of this ADR: while
  the master still exists, migration can derive and persist every child
  seed, move only the root child into agent custody, and delete the master;
  derivation is deterministic, so no public material changes. It is
  rejected here on honest grounds instead: it multiplies persistent custody
  artifacts (eight child seeds, each needing the care the master needs
  today), still leaves every operational signing key extractable at the
  daemon's UID, and costs most of the agent build (protocol, provisioning,
  migration) while closing only offline *root* theft. A future ADR may add
  it as an intermediate tier; this one does not.

## Decision

Three custody modes, reported and reasoned about as **three independent
axes** — not a ladder, because no mode dominates the others on every axis:

| axis | values |
|---|---|
| process boundary | `daemon` \| `agent` |
| at-rest custody | `plaintext` \| `passphrase` \| `tpm` |
| rollback anchor | `none` \| `agent-file` \| `tpm-nv` |

The `tpm` and `tpm-nv` values are **reserved**: nothing in this ADR ships
them (the deferred-composition section below). Consequently, in this ADR
only `agent` mode has a rollback anchor.

`file` is daemon/plaintext/none. `sealed` is daemon/passphrase/none.
`agent` moves the process boundary; the agent's *own* keystore
is independently plaintext, passphrase, or TPM-wrapped, and is reported
separately — `agent` with a plaintext inner keystore protects long-term keys
from the daemon process but **not** from a copied whole-host disk, and
`sealed` without an agent protects the copied disk but not against a running
daemon compromise. Neither subsumes the other; `doctor` reports all three
axes so the operator sees which properties actually hold. **No mode ever
silently degrades to a weaker one** — a locked keystore or an unreachable
agent refuses to serve, and a checkpoint disagreement opens the store in
`Recovery` (process up, authority off — the Recovery section); none of them
falls back.

### The keystore file (all modes)

`data_dir/keystore.json`, schema version 1, strict I-JSON, at most 16 KiB,
`0600`, written atomically (temp + rename + dir fsync). It replaces `kek`
and `identity.seed` as the single custody artifact, and it is a **closed
discriminated union** on `custody` — exactly one of three shapes, unknown
fields refused (design §18; this file gets no unknown-field tolerance):

```json
{ "schema_version": 1, "custody": "file",
  "secrets": { "kek": "<b64url, exactly 32 bytes>",
               "master": "<b64url, exactly 32 bytes>" } }
```

```json
{ "schema_version": 1, "custody": "sealed",
  "kdf": { "alg": "argon2id", "version": 19, "m_cost_kib": 262144,
           "t_cost": 3, "p_cost": 1, "salt": "<b64url, exactly 16 bytes>" },
  "sealed_secrets": "<b64url: 0x01 ‖ nonce(24) ‖ ciphertext‖tag>" }
```

```json
{ "schema_version": 1, "custody": "agent" }
```

Rules — every violation refuses with a named problem, none regenerates:

- **KDF**: argon2id only (RustCrypto, pure Rust — §3.3), version 19 (0x13)
  only, output length 32. Salt exactly 16 bytes. Parameters are written at
  seal time (defaults: m=262144 KiB, t=3, p=1) and validated at load against
  accepted bounds: `m_cost_kib` ∈ [65536, 1048576], `t_cost` ∈ [2, 16],
  `p_cost` ∈ [1, 4]. Below the floor refuses because the offline-theft claim
  would be false; above the ceiling refuses because attacker-written
  parameters must not be a startup denial of service. Recorded-in-file means
  costs can be raised without a format change — within the bounds.
- **Sealing**: ADR-0005's versioned seal (XChaCha20-Poly1305). The AAD is
  `"akson.keystore.v1" ‖ 0x00 ‖` the canonical I-JSON of the file *minus*
  `sealed_secrets`. This authenticates the **semantic metadata in canonical
  form** — mode, schema version, every KDF parameter, the salt: changing any
  *value* fails the tag. It does not (and cannot) authenticate raw file
  bytes: whitespace or member-order changes canonicalize identically and are
  accepted, because they alter nothing the parser yields. And the tag is not
  the first line of defense: an unknown `custody` value, a wrong
  `schema_version`, or an out-of-bounds KDF cost is refused by the closed
  union and the bounds *before* any KDF run or AEAD open — those are
  structural refusals, not tag failures (the PR2 tests are split
  accordingly).
- **Inner plaintext** (the `file` variant's `secrets`, and the sealed
  variant's decrypted content): the canonical I-JSON object
  `{"kek": …, "master": …}`, keys sorted, both values exactly 32 bytes.
- **Passphrase bytes**: exactly the bytes of the source, with one trailing
  LF stripped if present; no other transformation (no Unicode
  normalization, no trimming). Non-empty, at most 1024 bytes. Stated so two
  implementations agree and a passphrase set on one host unlocks on another.

**Deny by absence:** a data dir holding a store (or an `endpoint.der`) but
no keystore and no complete legacy pair fails closed with
`identity-missing` — the daemon never mints identity material beside
existing state. A data dir holding **exactly one** legacy secret file fails
closed with `identity-incomplete`, naming the missing file and naming
restore-from-backup — not regeneration — as the fix (this replaces all three
current silent/late-failure behaviors listed in Context). Auto-init
(generate master + KEK, `file` mode) happens only on a truly empty data dir,
so `aksond serve` on a fresh machine stays one command.

**`endpoint.der` is required continuity state.** Beside an initialized
store it must exist: missing refuses (`identity-missing` class, naming the
restore), never regenerates. Its exact bytes are preserved by every
migration. At every bootstrap its SPKI is validated against the TLS public
key (local derivation or agent manifest); a mismatch refuses at startup with
the two fingerprints in the message — today a stale DER is loaded unchecked
and fails later and confusingly at TLS setup. In agent mode the check is
stronger — **exact-DER against keyd's manifest**, current or pending
renewal, with a pending renewal completed forward at startup (the
two-phase renewal rule in the registry) — because same-SPKI divergence is
exactly what certificate renewal can produce.

### `sealed` mode — recommended for a laptop / single-host operator

`akson keys seal` (prompts twice, reseals in place, atomic). Unlock sources,
in order: `$CREDENTIALS_DIRECTORY/akson.keystore-passphrase` (systemd
`LoadCredential`), `AKSON_KEY_PASSPHRASE_FILE`, an interactive prompt when
stdin is a TTY. None available → the daemon refuses to serve, with the fix
in the message. Fail closed, never regenerate.

Closes: theft of **future logical copies** — a data dir copied after
sealing, backups taken after sealing. Not the physical disk as such: the
same powered-off disk that holds the sealed keystore may also still hold
pre-seal plaintext in freed blocks (next bullet), so the claim is scoped to
copies made after sealing, never to the medium. **Does not close, and we
say so:**

- same-UID malware while the daemon runs (master, KEK, and DEK are in
  daemon memory); a keylogged passphrase; a passphrase file on the same
  filesystem as the keystore, which reduces at-rest protection back to
  `file` mode — `doctor` warns on exactly that arrangement.
- **the past**: sealing cannot unwrite bytes already on disk. The legacy
  plaintext files — and a plaintext `keystore.json`, if one ever existed —
  may persist in freed filesystem blocks, snapshots, and backups already
  taken (the design's own §15.5 secure-deletion limits). For that reason
  `akson keys migrate --seal` migrates *directly* from the legacy files to
  the sealed form, so the plaintext single-file form never touches disk on
  that path; and the claim is conditional on passphrase entropy and on
  swap/core-dump hygiene (the daemon is non-dumpable and zeroizes, below).

### `agent` mode — recommended fleet profile, with `deploy/`'s per-role UIDs

A new `akson-keyd` (crate `crates/akson-keyd`) runs under its own Unix
identity `akson-key` (third row in `deploy/sysusers.d`), owns its own
directory, and holds four things: the custody artifact **entire** (master
*and* KEK, in its own inner keystore — itself `file` or `sealed` now,
TPM-wrapped under the future ADR; composition, not a fourth mode), the
**checkpoint record** `{lineage_id, generation, trusted_time_floor,
adopted}` (lineage: random 16 bytes; `adopted` is the one-way flag that
closes fresh-database adoption, below), the **reservation ledger** (bounded,
below), and the **public manifest**. All of keyd's durable state lives in
**one journaled file**, governed by three rules — together they are what
makes provisioning, reservation, and renewal crash-total below:

- **Linearized mutations.** Every mutating operation (`provision`,
  `checkpoint-reserve`, `checkpoint-commit`, `checkpoint-adopt`,
  `renew-certificate`, `renew-commit`) executes on a **single serialized
  writer** — one mutex over the journal state; each mutation reads the
  committed image, computes its successor, persists it, and replies, all
  inside the critical section. Read-only operations (`describe`,
  `public-manifest`, `checkpoint-read`, `renew-status`, the signing,
  wrap, and MAC ops) may run concurrently against the last committed
  image. Connection concurrency (the limit of 8, below) is I/O
  concurrency, never state concurrency. Atomic replacement prevents a
  *torn* image; only serialization prevents *lost updates* — two
  concurrent reserves both computing G+1, a reserve and a renewal each
  persisting an image without the other's change — and v3 specified the
  first while silently assuming the second.
- **Durability sequence.** One commit is: write the temp file →
  **`fsync` the temp file descriptor** → rename over the journal →
  `fsync` the directory. The temp-file fsync is load-bearing: rename plus
  directory fsync makes the *name* durable, not necessarily the bytes
  behind it after power loss (v3 omitted it). The journal file is
  `0600`, owned `akson-key` — it carries the inner keystore.
- **Corrupt means refuse.** A journal that exists but fails to parse, or
  is short or torn, refuses every operation with `journal-corrupt` —
  keyd never silently reinitializes over a damaged image; an *absent*
  journal on a never-provisioned keyd is the only fresh state. The fix
  named in the problem is restore-keyd-from-backup, matching the
  daemon's own never-regenerate rule.

The daemon's `keystore.json` is the third variant, `{"custody":"agent"}` —
the mode marker lives in the same single artifact as every other mode.

The socket path and keyd's UID come from **root-owned configuration** (the
systemd unit environment in `deploy/`, or `/etc/akson/keyd.conf`,
`0644 root:root`) — never from a daemon-writable file. A transiently
compromised daemon must not be able to durably redirect its honest successor
to an impostor agent.

#### Wire protocol (held to the `control-protocol.md` standard)

- **Transport & framing**: one Unix stream connection per request. A single
  I-JSON request line, at most 64 KiB (the largest legitimate message — a
  card plus key-binding record for introduction signing — is a few KiB); a
  single I-JSON response line; the connection closes after the response.
  Timeouts: 5 s to first request byte, 30 s per operation. At most 8
  concurrent connections; excess wait, they are not refused — and
  mutating operations serialize on the journal writer regardless of how
  many connections carry them (the journal discipline above).
- **Versioning**: every request carries `{"keyd": 1, "op": …}`. Unknown
  version, op, or field → a stable RFC 9457 problem
  (`urn:akson:error:keyd-protocol`). Results are additive (ADR-0010); the op
  tags and argument names are the stable contract.
- **Admission, both directions**: keyd admits only the configured daemon
  UID via `SO_PEERCRED`, checked **before the request line is read**
  (ADR-0016's rule). And the daemon authenticates keyd the same way: after
  `connect`, it reads the listener's credentials via `SO_PEERCRED` and
  refuses to send anything if the UID is not the root-configured keyd UID.
  Mutual, because `SO_PEERCRED` is symmetric and a one-way check invites a
  same-UID impostor on either end.
- **Socket file rules**: keyd's runtime directory is owned `akson-key`,
  mode `0750` with the daemon's group — the grant is one visible OS act
  (ADR-0016's posture); the socket is `0660`. A stale socket file is
  removed at bind. The configured path must resolve without symlinks and
  without world-writable parent directories; keyd refuses to bind otherwise.
- **Errors** are RFC 9457 problems; no refusal names key material or
  reveals which keys exist.
- **Golden wire vectors** in `spec/vectors/keyd/` for every op, every
  refusal, the reserve/provision idempotency matrix, the reservation
  retention matrix (including the consumed-status reply), the renewal
  two-phase matrix, and the provisioning crash matrix, re-derived by
  `xcheck/`.

#### The operation registry (closed, deny by absence — and typed)

There is deliberately **no raw `sign(purpose, message)` over the root**: v1
had one, and an independent review demonstrated it permits a persistent
first-contact takeover — a compromised daemon generates its own TLS and
statement keys, has the real root sign the resulting card and introduction
proofs (introduction verification anchors only the root against the imported
token; every other binding is caller-presented), and first-contact peers pin
attacker-owned keys that survive eviction. Identity-establishing signatures
are therefore *manifest-validated*:

- `describe` → protocol version, the inner keystore's at-rest axis, status
  (`locked` | `ready`), provisioning state.
- `public-manifest` → all eight purpose public keys (JWK + RFC 7638
  thumbprint), the exact endpoint certificate DER, and the raw root public
  key. This is what the daemon serves tokens from (the token embeds the raw
  root key) and introductions from (six statement JWKs) — signatures alone
  cannot recover public keys, so a registry without this op cannot even
  boot a daemon.
- `sign-statement {purpose, message}` — operational statement signing, for
  `contract-proposal | contract-decision | task-result | evidence |
  requester-outcome` only. keyd binds purpose to key exactly as
  `PurposeKey` does; the socket cannot pull a key across roles. (This is
  the online oracle — named honestly under "what agent mode does not
  close" — but it cannot mint identity.)
- `sign-card {card}` — specified against what a card actually is today: the
  A2A Agent Card (`introduce.rs::signed_card`) carries name, interfaces,
  capabilities, and security schemes — **no key bindings and no TLS
  digest**; those live in the separate key-binding record of
  `IntroMaterial`, not in the card. So there is nothing key-shaped in a
  card for keyd to check against its manifest (v2 claimed such a check; it
  was vacuous), and this op is honestly what it is: keyd validates the
  presented card against the closed introduction profile
  (`profile::validate_agent_card` — required Akson extensions, mTLS-only,
  streaming/push off, extended card) and signs it with the agent-card key;
  a card failing the profile refuses (`card-profile`). Should a future card
  representation embed key bindings or a certificate digest, the
  exact-manifest rule below extends to it before keyd may sign.
- `sign-introduction {transcript, key_binding}` — **exact manifest, set
  equality, not subset**: the presented record's `keys` must equal keyd's
  manifest exactly — all six statement purposes (`agent-card`,
  `contract-proposal`, `contract-decision`, `task-result`, `evidence`,
  `requester-outcome`), each entry's JWK and thumbprint byte-equal to the
  manifest's, **no purpose absent and none extra** — and its
  `tls_certificate_sha256` must equal the manifest DER's digest. A missing
  entry refuses exactly as a mismatched one does (`binding-mismatch`); v2
  checked only what was *presented*, which let an omission through. Only
  then does keyd recompute the key-binding digest and return the
  per-purpose proofs over the bound transcript. Attacker-supplied bindings
  refuse; the v1 takeover is structurally unavailable. **Named spec
  change** (PR3): the exact-set requirement ships as **`key-binding.v2`**
  — a new `spec/ext/key-binding.v2.schema.json` whose `keys` object
  `require`s the full six-purpose set, with its own vectors. v1 stays
  byte-frozen: published schemas are immutable — a change is a new
  version (`spec/ext/README.md`) — and the published v1 artifacts
  genuinely inhabit the looseness (the valid v1 schema vector carries
  five keys, the introduction vectors three), so tightening v1 in place —
  v3's plan — would have rewritten published history in the very registry
  whose first rule forbids it. keyd enforces exact set equality
  **locally, regardless of which schema version a record claims**, and
  introduction with an agent-mode endpoint requires a v2 record on the
  wire. The compatibility consequence, honestly: **a v1-only peer cannot
  complete an introduction with an agent-mode endpoint until it upgrades
  to producing v2** — an incomplete record refuses at keyd either way
  (`binding-mismatch`), and versioning the boundary makes that refusal
  diagnosable rather than mysterious. (The current producer already emits
  all six purposes — `introduce.rs::statement_keys` — so upgrading is
  emitting what it already emits, labeled v2.)
- `sign-tls {message}` — the rustls `SigningKey` bridge for the TLS
  endpoint key; handshake transcripts by construction of use.
- `unwrap-dek {wrapped_dek}` / `wrap-dek {dek}` — the KEK **never crosses
  the socket**. Unwrap returns the store's current DEK (which the daemon
  necessarily holds while the store is open, and which is rotatable in
  place); wrap serves first store init — the store generates its DEK and
  must have it wrapped — and future DEK rotation. v1 released the KEK
  itself "once per store open"; that was a permanent exfiltration of a
  durable custody secret to any same-UID caller, mislabeled a session
  secret, and `SO_PEERCRED` cannot tell one same-UID process from another.
- `mac-work-order {canonical_bytes}` / `verify-work-order
  {canonical_bytes, mac}` — the work-order MAC key (derived from the master
  under a fixed label: a stable long-term authority, the other secret v1
  mislabeled) never crosses the socket.
- `checkpoint-reserve {reservation_id, floor?}` / `checkpoint-commit
  {reservation_id}` / `checkpoint-read` / `checkpoint-adopt {lineage_id}`
  — the §15.5 monotonic generation plus trusted time, persisted under
  keyd's UID. A plain reserve allocates strictly monotonically from the
  external value. The optional `floor` is **reserve-at-least**: the
  reserved generation is strictly above both the external value and
  `floor`; its one sanctioned caller is `akson recover ack` (Recovery
  below), whose acknowledged generation must clear a database value that
  can legitimately exceed keyd's — ordinary authority reserves never pass
  it and keep strict monotonic-from-external. Reserve is **idempotent
  while active**: keyd durably records (reservation_id → generation) in
  the journal before replying, so a lost response retried with the same
  id returns `{status: "active"}` and the same generation, burning
  nothing. **The ledger is bounded by a reservation lifecycle**, not
  append-forever (v2 grew it without bound): a reservation is *consumed*
  either by the next successful `checkpoint-reserve` with a new id —
  which acknowledges the prior generation — or by an explicit
  `checkpoint-commit {reservation_id}`; keyd retains the single active
  reservation plus at most the last **N = 32** consumed records.
  **Consumed is a terminal answer, not a replay**: a retry of a retained
  consumed id returns `{status: "consumed"}` with **no generation and no
  effects** — v3 called that retry "idempotent", which would hand a
  delayed caller a stale generation after its successor had already
  acted on a later one — and the daemon must not perform authority work
  under a reservation keyd reports consumed. A retry of an evicted id
  refuses `reservation-unknown` (safe: consumption means a later
  reservation was already acted on). The database end is hardened to
  match (**named store change**, PR5): `Store::set_state_generation`
  becomes a monotonic **compare-and-set** — it writes G only when G is
  strictly above the stored value, refusing otherwise
  (`generation-regression`) — so even a daemon bug replaying a stale
  reservation cannot move the database generation backward (today the
  setter accepts any value: `akson-store`'s `set_state_generation`
  writes unconditionally). `checkpoint-read` returns the full checkpoint
  record — generation, trusted-time floor, **lineage id**, `adopted` —
  and is naturally idempotent. `checkpoint-adopt` is the **one-way
  adoption seal**, called by the daemon at the first successful store
  open (the lineage rule below): it verifies the presented lineage id
  matches, flips `adopted` to true, and is idempotent thereafter; a
  foreign lineage refuses `lineage-mismatch`. Reserving has nothing to
  do with adoption — v3 sealed at first reserve, and the lineage section
  records why that was wrong.
- `renew-certificate {}` / `renew-commit {renewal_id}` / `renew-status {}`
  — **certificate generation moves into keyd in agent mode, as a
  two-phase transition**, because the certificate lives in two files
  under two UIDs — keyd's manifest and the daemon's `endpoint.der` — and
  a one-shot operation that commits keyd's side before the daemon has
  durably persisted its side (v3's shape) splits the brain on a lost
  reply or a daemon crash, invisibly, since both certificates share an
  SPKI and the SPKI startup check accepts either. Today the daemon mints
  the 365-day endpoint certificate at bootstrap
  (`bootstrap.rs::load_or_init_endpoint_cert`, `ENDPOINT_CERT_VALIDITY`)
  and peers enforce expiry at every handshake (`tls.rs::check_cert_time`)
  — a manifest that fixes the exact DER forever is therefore a scheduled
  outage. The phases:
  1. `renew-certificate` generates a fresh DER over the **same**
     tls-endpoint key (the shared `self_signed_endpoint` path; SPKI
     unchanged) and journals it as the **pending renewal** — one journal
     commit recording `{renewal_id, pending DER}` — returning both.
     **Both certificates are now valid-in-manifest**: `public-manifest`
     reports current and pending, and `sign-introduction` accepts either
     DER's digest while a renewal is pending (both are keyd-minted over
     keyd's own key; nothing foreign is admitted). Re-calling
     `renew-certificate` while pending returns the same `renewal_id` and
     DER — there is never a second pending state.
  2. The daemon durably writes the returned DER to `endpoint.der` (temp
     + fsync + rename + dir fsync) and **restarts its TLS listener** on
     the new certificate. A listener restart is the specified mechanism
     — no rustls hot-swap is claimed or relied on.
  3. Only after the listener serves the new DER: `renew-commit
     {renewal_id}` — keyd atomically makes the pending DER the
     manifest's only certificate. Commit of an unknown id refuses
     `renewal-unknown`; commit of the already-committed retained id is
     idempotent `ok` (lost-reply safety).
  **Startup reconciliation makes the transition total**: every
  agent-mode bootstrap calls `renew-status`. Renewal pending and
  `endpoint.der` byte-equal to the pending DER → the crash hit after
  phase 2; complete: listener on the new DER, then `renew-commit`.
  Pending and `endpoint.der` byte-equal to the *current* DER → the crash
  hit before phase 2; complete forward: re-persist the pending DER,
  restart the listener, commit — one deterministic direction, no
  operator choice. Byte-equal to neither → refuse
  `certificate-divergence` (restore, never regenerate). In agent mode
  the bootstrap continuity check is therefore **exact-DER against the
  manifest** (current or pending), strictly stronger than the all-modes
  SPKI check — same-SPKI divergence, the split v3 could not see, cannot
  survive a start. **The peer-facing consequence, honestly**: peers pin the DER
  digest via the introduction key-binding (`tls_certificate_sha256`), so
  renewal moves the pinned digest and every peer must accept the new one
  through the only path that exists — the explicit §8.4 re-pair
  (`Store::remove_peer` then a fresh, operator-confirmed pairing;
  `akson-store/src/lib.rs`'s documented re-pair flow). No in-band
  certificate-rotation announcement exists in the protocol; that is a
  **named systemic gap** (`cert-rotation-unannounced`) affecting every
  custody mode, which this ADR does not solve. `doctor` warns starting 30
  days before `notAfter` (and the daemon logs the same warning at startup
  in that window), so the operator schedules re-pairs instead of
  discovering an expired fleet.
- `provision-challenge {}` — returns a single-use random nonce (TTL 5
  minutes, one outstanding at a time), the freshness half of the
  provisioning proof below.
- `provision {keystore, endpoint_der, lineage?, generation?,
  trusted_time?, nonce, root_signature}` / `provision-status` — the
  `keys to-agent` import and fresh agent-mode init (Migration below).
  **Verifiable without a root oracle**: the prover is the migration tool,
  which at that moment legitimately holds the master — it derives the root
  child through the shared derivation module and signs
  `"akson.keyd.provision.v1" ‖ nonce` **directly, with no keyd operation
  involved**; the signature is an *input* to `provision`, never the output
  of any keyd op, so no root-signing oracle re-enters the registry. keyd
  verifies the nonce is the outstanding one and the signature verifies
  under the root public key it derives from the submitted master —
  proving the submitter holds the root matching the material, freshly.
  Lineage and checkpoint seeding: a migration from an existing store
  carries the store's lineage id, current generation, and trusted time
  (keyd persists them with `adopted: true`); a fresh init carries none and
  keyd mints lineage, generation 0, trusted-time floor = provisioning
  time, `adopted: false`, returning all three. **Crash-total**: keyd
  persists the *entire* provisioned set — inner keystore, DER, manifest,
  lineage, checkpoint seed, provisioning status — in **one atomic journal
  commit** before replying `ok` with the manifest; after any interruption
  the set is either fully present or fully absent, and `provision-status`
  never reports a partial state. Idempotent by content: re-provisioning
  byte-identical material is `ok` (a fresh nonce is still required);
  different material while provisioned refuses.

#### What `agent` mode closes — and what it does not

**Closes: offline extraction of long-term keys by the daemon's UID.** The
master, every purpose private key, the KEK, and the work-order MAC key exist
only at keyd's UID; T14's "steal the root, impersonate at first contact"
now requires compromising `akson-keyd` or root, not the large,
network-facing daemon. Manifest validation additionally closes the
signed-in attacker-key path above.

**Narrows, not closes, and we say so — the online-authority residual:** an
attacker resident at the daemon's UID while the agent is up holds this
endpoint's *online authority*: it can sign statements, complete TLS
handshakes, and drive every operation the daemon may drive, for as long as
it is resident. What it cannot do is leave with the keys or get foreign
keys signed into identity material. **Eviction therefore ends the key
compromise but not the ledger of what was done**: relationships created or
materially changed during the compromise window were made with the real
keys and are not made trustworthy by eviction — post-compromise recovery
includes reviewing introductions, pairings, and contract decisions since
the window opened, and re-pairing where trust was minted. v1 claimed
eviction ends the compromise without re-pairing; with a raw signing oracle
that was false, and even without one it overreached. An agent configured
under the daemon's own UID is a nominal boundary; `doctor` warns.

**Rollback detection (T13), narrowed to what this design delivers.** The
checkpoint detects **an unmodified supported backup restored by an honest
operator while keyd's checkpoint survives** — the operational §15.5 case:
the store opens in `Recovery` and automatic authority stays off. It does
**not** detect an adversary at the daemon's UID, and this ADR does not
claim it does: the database's generation is an unauthenticated `meta` row
the daemon UID can rewrite, `checkpoint-read` tells that adversary the
expected value, and no blind external scalar can distinguish legitimate
current state from a relabeled old state. Two hardenings close the
*accidental* corners — and, unlike v2, which asserted a lineage "persisted
on both sides" while no operation established it on either, both are now
executable:

- **keyd's side**: the checkpoint record carries the lineage id, seeded by
  `provision` (carried from an existing store, or minted at fresh init)
  and returned by `checkpoint-read` (the registry above).
- **the store's side**: a new **`store_lineage` meta row**. No DDL — the
  existing `meta` key/value table (`schema.rs`) takes new keys without a
  `user_version` bump; the named schema change is `ExternalCheckpoint`
  gaining `lineage` plus a fresh-adoption flag, and the adoption/refusal
  rules in `Store::open`, landing in **PR5**. `keys to-agent` writes the
  row into the existing database (fsynced) *before* provisioning keyd
  with the same id, and a re-run re-reads it rather than re-minting, so a
  crash can never leave the two sides holding different ids.
- **the handshake at every open**: the daemon reads keyd's full checkpoint
  record and passes lineage into `Store::open`. A database whose
  `store_lineage` differs from keyd's refuses (`lineage-mismatch` — a
  foreign database). A **fresh** database (no wrapped DEK) adopts the
  external checkpoint and lineage **only while keyd's `adopted` flag is
  false**. **Adoption seals at the first successful open**: once
  `Store::open` returns — lineage verified, or freshly adopted with the
  `store_lineage` row durably written — and **before the daemon serves
  any request**, the daemon calls `checkpoint-adopt`; keyd flips
  `adopted` one-way. From then on a fresh or lineage-less database
  beside the initialized checkpoint refuses (`lineage-missing`) instead
  of adopting — today a deleted `state.db` silently adopts the current
  counter on first open (`lib.rs`'s first-init arm). v3 sealed adoption
  at the first `checkpoint-reserve` and called everything earlier
  harmless — "no authority state exists to roll back". The confirmation
  round disproved that using the design's own vocabulary: operations
  that are inert *by design* still write durable state that matters,
  with no reserve anywhere in their path. Coordination staging persists
  a sealed payload, an event, and an audit row (`coord.rs::stage`,
  `Store::stage_contract`), requires no prior peer (an empty performer
  is allowed), and is *proven* non-authority by its own test; peer
  import, pairing commit, auto-approve policy, and processor
  configuration are likewise direct store writes today. No
  operation-to-reserve classification can close that class — inert
  writes are the point of staging — so the seal moves to the strictly
  earliest event instead: a daemon cannot durably mutate a store it has
  not opened, hence no durable state of any kind — authority, inert, or
  audit — can predate a first-open seal. The remaining crash window
  (open succeeded, `checkpoint-adopt` not yet acknowledged) contains no
  served requests and therefore no user state; a re-open re-runs the
  handshake and seals.

The adversarial gap — same-generation relabelling by the daemon UID, whose
reach includes rewriting the plaintext `store_lineage` row — is a **named
residual with a claim-pinning test**, so the claim can never silently
inflate. Actually closing it requires replay-sensitive state
transitions validated *outside* the daemon (the agent authenticating state
digests, not holding a counter); that is future work in its own ADR.

#### Recovery semantics — one behavior, enforced centrally

Checkpoint disagreement opens the store in `Recovery` for diagnostics; the
process does not exit. The matrix (aligned with design §8.5's
time-uncertain recovery) is exhaustive and lives at one chokepoint:

- **Refused in Recovery**: introduction dial and accept, peer import and
  removal, contract acceptance and every work-order issue (manual *and*
  automatic), processor calls, coordination consent mint and dispatch,
  certificate renewal (either phase — `renew-certificate` and
  `renew-commit`). Each refusal names the recovery path: `akson
  recover ack`, below.
- **Allowed in Recovery**: `doctor`/`status`/`diagnose`, read-only
  listing, export — and `akson recover ack`, the one authority-adjacent
  mutation allowed, because it *is* the exit.

**The exit is an explicit operator acknowledgement — `akson recover ack`**
(v2 said "re-reserve converges" with no transition that performs it; this
is that transition). The operator inspects (`doctor`/`diagnose` name the
disagreement: external generation, database generation, lineage), decides
the restored state is the state they want, and runs `akson recover ack`.
The flow, in three steps whose boundaries are the only crash points:
verify lineage matches (a `lineage-mismatch` is not acknowledgeable — that
is a foreign database, and the fix is restoring the right one); then
`checkpoint-reserve` with a fresh reservation id **and `floor` = the
database generation** — reserve-at-least, the registry's one sanctioned
use — obtaining generation G strictly above both the external and
database values (v3 promised that G while reserving strictly from the
external value, which is arithmetically impossible when the database is
ahead — the direction a restored-older-keyd mismatch produces); then
**one database transaction** that both writes G into `state_generation`
and appends the `recovery.acknowledged` audit row carrying both prior
values — the generation change and its audit record commit or roll back
together, which is what design §15.3's shared-transaction rule requires
and v3's audit-after-commit ordering violated; then `checkpoint-commit`
the reservation. The next open compares equal and is `Normal`. The crash
intervals, exhaustively: **before the database transaction** — external
and database still disagree, the next open re-enters `Recovery`, and the
ack re-runs (the retained active reservation replays the same G; a fresh
reserve consumes it — either way the funnel holds). **After the database
transaction** — the generations compare equal *and the audit row is
already present*, because it committed in the same transaction, so the
next open is `Normal` with nothing unrecorded; the dangling reservation
is closed by an idempotent `checkpoint-commit` retry at that open, or
consumed by the next authority reserve. There is no interval in which
the database moved and the audit did not. Its own refusal matrix row:
`recover ack` refuses in `Normal` (`nothing-to-ack`), refuses on
`lineage-mismatch`, and refuses when the checkpoint anchor is
unreachable — it never edits the checkpoint side, only re-reserves
through it.

Enforcement is central — the store refuses authority-issuing mutations in
`Recovery` at its own transaction boundary, and every listener path
(receive, reactor, worker, coord, admin) asserts the same predicate rather
than each choosing its own. **Defect, found by the review and confirmed on
main:** the automatic reactor never checks `automatic_authority_enabled`
before approving and issuing work — today the flag is merely *reported* in
capability evidence and enforced nowhere. PR1 fixes this with a break-first
test (a store in `Recovery` plus an auto-approvable task must issue
nothing; on main it issues).

### `tpm` composition — explicitly deferred; nothing here ships it

**This ADR does not build, gate, or ship any TPM support.** v2 kept TPM
selected in present tense while deferring its entire design; that was not
an enforceable decision, and this revision makes the deferral itself the
decision: the `tpm` (at-rest) and `tpm-nv` (rollback-anchor) axis values
are *reserved*, no PR in the implementation plan touches them, no `tpm`
feature or `tss-esapi` dependency is added, and no assurance involving a
TPM is claimed. Until the future ADR lands, `sealed` mode's rollback
anchor is `none` — in this ADR only `agent` mode has one.

What the composition *would* be — recorded so the axis values mean
something — is machine-binding: sealing the keystore's wrapping secret to
the TPM protects the blob **moved off the machine** (a copied directory, a
backup, a pulled disk) with no passphrase to type; without a measured-boot
PCR policy and an authorization value it does not protect a stolen whole
machine that can boot into an allowed state and ask its own TPM to unseal;
an NV monotonic counter gives the checkpoint scalar hardware monotonicity —
which changes nothing about the relabelling residual above. Ed25519
signing residency on target hardware is **not assumed** (asserted in v1;
unverified). The gate is the composition's **own future ADR**, which must
specify the object and PCR policies, boot and user-presence assumptions,
NV lifecycle (provisioning, TPM-clear, lockout, write endurance), failure
recovery, and a supported-hardware survey before any of it is built.

### Migration

`akson keys migrate`, also run automatically at bootstrap when only the
legacy pair exists (the `file`-mode developer path stays zero-ceremony).
Byte-preserving: the master, KEK, and `endpoint.der` bytes are unchanged,
and since derivation is deterministic, every thumbprint, token, pinned
certificate fingerprint, and the database's decryption are unchanged — no
peer re-pairs. Steps, each fsynced (file, then directory): write
`keystore.json.tmp` → rename to `keystore.json` → delete `identity.seed` →
delete `kek`.

Bootstrap resolves the artifact state by **one total precedence table**
(K = `keystore.json`, T = `keystore.json.tmp`, S = `identity.seed`,
E = `kek`, D = store present, C = `endpoint.der` present — v2 omitted C,
so an `endpoint.der`-only directory matched "truly fresh" and auto-inited,
contradicting the continuity rule; C is now a table variable). A leftover
T is never read — it is removed and the row below applies:

| on disk | verdict |
|---|---|
| no K, no S, no E, no D, no C | auto-init `file` (truly fresh) |
| no K, no S, no E, C present (with or without D) | refuse `identity-missing` — `endpoint.der` is continuity state; restore the identity it belongs to, or remove it deliberately |
| no K, no S, no E, D present | refuse `identity-missing` |
| no K, S+E | legacy: run migration |
| no K, exactly one of S/E | refuse `identity-incomplete` (the Context defect, now fail-closed) |
| K only | open by K's variant |
| K + S + E | crash before deletions: K's secrets must equal S/E → delete both (fsync dir); unequal → refuse `migration-ambiguous` |
| K + exactly one of S/E | crash between the two unlinks: the survivor must equal K's copy → delete it (fsync dir); unequal → refuse `migration-ambiguous` |
| K = `agent`, keyd ready, lineage agrees | open over the socket |
| K = `agent`, keyd ready, store lineage absent or foreign | refuse `lineage-missing` / `lineage-mismatch` (the rollback-detection rules; fresh adoption only while keyd is unadopted) |
| K = `agent`, keyd unreachable/unprovisioned | refuse, fix in message — never a fallback to local files |
| K = `agent` + S present | leftover seed from a pre-`to-agent` state: derive its public keys through the shared module and compare against keyd's manifest → equal: delete it (fsync dir); else refuse `migration-ambiguous` |
| K = `agent` + E present | leftover KEK — **no derived public form exists to check** (v2's "verify derived public keys" was impossible for the symmetric KEK). D present: unwrap the store's wrapped DEK locally under E *and* via keyd `unwrap-dek`; equal DEKs → same KEK → delete E (fsync dir); unequal → refuse `migration-ambiguous`. No D: no equality is checkable → refuse `migration-ambiguous`, naming deliberate operator removal as the fix |

Two rules stand beside the table. **Quiescence**: the table is evaluated
by exactly one process — the daemon at bootstrap; `keys migrate` and `keys
to-agent` are offline operations that refuse with `daemon-running` while a
daemon holds the data-dir lock (`aksond.lock`, below). **Read-once**: the
daemon reads its custody mode from this table exactly once, at bootstrap;
no path re-reads it while serving, so a running daemon never changes
custody mid-flight — mode changes take effect at the next start, stated
plainly under `keys to-agent`.

Every row is exercised by fault injection after every write, fsync, rename,
and unlink (the recovery matrix below). No migration journal is needed
*because this table is total*: the artifact set itself encodes the state,
and both single-survivor crash states — which v1 failed to name — resolve
by the equality checks above.

**`keys to-agent`** moves the custody artifact **entire** — master *and*
KEK (v1 said "the master" while defining keyd as holding the KEK; both go).
An explicit operator step, available only once agent mode is whole
(implementation plan), and **offline by specification**: v2 provisioned
keyd and renamed a file while saying nothing about a running daemon — which
keeps concrete keys in memory (`DaemonState`) and keeps serving TLS off its
local key (`receive_serve.rs`), so both sides would have been live at once
and the exactly-one-authority claim was false as written. The phases:

0. **Quiesce**: the tool takes the exclusive data-dir lock (`aksond.lock`,
   the flock the serving daemon holds for its whole lifetime — PR1) with a
   non-blocking attempt; a held lock refuses `daemon-running` before any
   byte reaches keyd. The daemon is stopped first, by the operator; the
   tool never stops, drains, or races it.
1. **Lineage**: read the store's `store_lineage` meta row, or mint it (16
   random bytes) and write it, fsynced, if absent — a re-run *re-reads*
   rather than re-mints, so provisioning stays content-idempotent. Read
   the database's current generation and trusted time as the checkpoint
   seed.
2. **Provision, with proof**: fetch a nonce via `provision-challenge`;
   derive the root child from the master (shared derivation module) and
   sign `"akson.keyd.provision.v1" ‖ nonce` with it **directly** — the
   tool legitimately holds the master at this moment, and no keyd
   operation signs anything here; the signature is an input to
   `provision`, not an oracle's output. Send `provision {keystore,
   endpoint_der, lineage, generation, trusted_time, nonce,
   root_signature}`. keyd verifies and persists the full set in one
   atomic journal commit before replying `ok` (registry above), so a lost
   acknowledgment is recovered by re-sending and an interrupted persist
   leaves nothing partial.
3. **Verify**: the tool independently derives the same manifest from the
   material it sent and compares byte-for-byte — all eight thumbprints,
   the certificate DER, the root key — against what `provision` returned.
4. **Activate**: only after 3 verifies, atomically rename a new
   `{"custody":"agent"}` keystore over `keystore.json` (temp + rename +
   dir fsync). This one atomic step both installs the pointer and removes
   the local secrets — there is no window in which the secrets exist in
   zero or two authoritative places. **Activation takes effect at the
   next daemon start**: custody mode is read once at bootstrap
   (the read-once rule above), so no running daemon flips mid-flight —
   there is none running, by phase 0 — and the operator's restart is the
   moment agent mode begins.

Crash before 4: keyd is provisioned, custody is still local — `doctor`
warns (`agent provisioned but custody local`), re-running converges (same
lineage, same bytes, fresh nonce). Crash during 4: the rename is atomic —
either the old keystore or the pointer. After 4: keyd is authoritative;
keyd state lost afterwards refuses to serve (restore keyd from its backup —
no fallback exists to fall to).

### Shared derivation module

The identity derivation moves verbatim from `aksond/keys.rs` into a
normative `akson-crypto::derivation` module: master → eight purpose seeds +
the work-order MAC key, the exact
`SHA-256("akson/identity-key/v1/" ‖ label ‖ 0x00 ‖ master)` scheme, labels
pinned. Golden vectors in `spec/vectors/derivation/` cover all nine outputs
from a fixed master and are re-derived by `xcheck/` — keyd and the daemon
share one implementation, and any second implementation is held to the same
bytes. (This move also corrects a false doc comment on main:
`keypair.rs::from_seed` claims it is "never for production key material,"
while the daemon's production path is exactly that function.)

### `akson doctor`

A `custody` block beside the sandbox block, machine-readable through
`Diagnose` — the three axes, separately:

```
custody:
  process boundary  agent (keyd reachable, uid akson-key) | daemon
  at rest           keyd: sealed (unlocked) | plaintext file | passphrase | tpm
  rollback anchor   agent-file | tpm-nv | none
  keystore          ~/.local/share/akson/keystore.json  0600  (custody: agent)
  endpoint cert     endpoint.der present, SPKI matches tls-endpoint key,
                    notAfter 2027-07-30
  warnings          passphrase file shares the keystore's filesystem;
                    agent runs under the daemon's own uid;
                    legacy key files still present;
                    agent provisioned but custody still local;
                    endpoint certificate expires within 30 days —
                    renewal moves the pinned digest; peers re-pair (§8.4)
```

In `agent` mode the at-rest row is keyd's own answer (via `describe`), so
`agent` over a plaintext inner keystore is visible for what it is. `file`
mode is named `plaintext` in the developer's terminal, every time.

### Threat model updates (design/2026-07-19-threat-model.md)

- **New actors, with explicit capabilities** (the current table trusts
  same-UID processes and has no compromised-daemon actor at all):
  *compromised daemon process* (arbitrary code at the daemon's UID, network
  reachable); *other daemon-UID process* (same authority, no daemon
  memory); *keyd process / keyd-UID process*; *root* (holds everything —
  named, not defended); *whole-host snapshot holder* (offline copy of both
  UIDs' state; defeated only by `sealed` at-rest custody — or `tpm`, once
  its own future ADR ships it).
- Residual 1 ("key custody is interim") is rewritten as the axes table:
  per mode, which of the three axes hold and against which actor.
- T13's mitigation row gains the external counter — **scoped to
  honest-operator restores** — plus the lineage-id no-silent-adoption rule,
  and a new explicit residual: daemon-UID generation relabelling is
  undetected until transition validation lands (future ADR).
- T14 is rewritten for `agent` mode: offline root extraction requires
  keyd's UID or root; the online-authority residual and the
  review-and-re-pair rule for window-created relationships are recorded.
- New residuals: the online signing authority while resident; the
  passphrase entry surface; and — in every mode — the DEK and, in local
  modes, the master/KEK in daemon memory, bounded by `zeroize`-on-drop and
  marking the daemon non-dumpable at bootstrap (bounded, not closed).

## Consequences

- The README's "key custody is interim (ADR-0009)" caveat retires in favor
  of the axes table; `deploy/` gains the third identity, its unit, root-
  owned keyd configuration, and the recommended-profile framing the program
  plan requires. Defaults do not move: `file` mode remains what a bare
  `aksond serve` gets, and remains labeled `plaintext` by doctor.
- **ADR-0009 is partially superseded.** Its degrade rule (report rollback
  detection unavailable and operate, rather than block) stands. Its
  `KeyStore` trait does not: the trait returns borrowed concrete keys with
  an infallible in-memory `advance_state_generation` (only `put` returns
  `Result`), and was never adopted by the daemon — and it cannot represent
  remote fallible signing, a public manifest, DEK wrap/unwrap, MAC
  operations, or reserve retries. It is replaced by four fallible seams
  the daemon is made to *actually depend on*: `IdentitySigner` (describe /
  public manifest / typed signing / the two-phase renewal —
  `renew-certificate`, `renew-commit`, `renew-status`), `StoreCustody`
  (wrap/unwrap DEK), `WorkOrderAuthority` (mac/verify), and
  `CheckpointAnchor` (reserve/commit/read + lineage). Local modes
  implement them in-process; `agent` implements them over the socket.
  ADR-0009's header gains "partially superseded by ADR-0017" in the
  paperwork PR; its anticipated `keyring`-crate adapter is explicitly not
  built (Context records the scoped rejection).
- The fail-closed surface grows on purpose: locked keystore, unreachable
  or impostor agent, incomplete legacy pair, missing `endpoint.der`, SPKI
  mismatch (exact-DER divergence in agent mode), ambiguous migration,
  malformed or out-of-bounds keystore, a lineage that is missing or
  foreign, a corrupt keyd journal, a database generation moving backward,
  and `keys migrate`/`keys to-agent` against a running daemon all refuse;
  a checkpoint disagreement opens `Recovery` (diagnostics only) with
  `akson recover ack` as its explicit operator exit. Each refusal names
  its fix; none regenerates key material.
- **Named spec change**: a new `spec/ext/key-binding.v2.schema.json`
  requiring the full six-purpose key set, with its own vectors (PR3). v1
  is byte-frozen — published schemas are immutable, a change is a new
  version (`spec/ext/README.md`) — and the compatibility consequence is
  stated plainly: a v1-only peer cannot introduce with an agent-mode
  endpoint until it produces v2.
- **Named systemic gap, not solved here**: `cert-rotation-unannounced` —
  no in-band path tells peers a renewed certificate's new digest; renewal
  rides the explicit §8.4 re-pair, and `doctor` warns 30 days out.
- New dependencies: `argon2`, `zeroize` (both RustCrypto/pure Rust, §3.3).
  No `tss-esapi` and no `tpm` feature — the TPM composition is deferred to
  its own ADR, which brings its dependency. A new crate `akson-keyd`, one
  more socket protocol held to the ADR-0016 admission standard **in both
  directions**, a data-dir lifetime lock (`aksond.lock`), and a normative
  shared derivation module.
- Affected threat cases: T13, T14, residuals 1 and 3, plus the new actors.
  Test vectors: keystore golden files for all three variants (including a
  sealed vector with fixed KDF parameters), derivation golden vectors
  (eight purposes + work-order MAC), keyd wire vectors including every
  refusal, the reserve/provision idempotency matrix with **reservation
  retention** (consumption by successor, `checkpoint-commit`, the N = 32
  cap, the consumed-status no-generation reply, evicted-id refusal), the
  provisioning **crash matrix** (interrupt at every persistence point;
  all-or-nothing), the **renewal two-phase matrix** (pending and
  committed sets at every crash point, both files), the
  `key-binding.v2` schema vectors (valid, plus each purpose absent
  refusing), and the recovery matrix below.

## Implementation plan

Ordered PRs, each shippable alone behind the unchanged `file` default.
**Gate rule: agent mode is not selectable until it is whole** — the daemon
refuses `custody:"agent"` with `custody-unavailable` until remote TLS
signing, manifest validation, and checkpoint enforcement have all landed;
`keys to-agent` ships last. (v1 called PR3–PR5 independently shippable;
they were not: `to-agent` before remote TLS signing leaves a nonfunctional
or key-retaining daemon, and agent mode was defined as checkpoint-holding
while the checkpoint waited two PRs.)

Test honesty rule, replacing v1's blanket claim: every test below is
labeled **[red-on-main]** (an executable assertion that fails on today's
code), **[claim-pin]** (asserts a *residual* so the claim cannot silently
inflate), or **[conformance]** (new-scaffold behavior; the mutation named
is introduced and watched to fail before the fix, but no main baseline is
claimed, because the scaffold does not exist on main).

1. **Keystore file, migration, deny-by-absence, endpoint continuity,
   Recovery enforcement, the data-dir lock, memory hygiene.** The closed
   schema and parser, `keys migrate` + auto-migrate, the precedence table,
   the `identity-missing`/`identity-incomplete` refusals, the
   `endpoint.der` SPKI check and fail-closed-on-missing, the central
   Recovery matrix with the reactor fix, `aksond.lock` (an exclusive
   flock the serving daemon takes at bootstrap and holds for its
   lifetime; offline key operations take it non-blocking and refuse
   `daemon-running` on contention), `zeroize` + non-dumpable.
   - [red-on-main] delete `identity.seed`, keep `kek`: assert bootstrap
     refuses `identity-incomplete`; on main it mints fresh purpose keys.
   - [red-on-main] a data dir holding only `endpoint.der`: assert refusal
     `identity-missing`; on main a fresh identity is minted beside the
     stale DER, which is loaded unchecked and fails later at TLS setup.
   - [conformance] `keys migrate` while a daemon holds `aksond.lock`:
     refuses `daemon-running`, and the data dir's file inventory is
     byte-identical after the refusal.
   - [red-on-main] delete `identity.seed` **and** `endpoint.der`, keep
     `kek`: assert refusal; on main a coherent fresh identity silently
     appears beside the database — the worst of the three cases.
   - [red-on-main] delete `kek` (and separately: both secrets): assert
     refusal **before any file is written** — oracle: the data dir's file
     inventory is byte-identical after the failed start; on main a fresh
     `kek` is written before the DEK unwrap fails.
   - [red-on-main] a `keystore.json` present on main changes nothing (main
     ignores the unknown file); after PR1 it is authoritative — asserted by
     planting a keystore with different secrets beside legacy files and
     requiring `migration-ambiguous`.
   - [red-on-main] Recovery reactor: build state via `from_parts` over a
     store opened in `Recovery` (generation mismatch), submit an
     auto-approvable task, run one reactor sweep; assert **no work order
     row and an unmoved contract head** (durable no-effect oracle). On
     main the reactor issues — it never consults
     `automatic_authority_enabled`.
   - [conformance] corrupt / truncate / chmod-0644 the keystore; each KDF
     bound violated one field at a time (below floor and above ceiling
     separately); salt ≠ 16 bytes; unknown field; > 16 KiB file — each
     asserts its named problem type and no partial state.
   - [conformance] kill -9 injected after every write/fsync/rename/unlink
     of migration: rerun converges to a table row; across the run, token
     bytes, all six statement JWKs, every purpose thumbprint, the exact
     certificate DER and fingerprint, and database decryption are
     byte-identical, and an untouched peer's end-to-end acceptance still
     passes.
   - [conformance] the full Recovery matrix: every refused op asserts its
     problem *and* a durable no-effect oracle; every allowed op answers.
2. **`sealed` mode.** Seal/unseal, `--seal` direct migration, the three
   unlock sources, the doctor block.
   - [conformance] wrong passphrase: refusal, and the keystore's bytes and
     directory inventory unchanged (no partial state).
   - [conformance] **refusals before unseal** (structural, not tag): an
     unknown `custody` value, a wrong `schema_version`, and each KDF cost
     outside its bounds are refused by the closed union and the bounds
     with their named problems, asserting **no KDF run and no AEAD open
     was attempted** — these can never be tag tests, because the closed
     union and the DoS ceilings reject them first.
   - [conformance] **AEAD-tag failures** for in-range mutations only: flip
     a salt byte, move one KDF cost to a *different in-bounds* value, and
     flip a ciphertext byte — each asserts **tag failure**, not
     parse-level failure. (The AAD authenticates canonical semantic
     metadata; a re-serialization that canonicalizes identically is
     accepted, and the vector set includes one such re-encoding as a
     positive case.)
   - [conformance] plant a marker in the inner object; grep the sealed
     file and a simulated backup (§20.7 style) — plus the honest twin: the
     *legacy* files' bytes are asserted still recoverable from a pre-seal
     backup, pinning the "cannot unwrite the past" paragraph.
   - [conformance] locked start with no source: refuse-to-serve with the
     fix named; passphrase file on the keystore's filesystem: the warning.
3. **`akson-keyd`: crate, wire protocol, provisioning with proof,
   two-phase renewal, deploy profile — agent not yet selectable.** The
   full registry (including `provision-challenge`, the extended
   `provision`, `checkpoint-commit`, `checkpoint-adopt`, and the
   two-phase `renew-certificate` / `renew-commit` / `renew-status`), the
   journal under its full discipline (serialized writer, temp-fsync
   durability sequence, `0600` ownership, `journal-corrupt` refusal),
   mutual admission, sysusers + unit + root-owned config, the new
   **`key-binding.v2`** schema and vectors (v1 byte-frozen, untouched),
   `verify.sh` coverage.
   - [conformance] wrong-UID client refused before the request line is
     read — real-socket matrix over **every** op (`coord_boundary.rs`
     style).
   - [conformance] impostor server: a listener at the configured path
     under a wrong UID — the daemon refuses before sending any bytes.
   - [conformance] outside-registry op, unknown version, oversize line,
     slow-loris: each stable problem; nothing logged that names keys.
   - [conformance] `sign-introduction` exact-manifest matrix: one binding
     *mismatched* — for each of the six statement keys and the
     certificate digest independently — and one binding *absent*, for
     each of the six independently, plus one extra unknown entry: every
     case refuses `binding-mismatch`. The mismatch half is the review's
     first-contact-takeover attack, kept as a permanent vector; the
     omission half is what v2's presented-entries check let through. Plus
     the version boundary: a five-key record that is *valid under frozen
     v1* refuses `binding-mismatch` — keyd's exact-set rule is
     schema-version-independent — and agent-mode introduction requires
     v2 on the wire; the v1 schema file and its vectors are asserted
     byte-identical to their published form.
   - [conformance] `sign-card`: a card failing the closed introduction
     profile (a missing required extension; streaming on) refuses
     `card-profile`; a conforming card is signed and verifies under the
     manifest's agent-card key.
   - [conformance] provisioning proof: a `provision` with a wrong root
     signature, a reused nonce, or an expired nonce refuses; nothing is
     journaled (the durable no-effect oracle is keyd's journal bytes).
   - [conformance] provisioning crash matrix: kill keyd at every point
     while persisting the provisioned set; on restart the set is fully
     present or fully absent — `provision-status` never reports a partial
     state, and re-sending the same bytes with a fresh nonce converges to
     `ok`. Lost-response matrix likewise (same bytes `ok`, different
     bytes refused). **Honest scope**: the kill-9 matrix proves crash
     consistency — a process killed at any instruction leaves an
     all-or-nothing, parseable journal. Power-loss durability is carried
     by the fsync sequence itself (temp-file fsync before rename, the
     journal discipline) and is stated as resting there, not claimed as
     proven by kill-9.
   - [conformance] reserve idempotency and the **reservation lifecycle**:
     kill keyd after persist-before-reply; restart; re-send the same
     `reservation_id` → `{status: "active"}` and the same generation,
     exactly one active reservation. A successor reserve consumes the
     prior; `checkpoint-commit` consumes explicitly; a retry of a
     retained **consumed** id returns `{status: "consumed"}` with **no
     generation** and no journal change (journal bytes compared before
     and after — the durable no-effect oracle); after N = 32 consumed
     records the oldest is evicted and its retry refuses
     `reservation-unknown` — the retention bound is exercised at the
     cap, not asserted.
   - [conformance] the **concurrent-reserve race**: two simultaneous
     `checkpoint-reserve` calls with distinct ids on two connections —
     distinct generations in the replies, **exactly one of them G + 1**,
     the later consuming the earlier, exactly one reservation active
     afterward, and a journal that parses. The linearization rule,
     exercised rather than assumed.
   - [conformance] **`journal-corrupt` refusal**: truncate the journal
     mid-image, and separately flip one byte; keyd refuses every
     operation with `journal-corrupt`, serves nothing, and the corrupt
     bytes are unchanged after the refusal — never a silent
     reinitialize.
   - [conformance] **two-phase renewal, both files**: `renew-certificate`
     returns a `renewal_id` and a DER with the same SPKI and a fresh
     validity window, and the manifest then carries **both**
     certificates; re-calling returns the same pending pair. Kill the
     daemon at every point — before the `endpoint.der` write, after it,
     before `renew-commit` — and restart: `renew-status` reconciliation
     completes forward each time, and the oracle is **cross-file**:
     `endpoint.der`'s bytes and keyd's sole manifest DER are byte-equal
     after every path (v3's test watched only keyd's side; the split
     lived in the file it ignored). Kill keyd mid-journal in either
     phase: prior set or pending set, pending set or committed set —
     never mixed. An `endpoint.der` matching neither manifest DER
     refuses `certificate-divergence`. `doctor` warns inside the 30-day
     window and not outside it.
   - [conformance] kill keyd mid-`sign-statement`: the surrounding daemon
     operation fails closed with nothing half-committed — named oracle: no
     decision row, contract head unmoved, and the retry after keyd returns
     succeeds exactly once.
4. **Daemon custody seams + remote signing — agent still not selectable.**
   The four fallible interfaces; bootstrap moves onto them (this is where
   ADR-0009's trait is actually replaced, not just declared replaced); the
   rustls bridge; manifest consumption for tokens and introductions.
   - [conformance] stop keyd: the TLS handshake fails with no silent
     fallback to any local key; the refusal names keyd.
   - [conformance] the endpoint fingerprint is byte-identical across
     `file` → `sealed` → `agent` transitions of the same identity.
   - [conformance] e2e introduction + task exchange with signing remoted —
     paired with its adversarial twin from PR3 (mismatched-manifest
     introduction refused), so the positive path never stands alone.
5. **The external checkpoint + lineage + `to-agent` + `recover ack` +
   the gate lifts.** Reserve-before-authority-write wiring, the
   `store_lineage` meta row, the extended `ExternalCheckpoint` (lineage
   + fresh-adoption) and the `set_state_generation` monotonic
   **compare-and-set** (the two named store changes), the open
   handshake's adoption/refusal rules with the first-open
   `checkpoint-adopt` seal, `rollback_detectable: true` in agent mode,
   the four-phase offline `to-agent`, the transactional `akson recover
   ack`, `custody:"agent"` accepted.
   - [conformance] back up the data dir, do authority work, restore the
     backup: the store opens in `Recovery` with automatic authority off,
     and the PR1 reactor test re-runs in agent mode. (Relabeled from v2's
     `[red-on-main]`, which was wrong twice: an agent-mode assertion
     cannot execute on main, where agent mode and keyd do not exist; and
     the file-mode equivalent is not red but *intended* — file mode stays
     `RollbackDetectionUnavailable` by ADR-0009's degrade rule, unchanged
     after this PR, and a file-mode twin asserts exactly that.)
   - [conformance] roll keyd's counter backward: refusal.
   - [conformance] delete `state.db` beside an adopted checkpoint: the
     fresh database is **refused** (`lineage-missing`), not adopted at
     the current generation; a database carrying a foreign lineage id
     refuses `lineage-mismatch`; and the positive twin — a fresh
     database under a *never-opened* (unadopted) checkpoint adopts
     exactly once, at which open the `checkpoint-adopt` seal fires and
     the refusal case above holds. The confirmation round's exact
     counterexample is the pinned scenario: provision a fresh keyd →
     first open adopts and seals → **stage inert coordination content**
     (assert no reserve ever occurred) → delete `state.db` → the second
     fresh database **must refuse** `lineage-missing`. Under v3's
     first-reserve rule it silently adopted, and the staged payload,
     event, and audit rows vanished without a trace.
   - [red-on-main] the generation **compare-and-set**: commit generation
     G in a store, then call `set_state_generation` with G and with
     G − 1 — both refuse `generation-regression` and the stored value
     still reads G. On main the setter accepts any value
     (`akson-store`'s `set_state_generation` writes unconditionally), so
     the backward write succeeds and this assertion is red.
   - [claim-pin] same-generation relabel: restore an old database,
     rewrite its generation to the current value *and* its
     `store_lineage` row at the daemon's UID — assert the store opens
     `Normal`. This test *documents the residual*; if a future change
     makes it detectable, the test fails and the threat model's residual
     row gets updated in the same PR.
   - [conformance] the `recover ack` crash intervals, exhaustively:
     crash after the reserve but before the database transaction → the
     next open re-enters `Recovery` and a re-run ack converges (the
     retained reservation replays the same G). Crash after the database
     transaction but before `checkpoint-commit` → the next open is
     `Normal` **and the `recovery.acknowledged` audit row is present** —
     asserted, because it committed in the same transaction as the
     generation write (v3's test claimed `Recovery` for this interval;
     under v3's own ordering that was false, and the state it actually
     produced was a generation with no audit — the §15.3 violation);
     the dangling reservation closes idempotently at that open. The
     database-ahead direction: restore an older keyd journal so the
     database generation exceeds the external one → `Recovery`; ack
     reserves with `floor` and obtains G strictly above both; the next
     open is `Normal`. Refusal rows too: ack in `Normal` refuses
     `nothing-to-ack`, ack under `lineage-mismatch` refuses, ack with
     keyd unreachable refuses — never a silently-current older
     database.
   - [conformance] `keys to-agent` while a daemon holds `aksond.lock`:
     refuses `daemon-running` before any byte reaches keyd — this is the
     exactly-one-authority claim's enforcement test (v2 asserted the
     claim without the quiescence that makes it true).
   - [conformance] kill -9 during each `to-agent` phase (with no daemon
     running, per phase 0): rerun converges with the *same* lineage id
     and byte-identical provisioning; at every observed intermediate
     state the secrets are authoritative in **exactly one** place or the
     next daemon start refuses to serve.
6. **The honest paperwork.** Threat-model rewrite (new actors, T13/T14,
   residuals), README custody paragraphs, `deploy/README.md` third role,
   §7.3 profile mapping, ADR-0009 "partially superseded" header, the ADR
   index row, and the recommended-profile flip — documentation only; no
   default changes, and no tests (and it says so).

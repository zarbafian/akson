# ADR-0017: Key custody — sealed keystore, key agent, rollback checkpoint

Status: proposed
Date: 2026-07-30 (v2 — revised after independent adversarial review; see the
program record `reviews/2026-07-30-adr0017-codex-review.md`. v1's checkpoint
and eviction claims overreached, its socket registry could not boot a daemon,
and its migration state machine omitted reachable states; this revision
narrows the claims to what the design delivers and completes the protocols.)

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

The program repo's plan (`AKB-SOTA-PLAN.md`, Phase 1 "Trust track
(primary)" — an artifact outside this repository) requires: "Replace interim
key custody (ADR-0009) with real custody; make per-role UID separation the
documented recommended profile, not a footnote." This repo's own
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
  monotonic counter, with narrowed claims (its section below).
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

`file` is daemon/plaintext/none. `sealed` is daemon/passphrase/none (tpm-nv
composable). `agent` moves the process boundary; the agent's *own* keystore
is independently plaintext, passphrase, or TPM-wrapped, and is reported
separately — `agent` with a plaintext inner keystore protects long-term keys
from the daemon process but **not** from a copied whole-host disk, and
`sealed` without an agent protects the copied disk but not against a running
daemon compromise. Neither subsumes the other; `doctor` reports all three
axes so the operator sees which properties actually hold. **No mode ever
silently degrades to a weaker one** — a locked keystore, an unreachable
agent, or a checkpoint disagreement refuses, it does not fall back.

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
  `sealed_secrets` — so every non-ciphertext byte (mode, schema version, all
  KDF parameters, the salt) is authenticated, and tampering with metadata
  fails the tag, not merely strict parsing.
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
and fails later and confusingly at TLS setup.

### `sealed` mode — recommended for a laptop / single-host operator

`akson keys seal` (prompts twice, reseals in place, atomic). Unlock sources,
in order: `$CREDENTIALS_DIRECTORY/akson.keystore-passphrase` (systemd
`LoadCredential`), `AKSON_KEY_PASSPHRASE_FILE`, an interactive prompt when
stdin is a TTY. None available → the daemon refuses to serve, with the fix
in the message. Fail closed, never regenerate.

Closes: theft of **future logical copies** — the powered-off disk, a copied
data dir, backups taken after sealing. **Does not close, and we say so:**

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
*and* KEK, in its own inner keystore — itself `file`, `sealed`, or
TPM-wrapped; composition, not a fourth mode), the **external checkpoint**,
the **store lineage id**, and the **public manifest**. The daemon's
`keystore.json` is the third variant, `{"custody":"agent"}` — the mode
marker lives in the same single artifact as every other mode.

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
  concurrent connections; excess wait, they are not refused.
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
  refusal, and the reserve/provision idempotency matrix, re-derived by
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
- `sign-card {card}` — keyd verifies that every key thumbprint and the TLS
  certificate digest the card advertises match its **own manifest** before
  signing with the agent-card key. A card advertising any key keyd does not
  own refuses with `binding-mismatch`.
- `sign-introduction {transcript, key_binding}` — keyd recomputes the
  key-binding digest, verifies every key entry and the record's
  `tls_certificate_sha256` against the manifest, and only then returns the
  per-purpose proofs over the bound transcript. Attacker-supplied bindings
  refuse; the v1 takeover is structurally unavailable.
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
- `checkpoint-reserve {reservation_id}` / `checkpoint-read` — the §15.5
  monotonic generation plus trusted time, persisted under keyd's UID.
  Reserve is **idempotent**: keyd durably records (reservation_id →
  generation) before replying, so a lost response retried with the same id
  returns the same generation and burns nothing. Read is naturally
  idempotent.
- `provision {keystore, endpoint_der}` / `provision-status` — the
  `keys to-agent` import (Migration below). Idempotent by content:
  re-provisioning byte-identical material is `ok`; different material while
  provisioned refuses.

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
*accidental* corners: keyd holds a **store lineage id** (random, minted at
provision or first init, persisted on both sides), and a database that is
fresh or carries a foreign lineage id beside an initialized checkpoint
**refuses instead of adopting** the external generation — today a deleted
`state.db` would silently adopt the current counter on first open. The
adversarial gap — same-generation relabelling by the daemon UID — is a
**named residual with a claim-pinning test**, so the claim can never
silently inflate. Actually closing it requires replay-sensitive state
transitions validated *outside* the daemon (the agent authenticating state
digests, not holding a counter); that is future work in its own ADR.

#### Recovery semantics — one behavior, enforced centrally

Checkpoint disagreement opens the store in `Recovery` for diagnostics; the
process does not exit. The matrix (aligned with design §8.5's
time-uncertain recovery) is exhaustive and lives at one chokepoint:

- **Refused in Recovery**: introduction dial and accept, peer import and
  removal, contract acceptance and every work-order issue (manual *and*
  automatic), processor calls, coordination consent mint and dispatch,
  certificate renewal. Each refusal names the recovery path.
- **Allowed in Recovery**: `doctor`/`status`/`diagnose`, read-only
  listing, export.

Enforcement is central — the store refuses authority-issuing mutations in
`Recovery` at its own transaction boundary, and every listener path
(receive, reactor, worker, coord, admin) asserts the same predicate rather
than each choosing its own. **Defect, found by the review and confirmed on
main:** the automatic reactor never checks `automatic_authority_enabled`
before approving and issuing work — today the flag is merely *reported* in
capability evidence and enforced nowhere. PR1 fixes this with a break-first
test (a store in `Recovery` plus an auto-approvable task must issue
nothing; on main it issues).

### `tpm` composition (feature `tpm`, CI-gated separately — ADR-0009's stance)

Where hardware exists, `tss-esapi` seals the keystore's wrapping secret to
the TPM and backs the checkpoint with an NV monotonic counter (usable from
`sealed` mode too, where it is the only checkpoint option). **The claim is
narrow**: TPM sealing protects the keystore blob **moved off the machine**
— a copied directory, a backup, a pulled disk — with no passphrase to type.
It does not, without a measured-boot PCR policy and an authorization value
this ADR does not yet specify, protect a stolen *whole machine* that can
boot into an allowed state and ask its own TPM to unseal. The NV counter
gives the scalar hardware monotonicity — which changes nothing about the
relabelling residual above, since a hardware-honest counter does not make
the database's claim of it authentic. Ed25519 signing residency on target
hardware is **not assumed** (asserted in v1; unverified). Before the `tpm`
feature ships, its own ADR must specify the object and PCR policies, boot
and user-presence assumptions, NV lifecycle (provisioning, TPM-clear,
lockout, write endurance), failure recovery, and a supported-hardware
survey. Until then: seal + NV counter, behind the feature, with these
stated limits.

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
E = `kek`, D = store present). A leftover T is never read — it is removed
and the row below applies:

| on disk | verdict |
|---|---|
| no K, no S, no E, no D | auto-init `file` (truly fresh) |
| no K, no S, no E, D present | refuse `identity-missing` |
| no K, S+E | legacy: run migration |
| no K, exactly one of S/E | refuse `identity-incomplete` (the Context defect, now fail-closed) |
| K only | open by K's variant |
| K + S + E | crash before deletions: K's secrets must equal S/E → delete both (fsync dir); unequal → refuse `migration-ambiguous` |
| K + exactly one of S/E | crash between the two unlinks: the survivor must equal K's copy → delete it (fsync dir); unequal → refuse `migration-ambiguous` |
| K = `agent`, keyd ready | open over the socket |
| K = `agent`, keyd unreachable/unprovisioned | refuse, fix in message — never a fallback to local files |
| K = `agent` + S/E present | leftovers from a pre-`to-agent` state: verify their derived public keys against keyd's manifest → equal: delete them; else refuse |

Every row is exercised by fault injection after every write, fsync, rename,
and unlink (the recovery matrix below). No migration journal is needed
*because this table is total*: the artifact set itself encodes the state,
and both single-survivor crash states — which v1 failed to name — resolve
by the equality checks above.

**`keys to-agent`** moves the custody artifact **entire** — master *and*
KEK (v1 said "the master" while defining keyd as holding the KEK; both go).
Two-phase, explicit operator step, available only once agent mode is whole
(implementation plan):

1. **Provision**: send the keystore secrets and the exact `endpoint.der`
   to keyd. keyd persists them in its inner keystore, derives all eight
   public keys through the shared derivation module, stores the manifest,
   and returns it. Idempotent by content — a lost acknowledgment is
   recovered by re-sending; byte-identical material is `ok`, different
   material refuses.
2. **Verify**: the daemon independently derives the same manifest from the
   material it sent and compares byte-for-byte — all eight thumbprints,
   the certificate DER, the root key — and requires a fresh challenge
   signature that verifies under the manifest's root.
3. **Install**: atomically rename a new `{"custody":"agent"}` keystore over
   `keystore.json` (temp + rename + dir fsync). This one atomic step both
   installs the pointer and removes the local secrets — there is no window
   in which the secrets exist in zero or two authoritative places.

Crash before 3: keyd is provisioned, custody is still local — `doctor`
warns (`agent provisioned but custody local`), re-running converges. Crash
during 3: the rename is atomic — either the old keystore or the pointer.
After 3: keyd is authoritative; keyd state lost afterwards refuses to serve
(restore keyd from its backup — no fallback exists to fall to).

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
  endpoint cert     endpoint.der present, SPKI matches tls-endpoint key
  warnings          passphrase file shares the keystore's filesystem;
                    agent runs under the daemon's own uid;
                    legacy key files still present;
                    agent provisioned but custody still local
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
  UIDs' state; defeated only by `sealed`/`tpm` at-rest custody).
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
  `KeyStore` trait does not: the trait is infallible, returns borrowed
  concrete keys, and was never adopted by the daemon — and it cannot
  represent remote fallible signing, a public manifest, DEK wrap/unwrap,
  MAC operations, or reserve retries. It is replaced by four fallible
  seams the daemon is made to *actually depend on*: `IdentitySigner`
  (describe / public manifest / typed signing), `StoreCustody`
  (wrap/unwrap DEK), `WorkOrderAuthority` (mac/verify), and
  `CheckpointAnchor` (reserve/read + lineage). Local modes implement them
  in-process; `agent` implements them over the socket. ADR-0009's header
  gains "partially superseded by ADR-0017" in the paperwork PR; its
  anticipated `keyring`-crate adapter is explicitly not built (Context
  records the scoped rejection).
- The fail-closed surface grows on purpose: locked keystore, unreachable
  or impostor agent, incomplete legacy pair, missing `endpoint.der`, SPKI
  mismatch, ambiguous migration, malformed or out-of-bounds keystore, and
  checkpoint disagreement all refuse. Each refusal names its fix; none
  regenerates key material.
- New dependencies: `argon2`, `zeroize` (both RustCrypto/pure Rust, §3.3);
  `tss-esapi` only behind `tpm`. A new crate `akson-keyd`, one more socket
  protocol held to the ADR-0016 admission standard **in both directions**,
  and a normative shared derivation module.
- Affected threat cases: T13, T14, residuals 1 and 3, plus the new actors.
  Test vectors: keystore golden files for all three variants (including a
  sealed vector with fixed KDF parameters), derivation golden vectors
  (eight purposes + work-order MAC), keyd wire vectors including every
  refusal and the idempotency matrix, and the recovery matrix below.

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
   Recovery enforcement, memory hygiene.** The closed schema and parser,
   `keys migrate` + auto-migrate, the precedence table, the
   `identity-missing`/`identity-incomplete` refusals, the `endpoint.der`
   SPKI check and fail-closed-on-missing, the central Recovery matrix with
   the reactor fix, `zeroize` + non-dumpable.
   - [red-on-main] delete `identity.seed`, keep `kek`: assert bootstrap
     refuses `identity-incomplete`; on main it mints fresh purpose keys.
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
   - [conformance] flip one byte of each non-ciphertext field (mode,
     version, each KDF parameter, salt) and of the ciphertext: assert
     **tag failure**, not parse-level failure, for the AAD-covered fields.
   - [conformance] plant a marker in the inner object; grep the sealed
     file and a simulated backup (§20.7 style) — plus the honest twin: the
     *legacy* files' bytes are asserted still recoverable from a pre-seal
     backup, pinning the "cannot unwrite the past" paragraph.
   - [conformance] locked start with no source: refuse-to-serve with the
     fix named; passphrase file on the keystore's filesystem: the warning.
3. **`akson-keyd`: crate, wire protocol, provisioning, deploy profile —
   agent not yet selectable.** The registry, mutual admission, sysusers +
   unit + root-owned config, `verify.sh` coverage.
   - [conformance] wrong-UID client refused before the request line is
     read — real-socket matrix over **every** op (`coord_boundary.rs`
     style).
   - [conformance] impostor server: a listener at the configured path
     under a wrong UID — the daemon refuses before sending any bytes.
   - [conformance] outside-registry op, unknown version, oversize line,
     slow-loris: each stable problem; nothing logged that names keys.
   - [conformance] `sign-card` / `sign-introduction` with one binding not
     in the manifest — for each of the six statement keys and the
     certificate digest independently — refuse `binding-mismatch`. This is
     the review's first-contact-takeover attack, kept as a permanent
     vector.
   - [conformance] reserve idempotency: kill keyd after persist-before-
     reply; restart; re-send the same `reservation_id` → the same
     generation, exactly one reservation row. Lost-response matrix for
     `provision` likewise (same bytes `ok`, different bytes refused).
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
5. **The external checkpoint + `to-agent` + the gate lifts.**
   Reserve-before-authority-write wiring, lineage id,
   `rollback_detectable: true` in agent mode, two-phase `to-agent`,
   `custody:"agent"` accepted.
   - [red-on-main] back up the data dir, do authority work, restore the
     backup: the store opens in `Recovery` with automatic authority off,
     and the PR1 reactor test re-runs in agent mode. Red at the daemon
     level today because bootstrap hardcodes `rollback_detectable: false`.
   - [conformance] roll keyd's counter backward: refusal.
   - [conformance] delete `state.db` beside an initialized checkpoint: the
     fresh database is **refused**, not adopted at the current generation
     (the lineage rule; the store's own first-open adoption remains only
     for genuinely fresh provisioning).
   - [claim-pin] same-generation relabel: restore an old database and
     rewrite its generation to the current value at the daemon's UID —
     assert the store opens `Normal`. This test *documents the residual*;
     if a future change makes it detectable, the test fails and the threat
     model's residual row gets updated in the same PR.
   - [conformance] crash between reserve and commit: next open is
     `Recovery` (conservative, an operator acknowledges), and re-reserve
     converges; never a silently-current older database.
   - [conformance] kill -9 during each `to-agent` phase: rerun converges;
     at every observed intermediate state the secrets are authoritative in
     **exactly one** place or the daemon refuses to serve.
6. **The honest paperwork.** Threat-model rewrite (new actors, T13/T14,
   residuals), README custody paragraphs, `deploy/README.md` third role,
   §7.3 profile mapping, ADR-0009 "partially superseded" header, the ADR
   index row, and the recommended-profile flip — documentation only; no
   default changes, and no tests (and it says so).

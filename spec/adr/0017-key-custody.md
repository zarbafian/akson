# ADR-0017: Key custody — sealed keystore, key agent, rollback checkpoint

Status: proposed
Date: 2026-07-30

## Context

Custody today is two 32-byte owner-only files under the data dir
(`bootstrap.rs::load_or_init_secret`): `identity.seed` — the master seed from
which **every** purpose key and the work-order MAC derive (`aksond/keys.rs`)
— and `kek`, which wraps the store's DEK (ADR-0005). `endpoint.der` is public.
ADR-0009 built the `KeyStore` seam and the degrade rule and *anticipated*
`os-keystore`/`tpm` adapters; neither was ever built, and the threat model
carries the residuals plainly: a local attacker with the user's uid reads the
master and KEK; rollback is undetectable (T13, `rollback_detectable: false`
hardcoded at bootstrap); the root's private half alone is the identity (T14).
The design requires private keys and a monotonic state generation outside
database backups (§15.5), honest per-profile assurance (§7.3), and no escrow —
key loss means re-pairing (§8.4). The program plan (Phase 1 trust track) makes
replacing this the wedge's hardest item and makes per-role UID separation the
recommended profile; `deploy/` already has the two-identity fleet arrangement.

One derivation fact governs the whole decision: a single master derives all
eight purpose keys. One-key-one-role holds at the **usage** layer (purpose-bound
signing, distinct key material per role), but custody concentrates at the
master — whoever holds it holds the root. So "custody of the keys" is custody
of two 32-byte secrets, and any migration that keeps pinned identities (tokens,
certificates, all seven PAIRED thumbprints) must preserve their *values*.

Evaluated:

- **(a) passphrase-sealed keystore** (KDF + AEAD, unlock ceremony) — closes
  at-rest/offline theft only.
- **(b) OS keyring** — Secret Service is reachable over D-Bus by any same-UID
  process, so on the machines akson targets it adds *no* isolation over a
  `0600` file; desktop-only, absent on headless hosts; kernel `keyctl` keyrings
  do not survive reboot. **Rejected as an assurance tier** (it may later serve
  as a convenience passphrase *source* on desktops — that is ergonomics, not
  assurance, and is not this ADR).
- **(c) TPM2** — machine-binding for the sealed material and a real NV
  monotonic counter; no Ed25519-resident signing on common parts.
- **(d) a key-agent process under its own UID** (the ssh-agent model) — the
  daemon never holds long-term private keys; signs over a narrow socket.
- **(e) tiers of the above** — chosen.

## Decision

Three custody modes forming one honest ladder, plus an optional TPM
composition. The mode is written in the keystore file and reported by
`akson doctor`; **no mode ever silently degrades to a weaker one** — a locked
keystore, an unreachable agent, or a checkpoint disagreement refuses, it does
not fall back.

### The keystore file (all modes)

`data_dir/keystore.json`, schema version 1, strict I-JSON, `0600`, written
atomically (temp + rename + dir fsync). It replaces `kek` and `identity.seed`
as the single custody artifact:

```json
{ "schema_version": 1,
  "custody": "file" | "sealed",
  "kdf": { "alg": "argon2id", "m_cost": …, "t_cost": …, "p_cost": …, "salt": "<b64url>" },
  "secrets": "<b64url>" }
```

In `file` mode `secrets` is the plaintext inner object
`{"master":"<b64url32>","kek":"<b64url32>"}` — the developer profile, stated in
the file itself. In `sealed` mode it is that inner object under ADR-0005's
versioned seal (`0x01 ‖ nonce(24) ‖ ciphertext‖tag`, XChaCha20Poly1305) with
AAD `"akson.keystore.v1"`, the key derived by argon2id (RustCrypto, pure Rust —
§3.3 discipline; parameters recorded in the file so they can be raised without
a format change). Unknown `custody` values refuse (design §18).

**Deny by absence:** a data dir holding a store but no keystore (and no legacy
files) fails closed with `identity-missing` — the daemon never mints a fresh
identity beside existing state. Auto-init (generate master + KEK, `file` mode)
happens only on a truly empty data dir, so `aksond serve` on a fresh machine
stays one command.

### `sealed` mode — recommended for a laptop / single-host operator

`akson keys seal` (prompts twice, reseals in place, atomic). Unlock sources, in
order: `$CREDENTIALS_DIRECTORY/akson.keystore-passphrase` (systemd
`LoadCredential`), `AKSON_KEY_PASSPHRASE_FILE`, an interactive prompt when
stdin is a TTY. None available → the daemon refuses to serve, with the fix in
the message. Fail closed, never regenerate.

Closes: theft of the powered-off disk, a copied data dir, and backups — the
at-rest half of the residual. **Does not close, and we say so:** same-UID
malware while the daemon runs (master, KEK, and DEK are in daemon memory);
a keylogged passphrase; and a passphrase file on the same filesystem as the
keystore, which reduces at-rest protection back to `file` mode — `doctor`
warns on exactly that arrangement.

### `agent` mode — recommended fleet profile, with `deploy/`'s per-role UIDs

A new `akson-keyd` (crate `crates/akson-keyd`) runs under its own Unix identity
`akson-key` (third row in `deploy/sysusers.d`), owns its own directory, and
holds two things: the keystore (itself `file`, `sealed`, or TPM-wrapped —
composition, not a fourth mode) and the **external checkpoint**. The daemon's
`custody.json` pointer is `{"custody":"agent","socket":"<path>/key.sock"}`.

The socket is narrow in the ADR-0016 style — admission is `SO_PEERCRED`
against the one configured daemon UID, checked **before the request line is
read**, and the op registry is deny-by-absence:

- `sign` — `(purpose, message)` for the asymmetric purposes only; the agent
  binds purpose to key exactly as `PurposeKey` does, so the socket cannot pull
  a key across roles.
- `release-session-secrets` — the KEK and the work-order MAC key, once per
  store open.
- `checkpoint-reserve` / `checkpoint-read` — the §15.5 monotonic generation
  plus trusted time, persisted under the agent's UID.

TLS handshakes sign through the agent via a rustls `SigningKey` bridge, so
**no long-term private key ever enters daemon memory** — root, TLS, and all
statement keys sign remotely. The symmetric locals are session-released
deliberately: the daemon holds the DEK and reads the store regardless, so
withholding the KEK buys nothing; the line that matters, and the one this mode
draws, is that identity signing keys never cross the socket.

Closes: exfiltration of long-term keys by a compromised daemon — T14's "steal
the root, impersonate at first contact" now requires compromising `akson-keyd`
or root, not the large, network-facing daemon; and **rollback detection
becomes real** (T13): the checkpoint lives outside the daemon's UID and outside
the store backup, `ExternalCheckpoint.rollback_detectable` is finally true, and
the store's existing `Recovery` path does the refusing. **Narrows, not closes,
and we say so:** an attacker holding the daemon's UID while the agent is up has
a *signing oracle* — it can sign as this endpoint for as long as it is
resident; what it cannot do is leave with the keys, so eviction ends the
compromise without re-pairing every relationship. An agent configured under the
daemon's own UID is a nominal boundary; `doctor` warns.

### `tpm` composition (feature `tpm`, CI-gated separately — ADR-0009's stance)

Where hardware exists, `tss-esapi` seals the keystore's wrapping secret to the
TPM and backs the checkpoint with an NV monotonic counter (usable from `sealed`
mode too, where it is the only checkpoint option). Closes offline theft with no
passphrase to type and gives hardware monotonicity. **Honestly:** common TPMs
do not sign Ed25519, so signing stays host-side; and a live attacker on the
machine can ask the TPM to unseal — the TPM binds material to the machine, it
does not defend the running machine.

### Migration

`akson keys migrate`, also run automatically at bootstrap when only legacy
files exist (the `file`-mode developer path stays zero-ceremony): write
`keystore.json` from `identity.seed` + `kek` **byte-preserving** — every
thumbprint, token, and pinned certificate is unchanged, so no peer re-pairs —
fsync, then remove the legacy files. Idempotent across a crash at any step
(legacy-only, both-present-and-equal, keystore-only are all valid resume
states); both present and *unequal* refuses as ambiguous. `keys seal` and
`keys to-agent` are explicit operator steps on top.

`to-agent` moves the **master**, so every purpose rides along at once. There is
no partial "root-only" tier: derivation is one-way from a single master, so a
split would require fresh operational keys, which is changed material and a
§8.4 re-pair for every peer. A future ADR may buy per-key custody at that
price; this one does not pretend to.

### `akson doctor`

A `custody` block beside the sandbox block, machine-readable through
`Diagnose`:

```
custody:
  mode        agent (reachable, uid akson-key) | sealed (locked|unlocked) | file (unprotected at rest)
  keystore    ~/.local/share/akson/keystore.json  0600
  rollback    unavailable | agent-checkpoint | tpm-nv
  root key    agent-held | daemon-memory
  warnings    passphrase file shares the keystore's filesystem;
              agent runs under the daemon's own uid;
              legacy key files still present
```

`file` mode is named for what it is, in the developer's terminal, every time.

### Threat model updates (design/2026-07-19-threat-model.md)

- Residual 1 ("key custody is interim") is rewritten as the tier statement:
  `file` — unchanged, same-UID reads everything; `sealed` — at-rest closed,
  running-daemon exposure unchanged; `agent` — long-term keys unreadable at the
  daemon's UID, signing-oracle residual while resident.
- T13's mitigation row gains "external counter held by `akson-keyd` (or TPM
  NV); `file`/`sealed` without TPM still degrade to operate-but-flagged".
- T14 is narrowed in `agent` mode (theft requires the agent's UID or root) and
  gains the oracle residual explicitly.
- New residuals: the signing oracle; the passphrase entry surface; and — in
  every mode — the DEK and session secrets in daemon memory (bounded by
  `zeroize`-on-drop and marking the daemon non-dumpable at bootstrap; bounded,
  not closed).

## Consequences

- The README's "key custody is interim (ADR-0009)" caveat retires in favor of
  the tier table; `deploy/` gains the third identity, its unit, and the
  recommended-profile framing the plan requires. Defaults do not move: `file`
  mode remains what a bare `aksond serve` gets, and remains labeled.
- ADR-0009's `KeyStore` seam and degrade rule stand; its anticipated
  `keyring`-crate adapter is explicitly not built (Context records why). The
  checkpoint plumbing lands in the seam ADR-0009 reserved for it, and
  `Store::open`'s `Recovery` logic is finally exercised with
  `rollback_detectable: true`.
- The fail-closed surface grows on purpose: locked keystore, unreachable
  agent, ambiguous migration, and checkpoint disagreement all refuse. Each
  refusal names its fix; none regenerates key material.
- New dependencies: `argon2`, `zeroize` (both RustCrypto/pure Rust, §3.3);
  `tss-esapi` only behind `tpm`. A new crate `akson-keyd` and one more socket
  protocol to hold to the ADR-0016 admission standard.
- Affected threat cases: T13, T14, residuals 1 and 3. Test vectors: keystore
  golden files for both modes (including a sealed vector with fixed KDF
  parameters), agent wire-protocol vectors, and the recovery matrix below.

## Implementation plan

Ordered PRs, each shippable alone behind the unchanged `file` default. Per the
program rule, every test below is written by breaking the behavior first —
introduce the fault, watch the assertion fail, then fix.

1. **Keystore file, migration, deny-by-absence, memory hygiene.** The file
   format, `keys migrate` + auto-migrate, `identity-missing` refusal,
   `zeroize` + non-dumpable. Break first: corrupt/truncate/chmod-0644 the
   keystore and assert refusal with the right problem type; delete the
   keystore but keep `state.db` and assert `identity-missing` (today this
   silently mints a new identity — the test must fail before the fix); `kill
   -9` between each migration step and assert the rerun converges; assert
   every purpose thumbprint and the endpoint fingerprint are byte-identical
   across migration.
2. **`sealed` mode.** Seal/unseal, the three unlock sources, the `doctor`
   custody block. Break first: wrong passphrase leaves no partial state;
   flip one AAD/ciphertext byte and assert refusal; plant a marker in the
   inner object and grep the sealed file and a simulated backup for it
   (§20.7 style); start locked with no source and assert refuse-to-serve;
   put the passphrase file on the keystore's filesystem and assert the
   warning.
3. **`akson-keyd`: protocol, provisioning, deploy profile.** The agent, the
   socket, `keys to-agent`, sysusers + unit, `verify.sh` coverage. Break
   first: connect from a wrong UID and assert refusal before the request
   line is read (real-socket matrix, `coord_boundary.rs` style, over *every*
   op); ask for an op outside the registry and assert the
   forbidden-surface-class refusal; kill the agent mid-`sign` and assert the
   daemon's operation fails closed with nothing half-committed; restart the
   agent and assert session secrets are not re-released to a wrong-UID
   caller.
4. **TLS signing through the agent.** The rustls `SigningKey` bridge, ending
   the last long-term key in daemon memory. Break first: stop the agent and
   assert the handshake fails with no silent fallback to a local key; assert
   the endpoint fingerprint is identical across all three modes; e2e
   introduction + task exchange with signing remoted.
5. **The external checkpoint (agent, then TPM NV behind `tpm`).**
   Reserve-before-authority-write wiring, `rollback_detectable: true`. Break
   first: back up the data dir, do authority work, restore the backup, and
   assert the store opens in `Recovery` with automatic authority off (the
   §15.5 scenario, currently undetectable — the test must fail on main);
   roll the agent's counter backward and assert refusal; crash between
   reserve and commit and assert conservative recovery, never a
   silently-current older database.
6. **The honest paperwork.** Threat-model residual rewrite, README custody
   paragraphs, `deploy/README.md` third role, §7.3 profile mapping, and the
   recommended-profile flip — documentation only; no default changes.

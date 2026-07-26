# Verifying an akson release

Every akson release asset is meant to be checked, not trusted. This page is the
exact command sequence, and — just as important — what each command does and
does not establish.

The release side of this is `.github/workflows/release.yml`; A0.1 in
`design/a0-evidence.md` records its status.

> **No release has been cut yet.** The workflow exists and CI walks its first
> steps on every pull request (`provenance-dry-run` in
> `.github/workflows/ci.yml`), but nothing has been published, so there is
> nothing to download today. The commands below are what will apply to the
> first tag. Until the payload media types leave the unregistered
> `vnd.akson-dev` tree (A0.4b / milestone M15) the workflow refuses stable
> tags, so the first release will be a prerelease.

## Short version

```sh
TAG=v0.0.1-alpha.1
REPO=zarbafian/akson

gh release download "$TAG" --repo "$REPO" --dir "akson-$TAG"
cd "akson-$TAG"

# 1. the download is intact
sha256sum --check --ignore-missing SHA256SUMS

# 2. GitHub built these artifacts, from this repo, in this workflow
for f in *; do
  gh attestation verify "$f" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release.yml"
done

# 3. what is inside the binary you are about to run
jq -r '.components[] | "\(.name) \(.version) \(.licenses[0].expression // "?")"' aksond.cdx.json

# 4. rebuild it yourself and compare
cat BUILD-INFO.txt
```

Step 2 is the trust anchor. Steps 1, 3 and 4 are only as strong as step 2
unless you obtained the assets over a channel you already trust.

## What a release contains

| Asset | What it is |
|---|---|
| `aksond`, `akson`, `akson-mcp` | daemon, operator CLI, MCP server |
| `akson-adapter-openai`, `akson-adapter-anthropic`, `akson-adapter-gemini` | the three worker adapters |
| `<binary>.cdx.json` | CycloneDX 1.5 SBOM, one per binary |
| `<binary>.deps.tree.txt` | `cargo tree` output, human-readable, **supplementary — not the SBOM** |
| `SHA256SUMS` | sha256 of every other asset, in `sha256sum` format |
| `BUILD-INFO.txt` | tag, commit, toolchain, host target, `Cargo.lock` digest, exact build command |

All artifacts are built for one target: `x86_64-unknown-linux-gnu`.
`BUILD-INFO.txt` states it; there are no cross-compiled assets.

## Prerequisites

- `gh` 2.49 or newer — `gh attestation` does not exist in older versions.
  Check with `gh --version`.
- `jq` for the SBOM recipes (optional; `.deps.tree.txt` needs nothing).
- For step 4 only: `git`, and `rustup` (the pinned toolchain installs itself
  from the committed `rust-toolchain.toml`).

## 1. Download

```sh
gh release download v0.0.1-alpha.1 --repo zarbafian/akson --dir akson-v0.0.1-alpha.1
cd akson-v0.0.1-alpha.1
```

Or take a single asset:

```sh
gh release download v0.0.1-alpha.1 --repo zarbafian/akson --pattern 'aksond*' --pattern SHA256SUMS
```

Anything that fetches the files works — `curl -LO` against the release URLs is
fine. Nothing below depends on how they arrived.

## 2. Verify `SHA256SUMS`

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

Expect `OK` on every line. Drop `--ignore-missing` if you downloaded the whole
set and want missing files reported as failures too.

`SHA256SUMS` is a plain text file with no signature of its own. On its own it
proves only that the bytes you hold are internally consistent — an attacker who
replaced an asset would replace this file too. It becomes meaningful in step 3,
where `SHA256SUMS` is itself an attested subject.

## 3. Verify build provenance

This is the check that matters.

```sh
gh attestation verify aksond --repo zarbafian/akson \
  --signer-workflow zarbafian/akson/.github/workflows/release.yml
```

Every asset is an attested subject, so run it on each file you intend to use —
including `SHA256SUMS`:

```sh
for f in *; do
  gh attestation verify "$f" --repo zarbafian/akson \
    --signer-workflow zarbafian/akson/.github/workflows/release.yml || echo "FAILED: $f"
done
```

To see the predicate rather than just a pass/fail — the commit, the workflow
run, the builder:

```sh
gh attestation verify aksond --repo zarbafian/akson --format json \
  | jq '.[0].verificationResult.statement.predicate.buildDefinition
        | {workflow: .externalParameters.workflow, source: .resolvedDependencies}'
```

**What this establishes.** The artifact's digest appears in a SLSA v1 build
provenance statement signed through GitHub's own Sigstore instance, and the
signing identity is the `release.yml` workflow in `zarbafian/akson`. So: these
bytes came out of that workflow, running on GitHub-hosted infrastructure, at
the commit named in the predicate. Nobody can mint that signature by uploading
a file to a release page. Passing `--signer-workflow` is what pins it to
*this* workflow — without it, any workflow in the repo would satisfy the check.

**What it does not establish.** Not that the source is safe, not that the
dependency set is free of vulnerabilities, not that the maintainer is
trustworthy, and not that the build is bit-for-bit reproducible. It establishes
origin, nothing more. GitHub is in the trust path: the attestation says
GitHub's OIDC issuer asserted that this workflow ran.

### Offline verification

Fetch the bundle and the trusted root once, then verify with no network:

```sh
gh attestation download aksond --repo zarbafian/akson      # writes <digest>.jsonl
gh attestation trusted-root > trusted_root.jsonl

gh attestation verify aksond --repo zarbafian/akson \
  --bundle sha256:<digest>.jsonl \
  --custom-trusted-root trusted_root.jsonl \
  --signer-workflow zarbafian/akson/.github/workflows/release.yml
```

## 4. Inspect the SBOM

One CycloneDX 1.5 JSON per binary. Useful queries:

```sh
# how many crates, and which spec version
jq '{spec: .specVersion, components: (.components | length), tool: .metadata.tools}' aksond.cdx.json

# every crate with its version and declared license
jq -r '.components[] | "\(.name) \(.version) \(.licenses[0].expression // "unstated")"' \
  aksond.cdx.json | sort

# the distinct declared licenses
jq -r '.components[].licenses[]?.expression' aksond.cdx.json | sort -u

# is a specific crate in there, and at what version
jq -r '.components[] | select(.name == "rustls") | "\(.name) \(.version)"' aksond.cdx.json

# the registry checksum this SBOM records for a crate
jq -r '.components[] | select(.name == "rustls") | .hashes' aksond.cdx.json
```

Once you have the tagged source (step 5), cross-check a crate's recorded
checksum against the lockfile — they must agree, because the SBOM was generated
from that lockfile:

```sh
jq -r '.components[] | select(.name == "rustls") | .hashes[0].content' aksond.cdx.json
grep -A3 'name = "rustls"' path/to/akson/Cargo.lock | grep checksum
```

### What the SBOM genuinely is

Be precise about this, because "SBOM" is claimed loosely elsewhere:

- It is **CycloneDX 1.5 JSON**, produced by `cargo-cyclonedx` at the version
  pinned in `release.yml` (recorded in `BUILD-INFO.txt` and in the SBOM's own
  `metadata.tools`).
- Its contents are **the dependency graph `Cargo.lock` resolves for the host
  target** — around 250 crates for each binary — each with name, version,
  declared license expression, and `purl`.
- Every crate that comes from crates.io carries its **registry SHA-256**, taken
  from `Cargo.lock`. The in-tree `akson-*` path crates carry no hash: their
  bytes are the tagged commit, which the attestation already covers.
- Licenses are **as declared by upstream crate metadata**. The SBOM does not
  audit them. `deny.toml` plus the `deny` job in `.github/workflows/ci.yml`
  (`cargo-deny check licenses advisories bans sources`) is what enforces the
  allowlist, refuses yanked crates and known advisories, and requires every
  dependency to come from crates.io.
- It is a **build-time dependency inventory, not a scan of the linked binary**.
  Nothing here reads the ELF file and reports what the linker actually kept.
  A crate present in the graph but pruned by feature resolution or dead-code
  elimination still appears.
- It is **not an audited or certified bill of materials**, and it is not signed
  on its own — its authority comes from being an attested subject in step 3.

The `.deps.tree.txt` files are `cargo tree --locked -p <package> --edges
normal,build --target x86_64-unknown-linux-gnu`. They are a convenience for
eyeballing and diffing. They are **not** an SBOM and are not a substitute for
one.

## 5. Reproduce the build

```sh
git clone https://github.com/zarbafian/akson
cd akson
git checkout v0.0.1-alpha.1

# the commit must be the one the release was built from
git rev-parse HEAD
grep '^commit:' ../akson-v0.0.1-alpha.1/BUILD-INFO.txt

# the dependency set must be the one that was built
sha256sum Cargo.lock
grep '^Cargo.lock:' ../akson-v0.0.1-alpha.1/BUILD-INFO.txt

# build with the pinned toolchain, exactly as the release does
cat rust-toolchain.toml            # channel = "1.95.0"
rustc --version                    # rustup honours rust-toolchain.toml here
env -u RUSTFLAGS cargo build --locked --release --bins \
  -p aksond -p akson-cli -p akson-mcp \
  -p akson-adapter-openai -p akson-adapter-anthropic -p akson-adapter-gemini

# compare
sha256sum target/release/aksond
grep '  aksond$' ../akson-v0.0.1-alpha.1/SHA256SUMS
```

`env -u RUSTFLAGS` matters: the release build sets no `RUSTFLAGS` at all,
unlike CI, which builds with `-D warnings`. A different `RUSTFLAGS` is a
different build.

### What reproduction does and does not prove

Three of these comparisons are **deterministic** — they must match, and a
mismatch is a real finding:

| Comparison | Why it is deterministic |
|---|---|
| `git rev-parse HEAD` vs `BUILD-INFO.txt` | content-addressed |
| `sha256sum Cargo.lock` vs `BUILD-INFO.txt` | the lockfile is committed, and `--locked` forbids changing it |
| the SBOM's component set vs `cargo tree --locked` on your checkout | both derive from that same lockfile |

The binary digest comparison is **not** guaranteed across machines. Rust
embeds absolute source paths in panic location strings, so the same source and
the same toolchain can still produce different bytes when your workspace
directory or `CARGO_HOME` differs from the runner's (`/home/runner/work/akson/akson`
and `/home/runner/.cargo`). Other things that change the bytes: a different
host target, a different rustc patch release, a non-empty `RUSTFLAGS`, a
`~/.cargo/config.toml` that alters the profile or the linker, and a different
`CARGO_BUILD_JOBS` in the rare case a codegen unit boundary moves.

So read the outcomes this way:

- **Digests match** — strong independent confirmation. Note it.
- **Digests differ** — inconclusive on its own, *not* evidence of tampering.
  Narrow it down: confirm `rustc --version` and the host target against
  `BUILD-INFO.txt`, confirm `RUSTFLAGS` is unset, then diff the dependency
  graph, which is environment-independent:

  ```sh
  cargo tree --locked -p aksond --edges normal,build --target x86_64-unknown-linux-gnu \
    | sed 's| (/.*)||' > mine.tree
  sed '/^#/d' ../akson-v0.0.1-alpha.1/aksond.deps.tree.txt \
    | sed 's| (/.*)||' > theirs.tree
  diff -u theirs.tree mine.tree
  ```

  (The `sed` strips the local absolute paths `cargo tree` prints for in-tree
  path crates; those legitimately differ per machine.)

  If the dependency graphs agree and the provenance attestation verifies, a
  byte difference is an environment difference. If the graphs disagree, stop
  and report it: `SECURITY.md`.

Akson does not claim bit-for-bit reproducible builds. Making that claim would
mean pinning the build paths (`--remap-path-prefix`) and a normalised
environment; it is not done today, and A0.1 records that.

## What each check gets you

| Check | Establishes | Does not establish |
|---|---|---|
| `sha256sum -c SHA256SUMS` | the download is internally consistent | anything about origin — the file is unsigned on its own |
| `gh attestation verify` | these exact bytes came out of `release.yml` in this repo, at a named commit | that the code or its dependencies are safe |
| SBOM inspection | which crate versions and licenses the lockfile resolved, with registry checksums | what the linker actually kept; an audit of those licenses |
| local rebuild | the source and lockfile are the ones described, and usually that the bytes follow from them | bit-for-bit reproducibility (not claimed) |

## If a check fails

Report it through `SECURITY.md`, not a public issue, and say which check
failed, the tag, the asset, and the digest you computed. A failing
`gh attestation verify` on an asset you downloaded from the release page is the
serious case — do not run the binary.

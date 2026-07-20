# Fuzz targets (design §11.1, §19 Phase-1 gate)

libFuzzer harnesses for the hostile-input parsers. Each must never panic, overflow,
or allocate unboundedly — the same property the `hostile_*` regression suites pin,
run here continuously over random input.

This crate is **excluded from the workspace** (it needs nightly Rust + libFuzzer).

```sh
cargo install cargo-fuzz            # once
cargo +nightly fuzz run ijson       # or: contract, sarif
cargo +nightly fuzz run ijson -- -max_total_time=60   # bounded (CI)
```

Targets:
- `ijson`    — `akson_ext::ijson::parse` (the parser all payloads build on)
- `contract` — `akson_contract::parse_payload`
- `sarif`    — `akson_evidence::parse_sarif`

A crash writes a reproducer under `fuzz/artifacts/<target>/`; replay with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash>`.

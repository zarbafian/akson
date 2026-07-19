#![no_main]
//! Fuzz SARIF parsing (untrusted worker output, §14.2) under default limits.
use libfuzzer_sys::fuzz_target;
use axon_evidence::SarifLimits;

fuzz_target!(|data: &[u8]| {
    let _ = axon_evidence::parse_sarif(data, &SarifLimits::default());
});

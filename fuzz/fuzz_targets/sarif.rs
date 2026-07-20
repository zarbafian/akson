#![no_main]
//! Fuzz SARIF parsing (untrusted worker output, §14.2) under default limits.
use libfuzzer_sys::fuzz_target;
use akson_evidence::SarifLimits;

fuzz_target!(|data: &[u8]| {
    let _ = akson_evidence::parse_sarif(data, &SarifLimits::default());
});

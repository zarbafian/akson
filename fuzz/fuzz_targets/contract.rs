#![no_main]
//! Fuzz contract-payload parsing (I-JSON caps → canonical-bytes → schema, §10.2).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = axon_contract::parse_payload(data);
});

#![no_main]
//! Fuzz the strict I-JSON parser (design §11.1) — it must never panic or overflow.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = axon_ext::ijson::parse(data);
});

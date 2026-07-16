//! Compiles the vendored A2A definitions (spec/a2a/proto, see spec/a2a/PIN)
//! into Rust types. protox is a pure-Rust protobuf compiler: no system
//! protoc, no network, only the vendored bytes. pbjson generates the standard
//! proto3 JSON mapping the A2A HTTP+JSON binding is defined by.

use std::env;
use std::path::PathBuf;

use prost::Message as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("../../spec/a2a/proto");
    println!("cargo:rerun-if-changed={}", proto_root.display());

    let file_descriptor_set = protox::compile(["a2a.proto"], [&proto_root])?;
    let descriptor_bytes = file_descriptor_set.encode_to_vec();

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    std::fs::write(out_dir.join("a2a_descriptor.bin"), &descriptor_bytes)?;

    let mut config = prost_build::Config::new();
    config
        // Map well-known types onto pbjson-types so Struct/Value/Timestamp
        // carry serde implementations matching the proto3 JSON mapping.
        .compile_well_known_types()
        .extern_path(".google.protobuf", "::pbjson_types");
    config.compile_fds(file_descriptor_set)?;

    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_bytes)?
        .build(&[".lf.a2a.v1"])?;

    Ok(())
}

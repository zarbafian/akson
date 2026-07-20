//! The Akson extension-URI namespace.
//!
//! Design §3.1 makes a project-controlled HTTPS namespace a Phase 0 release
//! gate: no provisional private URI may ship in a stable release. That gate is
//! **met** — the project controls `akson.cc`, and every extension URI is built
//! from it.
//!
//! The media types below are a *separate* gate and are not met. Owning a domain
//! says nothing about the IANA registry: the `vnd.` tree requires registration
//! (RFC 6838 §3.2), which design §14.2 assigns in Phase 0. Release tooling must
//! still refuse to ship while [`MEDIA_TYPES_ARE_PROVISIONAL`] is true.

/// HTTPS prefix under which all Akson extension URIs live. Project-controlled,
/// so it satisfies the design §3.1 release gate.
pub const EXTENSION_NAMESPACE: &str = "https://akson.cc/ext";

/// True until the `vnd.akson-dev` media types are replaced by registered ones.
/// Checked by release gating (milestone M15); never disable by hand.
pub const MEDIA_TYPES_ARE_PROVISIONAL: bool = true;

/// Builds a versioned extension URI, e.g. `ext_uri("contract", 1)` →
/// `https://akson.cc/ext/contract/v1`.
pub fn ext_uri(name: &str, version: u32) -> String {
    format!("{EXTENSION_NAMESPACE}/{name}/v{version}")
}

/// The complete required Akson extension URI set every v1 operation activates
/// (design §10.1): contract, identity/key binding, passive delivery,
/// result/evidence, and outcome. Fed to
/// `akson_proto::profile::ProfileConfig` by the daemon.
pub fn required_extension_uris() -> [String; 5] {
    [
        ext_uri("contract", 1),
        ext_uri("key-binding", 1),
        ext_uri("delivery", 1),
        ext_uri("result-evidence", 1),
        ext_uri("outcome", 1),
    ]
}

/// Builds the versioned payload media type for an extension object, e.g.
/// `payload_media_type("contract", 1)` →
/// `application/vnd.akson-dev.contract.v1+json`. This is the DSSE `payloadType`
/// that identifies the signed content; it is covered by the signature.
///
/// The `vnd.akson-dev` tree is an unregistered development placeholder; design
/// §14.2 assigns the real media types through the normal registration process
/// in Phase 0, gated by [`MEDIA_TYPES_ARE_PROVISIONAL`].
pub fn payload_media_type(name: &str, version: u32) -> String {
    format!("application/vnd.akson-dev.{name}.v{version}+json")
}

/// The media type carried on the A2A `Part` that holds a signed Akson extension
/// object as a DSSE envelope — the "envelope media type" of design §10.2.
///
/// One uniform envelope type is used for *every* signed object (contract,
/// decision, result-manifest, …); the DSSE `payloadType` (see
/// [`payload_media_type`]) is the sole discriminator of the content (ADR-0012).
/// The `Part` media type is a routing label only and is not covered by the
/// signature, so it is never a trust anchor. The `v1` is the DSSE-envelope
/// profile version, independent of any payload schema version. Placeholder tree,
/// gated by [`MEDIA_TYPES_ARE_PROVISIONAL`] like the payload types.
pub const DSSE_ENVELOPE_MEDIA_TYPE: &str = "application/vnd.akson-dev.dsse.v1+json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_namespace_is_a_real_project_controlled_https_origin() {
        // Design §3.1: no provisional private URI ships. A regression to a
        // reserved-for-documentation TLD (RFC 2606/6761) must fail here.
        let uri = ext_uri("contract", 1);
        assert!(uri.starts_with("https://akson.cc/"), "{uri}");
        for reserved in [".invalid/", ".example/", ".test/", ".localhost/"] {
            assert!(!uri.contains(reserved), "{uri} uses reserved {reserved}");
        }
    }

    #[test]
    fn the_media_types_are_still_the_unregistered_development_tree() {
        // The other half of the Phase 0 gate: owning a domain does not confer
        // an IANA registration. These two must not drift back together.
        let media_type = payload_media_type("contract", 1);
        assert_eq!(
            MEDIA_TYPES_ARE_PROVISIONAL,
            media_type.contains("vnd.akson-dev."),
            "{media_type}"
        );
    }

    #[test]
    fn uri_shape() {
        assert_eq!(ext_uri("contract", 1), "https://akson.cc/ext/contract/v1");
    }
}

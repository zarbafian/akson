//! The Axon extension-URI namespace.
//!
//! Design §3.1 makes a project-controlled HTTPS namespace a Phase 0 release
//! gate: no provisional private URI may ship in a stable release. That domain
//! is not secured yet, so every extension URI is built from the placeholder
//! prefix below. The prefix uses the reserved `.invalid` TLD (RFC 2606) so it
//! can never resolve, and release tooling must refuse to ship while
//! [`NAMESPACE_IS_PLACEHOLDER`] is true.

/// True until the project-controlled domain replaces the placeholder.
/// Checked by release gating (milestone M15); never disable by hand.
pub const NAMESPACE_IS_PLACEHOLDER: bool = true;

/// HTTPS prefix under which all Axon extension URIs live.
pub const EXTENSION_NAMESPACE: &str = "https://axon.invalid/ext";

/// Builds a versioned extension URI, e.g. `ext_uri("contract", 1)` →
/// `https://axon.invalid/ext/contract/v1`.
pub fn ext_uri(name: &str, version: u32) -> String {
    format!("{EXTENSION_NAMESPACE}/{name}/v{version}")
}

/// The complete required Axon extension URI set every v1 operation activates
/// (design §10.1): contract, identity/key binding, passive delivery,
/// result/evidence, and outcome. Fed to
/// `axon_proto::profile::ProfileConfig` by the daemon.
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
/// `application/vnd.axon-dev.contract.v1+json`. This is the DSSE `payloadType`
/// that identifies the signed content; it is covered by the signature.
///
/// The `vnd.axon-dev` tree is an unregistered development placeholder; design
/// §14.2 assigns the real media types through the normal registration process
/// in Phase 0, gated together with [`NAMESPACE_IS_PLACEHOLDER`].
pub fn payload_media_type(name: &str, version: u32) -> String {
    format!("application/vnd.axon-dev.{name}.v{version}+json")
}

/// The media type carried on the A2A `Part` that holds a signed Axon extension
/// object as a DSSE envelope — the "envelope media type" of design §10.2.
///
/// One uniform envelope type is used for *every* signed object (contract,
/// decision, result-manifest, …); the DSSE `payloadType` (see
/// [`payload_media_type`]) is the sole discriminator of the content (ADR-0012).
/// The `Part` media type is a routing label only and is not covered by the
/// signature, so it is never a trust anchor. The `v1` is the DSSE-envelope
/// profile version, independent of any payload schema version. Placeholder tree,
/// gated by [`NAMESPACE_IS_PLACEHOLDER`] like the payload types.
pub const DSSE_ENVELOPE_MEDIA_TYPE: &str = "application/vnd.axon-dev.dsse.v1+json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_cannot_resolve() {
        // RFC 2606 reserves .invalid; a "fix" that points the placeholder at
        // a real domain without going through the release gate must fail here.
        let uri = ext_uri("contract", 1);
        assert_eq!(NAMESPACE_IS_PLACEHOLDER, uri.contains(".invalid/"));
        assert!(uri.starts_with("https://"));
    }

    #[test]
    fn uri_shape() {
        assert_eq!(
            ext_uri("contract", 1),
            "https://axon.invalid/ext/contract/v1"
        );
    }
}

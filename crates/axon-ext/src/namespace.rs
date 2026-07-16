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

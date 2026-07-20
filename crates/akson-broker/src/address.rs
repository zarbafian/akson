//! Egress destination checks (design §13.1): the origin allowlist and the
//! connection-time address-class check that stop a task — or a DNS-rebinding
//! response — from steering a processor call to an unintended destination.
//!
//! Two gates, both fail-closed:
//! - [`check_origin`] — the configured processor origin must be `https`, and (when
//!   an allowlist is set) one of the exact allowed origins. A task never selects
//!   the destination; the broker uses only the configured one.
//! - [`check_resolved_address`] — the IP the origin *actually resolves to at
//!   connection time* must be a globally-routable unicast address. Loopback,
//!   private, link-local, unique-local, multicast, and every other special class
//!   are refused, so a hostname that resolves inward (SSRF / rebinding) cannot
//!   reach the host or the local network.
//!
//! What you write:
//! ```
//! use akson_broker::{check_origin, check_resolved_address, EgressPolicy, Origin};
//! use std::net::IpAddr;
//! let policy = EgressPolicy::allowing([Origin::https("api.example.com", 443)]);
//! check_origin(&Origin::https("api.example.com", 443), &policy).unwrap();
//! check_resolved_address("93.184.216.34".parse::<IpAddr>().unwrap(), &policy).unwrap();
//! // A hostname resolving to loopback is refused:
//! assert!(check_resolved_address("127.0.0.1".parse::<IpAddr>().unwrap(), &policy).is_err());
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// An exact destination origin: scheme, host, and port. The broker only ever
/// dials the configured origin; a task cannot supply one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// An `https` origin on `host:port`. Host is lowercased (origins compare
    /// case-insensitively on host).
    pub fn https(host: &str, port: u16) -> Self {
        Self {
            scheme: "https".to_owned(),
            host: host.to_ascii_lowercase(),
            port,
        }
    }
}

/// The egress policy for processor calls (design §13.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// The exact origins a processor may be dialed at. Empty means "no origin is
    /// allowed" (fail closed) — a configured processor always names one.
    pub origin_allowlist: Vec<Origin>,
    /// Permit non-global addresses (e.g. a local processor on `127.0.0.1`). Off by
    /// default: the address-class check refuses inward addresses unless a call
    /// deliberately opts in for a declared-local processor.
    pub allow_non_global: bool,
}

impl EgressPolicy {
    /// A policy allowing exactly `origins`, refusing non-global addresses.
    pub fn allowing(origins: impl IntoIterator<Item = Origin>) -> Self {
        Self {
            origin_allowlist: origins.into_iter().collect(),
            allow_non_global: false,
        }
    }

    /// Marks this policy as permitting non-global addresses (a declared-local
    /// processor). The origin allowlist still applies.
    pub fn allow_local(mut self) -> Self {
        self.allow_non_global = true;
        self
    }
}

/// Why an egress destination was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EgressError {
    #[error("scheme {0:?} is not permitted; only https")]
    NotHttps(String),
    #[error("origin {0:?} is not in the configured allowlist")]
    OriginNotAllowed(String),
    #[error("address {addr} is a {class} address, not globally routable")]
    NonGlobalAddress { addr: IpAddr, class: &'static str },
}

/// Checks a configured origin against the policy (design §13.1): it must be
/// `https` and, when an allowlist is set, one of the exact allowed origins.
pub fn check_origin(origin: &Origin, policy: &EgressPolicy) -> Result<(), EgressError> {
    if origin.scheme != "https" {
        return Err(EgressError::NotHttps(origin.scheme.clone()));
    }
    if !policy.origin_allowlist.iter().any(|o| o == origin) {
        return Err(EgressError::OriginNotAllowed(format!(
            "{}:{}",
            origin.host, origin.port
        )));
    }
    Ok(())
}

/// Checks the address an origin *resolved to* at connection time (design §13.1).
/// A globally-routable unicast address is allowed; every special class is refused
/// unless the policy opts into non-global addresses for a declared-local
/// processor. This is the anti-SSRF / anti-rebinding gate.
pub fn check_resolved_address(addr: IpAddr, policy: &EgressPolicy) -> Result<(), EgressError> {
    if let Some(class) = non_global_class(addr) {
        if !policy.allow_non_global {
            return Err(EgressError::NonGlobalAddress { addr, class });
        }
    }
    Ok(())
}

/// Classifies `addr` as a non-global address class, or `None` if it is a
/// globally-routable unicast address. Conservative and fail-closed: any address
/// that is not clearly global unicast is named as a blocked class.
fn non_global_class(addr: IpAddr) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => non_global_v4(v4),
        IpAddr::V6(v6) => non_global_v6(v6),
    }
}

fn non_global_v4(v4: Ipv4Addr) -> Option<&'static str> {
    let o = v4.octets();
    if v4.is_unspecified() {
        Some("unspecified")
    } else if v4.is_loopback() {
        Some("loopback")
    } else if v4.is_private() {
        Some("private")
    } else if v4.is_link_local() {
        Some("link-local")
    } else if v4.is_broadcast() {
        Some("broadcast")
    } else if v4.is_multicast() {
        Some("multicast")
    } else if v4.is_documentation() {
        Some("documentation")
    } else if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
        // 100.64.0.0/10 — carrier-grade NAT (RFC 6598).
        Some("shared-cgnat")
    } else if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        // 192.0.0.0/24 — IETF protocol assignments.
        Some("protocol-assignment")
    } else if o[0] == 198 && (o[1] & 0xfe) == 18 {
        // 198.18.0.0/15 — benchmarking (RFC 2544).
        Some("benchmarking")
    } else if o[0] >= 240 {
        // 240.0.0.0/4 — reserved (class E).
        Some("reserved")
    } else {
        None
    }
}

fn non_global_v6(v6: Ipv6Addr) -> Option<&'static str> {
    // Check the loopback/unspecified sentinels first: `::1` and `::` are IPv4-
    // *compatible* (::/96), so `to_ipv4()` would misread them as 0.0.0.1 / 0.0.0.0.
    if v6.is_unspecified() {
        return Some("unspecified");
    }
    if v6.is_loopback() {
        return Some("loopback");
    }
    // An IPv4-*mapped* address (::ffff:a.b.c.d) must be judged by its embedded v4
    // class, or an inward v4 could hide behind ::ffff:127.0.0.1.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return non_global_v4(v4).or(Some("ipv4-mapped"));
    }
    let seg = v6.segments();
    // 64:ff9b::/96 — well-known NAT64: judge by the embedded IPv4, so a rebound
    // translated answer cannot hide an inward v4 (127./10./…) (codex review).
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6].iter().all(|&s| s == 0) {
        let v4 = Ipv4Addr::from(((seg[6] as u32) << 16) | seg[7] as u32);
        return non_global_v4(v4).or(Some("nat64"));
    }
    if v6.is_multicast() {
        Some("multicast")
    } else if (seg[0] & 0xffc0) == 0xfec0 {
        // fec0::/10 — deprecated site-local unicast.
        Some("site-local")
    } else if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
        // 64:ff9b:1::/48 — local-use NAT64 translation (RFC 8215).
        Some("nat64-local")
    } else if (seg[0] & 0xfe00) == 0xfc00 {
        // fc00::/7 — unique local addresses.
        Some("unique-local")
    } else if (seg[0] & 0xffc0) == 0xfe80 {
        // fe80::/10 — link-local unicast.
        Some("link-local")
    } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        // 2001:db8::/32 — documentation.
        Some("documentation")
    } else if seg[..6].iter().all(|&s| s == 0) {
        // ::/96 — deprecated IPv4-compatible addresses (not loopback/unspecified).
        Some("ipv4-compatible")
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::allowing([Origin::https("api.example.com", 443)])
    }

    #[test]
    fn only_https_and_allowlisted_origins_pass() {
        check_origin(&Origin::https("api.example.com", 443), &policy()).unwrap();
        // Wrong scheme.
        assert!(matches!(
            check_origin(
                &Origin {
                    scheme: "http".into(),
                    host: "api.example.com".into(),
                    port: 443
                },
                &policy()
            ),
            Err(EgressError::NotHttps(_))
        ));
        // Not allowlisted.
        assert!(matches!(
            check_origin(&Origin::https("evil.example.com", 443), &policy()),
            Err(EgressError::OriginNotAllowed(_))
        ));
        // Same host, wrong port is a different origin.
        assert!(matches!(
            check_origin(&Origin::https("api.example.com", 8443), &policy()),
            Err(EgressError::OriginNotAllowed(_))
        ));
    }

    #[test]
    fn global_unicast_addresses_pass() {
        for a in [
            "93.184.216.34",
            "8.8.8.8",
            "2606:2800:220:1:248:1893:25c8:1946",
        ] {
            check_resolved_address(a.parse().unwrap(), &policy())
                .unwrap_or_else(|e| panic!("{a} should be global: {e}"));
        }
    }

    #[test]
    fn inward_and_special_addresses_are_refused() {
        for (a, class) in [
            ("0.0.0.0", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("10.1.2.3", "private"),
            ("192.168.1.1", "private"),
            ("172.16.0.1", "private"),
            ("169.254.1.1", "link-local"),
            ("100.64.0.1", "shared-cgnat"),
            ("198.18.0.1", "benchmarking"),
            ("255.255.255.255", "broadcast"),
            ("224.0.0.1", "multicast"),
            ("::1", "loopback"),
            ("fe80::1", "link-local"),
            ("fc00::1", "unique-local"),
            ("::ffff:127.0.0.1", "loopback"), // v4 loopback mapped into v6
            ("fec0::1", "site-local"),        // deprecated site-local
            ("64:ff9b:1::1", "nat64-local"),  // local-use NAT64
            ("64:ff9b::7f00:1", "loopback"),  // well-known NAT64 of 127.0.0.1
            ("64:ff9b::a00:1", "private"),    // well-known NAT64 of 10.0.0.1
        ] {
            let err = check_resolved_address(a.parse().unwrap(), &policy()).unwrap_err();
            match err {
                EgressError::NonGlobalAddress { class: c, .. } => {
                    assert_eq!(c, class, "{a} classified wrong")
                }
                other => panic!("{a} should be non-global, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_local_processor_may_opt_into_non_global() {
        let local = EgressPolicy::allowing([Origin::https("localhost", 8443)]).allow_local();
        check_resolved_address("127.0.0.1".parse().unwrap(), &local).unwrap();
        // The origin allowlist still applies even for a local processor.
        assert!(check_origin(&Origin::https("other", 8443), &local).is_err());
    }
}

//! The Akson v1 A2A profile validator (design §10.1, documented in
//! `spec/a2a/profile.md`).
//!
//! These checks run on inbound and outbound standard A2A objects before any
//! state lookup or content processing. They are structural, deterministic,
//! and deny by default: anything the v1 profile does not affirmatively
//! support is a violation. The Akson-specific extension URI set is
//! configuration (`ProfileConfig`) so this crate stays independent of the
//! extension crates.

use std::collections::BTreeSet;

use crate::v1::{part, security_scheme, AgentCard, Message, Role, SendMessageRequest, TaskState};

/// Hard bound on extension URI length accepted by the profile.
pub const MAX_EXTENSION_URI_LEN: usize = 256;

/// The v1 HTTP+JSON interface advertisement (design §10.1).
pub const HTTP_JSON_BINDING: &str = "HTTP+JSON";

/// Akson-side configuration for profile validation. Deliberately has no
/// `Default`: an empty required-extension set would silently disable the
/// downgrade check, so callers must construct it explicitly from the real set
/// (`akson_ext::namespace::required_extension_uris`).
#[derive(Debug, Clone)]
pub struct ProfileConfig {
    /// The complete required Akson extension URI set. Every v1 operation
    /// activates exactly this set; an Agent Card must advertise each with
    /// `required: true`. Must be non-empty.
    pub required_extensions: BTreeSet<String>,
}

impl ProfileConfig {
    /// Constructs a config, rejecting an empty required set so a downgrade
    /// cannot be configured by accident.
    pub fn new(required_extensions: BTreeSet<String>) -> Result<Self, ProfileError> {
        if required_extensions.is_empty() {
            return Err(ProfileError(vec![Violation::EmptyRequiredExtensionSet]));
        }
        Ok(Self {
            required_extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    #[error("message id must be 1..=128 printable ASCII characters")]
    BadMessageId,
    #[error("id field {0:?} must be 1..=128 printable ASCII characters")]
    BadId(&'static str),
    #[error("message role must be ROLE_USER or ROLE_AGENT")]
    BadRole,
    #[error("message must carry at least one part")]
    NoParts,
    #[error("part {0} has no content")]
    EmptyPart(usize),
    #[error("part {0} is a raw-bytes part; raw parts are unsupported in v1")]
    RawPartUnsupported(usize),
    #[error("part {0} is a URL part; URL parts are unsupported in v1")]
    UrlPartUnsupported(usize),
    #[error("extension URI {0:?} must be a bounded https URI with a host")]
    BadExtensionUri(String),
    #[error("required extension set must not be empty")]
    EmptyRequiredExtensionSet,
    #[error("A2A-Version {0:?} is not the pinned version {1:?}")]
    BadA2aVersion(String, &'static str),
    #[error("request must carry a message")]
    NoMessage,
    #[error("request must set returnImmediately (nonblocking v1 profile)")]
    NotNonblocking,
    #[error("push-notification configuration is forbidden in v1")]
    PushConfigForbidden,
    #[error("agent card must advertise an https HTTP+JSON interface at protocol 1.0")]
    NoV1Interface,
    #[error("agent card must set capabilities.streaming = false")]
    StreamingNotDisabled,
    #[error("agent card must set capabilities.pushNotifications = false")]
    PushNotDisabled,
    #[error("agent card must set capabilities.extendedAgentCard = true")]
    NoExtendedCard,
    #[error("agent card must advertise required extension {0:?} with required = true")]
    MissingRequiredExtension(String),
    #[error("agent card must require a mutual-TLS security scheme")]
    NoMutualTls,
    #[error("task state {0:?} is not reachable in the v1 profile")]
    DisallowedTaskState(i32),
    #[error("required extension {0:?} was not activated")]
    ExtensionNotActivated(String),
    #[error("activated extension {0:?} is not supported")]
    ExtensionNotSupported(String),
}

/// Non-empty list of violations; empty result means the object conforms.
#[derive(Debug, thiserror::Error)]
#[error("A2A v1 profile violation: {} ({} total)", .0[0], .0.len())]
pub struct ProfileError(pub Vec<Violation>);

fn finish(violations: Vec<Violation>) -> Result<(), ProfileError> {
    if violations.is_empty() {
        Ok(())
    } else {
        Err(ProfileError(violations))
    }
}

/// A2A identifiers under the Akson profile: bounded, printable ASCII.
pub fn is_valid_id(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// A bounded `https` URI with a non-empty authority and no control characters
/// or whitespace. Rejects `https://` alone and hostless/control-containing
/// values. This is structural only; it is not a full URI parser.
pub fn is_bounded_https_uri(uri: &str) -> bool {
    if uri.len() > MAX_EXTENSION_URI_LEN {
        return false;
    }
    let Some(rest) = uri.strip_prefix("https://") else {
        return false;
    };
    // Authority runs up to the first '/', '?' or '#'; it must be non-empty and
    // free of control characters and spaces.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && !rest.bytes().any(|b| b <= 0x20 || b == 0x7f)
}

/// The A2A-Version an operation carries MUST be the pinned version
/// (design §10.1, §18 downgrade resistance).
pub fn validate_a2a_version(version: &str) -> Result<(), ProfileError> {
    if version == crate::A2A_VERSION {
        Ok(())
    } else {
        Err(ProfileError(vec![Violation::BadA2aVersion(
            version.to_owned(),
            crate::A2A_VERSION,
        )]))
    }
}

fn check_extension_uri(uri: &str, violations: &mut Vec<Violation>) {
    if !is_bounded_https_uri(uri) {
        violations.push(Violation::BadExtensionUri(uri.to_owned()));
    }
}

/// Validates one standard Message under the v1 profile.
pub fn validate_message(message: &Message) -> Result<(), ProfileError> {
    let mut violations = Vec::new();
    if !is_valid_id(&message.message_id) {
        violations.push(Violation::BadMessageId);
    }
    if !message.context_id.is_empty() && !is_valid_id(&message.context_id) {
        violations.push(Violation::BadId("contextId"));
    }
    if !message.task_id.is_empty() && !is_valid_id(&message.task_id) {
        violations.push(Violation::BadId("taskId"));
    }
    for id in &message.reference_task_ids {
        if !is_valid_id(id) {
            violations.push(Violation::BadId("referenceTaskIds"));
        }
    }
    if !matches!(Role::try_from(message.role), Ok(Role::User | Role::Agent)) {
        violations.push(Violation::BadRole);
    }
    if message.parts.is_empty() {
        violations.push(Violation::NoParts);
    }
    for (index, p) in message.parts.iter().enumerate() {
        match &p.content {
            Some(part::Content::Text(_) | part::Content::Data(_)) => {}
            Some(part::Content::Raw(_)) => violations.push(Violation::RawPartUnsupported(index)),
            Some(part::Content::Url(_)) => violations.push(Violation::UrlPartUnsupported(index)),
            None => violations.push(Violation::EmptyPart(index)),
        }
    }
    for uri in &message.extensions {
        check_extension_uri(uri, &mut violations);
    }
    finish(violations)
}

/// Validates an initiating SendMessage request: nonblocking, no push
/// configuration, and a conforming message (design §10.1).
pub fn validate_send_message_request(request: &SendMessageRequest) -> Result<(), ProfileError> {
    let mut violations = Vec::new();
    match &request.message {
        None => violations.push(Violation::NoMessage),
        Some(message) => {
            if let Err(ProfileError(inner)) = validate_message(message) {
                violations.extend(inner);
            }
        }
    }
    match &request.configuration {
        None => violations.push(Violation::NotNonblocking),
        Some(configuration) => {
            if !configuration.return_immediately {
                violations.push(Violation::NotNonblocking);
            }
            if configuration.task_push_notification_config.is_some() {
                violations.push(Violation::PushConfigForbidden);
            }
        }
    }
    finish(violations)
}

/// Validates that a peer Agent Card advertises the v1 profile (design §10.1):
/// an https HTTP+JSON interface at the pinned protocol version, streaming and
/// push disabled, the authenticated extended card, every required Akson
/// extension marked required, and a mutual-TLS security requirement.
pub fn validate_agent_card(card: &AgentCard, config: &ProfileConfig) -> Result<(), ProfileError> {
    let mut violations = Vec::new();

    if !card.supported_interfaces.iter().any(|i| {
        i.protocol_binding == HTTP_JSON_BINDING
            && i.protocol_version == crate::A2A_VERSION
            && is_bounded_https_uri(&i.url)
    }) {
        violations.push(Violation::NoV1Interface);
    }

    match &card.capabilities {
        None => {
            violations.push(Violation::StreamingNotDisabled);
            violations.push(Violation::PushNotDisabled);
            violations.push(Violation::NoExtendedCard);
            for uri in &config.required_extensions {
                violations.push(Violation::MissingRequiredExtension(uri.clone()));
            }
        }
        Some(caps) => {
            if caps.streaming != Some(false) {
                violations.push(Violation::StreamingNotDisabled);
            }
            if caps.push_notifications != Some(false) {
                violations.push(Violation::PushNotDisabled);
            }
            if caps.extended_agent_card != Some(true) {
                violations.push(Violation::NoExtendedCard);
            }
            for uri in &config.required_extensions {
                if !caps.extensions.iter().any(|e| &e.uri == uri && e.required) {
                    violations.push(Violation::MissingRequiredExtension(uri.clone()));
                }
            }
        }
    }

    // mTLS must be mandatory: there must be at least one security requirement,
    // and EVERY requirement alternative must include an mTLS scheme. A card
    // offering an mTLS alternative *and* a non-mTLS one (e.g. bearer, or an
    // empty anonymous requirement) lets a client pick the weaker path, so it
    // fails (design §9.1: no non-mTLS fallback).
    let mtls_scheme_names: BTreeSet<&String> = card
        .security_schemes
        .iter()
        .filter(|(_, scheme)| {
            matches!(
                scheme.scheme,
                Some(security_scheme::Scheme::MtlsSecurityScheme(_))
            )
        })
        .map(|(name, _)| name)
        .collect();
    let mtls_mandatory = !card.security_requirements.is_empty()
        && card.security_requirements.iter().all(|req| {
            req.schemes
                .keys()
                .any(|name| mtls_scheme_names.contains(name))
        });
    if !mtls_mandatory {
        violations.push(Violation::NoMutualTls);
    }

    finish(violations)
}

/// Task states a v1 producer may report (design §10.1 matrix).
/// `TASK_STATE_AUTH_REQUIRED` is disabled in v1 and unknown values are
/// rejected outright.
pub fn validate_task_state(state: i32) -> Result<(), ProfileError> {
    match TaskState::try_from(state) {
        Ok(
            TaskState::Submitted
            | TaskState::Working
            | TaskState::Completed
            | TaskState::Failed
            | TaskState::Rejected
            | TaskState::InputRequired
            | TaskState::Canceled,
        ) => Ok(()),
        _ => Err(ProfileError(vec![Violation::DisallowedTaskState(state)])),
    }
}

/// Extension negotiation (design §10.1): every operation must activate the
/// complete required set, and the strict v1 profile rejects activation of
/// anything this endpoint does not support. Returns the set to echo in the
/// response `A2A-Extensions`.
pub fn negotiate_extensions(
    supported: &BTreeSet<String>,
    required: &BTreeSet<String>,
    activated: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ProfileError> {
    let mut violations = Vec::new();
    for uri in required {
        if !activated.contains(uri) {
            violations.push(Violation::ExtensionNotActivated(uri.clone()));
        }
    }
    for uri in activated {
        if !supported.contains(uri) {
            violations.push(Violation::ExtensionNotSupported(uri.clone()));
        }
    }
    finish(violations)?;
    Ok(activated.clone())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a2a_version_must_be_pinned() {
        assert!(validate_a2a_version("1.0").is_ok());
        assert!(validate_a2a_version("0.3").is_err());
        assert!(validate_a2a_version("2.0").is_err());
        assert!(validate_a2a_version("").is_err());
    }

    #[test]
    fn https_uri_rejects_hostless_and_control() {
        assert!(is_bounded_https_uri("https://reviewer.example:7300/a2a"));
        assert!(!is_bounded_https_uri("https://"));
        assert!(!is_bounded_https_uri("http://reviewer.example"));
        assert!(!is_bounded_https_uri("https:///path"));
        assert!(!is_bounded_https_uri("https://host\u{7f}/x"));
        assert!(!is_bounded_https_uri("https://host with space"));
        assert!(!is_bounded_https_uri(&format!(
            "https://{}",
            "a".repeat(300)
        )));
    }

    #[test]
    fn profile_config_rejects_empty_required_set() {
        assert!(ProfileConfig::new(BTreeSet::new()).is_err());
        assert!(ProfileConfig::new(BTreeSet::from(["https://x.invalid/e".to_owned()])).is_ok());
    }
}

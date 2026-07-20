//! The output gate (design §7.2 step 10): every worker result passes size,
//! media-type, and recipient checks against exactly what the work order granted.
//!
//! The gate is the last line of defense on the way out of the sandbox. It never
//! trusts the worker: each proposed output must fall inside the granted
//! capability scope (§12.1) for its channel — a `respond` grant for a response, an
//! `artifact_export` grant for an artifact — or it is rejected. Absence of the
//! grant is a denial. Recipients cannot be widened, media types cannot be added,
//! byte budgets and response/artifact counts cannot be exceeded. (The schema gate
//! — validating a result against its deliverable's `result-manifest` shape — lands
//! with the evidence engine in M11.)
//!
//! What you write:
//! ```
//! use akson_worker::{gate_outputs, ProposedOutput, OutputChannel};
//! use akson_authority::{CapabilityVector, Grant, RespondScope};
//! let vector = CapabilityVector::new(vec![Grant::Respond(RespondScope {
//!     task_id: "task-1".into(), message_id: "msg-1".into(),
//!     recipient: "request-origin".into(), max_responses: 1, max_bytes: 8192,
//!     deadline: "2030-01-01T00:00:00Z".into(),
//! })]).unwrap();
//! let outputs = vec![ProposedOutput {
//!     channel: OutputChannel::Response,
//!     recipient: "request-origin".into(),
//!     media_type: "application/json".into(),
//!     bytes: 100,
//! }];
//! gate_outputs(&vector, &outputs).unwrap();
//! ```

use akson_authority::{CapabilityComponent, CapabilityVector, Grant};

/// The channel a worker output is emitted on. Each maps to the capability that
/// must authorize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputChannel {
    /// A response to the requester — needs a `respond` grant.
    Response,
    /// An exported artifact — needs an `artifact_export` grant.
    Artifact,
}

impl OutputChannel {
    fn component(self) -> CapabilityComponent {
        match self {
            OutputChannel::Response => CapabilityComponent::Respond,
            OutputChannel::Artifact => CapabilityComponent::ArtifactExport,
        }
    }
}

/// One output a worker proposes to emit, reduced to what the gate checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedOutput {
    pub channel: OutputChannel,
    pub recipient: String,
    pub media_type: String,
    pub bytes: u64,
}

/// Why an output was rejected by the gate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GateReject {
    #[error("no {0:?} capability grants this channel")]
    NoGrant(CapabilityComponent),
    #[error("recipient {got:?} is not the granted recipient {allowed:?}")]
    Recipient { allowed: String, got: String },
    #[error("media type {got:?} is not in the granted set")]
    MediaType { got: String },
    #[error("output is {got} bytes, over the {max}-byte budget")]
    Size { max: u64, got: u64 },
    #[error("output count exceeds the granted maximum {max}")]
    Count { max: u32 },
}

/// A rejection with the index of the offending output.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("output {index}: {reason}")]
pub struct GateError {
    pub index: usize,
    pub reason: GateReject,
}

/// Gates a batch of worker outputs against the granted capability vector
/// (design §7.2 step 10). Returns `Ok(())` only if *every* output falls inside
/// its channel's grant; otherwise the first offending output's index and reason.
///
/// Per-output: the channel must be granted, the recipient must match exactly, an
/// artifact's media type must be in the granted set, and the byte length must be
/// within budget. Aggregate: response and artifact counts must not exceed their
/// granted maxima.
pub fn gate_outputs(
    vector: &CapabilityVector,
    outputs: &[ProposedOutput],
) -> Result<(), GateError> {
    let mut responses = 0u32;
    let mut artifacts = 0u32;

    for (index, out) in outputs.iter().enumerate() {
        let err = |reason| GateError { index, reason };
        let grant = vector
            .grant(out.channel.component())
            .ok_or_else(|| err(GateReject::NoGrant(out.channel.component())))?;

        match (out.channel, grant) {
            (OutputChannel::Response, Grant::Respond(scope)) => {
                if out.recipient != scope.recipient {
                    return Err(err(GateReject::Recipient {
                        allowed: scope.recipient.clone(),
                        got: out.recipient.clone(),
                    }));
                }
                if out.bytes > scope.max_bytes {
                    return Err(err(GateReject::Size {
                        max: scope.max_bytes,
                        got: out.bytes,
                    }));
                }
                responses += 1;
                if responses > scope.max_responses {
                    return Err(err(GateReject::Count {
                        max: scope.max_responses,
                    }));
                }
            }
            (OutputChannel::Artifact, Grant::ArtifactExport(scope)) => {
                if out.recipient != scope.recipient {
                    return Err(err(GateReject::Recipient {
                        allowed: scope.recipient.clone(),
                        got: out.recipient.clone(),
                    }));
                }
                if !scope.media_types.iter().any(|m| m == &out.media_type) {
                    return Err(err(GateReject::MediaType {
                        got: out.media_type.clone(),
                    }));
                }
                if out.bytes > scope.max_bytes {
                    return Err(err(GateReject::Size {
                        max: scope.max_bytes,
                        got: out.bytes,
                    }));
                }
                artifacts += 1;
                if artifacts > scope.max_count {
                    return Err(err(GateReject::Count {
                        max: scope.max_count,
                    }));
                }
            }
            // The vector indexes grants by component, so a component's grant is
            // always the matching variant; this arm is unreachable in practice.
            _ => return Err(err(GateReject::NoGrant(out.channel.component()))),
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use akson_authority::{ArtifactExportScope, RespondScope};

    fn vector() -> CapabilityVector {
        CapabilityVector::new(vec![
            Grant::Respond(RespondScope {
                task_id: "task-1".to_owned(),
                message_id: "msg-1".to_owned(),
                recipient: "request-origin".to_owned(),
                max_responses: 1,
                max_bytes: 8192,
                deadline: "2030-01-01T00:00:00Z".to_owned(),
            }),
            Grant::ArtifactExport(ArtifactExportScope {
                recipient: "request-origin".to_owned(),
                task_id: "task-1".to_owned(),
                media_types: vec!["application/json".to_owned(), "text/plain".to_owned()],
                max_count: 2,
                max_bytes: 4096,
            }),
        ])
        .unwrap()
    }

    fn response(recipient: &str, bytes: u64) -> ProposedOutput {
        ProposedOutput {
            channel: OutputChannel::Response,
            recipient: recipient.to_owned(),
            media_type: "application/json".to_owned(),
            bytes,
        }
    }

    fn artifact(media_type: &str, bytes: u64) -> ProposedOutput {
        ProposedOutput {
            channel: OutputChannel::Artifact,
            recipient: "request-origin".to_owned(),
            media_type: media_type.to_owned(),
            bytes,
        }
    }

    #[test]
    fn in_scope_outputs_admit() {
        gate_outputs(
            &vector(),
            &[response("request-origin", 100), artifact("text/plain", 200)],
        )
        .unwrap();
    }

    #[test]
    fn a_channel_without_a_grant_is_denied() {
        // A vector that grants only respond rejects an artifact.
        let only_respond = CapabilityVector::new(vec![Grant::Respond(RespondScope {
            task_id: "t".to_owned(),
            message_id: "m".to_owned(),
            recipient: "request-origin".to_owned(),
            max_responses: 1,
            max_bytes: 8192,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
        })])
        .unwrap();
        let err = gate_outputs(&only_respond, &[artifact("application/json", 10)]).unwrap_err();
        assert_eq!(err.index, 0);
        assert_eq!(
            err.reason,
            GateReject::NoGrant(CapabilityComponent::ArtifactExport)
        );
    }

    #[test]
    fn a_widened_recipient_is_rejected() {
        let err = gate_outputs(&vector(), &[response("someone-else", 100)]).unwrap_err();
        assert!(matches!(err.reason, GateReject::Recipient { .. }));
    }

    #[test]
    fn an_unlisted_media_type_is_rejected() {
        let err = gate_outputs(&vector(), &[artifact("image/png", 100)]).unwrap_err();
        assert_eq!(
            err.reason,
            GateReject::MediaType {
                got: "image/png".to_owned()
            }
        );
    }

    #[test]
    fn an_oversize_output_is_rejected_with_its_index() {
        // Second output (index 1) is over the artifact byte budget.
        let outputs = vec![
            response("request-origin", 100),
            artifact("text/plain", 5000),
        ];
        let err = gate_outputs(&vector(), &outputs).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(
            err.reason,
            GateReject::Size {
                max: 4096,
                got: 5000
            }
        );
    }

    #[test]
    fn exceeding_the_response_count_is_rejected() {
        // max_responses is 1; a second response trips the count.
        let outputs = vec![
            response("request-origin", 10),
            response("request-origin", 10),
        ];
        let err = gate_outputs(&vector(), &outputs).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.reason, GateReject::Count { max: 1 });
    }
}

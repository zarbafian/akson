//! Deriving a peer task's sandbox boundary from its work-order capability vector
//! (design §13.1, §12.1). The confinement is a pure function of the grants:
//! default-deny, and each grant adds exactly its own access. Nothing the peer was
//! not granted is constructed into the worker — no host filesystem, no network, no
//! inputs beyond the ones named.
//!
//! What you write (the grant) → what the worker gets (the boundary):
//!
//! ```text
//!   read_supplied_inputs {ids}  →  /inputs (ro), holding exactly those input files
//!   respond | artifact_export   →  /output (rw), the only writable place
//!   processor_use {processor}   →  a brokered model call (the fd is wired next)
//!   (anything not granted)      →  denied: no bind, no channel, no reach
//! ```
//!
//! The read-only OS runtime (interpreter + shared libraries) is the execution
//! substrate — it carries no task or user data and is always present, independent
//! of the grants.

use axon_authority::{CapabilityVector, Grant};
use axon_sandbox::SandboxSpec;

/// The access a work order's capability vector authorizes, as a boundary. Purely a
/// function of the grants — no host state — so it is unit-testable without ever
/// launching a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confinement {
    /// Whether `read_supplied_inputs` was granted at all (distinguishes "granted,
    /// zero ids" from "not granted" — the latter binds no `/inputs`).
    pub reads_inputs: bool,
    /// The input ids the worker may read, from the `read_supplied_inputs` scope.
    /// Empty (and `reads_inputs == false`) when the grant is absent: the worker
    /// then sees no supplied inputs at all.
    pub input_ids: Vec<String>,
    /// Whether the worker has any writable output channel (`respond` or
    /// `artifact_export`); without one, no `/output` is bound.
    pub writes_output: bool,
    /// The processor a `processor_use` grant authorizes, if any. The brokered
    /// model-call fd is wired from this in a following step; today it only records
    /// that peer work may reach a model, and which one.
    pub processor: Option<String>,
}

impl Confinement {
    /// Derives the confinement from the granted capabilities (§12.1). Default-deny:
    /// a component with no grant contributes no access.
    pub fn from_capabilities(capabilities: &CapabilityVector) -> Self {
        let mut confinement = Confinement {
            reads_inputs: false,
            input_ids: Vec::new(),
            writes_output: false,
            processor: None,
        };
        for grant in capabilities.grants() {
            match grant {
                Grant::ReadSuppliedInputs(scope) => {
                    confinement.reads_inputs = true;
                    confinement.input_ids = scope.input_ids.clone();
                }
                Grant::Respond(_) | Grant::ArtifactExport(_) => {
                    confinement.writes_output = true;
                }
                Grant::ProcessorUse(scope) => {
                    confinement.processor = Some(scope.processor_id.clone());
                }
            }
        }
        confinement
    }

    /// Builds the sandbox spec for this confinement: the read-only OS runtime
    /// substrate (`runtime_binds`, each `(host, sandbox)` — system libraries, no
    /// task data), plus exactly the binds the grants authorize — `/inputs` (ro)
    /// iff inputs are read, `/output` (rw) iff there is an output channel.
    ///
    /// `staging_dir` is the host directory the granted inputs are staged into;
    /// `output_dir` is where the worker's outputs are collected.
    pub fn to_spec(
        &self,
        staging_dir: &str,
        output_dir: &str,
        runtime_binds: &[(&str, &str)],
    ) -> SandboxSpec {
        let mut spec = SandboxSpec::clean_worker("/");
        for (host, sandbox) in runtime_binds {
            spec = spec.ro_bind(host, sandbox);
        }
        if self.reads_inputs {
            spec = spec.ro_bind(staging_dir, "/inputs");
        }
        if self.writes_output {
            spec = spec.rw_bind(output_dir, "/output");
        }
        spec
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axon_authority::{ArtifactExportScope, ProcessorUseScope, ReadInputsScope, RespondScope};
    use axon_sandbox::BubblewrapLauncher;

    fn respond() -> Grant {
        Grant::Respond(RespondScope {
            task_id: "task-1".to_owned(),
            message_id: "msg-1".to_owned(),
            recipient: "request-origin".to_owned(),
            max_responses: 1,
            max_bytes: 8192,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
        })
    }

    fn read_inputs(ids: &[&str]) -> Grant {
        Grant::ReadSuppliedInputs(ReadInputsScope {
            input_ids: ids.iter().map(|s| (*s).to_owned()).collect(),
            contract_digest: "a".repeat(64),
        })
    }

    fn vector(grants: Vec<Grant>) -> CapabilityVector {
        CapabilityVector::new(grants).unwrap()
    }

    // The runtime substrate is orthogonal to the grants; a small fixed list is
    // enough to prove it is always present.
    const RUNTIME: &[(&str, &str)] = &[("/usr", "/usr"), ("/bin", "/bin")];

    fn sandbox_paths(spec: &SandboxSpec) -> Vec<String> {
        // The spec renders to the bubblewrap argv; the sandbox-side path after each
        // --ro-bind / --bind is the boundary we assert on.
        let argv = BubblewrapLauncher::build_argv(spec, "/bin/sh", &[], None);
        let mut out = Vec::new();
        for (i, a) in argv.iter().enumerate() {
            if (a == "--ro-bind" || a == "--bind") && i + 2 < argv.len() {
                out.push(argv[i + 2].clone());
            }
        }
        out
    }

    #[test]
    fn read_and_respond_bind_inputs_ro_and_output_rw() {
        let c = Confinement::from_capabilities(&vector(vec![read_inputs(&["diff"]), respond()]));
        assert!(c.reads_inputs);
        assert_eq!(c.input_ids, vec!["diff".to_owned()]);
        assert!(c.writes_output);
        assert!(c.processor.is_none());
        let paths = sandbox_paths(&c.to_spec("/host/in", "/host/out", RUNTIME));
        assert!(paths.contains(&"/inputs".to_owned()));
        assert!(paths.contains(&"/output".to_owned()));
        assert!(paths.contains(&"/usr".to_owned()));
    }

    #[test]
    fn respond_only_gives_no_input_view() {
        // A peer granted only `respond` sees NO supplied files — /inputs is absent.
        let c = Confinement::from_capabilities(&vector(vec![respond()]));
        assert!(!c.reads_inputs);
        assert!(c.input_ids.is_empty());
        assert!(c.writes_output);
        let paths = sandbox_paths(&c.to_spec("/host/in", "/host/out", RUNTIME));
        assert!(
            !paths.contains(&"/inputs".to_owned()),
            "no input grant → no /inputs"
        );
        assert!(paths.contains(&"/output".to_owned()));
    }

    #[test]
    fn read_only_gives_no_output_channel() {
        let c = Confinement::from_capabilities(&vector(vec![read_inputs(&["diff"])]));
        assert!(c.reads_inputs);
        assert!(!c.writes_output);
        let paths = sandbox_paths(&c.to_spec("/host/in", "/host/out", RUNTIME));
        assert!(paths.contains(&"/inputs".to_owned()));
        assert!(
            !paths.contains(&"/output".to_owned()),
            "no output grant → no /output"
        );
    }

    #[test]
    fn processor_use_is_recorded_for_the_broker_step() {
        let c = Confinement::from_capabilities(&vector(vec![
            respond(),
            Grant::ProcessorUse(ProcessorUseScope {
                processor_id: "model-x".to_owned(),
                input_ids: vec!["diff".to_owned()],
                max_cost_microusd: 1000,
                max_bytes: 4096,
            }),
        ]));
        assert_eq!(c.processor.as_deref(), Some("model-x"));
    }

    #[test]
    fn artifact_export_alone_still_opens_an_output_channel() {
        let c = Confinement::from_capabilities(&vector(vec![Grant::ArtifactExport(
            ArtifactExportScope {
                recipient: "request-origin".to_owned(),
                task_id: "task-1".to_owned(),
                media_types: vec!["application/sarif+json".to_owned()],
                max_count: 4,
                max_bytes: 65536,
            },
        )]));
        assert!(c.writes_output);
        assert!(!c.reads_inputs);
    }
}

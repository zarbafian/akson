//! End-to-end clean-worker demo — the tracer bullet's execution half (design §7.2,
//! §13.1). It composes the real M8 authority and M9 sandbox/worker pieces into one
//! flow and asserts the spine holds:
//!
//!   work order (issued + MAC-verified) → stage exactly the approved inputs →
//!   launch a fully-confined worker that reads them and writes a bounded result →
//!   gate that result against the work order's capability grant.
//!
//! The worker here is `/bin/sh` running a tiny pure-shell "echo review" — a
//! DEV-ONLY, non-shippable stand-in (it satisfies no evidence gate, §4.4). It
//! exists only to prove the M8→M9 integration end to end before the daemon and
//! real adapters land.
//!
//! Needs bwrap + unprivileged user namespaces + a delegated cgroup v2 subtree, so
//! it is `#[ignore]`d and runs in CI's isolation job (or locally once userns is
//! enabled). Run it as a narrated demo with:
//!   cargo test -p axon-harness --test clean_worker_e2e -- --ignored --nocapture
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use axon_authority::{
    Audience, Budgets, CapabilityVector, Grant, RequestOrigin, RespondScope, WorkOrder,
    WorkOrderKey,
};
use axon_contract::Identity;
use axon_sandbox::{
    BubblewrapLauncher, CgroupLimits, CgroupScope, DenyAction, SandboxLauncher, SandboxSpec,
    SeccompPolicy,
};
use axon_worker::{
    gate_outputs, stage_inputs, GateReject, OutputChannel, ProposedOutput, StageItem,
};

/// The locally-issued work order authorizing this attempt: a single `respond`
/// grant to the request origin, capped at 1 KiB. (Every other field is bound into
/// the MAC too; this is the §12.3 shape.)
fn work_order() -> WorkOrder {
    let id = |agent: &str| Identity {
        issuer: "local".to_owned(),
        agent: agent.to_owned(),
    };
    WorkOrder {
        version: 1,
        work_order_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        issuer: id("authority"),
        issuer_assurance: "local-human".to_owned(),
        audience: Audience {
            daemon: "axond".to_owned(),
            executor: "worker-1".to_owned(),
        },
        request_origin: RequestOrigin {
            peer: id("requester"),
            tls_certificate_sha256: "ab".repeat(32),
        },
        task_id: "task-1".to_owned(),
        context_id: "ctx-1".to_owned(),
        message_id: "msg-1".to_owned(),
        contract_revision: 0,
        contract_digest: "a".repeat(64),
        capabilities: CapabilityVector::new(vec![Grant::Respond(RespondScope {
            task_id: "task-1".to_owned(),
            message_id: "msg-1".to_owned(),
            recipient: "request-origin".to_owned(),
            max_responses: 1,
            max_bytes: 1024,
            deadline: "2030-01-01T00:00:00Z".to_owned(),
        })])
        .unwrap(),
        input_manifest: vec!["diff".to_owned()],
        processor_digest: None,
        runner_digest: None,
        sandbox_digest: None,
        profile_digest: None,
        budgets: Budgets {
            max_cost_microusd: 0,
            max_bytes: 8192,
            max_operations: 4,
        },
        evidence_slots: vec![],
        policy_version: 1,
        decision_id: "d-1".to_owned(),
        not_before: "2026-01-01T00:00:00Z".to_owned(),
        deadline: "2030-01-01T00:00:00Z".to_owned(),
        nonce: "n".repeat(43),
        remote_cancel: None,
    }
}

#[test]
#[ignore = "needs bwrap + unprivileged userns + a delegated cgroup; runs in CI's isolation job"]
fn clean_worker_runs_and_its_output_is_gated_end_to_end() {
    let tmp = std::env::temp_dir().join(format!("axon-e2e-{}", std::process::id()));
    let staging = tmp.join("inputs");
    let output = tmp.join("output");
    std::fs::create_dir_all(&output).unwrap();

    // 1. Issue the work order and verify its MAC — the executor authorizes exactly
    //    this (design §12.3). The gate later uses its capability grant.
    let key = WorkOrderKey::from_bytes([7u8; 32]);
    let issued = work_order().issue(&key).expect("issue work order");
    issued.verify(&key).expect("work order MAC verifies");
    eprintln!(
        "[1] work order {} issued + MAC-verified",
        issued.order.work_order_id
    );

    // 2. Stage exactly the approved input (the one named in input_manifest).
    let staged = stage_inputs(
        &[StageItem {
            id: "diff".to_owned(),
            media_type: "text/x-diff".to_owned(),
            content: b"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n".to_vec(),
        }],
        &staging,
        "/inputs",
    )
    .expect("stage inputs");
    eprintln!(
        "[2] staged {} input(s); in-sandbox path {}",
        staged.manifest.len(),
        staged.manifest[0].path
    );

    // 3. Author the isolation policy: read-only runtime + the staged inputs at
    //    /inputs, a read-write output bind at /output. The Landlock profile the real
    //    worker entrypoint would apply is derivable straight from this spec.
    let spec = SandboxSpec::clean_worker("/")
        .ro_bind("/usr", "/usr")
        .ro_bind("/bin", "/bin")
        .ro_bind("/lib", "/lib")
        .ro_bind("/lib64", "/lib64")
        .ro_bind(staging.to_str().unwrap(), "/inputs")
        .rw_bind(output.to_str().unwrap(), "/output");
    let ll = spec.landlock_profile();
    assert!(ll.read_only.contains(&PathBuf::from("/inputs")));
    assert!(ll.read_write.contains(&PathBuf::from("/output")));

    // 4. The dev "echo review" worker: pure shell (the seccomp baseline blocks the
    //    fork/exec external commands need). It confirms the approved inputs arrived
    //    and writes a bounded response to the output bind.
    let script = concat!(
        "[ -r /inputs/diff ] || exit 40\n", // the approved input is present
        "[ -r /inputs/manifest.json ] || exit 41\n", // and its manifest
        "printf '%s' 'reviewed: LGTM' > /output/response || exit 42\n",
    );
    let seccomp = SeccompPolicy::clean_worker_baseline(DenyAction::KillProcess);
    let cgroup = match CgroupScope::create(
        &format!("axon-e2e-{}", std::process::id()),
        &CgroupLimits {
            max_memory_bytes: Some(64 * 1024 * 1024),
            max_pids: Some(16),
            cpu_max: None,
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            // No writable delegated cgroup subtree here — skip the confined launch
            // rather than fail (the sandbox's own tests cover cgroup enforcement).
            eprintln!("[skip] no delegated cgroup subtree ({e}); confined-launch demo not run");
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
    };

    // 5. Launch through the only public seam — full isolation stack, or nothing.
    BubblewrapLauncher
        .launch(
            &spec,
            "/bin/sh",
            &["-c".to_owned(), script.to_owned()],
            &seccomp,
            &cgroup,
        )
        .expect("confined worker ran to completion");
    eprintln!("[3-5] worker ran fully confined (namespaces + mount + seccomp + cgroup)");

    // 6. Collect the worker's output from the host side of the bind and gate it
    //    against the work order's granted capability.
    let body = std::fs::read(output.join("response")).expect("worker wrote a response");
    assert_eq!(body, b"reviewed: LGTM");
    let proposed = ProposedOutput {
        channel: OutputChannel::Response,
        recipient: "request-origin".to_owned(),
        media_type: "text/plain".to_owned(),
        bytes: body.len() as u64,
    };
    gate_outputs(&issued.order.capabilities, &[proposed]).expect("in-scope output admits");
    eprintln!(
        "[6] {}-byte response gated OK against the respond grant",
        body.len()
    );

    // The gate is not a rubber stamp: an over-budget response (> the granted
    // max_bytes) is refused with its offending index.
    let over = ProposedOutput {
        channel: OutputChannel::Response,
        recipient: "request-origin".to_owned(),
        media_type: "text/plain".to_owned(),
        bytes: 4096,
    };
    let err = gate_outputs(&issued.order.capabilities, &[over]).unwrap_err();
    assert_eq!(err.index, 0);
    assert!(matches!(err.reason, GateReject::Size { max: 1024, .. }));
    eprintln!("[6b] an over-budget response is correctly rejected");

    let _ = std::fs::remove_dir_all(&tmp);
}

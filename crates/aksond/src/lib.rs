//! The Akson daemon library (design §16.2): the local control plane.
//!
//! The daemon exposes up to three OS-protected local surfaces — an
//! [`Admin`](Surface::Admin) socket for authority-bearing operator operations, a
//! narrow [`Worker`](Surface::Worker) socket for task I/O, and (only when
//! `AKSON_COORD_UID` names one) a [`Coord`](Surface::Coord) socket for a separate
//! local principal (ADR-0016) — and authenticates every local peer by its Unix
//! credentials. Two pure gates enforce §16.2:
//!
//! - [`authorize`] — a control operation is refused unless the caller's surface
//!   dominates the operation's required surface, so neither narrow surface can
//!   pair, set policy, approve, issue a work order, sign an outcome, export, or
//!   mint consent for an outbound disclosure.
//! - [`authenticate_same_uid`] / [`Admission`] — a local peer is refused unless its
//!   UID is one the socket it connected to admits: the daemon's own for admin and
//!   worker, plus the configured coordination UID for coord.
//!
//! The socket wiring, the OpenAPI 3.1 control API, the risk-card rendering, and the
//! operator command set build on these gates.

mod a2a_client;
mod approve;
mod bootstrap;
mod broker;
mod broker_channel;
mod confinement;
mod control;
mod control_dispatch;
mod coord;
mod coord_egress;
mod decision;
mod delivery;
mod export;
mod introduce;
mod issue;
mod keys;
mod outcome;
mod peercred;
mod reactor;
mod receive;
mod receive_http;
mod receive_serve;
mod receive_server;
mod result;
mod send;
mod socket;
mod worker_run;

pub use a2a_client::{parse_endpoint, post_a2a, MAX_POST_A2A_DURATION};
pub use bootstrap::{BootstrapError, DaemonConfig, DaemonState};
pub use broker::{
    dispatch_processor_call, run_processor_call, CallResponse, CallTransport, HttpsTransport,
    TransportError,
};
pub use control::{authorize, ControlOp, Problem, Surface};
pub use control_dispatch::dispatch_control;
pub use coord::{
    dispatch_coord, encode_cursor, stage_reference, COORD_PROTOCOL, COORD_PROTOCOL_VERSION,
    MAX_STAGED_PAYLOAD_BYTES,
};
pub use decision::{decide, DecisionRecord};
pub use delivery::{deliver_job, prepare_delivery, run_delivery, DeliveryJob};
pub use export::export_result_bundle;
pub use introduce::{
    dial_introduction, intro_profile, respond_introduction, IntroConnState, IntroIdentity,
    IntroduceError, PendingIntro,
};
pub use issue::{issue_for_accepted, IssueConfig};
pub use keys::IdentityKeys;
pub use outcome::finalize_result;
pub use peercred::{
    authenticate_same_uid, current_uid, peer_credentials, AuthError, PeerCredentials,
};
pub use reactor::{react_once, run_reactor};
pub use receive::{dispatch_proposal, DispatchOutcome, Dispatched};
pub use receive_http::{handle_receive, HttpRequest, HttpResponse, ReceiveConfig};
pub use receive_serve::{bind_receive_addr, run_receive_listener, ReceiveServeError};
pub use receive_server::{
    serve as serve_receive, PeerContext, PeerResolver, ReceiveState, StorePeerResolver,
};
pub use result::{submit_result, OutputKind, ResultOutput, ResultSubmission};
pub use send::{run_send, Deliverable, TaskInput, TaskSpec};
pub use socket::{
    admin_socket_path, bind_coord_socket, bind_socket, configured_coord_uid, coord_socket_path,
    handle_connection, send_request, serve, socket_dir, worker_socket_path, Admission,
    ControlRequest, ControlResponse, FulfillOutput, SocketError,
};
pub use worker_run::{run_fulfill, run_worker};

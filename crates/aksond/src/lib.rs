//! The Akson daemon library (design §16.2): the local control plane.
//!
//! The daemon exposes two OS-protected local surfaces — an [`Admin`](Surface::Admin)
//! socket for authority-bearing operator operations and a narrow
//! [`Worker`](Surface::Worker) socket for task I/O — and authenticates every local
//! peer by its Unix credentials. Two pure gates enforce §16.2:
//!
//! - [`authorize`] — a control operation is refused unless the caller's surface is
//!   at least the operation's required surface, so the worker surface can never
//!   pair, set policy, approve, issue a work order, sign an outcome, or export.
//! - [`authenticate_same_uid`] — a local peer is refused unless its UID is the
//!   daemon's own (personal-profile convenience authentication).
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
mod decision;
mod delivery;
mod introduce;
mod issue;
mod keys;
mod outcome;
mod pair_serve;
mod pairing;
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

pub use bootstrap::{BootstrapError, DaemonConfig, DaemonState};
pub use broker::{
    dispatch_processor_call, run_processor_call, CallResponse, CallTransport, HttpsTransport,
    TransportError,
};
pub use control::{authorize, ControlOp, Problem, Surface};
pub use control_dispatch::dispatch_control;
pub use decision::{decide, DecisionRecord};
pub use delivery::{deliver_job, prepare_delivery, run_delivery, DeliveryJob};
pub use introduce::{
    dial_introduction, intro_profile, respond_introduction, IntroConnState, IntroIdentity,
    IntroduceError, PendingIntro,
};
pub use issue::{issue_for_accepted, IssueConfig};
pub use keys::IdentityKeys;
pub use outcome::finalize_result;
pub use pair_serve::{run_pair_invite, run_pair_listener, PairServeError, SharedStore};
pub use pairing::run_pair_accept;
pub use peercred::{
    authenticate_same_uid, current_uid, peer_credentials, AuthError, PeerCredentials,
};
pub use reactor::{react_once, run_reactor};
pub use receive::{dispatch_proposal, DispatchOutcome, Dispatched};
pub use receive_http::{handle_receive, HttpRequest, HttpResponse, ReceiveConfig};
pub use receive_serve::{run_receive_listener, ReceiveServeError};
pub use receive_server::{
    serve as serve_receive, PeerContext, PeerResolver, ReceiveState, StorePeerResolver,
};
pub use result::{submit_result, OutputKind, ResultOutput, ResultSubmission};
pub use send::{run_send, Deliverable, TaskInput, TaskSpec};
pub use socket::{
    admin_socket_path, bind_socket, handle_connection, send_request, serve, socket_dir,
    worker_socket_path, ControlRequest, ControlResponse, FulfillOutput, SocketError,
};
pub use worker_run::{run_fulfill, run_worker};

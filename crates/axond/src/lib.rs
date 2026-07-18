//! The Axon daemon library (design §16.2): the local control plane.
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

mod control;
mod peercred;
mod receive;
mod socket;

pub use control::{authorize, ControlOp, Problem, Surface};
pub use peercred::{
    authenticate_same_uid, current_uid, peer_credentials, AuthError, PeerCredentials,
};
pub use receive::{dispatch_proposal, DispatchOutcome};
pub use socket::{
    admin_socket_path, bind_socket, handle_connection, send_request, serve, socket_dir,
    worker_socket_path, ControlRequest, ControlResponse, SocketError,
};

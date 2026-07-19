//! Pre-auth connection limits shared by the daemon's TLS accept loops (design
//! §9.1). Both the pairing bootstrap endpoint and the A2A receive endpoint accept
//! connections *before* the peer is authenticated, so an unauthenticated peer must
//! never be able to pin memory, file descriptors, or a task indefinitely.
//!
//! Three ceilings, applied together, defeat a slow-loris / connection flood:
//! - [`MAX_CONCURRENT_CONNECTIONS`] bounds how many connections are in flight at
//!   once (a permit held for the whole connection, released when it ends). Excess
//!   connections wait in the kernel accept backlog rather than spawning unbounded
//!   tasks.
//! - [`HANDSHAKE_TIMEOUT`] drops a peer that opens a socket but stalls the TLS
//!   handshake, so it cannot hold a concurrency slot forever.
//! - [`CONNECTION_TIMEOUT`] bounds the whole post-handshake connection (header +
//!   body read, handling, response), so a peer that dribbles a request under the
//!   size cap is still cut off.
//!
//! Together the worst an unauthenticated peer holds is `MAX_CONCURRENT_CONNECTIONS`
//! slots, each for at most `HANDSHAKE_TIMEOUT + CONNECTION_TIMEOUT`.

use std::time::Duration;

/// Cap on connections served concurrently by one accept loop. Local-first daemons
/// talk to a handful of peers; this is generous for real use yet small enough that
/// a flood cannot exhaust memory or descriptors.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// A peer must complete the TLS handshake within this long or be dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Whole-connection ceiling after the handshake: request read + handling +
/// response. Cuts off a slow-header / slow-body sender that stays under the size
/// cap but sends bytes a dribble at a time.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

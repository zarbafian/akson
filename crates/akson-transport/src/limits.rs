//! Pre-auth connection limits shared by the daemon's TLS accept loops (design
//! §9.1). Both the pairing bootstrap endpoint and the A2A receive endpoint accept
//! connections *before* the peer is authorized, so an unauthorized peer must never
//! be able to pin memory, file descriptors, or a task indefinitely.
//!
//! Four ceilings, applied together, defeat a slow-loris / connection flood without
//! penalising a legitimate connection that stays open for several exchanges:
//! - [`MAX_CONCURRENT_CONNECTIONS`] bounds how many connections are in flight at
//!   once (a permit held for the whole connection, released when it ends). Excess
//!   connections wait in the kernel accept backlog rather than spawning unbounded
//!   tasks.
//! - [`HANDSHAKE_TIMEOUT`] drops a peer that opens a socket but stalls the TLS
//!   handshake, so it cannot hold a concurrency slot forever.
//! - [`HEADER_READ_TIMEOUT`] bounds the wait for each request's headers. Because it
//!   re-arms while a keep-alive connection waits for the *next* request, it also
//!   caps idle time between exchanges — a slow-header sender or an idle squatter is
//!   cut off, but a connection that keeps exchanging promptly lives as long as it
//!   likes.
//! - [`BODY_READ_TIMEOUT`] bounds reading each (already size-capped) request body,
//!   so a peer dribbling the body a byte at a time is cut off per request.
//!
//! These are per-request, not a whole-connection cap: back-and-forth over one
//! connection is unbounded in count and total duration, as long as each exchange is
//! prompt.

use std::time::Duration;

/// Cap on connections served concurrently by one accept loop. Local-first daemons
/// talk to a handful of peers; this is generous for real use yet small enough that
/// a flood cannot exhaust memory or descriptors.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// A peer must complete the TLS handshake within this long or be dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-request ceiling on reading the request head. Re-arms for each request on a
/// keep-alive connection, so it doubles as the idle-between-exchanges cap.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-request ceiling on reading the (size-capped) request body.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

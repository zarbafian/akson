# Axon v1 A2A profile

Status: draft, tracks design §10.1

This is the exact mapping between Axon v1 and the pinned A2A definitions
(`PIN`, `proto/a2a.proto`, package `lf.a2a.v1`). The validator implementing
it is `crates/axon-proto/src/profile.rs`; the conformance vectors are
`vectors/`. BCP 14 keywords as in the design.

## Binding

- Transport: the A2A HTTP+JSON binding — the standard proto3 JSON mapping of
  the pinned definitions — over TLS 1.3 with mutual authentication
  (design §9.1), media type `application/a2a+json`.
- Every authenticated operation carries `A2A-Version: 1.0` and activates the
  complete required Axon extension set via the `A2A-Extensions` service
  parameter. Responses echo the activated set.
- Extension negotiation is strict: a request missing any required extension,
  or activating a URI this endpoint does not support, fails before state
  lookup, Task creation, or content processing
  (`profile::negotiate_extensions`).

## Operations used

| Operation | v1 use |
|---|---|
| `SendMessage` | task proposals, follow-up revisions, and the task-less signed outcome |
| `GetTask` | polling; status/history carry signed decision Messages |
| `ListTasks` | scoped to the authenticated origin |
| `CancelTask` | returns `TaskNotCancelableError` unless the work order grants `remote_cancel` |
| `GetExtendedAgentCard` | authenticated identity/key projection after pairing |

`SendStreamingMessage`, `SubscribeToTask`, and every push-notification-config
operation are not part of the profile; the Agent Card advertises them
disabled, and requests configuring push fail
(`Violation::PushConfigForbidden`).

## Nonblocking rule

The initiating `SendMessageRequest` MUST set
`configuration.returnImmediately = true`. For a valid proposal the server
returns a Task in `TASK_STATE_SUBMITTED` — after the Axon delivery
extension's durable commit — and never a direct Message response. This keeps
approval and execution out of the receive request (design §10.1).

## Objects

- **Message**: ids are 1–128 printable ASCII; role MUST be `ROLE_USER` or
  `ROLE_AGENT`; at least one Part; `extensions` lists the exact contributing
  URIs (https, ≤256 chars).
- **Part**: only `text` and `data` contents are supported. `raw` and `url`
  Parts are rejected (design §10.2); filenames are display labels only.
- **Task**: server-assigned id; state per the matrix below.
- **Artifact**: outputs only; every transported output is covered by a
  SHA-256 entry in the Axon result manifest.
- **Agent Card**: MUST advertise an `https` `HTTP+JSON` interface at
  protocol `1.0`, `streaming: false`, `pushNotifications: false`,
  `extendedAgentCard: true`, every safety-critical Axon extension with
  `required: true`, and a security requirement referencing a
  `mtlsSecurityScheme`. Skills are advertisements, never grants.

## Task-state matrix (design §10.1)

| Axon event | A2A state |
|---|---|
| durable inert proposal | `TASK_STATE_SUBMITTED` |
| accepted, awaiting work-order claim | `TASK_STATE_SUBMITTED` + signed accept Message |
| revision requested | `TASK_STATE_INPUT_REQUIRED` + signed request Message |
| locally rejected or proposal expired | `TASK_STATE_REJECTED` |
| authorized attempt running | `TASK_STATE_WORKING` |
| result manifest + outputs durably committed | `TASK_STATE_COMPLETED` |
| failed or ambiguous attempt | `TASK_STATE_FAILED` + non-sensitive reason |
| caveated remote cancel honored | `TASK_STATE_CANCELED` |

`TASK_STATE_AUTH_REQUIRED` is disabled in v1 and `TASK_STATE_UNSPECIFIED` is
never valid; both fail `profile::validate_task_state`. Producer completion is
not verification or acceptance — those are separate Axon records
(design §10.4).

## Errors and scoping

- `GetTask`/`ListTasks`/`CancelTask` and outcome references are scoped to the
  authenticated paired origin; cross-peer ids return the standard not-found
  shape without revealing existence.
- `CancelTask` without an exact `remote_cancel` caveat returns the standard
  `TaskNotCancelableError`; Axon never acknowledges-and-ignores.
- Outside A2A-defined errors, local HTTP surfaces use RFC 9457.

## Required Axon extension set

The five safety-critical extension URIs (contract, key-binding, delivery,
result-evidence, outcome) are defined by the extension registry
(`spec/ext/`) under the namespace placeholder rules — see
`crates/axon-ext/src/namespace.rs`. The profile validator takes the set as
configuration so the pinned A2A layer stays independent of the extension
crates.

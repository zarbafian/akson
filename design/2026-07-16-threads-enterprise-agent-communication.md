# Axon: private, reliable connections between agents

Status: proposed design

Date: 2026-07-16

Scope: open-source, local-first agent communication and bounded delegation

The filename is historical. The product and public vocabulary are **Axon**, not
Threads.

## 1. Executive decision

Axon is an open-source, local-first gateway that lets independently operated
agents exchange tasks, messages, artifacts, and evidence without sharing
credentials or giving a peer ambient access to the local machine.

Axon is not a new agent language, general orchestration framework, remote shell,
identity system, marketplace, or rich-media renderer. Its product value is the
secure boundary between an authenticated remote request and a locally
authorized, bounded worker, followed by a portable evidence-backed result.

The first complete product slice is a two-party code-review task:

1. two endpoints pair without an Axon-hosted account or organization identity
   provider;
2. a requester sends an A2A Message with an immutable change and proposed
   terms; the recipient durably creates the standard A2A Task;
3. the recipient sees one clear risk card and accepts or rejects the exact
   contract revision;
4. an approved clean worker receives only the supplied change and context;
5. the worker returns structured findings and signed evidence;
6. the requester validates the bundle and records an accepted, rejected, or
   disputed outcome.

The first release uses the A2A 1.0 HTTP+JSON binding over HTTPS with TLS 1.3 and
mutual endpoint authentication. It does not require a relay, directory, group
protocol, OIDC, SCIM, or organization administrator. Direct delivery
deliberately trades offline store-and-forward for a much smaller security and
operational surface. A sender keeps a durable outbox and retries when both
endpoints are reachable.

If a later relay is justified, content encryption through that relay must use
an accepted end-to-end group-security scheme such as MLS 1.0. Axon will not
invent a cryptographic transport or silently weaken the direct security
profile.

### 1.1 Product principles

1. The complete secure path is open source and self-hostable.
2. Personal, independent, and managed deployments use the same protocol,
   cryptography, export features, and essential security controls.
3. Receiving data is not authorization. A connection grants no local
   capability.
4. Messages, Agent Cards, skill descriptions, and model output cannot authorize
   effects.
5. Security properties fail closed. There is no plaintext, anonymous, or
   weaker-protocol fallback.
6. Established formats and reviewed schemes are reused whenever they satisfy
   the requirement.
7. Axon-specific formats are limited, versioned extensions with a documented
   standards gap and interoperability tests.
8. Delivery, execution, verification, and requester acceptance are distinct
   states.
9. Evidence identifies who asserted what about exact bytes; it is not marketed
   as proof that an answer is correct.
10. The happy path exposes peers, tasks, risks, progress, and results—not
    certificates, policy records, or work-order internals.

### 1.2 Product promise

The concise promise is:

> Connect an agent, approve exactly what it may do, and receive a result whose
> inputs, producer, limits, and verification can be checked independently.

“Evidence-backed outcome” is the preferred term. “Verified outcome” is used
only when a named verifier actually checked the stated claim.

## 2. Normative language and vocabulary

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are used as
described by BCP 14.

Axon uses the following public vocabulary:

| Concept | Meaning |
|---|---|
| peer | An issuer-qualified, cryptographically pinned remote endpoint |
| connection | The local record that authorizes communication with one peer |
| task | The A2A Task and standard lifecycle; Axon’s required delivery extension adds durable receipt |
| message | The A2A Message used for conversational or task content |
| artifact | An A2A Artifact containing a task output |
| contract | A signed Axon extension describing one exact proposed task revision and its input Message Parts |
| decision | A signed accept or reject decision about a contract |
| policy ceiling | A reusable, local rule that limits what may be approved |
| work order | A local, one-shot authorization for one executor and exact task |
| attempt | One authorized execution of a task revision |
| evidence | DSSE-protected in-toto statements and referenced standard reports |
| outcome | The requester’s signed accepted, rejected, or disputed result state |
| processor | A local or remote model/service that receives approved plaintext |

“Thread,” “home,” “tenant,” and “enterprise” are not base protocol concepts.
Organization integrations are described as the optional managed profile.

## 3. Standards-first policy

Axon must not create a new envelope, message model, identity token, attachment
container, signature convention, or transport when a suitable established
format exists.

| Concern | Normative or preferred reuse |
|---|---|
| agent semantics | A2A 1.0 Agent Card, Message, Task, Part, Artifact, operations, lifecycle, and extension mechanism |
| direct network transport | A2A 1.0 HTTP+JSON with <code>application/a2a+json</code> over TLS 1.3 |
| HTTP body integrity/deduplication | RFC 9530 <code>Content-Digest</code> plus the required Axon delivery profile |
| standard A2A validation | A2A’s normative Protocol Buffer definitions and standard JSON mapping |
| endpoint authentication | X.509 certificates and mutual TLS |
| Agent Card signatures | A2A AgentCardSignature using JWS and the A2A canonicalization rules |
| managed workload identity | SPIFFE X.509-SVID where workload federation is needed |
| managed human identity | OIDC; SCIM only for organization lifecycle input |
| identifiers | A2A identifier rules; UUIDv4 under RFC 9562 for Axon-created extension IDs |
| times | RFC 3339 UTC timestamps |
| content types | Registered IANA media types when one exists |
| structured extension validation | JSON Schema Draft 2020-12 |
| deterministic extension bytes | RFC 8785 JSON Canonicalization Scheme |
| signed statements | DSSE v1 |
| attestations | in-toto Attestation Framework |
| build provenance | SLSA Provenance only for actual build-like work |
| code findings | SARIF 2.1.0 |
| Git inputs | Git object IDs, bundle v3, format-patch, and unified diff as applicable |
| HTTP errors outside A2A | RFC 9457 Problem Details |
| group end-to-end security, later | MLS 1.0, RFC 9420 and its architecture |
| operational telemetry | OpenTelemetry, with content disabled |

JUnit XML MAY be imported for compatibility, but it is a family of de facto
dialects rather than one normative format. Axon must define and test a narrow
parser profile while preserving the original bytes.

Sigstore bundles MAY be used as an evidence signer/verifier provider. Upload to
a public transparency service is never automatic because names, artifact
digests, and timing can cross Axon’s privacy boundary. Private deployments do
not need a public log to exchange valid DSSE/in-toto evidence.

### 3.1 Rule for an Axon-specific extension

An Axon-specific wire field or schema may be added only when all of the
following are true:

1. an ADR states the exact unmet requirement;
2. the ADR evaluates current standards and widely used ecosystem formats;
3. the extension changes only the missing semantics instead of replacing the
   surrounding standard;
4. the project controls a stable HTTPS namespace for the extension;
5. the schema is versioned, bounded, reject-unknown where safety requires, and
   has canonical bytes and golden vectors;
6. a security review covers parsing, downgrade, replay, ambiguity, and privacy;
7. at least two independent adapters pass interoperability tests.

No provisional private URI or unregistered collision-prone name may ship in a
stable release. The project domain and extension registry are Phase 0 release
gates.

### 3.2 Intentional Axon extension surface

A2A already defines the agent, task, message, part, artifact, and operation
model. Axon adds only the semantics A2A does not provide:

- a bilateral task contract and revision chain;
- a contract decision;
- a paired identity projection and purpose-bound statement keys;
- requested local capability metadata, which is never authority;
- durable passive submission and idempotent retry semantics;
- a canonical result manifest, evidence references, and required evidence slots;
- a requester outcome decision distinct from task completion.

These objects travel in standard A2A Message Parts or output Artifacts as
appropriate. Axon does not wrap the whole A2A object in a second message
schema.

Grants, policies, work orders, sandbox descriptors, and local audit records are
endpoint-private and are never A2A objects.

### 3.3 Dependency discipline

Each external protocol and library is pinned to a reviewed version. Axon
publishes:

- the supported A2A version and binding;
- required and optional Axon extension versions;
- the TLS and signature algorithm profile;
- conformance vectors;
- dependency provenance, SBOMs, and vulnerability response policy.

Experimental drafts cannot become an invisible core dependency. AGNTCY SLIM
may be evaluated as a later secure-session provider, and MIMI should be
monitored for group interoperability, but neither is normative for the direct
v1 path.

Axon generates standard A2A types from A2A’s normative Protocol Buffer
definitions instead of maintaining a competing schema. JSON Schema is used
only for the Axon extension objects.

Axon never implements cryptographic primitives, TreeKEM, HPKE, AEAD framing, or
certificate validation itself. It uses maintained, reviewed libraries and
tests their configuration.

## 4. First release

### 4.1 Included

The v1 product includes:

- one-to-one local and cross-host pairing;
- no-Axon-account personal use and an isolated service profile;
- an authenticated A2A Agent Card;
- direct A2A Messages, Tasks, Parts, and Artifacts;
- a complete <code>code_review.v1</code> contract, decision, execution,
  evidence, and outcome loop;
- bounded UTF-8 text and validated JSON;
- durable sender outbox, receiver inbox, retry, and deduplication;
- a local CLI and inbox/risk-card interface;
- one-time approval and deny;
- a clean worker with no host workspace, arbitrary tools, generic network, or
  ambient credentials;
- an explicit configured model processor; local versus remote is always shown;
- DSSE/in-toto evidence and SARIF findings where applicable;
- two real agent adapters and a documented adapter SDK;
- encrypted local sensitive state and explicit retention;
- self-hosting from signed native packages.

The supported v1 capability subset is:

- respond to the exact task;
- read only the task’s supplied text Message Parts;
- use one explicitly configured processor if the operator approves the data
  disclosure;
- export bounded results and evidence back to the requester.

Everything else is absent and therefore denied.

### 4.2 Explicitly deferred

The first release does not include:

- groups or multi-party membership;
- a store-and-forward relay;
- public, semantic, or organization directory discovery;
- OIDC, SCIM, legal hold, fleet policy, or recovery escrow;
- host workspace reads;
- host writes, patch apply, or repository mutation;
- arbitrary shell commands or general command execution;
- peer-selected network access, callbacks, webhooks, or URL fetching;
- remote secret use;
- delegation to a third agent;
- large files or a custom encrypted blob store;
- binary media preview or decoding;
- SVG, Markdown, Mermaid, or Graphviz rendering;
- marketplace, reputation, payment, or settlement.

Deferral is a security boundary, not an unfinished hidden feature. Unsupported
requests return a stable, non-sensitive error and create no effect.

### 4.3 Success criteria

The first release is successful when:

- two independent users on two directly reachable machines with supported
  processors already configured complete fresh Axon installation and the
  code-review loop in under ten minutes;
- neither user needs an Axon-hosted account, organization IdP, public
  directory, or shared secret copied into a command-line argument;
- the recipient can understand the exact disclosure and local operations from
  one risk card;
- a restarted sender or receiver neither loses an acknowledged task nor starts
  duplicate work;
- an independent validator can validate the result manifest and referenced
  bytes without the producer’s database;
- all inbound paths remain inert until an endpoint-local authorization exists;
- the same flow passes through two independent A2A adapters.

### 4.4 Supported launch profile

Phase 1 execution support is Linux on x86-64 and arm64 with the isolation
features in Section 13.1. Other operating systems may support communication,
inbox, and evidence validation only; Axon does not advertise worker execution
until an equivalent backend passes the same suite.

Signed native packages are the Phase 1 installation. They install a per-user
service for the personal profile or a dedicated system service for the isolated
profile. Containers are not a v1 release artifact. A later server/CI container
requires an ADR and tests for its keystore, host socket, update, namespace, and
backup boundaries; “run this container with the host socket mounted” is never
the personal quick start.

The guided installer recommends the isolated service when the operator can
authorize it. Personal mode is an explicit lower-local-assurance choice and
never displays the same badge. The cross-host Phase 1 security gate runs the
reviewer in the isolated profile; <code>axon demo review</code> may use personal
mode and labels the same-UID TCB.

The two Phase 1 release adapters are OpenCode with a documented fully local
model path, and Codex, exercised through supported non-interactive,
task-bounded interfaces. If either cannot meet the passive-arrival and sandbox
contract, Phase 0 must name a real replacement in a public ADR; an echo/demo
adapter never satisfies the gate. Claude Code is a high-priority follow-on
adapter, not a reason to delay the open local path.

Processor setup is explicit:

~~~text
axon processor add <adapter> --name <local-name>
axon processor list
axon processor test <local-name>
~~~

A processor named <code>local</code> is a user-created alias, not an implicit
claim that the model runs on-device. The setup and risk card state whether the
adapter and model are local, which network service receives plaintext, and what
credentials are brokered. The OpenCode reference fixture uses a documented
local model endpoint and no vendor account.

The under-five-minute local and under-ten-minute cross-host metrics begin after
a supported processor is installed and tested; they include fresh Axon
installation, initialization, pairing, and the task loop. A separate setup
benchmark records processor installation and model-download time so the quick
metric cannot hide it.

## 5. User experience

### 5.1 Happy path

Initial setup makes the network prerequisite explicit:

| Reviewer/server | Requester/client |
|---|---|
| <code>axon init</code> | <code>axon init</code> |
| <code>axon serve --listen &lt;address&gt;</code> | |
| <code>axon endpoint check</code> | |
| <code>axon pair create --invite-file invite.axon --expires 10m</code> | <code>axon pair accept --invite-file invite.axon --alias reviewer</code> |

After pairing, the normal product flow has three user moments:

1. The requester runs
   <code>axon review reviewer change.patch --wait</code>.
2. The reviewer receives one risk card and chooses **Approve once** or
   **Deny**.
3. Axon validates the returned identities, signatures, schemas, and digests,
   presents the review, and asks the requester to **Accept**, **Reject**, or
   **Dispute**.

Polling, retry, evidence validation, and progress display happen automatically
under <code>--wait</code>. Advanced commands remain available for scripting,
debugging, and export; users do not need them to complete a review.

An invitation secret is accepted through a mode-0600 file, standard input, or a
QR flow. The CLI MUST NOT encourage placing it in argv, a URL query string, a
shell history entry, or logs.

<code>axon serve</code> never opens a router port or publishes an address
implicitly. It explains whether the listener is local-only, private-network, or
public; <code>axon endpoint check</code> verifies the advertised address,
certificate, Agent Card, and reachability from the intended network. The
pairing invitation states the connection direction and which endpoint must be
reachable. <code>axon pair diagnose</code> explains firewall, DNS, certificate,
and private-network failures without printing the bearer invitation.

The simple text-message path may exist for diagnostics and conversation, but it
is not the release milestone. The evidence-backed task loop is the product
milestone.

For evaluation, <code>axon demo review change.patch</code> creates two
separately keyed local endpoints and runs the same real adapter, contract,
worker, evidence, and outcome path. It is clearly labeled a product
demonstration: same-host use does not prove a cross-owner trust boundary or
cross-host transport. A local evaluation should complete in under five minutes.

### 5.2 Risk card

Before local work, Axon groups the decision into five questions:

1. **Who:** exact issuer-qualified peer and assurance, highlighting any key,
   Agent Card, endpoint, or processor change.
2. **What leaves:** every input exposed to the worker or processor, plus the
   processor’s local/remote status, operator, region, retention, and training
   policy known to Axon.
3. **What runs:** task type, requested operations, actual processor, and
   explicit denials for host files, generic network, secrets, and mutation.
4. **Limits:** revision digest, time, byte, response, and cost bounds.
5. **Evidence and destination:** required evidence slots, “Independent
   verifier: none” unless one is configured, result recipient, and retention.

Advanced details expand the exact contract, policy ceiling, and one-shot work
order. Those implementation concepts do not appear in the primary approval
sentence.

The primary actions are deny, allow once, and—after v1—always allow this exact
bounded rule. One UI action may sign a remote contract decision and create a
local work order, but those records remain separate.

Approval language is concrete. “Review this supplied 84 KiB diff with local
model X and return findings to peer Y” is acceptable. “Allow agent access” is
not.

### 5.3 Quiet, abuse-resistant arrival

Arrival may add a bounded item to the inbox. It MUST NOT foreground an approval
dialog, start a model, speak, play media, or create an attacker-controlled OS
notification by default. Operators may enable rate-limited generic
notifications that reveal no remote body.

Blocking, rate limits, connection close, and peer removal are always local and
immediate.

## 6. Threat model and security invariants

### 6.1 Protected assets

Axon protects:

- endpoint identity and signing keys;
- local policy and approval authority;
- task, message, artifact, and evidence plaintext;
- host files, repositories, tools, processes, network, and credentials;
- processor credentials and configuration;
- peer relationships and task metadata;
- audit integrity and recovery state.

### 6.2 Adversaries

The design assumes:

- a malicious or compromised remote agent;
- prompt injection in every remote text field;
- malformed, oversized, recursive, compressed, or ambiguous inputs;
- replay, reorder, duplication, truncation, and connection interruption;
- an active network attacker;
- a compromised future relay;
- a compromised model or adapter process;
- an untrusted local agent process outside <code>axond</code> in the isolated
  profile; same-UID processes are explicitly in the personal profile’s TCB;
- a worker that crashes before, during, or after a side effect;
- an operator who restores an old database snapshot;
- a dependency or parser vulnerability.

Axon does not claim to protect plaintext from the endpoint process that must use
it, from an approved external processor that receives it, or from a fully
compromised host kernel. These trust boundaries are visible in the risk card
and <code>axon doctor</code>.

### 6.3 Normative invariants

#### Arrival is not execution

Receiving any A2A Message, Task, Artifact, cancellation, Agent Card,
authentication request, metadata extension, callback configuration, or
transport control MUST NOT:

- start or resume a model;
- create an approval decision;
- mint or consume execution authority;
- access a host workspace;
- invoke a tool or process;
- fetch a URL;
- import an attachment into a repository;
- contact a peer-selected third party;
- reveal a host or processor credential;
- apply, commit, or publish a change.

An A2A handler MAY durably create an inert local Task and return the standard
Task in <code>submitted</code> state. The signed-outcome profile MAY instead
return a fixed direct Message receipt without creating another Task. Either
response is generated without a model or tool, contains only bounded
correlation information, and means durable receipt only.

#### All peer content is untrusted data

Agent Card fields, skills, display names, objectives, messages, metadata,
filenames, paths, URLs, status text, artifacts, reports, and model output are
data. Only a validated, supported Axon extension field may be considered by
policy, and it still cannot grant authority.

Unknown extensions are preserved for forwarding when safe or ignored. They are
never interpreted as policy.

#### Authority is endpoint-local

A valid certificate, successful TLS session, valid signature, paired
connection, advertised skill, accepted contract, or A2A task state does not
grant a host capability. Authority exists only in a locally issued one-shot
work order addressed to a local executor.

#### The model does not enforce its own sandbox

Inbound content never enters an existing full-power session. A clean worker
receives only the approved context and typed operations. A trusted gateway,
secret broker, output gate, and operating-system sandbox enforce limits outside
the model.

#### Deny by default

Missing, malformed, stale, unsupported, conflicting, unverified, or
downgraded state resolves to no effect. Failure to prove a required provider or
sandbox property is a denial, not a warning-and-continue path.

#### Effects are one-shot and crash-honest

An effectful work order is durably claimed before its first effect. A crash
after effect start without a durable terminal record becomes
<code>ambiguous</code> and is never automatically retried.

#### Identity is issuer-qualified

Aliases, display names, URL hostnames alone, process IDs, routing names, and
unverified Agent Card claims never authorize. Policy keys include the identity
issuer or trust domain and current key binding.

#### Cancellation is not implicit kill authority

Remote cancellation is advisory unless the exact work order grants
<code>remote_cancel</code> to the exact request origin and task. Cancellation
cannot undo a committed result or change. In the A2A interface, “advisory”
means Axon returns TaskNotCancelableError when that caveat is absent; it does
not acknowledge cancellation and then ignore it.

#### Credentials remain local

A2A authentication flows cannot solicit or return host credentials through
task conversation. Later secret use is mediated by a local broker reference,
purpose, audience, and work order. Raw secrets never enter peer-visible or
model-visible text.

#### Receipts remain distinct

Network receipt, durable inbox storage, contract acceptance, worker claim,
processor consumption, task completion, verifier result, and requester outcome
are separate states. The UI and protocol never collapse them into “done.”

#### Evidence proves claims, not truth

Every claim is labeled self-attested, independently verified, or
hardware-attested. A valid signature proves integrity and signer attribution,
not semantic correctness.

## 7. Architecture

### 7.1 Components

~~~text
remote A2A endpoint
        |
        | HTTPS / TLS 1.3 / mutual authentication
        v
+----------------------------------------------------------+
| axond                                                    |
|                                                          |
|  network endpoint -> bounded A2A parser -> inbox/dedupe  |
|                                           |              |
|                                      contract engine     |
|                                           |              |
|  local UI/admin -> policy decision -> one-shot work order|
|                                           |              |
|                         clean worker + output gate        |
|                              |              |            |
|                     processor broker   evidence engine   |
|                                                          |
|       encrypted state, outbox, audit, key-store adapter  |
+----------------------------------------------------------+
        |                                      |
        | standard local adapter API           | A2A response
        v                                      v
configured agent/model                    remote requester
~~~

The network endpoint, policy engine, work-order issuer, output gate, and
evidence validator are trusted code. The model, remote peer, task content,
reports, and worker output are untrusted.

The processor broker is the only v1 component allowed to disclose approved task
content to a configured external model service. It enforces the exact processor
identity, destination, input manifest, byte/cost limits, and credential
separation recorded in the work order.

### 7.2 Processing sequence

1. The network endpoint authenticates the peer certificate before accepting an
   A2A request body.
2. It enforces connection, content-length, rate, and parse limits.
3. It validates the standard A2A object and recognized Axon extension.
4. It stores the encrypted object and stable digest transactionally.
5. Under the required Axon passive-delivery extension, it returns the standard
   A2A Task shape only after the stronger Axon durability commit.
6. A user or standing local policy evaluates the exact immutable contract
   revision.
7. Contract acceptance is signed separately from local authorization.
8. The local issuer creates a one-shot work order for a clean executor.
9. The executor receives only the selected input manifest and typed
   capabilities.
10. Results pass through size, media-type, recipient, and schema gates.
11. The evidence engine signs statements over exact inputs, attempt, outputs,
    and verifier results.
12. The requester validates the bundle and signs its own outcome.

No receive-path code calls an agent adapter or model.

### 7.3 Assurance profiles

All profiles use the same protocol and cryptography.

| Profile | Local assurance |
|---|---|
| personal | Per-user daemon, OS keystore, pinned peer certificates; all processes with the same OS user are explicitly inside the local TCB |
| isolated | Dedicated service identity, separate client/admin sockets, OS ACLs, sandbox/cgroup, protected keystore; recommended for servers and teams |
| managed | Isolated profile plus optional OIDC, SCIM, SPIFFE, central policy/audit, and visible recovery/compliance participants |

A personal endpoint can pair across hosts and organizations. It is not a
development-only or weaker-network mode. Its narrower local-process isolation
is reported precisely. It does not claim to resist a compromised process with
the same UID and access to the user’s keystore, sockets, debugger, or files.

Managed integrations add operational and identity assurance. They do not
unlock stronger encryption, essential policy controls, export, private
connections, or interoperability unavailable to self-hosters.

## 8. Identity and pairing

### 8.1 Identity tuple

Internal peer references contain:

~~~text
identity issuer or trust domain
stable agent identity
workload or device identity
endpoint instance identity
current TLS certificate thumbprint
current Agent Card JWS verification-key thumbprint
current task-statement verification-key identifiers and allowed purposes
current evidence-signing key identifiers and allowed purposes
authenticated Agent Card security-projection digest
full Agent Card digest for display and change history
~~~

Not every profile has a federated issuer, but the tuple remains issuer-qualified
and typed. Local aliases are presentation only.

Transport identity, Agent Card identity, task-statement signer, local authority
issuer, executor identity, processor identity, and evidence signer are separate
roles. Every verification key is bound to its permitted purposes during
pairing or through an issuer-authorized managed binding. If one key is reused
during an early implementation, the reuse is explicit, purpose-constrained,
and removed before stable release. The target design uses separate TLS, Agent
Card JWS, task-statement, local-authority, and evidence-signing keys.

The security projection contains only stable identity, AgentInterface,
security requirement, required extension, and identity/key-binding fields.
Policy pins this projection rather than cosmetic skill descriptions. The full
card digest is retained so every change remains visible.

Certificate fingerprints are SHA-256 over the complete DER certificate.
Public JWK fingerprints use RFC 7638. A non-JWK public key uses SHA-256 over
DER SubjectPublicKeyInfo. Displays include the algorithm and full digest;
truncation is presentation only and never used for matching.

### 8.2 Personal pairing

Personal pairing uses standard TLS and X.509 with explicit pinning:

1. The inviting endpoint creates a cryptographically random 256-bit,
   single-use bearer secret, an expiry, a maximum attempt count, its endpoint,
   its full TLS certificate fingerprint, and its Agent Card JWS key
   fingerprint.
2. The invitation is transferred out of band as a protected file or QR code.
   The daemon stores only a verifier for the secret.
3. The accepting endpoint opens a server-authenticated TLS 1.3 bootstrap
   connection pinned to the invitation fingerprint.
4. It sends the 256-bit secret as an HTTP Bearer credential inside that pinned
   TLS connection and presents its generated endpoint certificate and signed
   extended Agent Card.
5. The extended card’s required Axon identity/key-binding AgentExtension
   carries the Agent Card JWS, task-statement, and evidence verification keys,
   their RFC 7638 thumbprints, allowed purposes, generation, and validity. The
   inviter verifies the card, key bindings, and proof of possession.
6. The inviter atomically consumes the secret into a pending-pair record and
   returns its own equivalently signed extended Agent Card and key bindings.
7. Both endpoints verify and pin the symmetric identity records and display the
   full identity summary. Local confirmation changes the pending record into an
   active connection. All subsequent A2A traffic requires mutual TLS.

The bootstrap endpoint is separate from the A2A endpoint, aggressively rate
limited, small, and disabled when no invitation is active. Invitation secrets
never become long-lived peer keys. The daemon compares the high-entropy
secret’s stored verifier in constant time, consumes it in the same transaction
that creates the pending peer, redacts the Authorization header from every log,
and permits no redirect or proxy termination on the bootstrap path.

Pairing is retry-safe, not exactly once. Until invitation expiry, the inviter
retains the consumed-secret verifier, a digest of the canonical presented
certificate/key/card transcript, and the encrypted serialized pending-pair
response. An exact retry with the same secret and transcript returns the same
pending peer and response. The same secret with a changed transcript is
rejected as an attack. The acceptor persists and reuses its exact bootstrap
request until a response or expiry. No second peer can be created.

The invitation is a bearer credential: anyone who obtains it before use can
become the pending peer. It therefore travels through an authenticated,
confidential channel or an in-person QR flow. For a remote channel whose
authenticity is uncertain, users compare the displayed transcript fingerprint
through a second trusted channel before activation.

Axon does not invent a challenge-response protocol for a shorter human code. If
such a flow is later required, an ADR must select a standardized, reviewed PAKE
and define its transcript and identity bindings.

Self-issued X.509 endpoint certificates are acceptable in the personal profile
because the full certificate is pinned out of band. They are not treated as
public-PKI identities.

The public <code>/.well-known/agent-card.json</code> is a minimal signed A2A
card containing no private peer or processor data. It advertises mTLS and the
required Axon extensions, and sets
<code>capabilities.extendedAgentCard: true</code>. The signed extended card
exchanged during bootstrap and later retrieved through the standard
authenticated GetExtendedAgentCard operation carries the purpose-bound
identity/key projection. Axon never substitutes the public card for that
authenticated projection.

### 8.3 Isolated and managed identities

The isolated profile may use an operator CA or pinned self-issued certificates.
The managed profile may use SPIFFE X.509-SVID and trust-domain federation.
OIDC or OS/WebAuthn presence authenticates a local human authority issuer; a
remote OIDC claim cannot impersonate that local issuer. SCIM group data is
optional local policy input, not connection membership.

Assurance labels are computed locally from successful validation. A peer cannot
self-assert <code>managed</code>, <code>independent-verifier</code>, or similar
labels.

### 8.4 Rotation, removal, and recovery

Personal v1 keeps rotation simple: changing a TLS, Agent Card JWS,
task-statement, or evidence key requires explicit re-pairing. A later personal
successor mechanism would be a registered Axon identity extension and require
old-key authorization, new-key proof of possession, peer identity, purpose,
monotonic generation, validity interval, and old/new thumbprints.

Managed SPIFFE rotation follows a different rule. Identity continuity is the
validated SPIFFE ID, trust domain, issuer bundle, purpose, and locally allowed
federation—not an old leaf signature. A new X.509-SVID is accepted under issuer
authorization, expiry, and revocation policy. Each live session and work order
still binds its current leaf certificate; standing policy does not bind a
routine managed identity to one leaf thumbprint.

Managed Agent Card, task-statement, and evidence keys rotate through a signed
issuer-authorized key-binding update containing purpose, predecessor
thumbprint, monotonic generation, validity interval, and new-key proof of
possession.

Unexpected key, endpoint, issuer, or Agent Card security-projection changes
suspend the connection and require review. A cosmetic description/example
change updates the full-card history and UI but does not invalidate policy by
itself. Removing a peer immediately denies new sessions and new work orders.

V1 does not hide key escrow behind recovery. Loss of endpoint identity keys
requires re-pairing. Restored databases enter a recovery state in which
standing automatic policy is disabled until freshness is re-established.
Managed recovery, if added, lists every recovery participant in the assurance
report and audit.

### 8.5 Time and expiry

Expiry is an authority boundary. Within one boot, invitations, contracts, work
orders, and processor calls use monotonic deadlines. Across boots, Axon stores
the last trusted wall-clock checkpoint and database generation in the OS
keystore or HSM, outside database backups.

The default hard maximum lifetimes are:

- invitation: 15 minutes;
- unaccepted contract revision: 24 hours;
- one-shot work order: 1 hour;
- one processor call: 30 minutes.

Deployments may lower them. Raising a hard maximum requires an ADR and threat
tests.

If wall time moves backward by more than five minutes, or by a lower
operator-configured tolerance, the
keystore/database checkpoint disagrees, or certificate validity cannot be
established, Axon enters time-uncertain recovery. It refuses pairing, contract
acceptance, new work orders, automatic policy, and managed certificate renewal
until an operator restores trusted time and acknowledges the audit event.
Restart cannot extend an already issued TTL.

## 9. Direct transport and reliable delivery

### 9.1 TLS profile

The v1 network profile is:

- the A2A 1.0 HTTP+JSON binding and its
  <code>application/a2a+json</code> representation;
- TLS 1.3 only;
- server authentication during pairing and mutual authentication afterward;
- certificate validation and peer pinning appropriate to the selected identity
  profile;
- TLS 0-RTT disabled;
- TLS session tickets/resumption disabled in v1;
- no plaintext, anonymous, TLS-version, or certificate-validation fallback;
- no automatic redirect to a different origin;
- TLS termination inside <code>axond</code> by default.

A deployment that terminates TLS in a proxy has added that proxy to its
plaintext trusted computing base and cannot describe the hop as endpoint
end-to-end protection. The deployment report must say so.

Compression is disabled initially. Parsers apply limits before allocation and
before structured validation.

### 9.2 Honest semantics

Direct v1 transport provides authenticated, confidential delivery while both
endpoints can establish a connection. It does not claim always-online delivery
or asynchronous store-and-forward.

It also does not provide NAT traversal, automatic router changes, or a hidden
rendezvous service. The receiving A2A server must be reachable through a local
network, a user-managed private network such as WireGuard, or an explicitly
configured public HTTPS address. Axon still uses mTLS over that network. A
connection can be directional: the client-only requester need not accept
inbound traffic to poll the Task and send follow-up Messages. Both peers need
reachable servers only when both must originate new tasks.

The sender:

1. assigns a stable A2A Message identifier; the receiving server assigns the
   Task identifier;
2. persists the exact outbound HTTP body, its RFC 9530
   <code>Content-Digest</code>, selected AgentInterface URL and tenant value,
   <code>A2A-Version</code>, normalized activated extension URI set, content
   type, and HTTP method;
3. retries with the same Message identifier, exact body bytes, and identical
   covered profile fields;
4. removes the outbox item only after a durable receiver response or explicit
   local expiry.

V1 accepts exactly one RFC 9530 <code>Content-Digest</code> value using
<code>sha-256</code>. A missing, duplicate, mismatched, or unsupported digest
algorithm rejects the request before Message parsing.

The receiver validates <code>Content-Digest</code> and atomically stores the
authenticated peer, Message identifier, exact body digest, selected interface
and tenant, A2A version, activated extension set, content type, encrypted body,
HTTP method, and serialized response before returning. A task proposal also stores its newly
assigned Task identifier. A signed outcome instead stores and returns the fixed
direct Message receipt defined in Section 14.5.

Delivery is at least once with idempotent processing:

- the required Axon delivery extension—not base A2A—defines
  durable-before-response and retry behavior;
- same peer, Message identifier, body digest, interface/tenant, A2A version,
  extension set, content type, and HTTP method returns the byte-equivalent
  saved response with the identical server-generated Task identifier;
- the same peer and Message identifier with any different covered value is a
  conflict and security event;
- a duplicate never creates a second contract decision, work order, attempt,
  artifact, or outcome.

No “exactly once” claim is made. A receipt does not imply acceptance or
execution.

After payload retention ends, the receiver keeps a keyed replay tombstone
containing the peer, Message identifier, covered-value commitment, response
class, Task identifier, and encrypted serialized response needed for exact
replay. The tombstone lasts through the configured task retention window and
never less than the maximum sender retry window plus contract expiry. Only
after that advertised retry horizon may the saved response be purged. Its
commitment is not exported as a public content hash.

### 9.3 Ordering and state conflicts

Axon does not require a global message order. Each Task has one local
compare-and-swap contract head. A new revision is accepted only when its
predecessor equals that head and the Task is awaiting input. A signed
acceptance atomically locks that exact head before a work order can be issued.
Later siblings or revisions are rejected as stale; they cannot retroactively
cancel authority already issued for the selected head. Remote revocation or
cancellation remains advisory unless the work order explicitly grants it.

Conflicting or stale messages may be retained as visible diagnostics but never
become policy inputs.

Clock time is informational for ordering. Security decisions use identifiers,
digests, revision links, expiry bounds, and local monotonic time where
available.

### 9.4 Future secure-session provider

A future relay or group implementation must sit behind a narrow provider
interface:

~~~text
resolve and pin peer identity
open authenticated direct or group session
send stable event bytes
receive authenticated origin and stable event bytes
acknowledge or synchronize under an advertised durability class
report membership and security state
close or revoke
~~~

A production provider must demonstrate:

- mandatory end-to-end encryption, including same-host paths;
- authenticated binding from session membership to the Axon peer identity;
- no weaker-suite fallback;
- replay rejection and stable application identifiers;
- exact durability semantics proven by crash tests;
- bounded messages, metadata, decompression, and queues;
- sender identity on every delivery;
- removal and rekey behavior before groups are enabled;
- protected key persistence and rollback handling;
- an explicit metadata-leakage inventory;
- rate limits, backpressure, reproducible builds, and a vulnerability process.

If a relay can read content, it is an endpoint/proxy deployment, not an
end-to-end Axon relay.

For MLS, Axon uses an audited RFC 9420 implementation and a reviewed binding; it
does not implement TreeKEM or define a new group cryptosystem. If SLIM is used,
MLS, TLS verification, authenticated identities, stable deduplication, and the
advertised durability class are mandatory. Insecure or MLS-disabled modes are
not compatible with the Axon profile. Nested MLS and two competing membership
states are prohibited.

## 10. A2A profile and task contract

### 10.1 Standard A2A objects

Axon uses:

- Agent Card for supported skills, endpoint, bindings, and Axon extension
  advertisement;
- Message and Part for conversation and structured task input;
- Task and its standard lifecycle for tracked work, with durability added only
  by the required Axon delivery extension;
- Artifact and Part for outputs and evidence;
- standard A2A operations and error semantics.

Agent Card skills are advertisements, never grants. The card is fetched through
the authenticated connection, signed with the standard A2A
AgentCardSignature/JWS mechanism, and its digest and verification key are
pinned. Axon does not invent another Agent Card signature field. A
<code>jku</code> or other key URL is never fetched automatically; the
verification key comes from pairing or a locally configured trust domain. A
card change cannot widen standing local policy without review.

The mandatory v1 Agent Card JWS profile uses a separate Ed25519 key,
<code>alg: EdDSA</code>, <code>typ: JOSE</code>, and an RFC 7638
thumbprint-based <code>kid</code>. Additional managed algorithms require a
negotiated profile and vectors; <code>none</code>, symmetric peer-supplied
keys, and unpinned remote key URLs are forbidden.

External file URLs and push callback URLs are disabled in v1. A URI may be
displayed as inert text but is never fetched. Later callback support requires a
pre-registered, identity-bound local destination policy; a request field alone
can never authorize egress.

#### V1 nonblocking operation profile

The Agent Card advertises:

- protocol version <code>1.0</code> and the <code>HTTP+JSON</code>
  AgentInterface;
- an A2A MutualTlsSecurityScheme and a mandatory security requirement for that
  interface;
- each safety-critical Axon AgentExtension URI with
  <code>required: true</code>;
- <code>streaming: false</code> and
  <code>pushNotifications: false</code>.

Every authenticated v1 A2A operation supplies
<code>A2A-Version: 1.0</code> and activates the complete required contract,
identity/key-binding, passive-delivery, result/evidence, and outcome extension
set with the standard <code>A2A-Extensions</code> service parameter. This rule
applies to initial and follow-up SendMessage, GetTask, ListTasks, CancelTask,
GetExtendedAgentCard, and the task-less outcome SendMessage. The Message
<code>extensions</code> field lists the exact URIs that contribute to that
Message. Missing, extra-conflicting, or unsupported required extensions fail
before state lookup, Task creation, or content processing.

Responses echo the activated <code>A2A-Extensions</code> set. Every status
Message or Artifact containing Axon data lists the contributing URI in its
standard <code>extensions</code> field. An Axon client never assumes extension
semantics from metadata whose URI was not successfully negotiated.

The initiating SendMessage request sets
<code>SendMessageConfiguration.returnImmediately = true</code>. For a valid
code-review proposal the server MUST return a Task in
<code>TASK_STATE_SUBMITTED</code>, never a direct Message response, after the
inert request is durably stored. The client polls the standard GetTask
operation. V1 does not use streaming, SSE, push configuration, or peer-selected
webhooks.

This profile prevents the A2A binding’s default blocking behavior from holding
an approval or model execution inside the receive request.

Signed accept, reject, and revision-request records are delivered in the
agent-role Message attached to Task status/history and become visible through
GetTask polling:

| Axon event | A2A state/behavior |
|---|---|
| durable inert proposal | <code>TASK_STATE_SUBMITTED</code> under the required Axon delivery extension |
| accepted, awaiting work-order claim | remains <code>TASK_STATE_SUBMITTED</code> with signed accept Message |
| revision requested | <code>TASK_STATE_INPUT_REQUIRED</code> with signed request Message |
| locally rejected or proposal’s signed expiry reached | <code>TASK_STATE_REJECTED</code> |
| authorized attempt actually running | <code>TASK_STATE_WORKING</code> |
| result manifest, required slots, and outputs durably committed | <code>TASK_STATE_COMPLETED</code> |
| failed or ambiguous attempt | <code>TASK_STATE_FAILED</code> with a non-sensitive Axon reason |

<code>TASK_STATE_AUTH_REQUIRED</code> is disabled in v1; local approval is not
a credential request to the client. Without an exact
<code>remote_cancel</code> caveat, CancelTask returns the standard
TaskNotCancelableError rather than accepting and ignoring the request.

GetTask, ListTasks, CancelTask, and outcome references are scoped to the
authenticated paired origin. A peer cannot enumerate or address another peer’s
Tasks even if it learns an identifier; Axon returns the standard not-found
shape without creating an ownership oracle.

### 10.2 Contract revision

The contract is a versioned Axon structured-data Part carried by the initiating
A2A Message. The receiving endpoint associates it with the standard Task that
the endpoint creates. It contains:

~~~text
schema version
contract UUID and integer revision
predecessor contract digest, except for revision zero
task type URI, initiating A2A Message identifier, Context identifier if one was
supplied, and existing Task identifier for a follow-up revision
issuer-qualified requester and proposed performer
objective text, explicitly non-authoritative
ordered input manifest binding exact Message Parts
required deliverables and media types
required evidence slots and acceptable trust classes
requested capability vector
processor and data-handling constraints
deadline, resource, response, byte, and cost limits
result recipient and retention request
creation and expiry times
~~~

JSON contract payloads conform to I-JSON constraints, reject duplicate keys,
validate against JSON Schema Draft 2020-12, and are canonicalized with RFC 8785
before digesting and DSSE signing.

The Message contains exactly one contract-control Part whose
<code>data</code> value is the DSSE envelope and whose media type is the
versioned contract-envelope media type selected in Phase 0. The DSSE
<code>payloadType</code> identifies the corresponding contract payload. A
missing or second contract Part rejects the request. Each input manifest entry
contains:

~~~text
logical input identifier
initiating Message identifier
zero-based Part index
content kind: text or data
media type and declared character set
canonical-byte rule
byte length and SHA-256 digest
whether the worker and processor may receive it
~~~

For a text Part, the digested content is the exact UTF-8 encoding of the A2A
string value with no Unicode normalization. For a data Part, it is RFC
8785-canonical JSON. Raw and URL Parts are unsupported in v1. The contract Part
itself is control data and is not a worker input. Every other Part must have
exactly one manifest entry; an unmanifested, multiply referenced, kind-mismatched,
or digest-mismatched Part rejects the proposal. Part metadata and filenames do
not reach the worker unless a future schema explicitly manifests their
individual fields.

The standard SendMessageConfiguration
<code>acceptedOutputModes</code> must match the contract’s deliverable media
types; it cannot widen them. A push-notification configuration is forbidden.
Request-level and Message metadata remain inert and never enter the worker
unless a future required extension manifests a specific field.

The requester identity in the signed contract MUST equal the identity mapped
from the authenticated mTLS origin. The proposed performer MUST equal the local
endpoint identity. The DSSE key MUST be pinned for the
<code>contract-proposal</code> purpose. A mismatch is rejected before Task
creation for an initial proposal or before revision acceptance for a follow-up.

The requester signs a proposal. The performer signs a separate accept or
reject decision referencing the exact proposal digest and the receiver-assigned
A2A Task and Context identifiers. That decision is the cryptographic binding
between the proposal and Task and uses a key pinned for the
<code>contract-decision</code> purpose. Expiry follows the signed proposal
expiry and the trusted-time rules; it is not a performer assertion.

V1 has no performer-authored counterproposal. A performer may either reject the
Task, or emit a signed revision-request status Message and move the nonterminal
Task to <code>TASK_STATE_INPUT_REQUIRED</code>. In the latter case the requester
may send a new requester-signed revision on that Task naming the predecessor.
The revision request uses the contract-decision key and is not itself a new
contract revision. Editing a proposal in place is impossible.

Free-form objective text, filenames, requested skills, or model instructions
cannot widen any typed field.

### 10.3 Requested capabilities are not authority

The contract may describe what the requester thinks the task needs. This helps
the risk card and negotiation, but has no local force.

Data-handling and processor fields are bilateral ceilings. A performer cannot
send requester content to an external processor unless the accepted contract
permits that class of disclosure and the local work order names the exact
configured processor. A requester cannot force the performer to retain content
longer, use a less private processor, or weaken local policy. Either side may
choose stricter handling or reject the task.

In v1 the result recipient MUST be the authenticated request origin on the same
paired connection. A third-party recipient is an egress/delegation feature and
is unsupported regardless of what free-form or typed request data says.

The actual capability is always the intersection of:

~~~text
hard platform policy
intersection current operator or organization policy
intersection policy for the authenticated request origin
intersection accepted contract constraints
intersection one-shot local work order
intersection available provider and sandbox guarantees
intersection remaining budgets
~~~

An absent or unknown component denies that operation.

### 10.4 Task, attempt, evidence, and outcome states

A2A Task state reports producer-side task progress. In particular:

- submitted means durably inert only because the required Axon passive-delivery
  extension adds that stronger behavior to A2A;
- working is reported only after a local work order is claimed and a worker
  actually starts;
- completed is committed only after the canonical result manifest, output
  Artifacts, evidence-slot records, and required evidence envelopes are durably
  stored in one transaction or recoverable commit protocol;
- the exact failed, rejected, canceled, input-required, authentication, and
  cancellation behavior is the matrix in Section 10.1.

Axon does not overload A2A completion to mean verification or business
acceptance. It separately records:

~~~text
contract: proposed | accepted | rejected | expired | superseded
attempt: pending | claimed | running | succeeded | failed | ambiguous | cancelled
evidence result: passed | failed | error | not_run | unavailable
evidence disclosure: full | summary | redacted
outcome: accepted | rejected | disputed
~~~

The Phase 0 profile contains an exact mapping to the pinned A2A version and
conformance vectors. If a standard task-state name changes, Axon updates the
profile instead of creating a competing lifecycle.

### 10.5 Code-review v1 profile

The first task profile uses existing representations:

- claimed Git base and result object IDs, including their hash algorithm;
- Git format-patch generated with <code>--full-index</code> and transported as
  bounded UTF-8 text;
- unified diff only as explicitly labeled compatibility syntax, because it has
  no single normative specification;
- optional bounded UTF-8 source context as separate A2A Parts;
- SARIF 2.1.0 Plus Errata 01 with its pinned official schema and
  <code>application/sarif+json</code> for machine-readable findings;
- plain text for the human summary;
- DSSE/in-toto for signed evidence.

Git object IDs are unverified claims until a named repository or bundle
verifier reconstructs and checks the objects. V1 does not make that claim. It
records the Git hash algorithm and covers every transported output Artifact
with a SHA-256 digest for Axon/in-toto integrity validation.

Git binary patches are rejected in text-only v1; <code>--binary</code> is not an
accepted profile. A future binary profile treats its bytes as inert input and
requires a sandboxed Git verifier.

V1 never auto-applies a patch and never imports Git objects into a host
repository. A later Git bundle importer must run in a parser sandbox, validate
prerequisites and object IDs, and still cannot auto-apply.

## 11. Content, artifacts, and media

### 11.1 Allowed v1 content

V1 accepts:

- bounded UTF-8 <code>text/plain</code>;
- bounded UTF-8 <code>text/markdown</code>, displayed as escaped source;
- <code>application/json</code> when a declared schema applies;
- standard JSON reports such as SARIF and in-toto after profile validation.

The implementation sets conservative hard limits before Phase 1. The initial
target is an 8 MiB total HTTP body, 4 MiB per non-text Part, 1 MiB per text
Part, JSON nesting depth 64, and no content encoding. Deployments may lower
limits. Raising compile-time hard limits requires an ADR and resource tests.

All original bytes, media type, declared character set, size, and digest are
preserved. A parser’s normalized representation never replaces the signed
original.

### 11.2 SVG and diagram source

SVG rendering is not and has never been an Axon feature.

SVG output is transported only as bounded UTF-8 source text using standard A2A
Part/Artifact fields. If preserving the exact artifact matters, its registered
<code>image/svg+xml</code> media type is retained, but the Axon UI still shows
escaped source or offers an explicit save operation.

Axon MUST NOT:

- parse SVG into a browser or XML DOM;
- execute or sanitize-and-render it;
- rasterize or preview it;
- resolve entities, scripts, fonts, styles, links, or external references;
- embed it with an image, object, iframe, data, or equivalent active element;
- pass it to an OS thumbnailer.

Mermaid and Graphviz are handled the same way: escaped, bounded, untrusted text
only. Markdown is also source text in v1; no HTML rendering or link preview is
needed.

If SVG or diagram source is supplied to a model, the input manifest labels it
as untrusted remote text and the processor disclosure remains subject to the
work order.

### 11.3 Unsupported and binary content

Unsupported media is retained only as an inert descriptor when safe. It is not
decoded, previewed, indexed, executed, or passed to a model.

Arbitrary binary and large-artifact transfer do not ship in v1. A later feature
must select an established, independently reviewed container or secure-session
facility. Axon will not design an <code>aes-*-chunks-v1</code> format or any
other streaming AEAD construction.

Filenames are display labels, not paths. They are length-bounded, normalized
for display, and never used directly for filesystem placement.

## 12. Local authority

### 12.1 Orthogonal capability vector

Enforcement uses independent components rather than cumulative
NONE/READ/WRITE/EXECUTE levels:

| Component | Scope |
|---|---|
| respond | exact task/message, recipient, response count, bytes, deadline |
| read_supplied_inputs | exact signed input Message-Part manifest |
| read_snapshot | later: pinned root/snapshot and bounded path set |
| processor_use | exact configured processor, approved input manifest, cost/byte budget |
| stage_write | later: private overlay paths and byte/file budget |
| run_profile | later: named immutable verifier/command profiles and resources |
| apply | later: exact operation/path set with base digests |
| egress | later: exact destination/service/protocol and request/byte budget |
| secret_use | later: broker reference, purpose, audience; never secret bytes |
| artifact_export | exact recipient, task, media types, count, bytes |
| delegate | later: exact target, depth, fan-out, and cost budget |
| remote_cancel | whether the authenticated origin may stop this exact attempt |

Components do not imply one another. Running a verifier does not imply host
write, network, secret, apply, or arbitrary command authority. Staging a patch
does not imply permission to apply it.

Friendly UI presets are templates only:

- Review supplied change;
- Verify with named profile;
- Propose change in private overlay;
- Apply exact change, later.

The risk card always expands the effective vector.

### 12.2 Roles

Axon keeps four roles distinct:

- request origin: authenticated peer plus exact A2A task/message and contract
  digest;
- authority issuer: local human, local policy engine, or trusted organization
  policy issuer;
- executor subject: local daemon/worker process and sandbox identity;
- execution capability: one-use local descriptor bound to the executor and work
  order.

A reusable policy ceiling is not a bearer capability and is never possessed by
the remote peer.

### 12.3 One-shot work order

A work order binds at least:

~~~text
version and work-order UUID
local authority issuer and assurance
audience: exact local daemon and executor
request origin and paired certificate thumbprint
A2A task, context, and message identifiers
accepted contract revision and canonical digest
explicit capability vector
exact input/context manifest
processor, runner, sandbox, and profile digests
per-operation and aggregate budgets
required evidence slots
policy version and decision identifier
not-before, deadline, and one-use nonce
remote-cancel caveat, if any
local signature or MAC
~~~

The executor receives the capability through a short-lived local descriptor
bound to its OS process/cgroup and exact work-order digest. It is
<code>CLOEXEC</code> except for the intended child, cannot be serialized into
model context, and is consumed once.

Work-order state is:

~~~text
pending -> claimed -> running -> succeeded | failed | ambiguous | cancelled
~~~

Claim, budget reservation, and nonce consumption are atomic. Revocation and
operation-start linearization points are documented and tested.

### 12.4 Standing policy

V1 supports deny and allow once. Phase 2 may add deterministic rules such as:

> Allow code_review.v1 from this exact peer, using only supplied inputs,
> local processor X, no generic network, no secrets, under these byte, time,
> and cost limits.

Standing rules are local policy ceilings evaluated by a reconciler outside the
receive path. They never turn message parsing into execution. A changed peer
key, Agent Card, contract version, processor, sandbox, or extension version
suspends an otherwise matching rule.

## 13. Worker, filesystem, and sandbox

### 13.1 V1 clean worker

The v1 worker:

- starts in a new process and empty task-specific directory inside the
  normative Linux isolation backend;
- inherits no ambient file descriptors, environment credentials, shell
  profile, agent session, conversation history, or workspace;
- receives only the exact approved A2A Parts and local non-secret processor
  configuration;
- has no host filesystem mount beyond runtime dependencies and private scratch;
- has no generic network socket;
- reaches an approved external model only through the processor broker;
- cannot invoke arbitrary commands or tools;
- writes only to a private output directory with byte/file limits;
- returns output through a schema- and recipient-checking gate;
- is destroyed at the terminal attempt state.

The Phase 1 Linux backend requires:

- separate user, mount, PID, network, IPC, and UTS namespaces;
- <code>no_new_privs</code> and a reviewed default-deny seccomp profile;
- cgroups v2 CPU, memory, process, and wall-time enforcement;
- a minimal digest-pinned read-only runtime plus private tmpfs scratch/output;
- no host home, workspace, device, Docker socket, SSH agent, D-Bus, keyring,
  cloud metadata, or host Unix socket;
- a private <code>/proc</code> that exposes only sandbox processes;
- an explicit inherited-file-descriptor allowlist;
- no network interface or DNS; an approved remote processor is reachable only
  through one pre-opened broker channel with typed requests;
- Landlock as defense in depth where the detected kernel ABI supports the
  required rules.

The sandbox launcher and policy are trusted, version-pinned components. Phase 0
must select and publish the concrete reviewed namespace launcher and seccomp
profile; Phase 1 cannot substitute an ordinary subprocess, working-directory
change, or broadly privileged container.

If the operating system cannot provide the selected isolation profile,
execution fails closed. <code>axon doctor</code> reports every relevant kernel,
keystore, socket, namespace, and sandbox capability.

The personal profile’s same-user limitations remain visible: a malicious
same-UID process is inside that profile’s TCB and may be able to observe or
interfere with its sandbox. The isolated profile uses a dedicated service
account and denies ptrace/process access from ordinary agent users.

#### Processor calls are effects

Sending plaintext to a remote processor discloses data and may incur cost, so
each call has a durable sub-attempt:

~~~text
prepared -> dispatching -> completed | failed | ambiguous | cancelled
~~~

Before dispatch, the broker stores the provider, exact HTTPS origin and
configuration digest, request-content digest, task/work-order binding, generated
idempotency key, estimated cost bound, deadline, and response limit. Redirects
and ambient HTTP proxies are disabled. TLS hostname validation, configured
origin allowlists, address-class checks, and connection-time DNS validation
prevent a task or rebinding response from selecting a different destination.
Credentials remain in the broker.

If the provider documents an idempotency facility with the required semantics,
an exact retry may reuse its key. Otherwise, loss of a response after possible
transmission marks the processor sub-attempt <code>ambiguous</code> and Axon
does not retry automatically. The operator may authorize a new attempt after
seeing the possible duplicate disclosure and cost.

Cost limits are labeled estimates unless the provider exposes a hard,
independently enforced reservation. A local processor still uses the same
durable state because crashes can duplicate work even without data egress.

### 13.2 Later read-only snapshots

Host read access is not part of v1. When introduced, high-assurance reads use an
immutable VCS or content-addressed snapshot, not a mutable path tree.

For path-backed compatibility, the trusted gateway:

- pins the root by descriptor and stable identity;
- accepts structured relative path components, never shell strings;
- rejects absolute paths, empty components, dot, dot-dot, NUL, and platform
  aliases;
- resolves with descriptor-relative facilities such as Linux
  <code>openat2</code> using beneath/no-symlink/no-magic-link constraints;
- refuses symlinks, reparse points, device files, sockets, and unexpected mount
  crossings;
- addresses hardlink disclosure rather than treating symlink checks as enough;
- enforces path, file, byte, and total budgets;
- records exact observed content digests when an immutable snapshot is
  unavailable.

Permission checks and I/O use the same resolved object. A check-then-open path
sequence is forbidden.

### 13.3 Later stage and apply

Worker writes go only to a private overlay. Host apply is a separate trusted
operation with a separate capability and approval. It requires:

- exact base object/digest and destination;
- create, replace, or delete semantics per path;
- descriptor-based resolution;
- a real compare-and-swap or versioned backend, not a precheck followed by
  blind rename;
- atomicity and crash behavior documented per backend;
- no symlink or hardlink escape;
- an evidence statement over the applied result.

The worker never commits, pushes, deploys, or publishes directly.

### 13.4 Later named verifier profiles

Execution, when added, is limited to immutable named profiles. A profile pins:

- executable and dependency digests;
- argv template and typed parameters;
- working snapshot;
- environment allowlist;
- filesystem, network, secret, CPU, memory, process, output, and time limits;
- sandbox backend and version;
- result parser and expected artifact schema.

There is no shell expansion and no peer-selected executable, argv prefix, PATH,
working directory, environment, URL, or secret.

On Linux the isolated backend should combine an unprivileged service identity,
no-new-privileges, namespaces or a microVM boundary, seccomp, cgroups, a
minimal read-only runtime, private temporary storage, and Landlock where its
feature set satisfies the profile. Capability probing is normative; a missing
control is a denial unless the profile explicitly names an independently
reviewed equivalent backend.

## 14. Evidence and requester outcome

### 14.1 Canonical result manifest

Before Task completion, the producer creates
<code>result-manifest-v1</code>. It contains:

~~~text
schema version
A2A Task and Context identifiers
accepted contract UUID, revision, and canonical digest
attempt and work-order receipt digests
sorted output entries:
  logical role, A2A Artifact ID, Part index, media type, size, SHA-256
sorted evidence entries:
  logical role, payload type, size, SHA-256, signer/key reference
required evidence-slot mapping:
  slot ID, evidence entry, result, disclosure
declared omissions and redactions
~~~

Sorting is bytewise by logical role, object identifier, Part index, and digest
as specified by the schema. The JSON is validated, RFC 8785-canonicalized, and
DSSE-signed by the producer’s task-result key. Evidence statements reference
the output subjects and attempt; they do not reference the enclosing manifest,
which avoids a digest cycle.

The output Artifacts, evidence envelopes, slot records, and result manifest are
staged first. The Task moves to <code>TASK_STATE_COMPLETED</code> only when all
referenced bytes and the manifest commit durably. Validation, output-gate, or
evidence failure produces <code>TASK_STATE_FAILED</code>, never a partial
completed result.

The requester outcome binds the canonical result-manifest digest. A “bundle
digest” anywhere in Axon means this precisely defined digest, not an archive’s
incidental byte layout.

### 14.2 Evidence model

Evidence uses a pinned version of the in-toto Attestation Framework in DSSE
envelopes. Axon defines only the minimal predicate semantics required for its
task and authorization facts.

The v1 profile pins in-toto Statement v1 and DSSE v1. In-toto attestations use
the payload and storage media types required by the in-toto envelope
specification. Contracts, decisions, result manifests, and outcomes use
project-controlled versioned payload media types and are DSSE statements, not
mislabeled in-toto attestations. Phase 0 assigns the media types through the
normal standards/registration process.

The mandatory task/evidence signature algorithm is Ed25519 under RFC 8032; keys
are represented as public JWKs and identified by RFC 7638 thumbprints. A
managed algorithm profile may add a reviewed HSM-compatible algorithm only
through authenticated negotiation and conformance vectors. Algorithm,
payload-type, key purpose, and identity binding are all verified; an unknown or
cross-purpose key fails closed.

A result bundle may contain independently signed statements for:

1. authorization: request digest, local issuer, effective capability vector,
   policy decision, and executor audience;
2. execution: exact materials, processor/runner/sandbox identity, external
   parameters, outputs, resource use, and terminal state;
3. verification: verifier identity and trust class, exact subjects, check
   profile, and passed/failed/error/not-run result;
4. requester outcome: exact result-manifest digest and
   accepted/rejected/disputed state.

V1 validates only objective integrity and provenance facts:

- contract proposal and decision signatures and identity bindings are valid;
- every approved input manifest digest matches its Message Part;
- the producer/executor self-attestation covers the accepted inputs and exact
  outputs;
- the result manifest and output schemas are valid;
- optional SARIF is structurally valid and its attested digest matches.

These checks do not establish that the code review is correct. The UI says
“Independent verifier: none” unless a separately trusted named verifier
actually evaluated the exact outputs. The v1 command is
<code>axon evidence validate</code>; “verified review” is reserved for the
later semantic-verifier path.

SLSA Provenance is emitted only when the operation actually matches its build
provenance model. Merely serializing SLSA JSON does not grant a SLSA level.

SARIF is an output report, not an authority record. It is parsed as hostile
input with strict limits. Its original bytes are preserved and their SHA-256
digest is covered by an attestation; SARIF is not assumed to sign itself. Axon
never fetches a SARIF <code>$schema</code>, artifact URI, help URI, or external
property reference.

DSSE supplies integrity framing, not identity trust, revocation history, or
trusted time. A portable personal-profile verification pack therefore includes
the exported, locally signed pairing record, security-projection Agent Card,
verification keys and purposes, validity bounds, and rotation/re-pair history.
An independent validator can prove continuity with that exported pairing root;
it cannot infer a legal or real-world identity that was never certified.

Managed verification uses its configured X.509/SPIFFE trust chain and historical
trust material. A claimed signing time is informational unless accompanied by
a validated RFC 3161 timestamp or configured transparency checkpoint. Public
timestamp/transparency submission remains explicit because it can leak
metadata.

### 14.3 Required slots and redaction

The contract enumerates required evidence slots. Every slot has two orthogonal
fields:

~~~text
result = passed | failed | error | not_run | unavailable
disclosure = full | summary | redacted
~~~

Omission cannot look like success. A redacted view does not satisfy a contract
that requires visible passing evidence. A partner-facing summary is separately
signed and preserves the underlying result state rather than deleting or
relabeling a failure.

Portable artifact subjects use standard digest maps, initially SHA-256.
Raw digests of private low-entropy content MUST NOT enter a public audit,
Sigstore/Rekor service, or other transparency log by default: they enable
dictionary guessing and cross-context correlation. Private audit uses keyed
commitments. Publishing a portable artifact digest requires an explicit export
decision that discloses this risk.

### 14.4 Trust classes

The verifier presents each claim as:

- self-attested: signer and producer are the same trust domain;
- independently verified: a separately trusted verifier checked the exact
  subjects;
- hardware-attested: a configured hardware-backed verifier attested the
  declared execution facts.

Trust class is derived by the recipient’s policy from validated identities and
chains. It is not copied from a self-asserted field.

### 14.5 Outcome

Producer completion and requester acceptance are separate. After validating
the result manifest and any configured semantic verification, the requester
signs an outcome referencing:

- task and accepted contract revision;
- exact canonical result-manifest digest;
- accepted, rejected, or disputed state;
- optional bounded reason code and human note;
- requester identity and signing time.

An outcome cannot retroactively change what ran. A disputed outcome preserves
all prior evidence.

A2A does not permit another Message to be attached to a terminal Task. The
requester therefore sends the signed outcome in a new task-less SendMessage:

- it uses the same A2A Context identifier;
- <code>referenceTaskIds</code> contains the completed Task identifier;
- it carries the signed Axon outcome Part;
- it does not set <code>taskId</code>;
- the producer durably records it and returns a fixed, direct Message receipt
  generated without a model or tool.

The outcome Message does not create another Task. Its stable Message identifier
and signed outcome digest use the normal deduplication rules.

## 15. State, privacy, audit, and recovery

### 15.1 Local state

The endpoint stores:

- paired identities and key history;
- exact encrypted A2A objects and deduplication digests;
- contract revisions and signed decisions;
- local policy ceilings and one-shot work orders;
- attempts and state transitions;
- artifacts, attestations, verifier summaries, and outcomes;
- outbox/inbox retry state;
- body-free audit records with keyed local commitments.

Business records are first-class. Free-form conversation history is optional
and has a short explicit retention policy rather than becoming an unlimited
archive.

Sensitive columns and blobs are encrypted before database persistence with an
audited envelope-encryption library and a key protected by the OS keystore or
configured HSM. Axon adopts the library’s reviewed ciphertext format; it does
not create one. WAL files, temporary files, crash dumps, and backups must not
contain plaintext task bodies.

Full-disk encryption is recommended but is not presented as a substitute for
application-layer protection against accidental database or backup disclosure.

### 15.2 Metadata and processor disclosure

Direct peers and network observers can learn endpoint addresses, timing,
approximate sizes, and connection frequency. TLS does not hide this metadata.

Each processor is a separate plaintext trust boundary. Configuration records
whether it is local or remote and, when known, its operator, region, retention,
training, and subprocessors. The risk card shows this before disclosure.
“End-to-end encrypted transport” never implies that an approved remote model
cannot read its input.

### 15.3 Audit

The audit records security-relevant facts before effects:

- authenticated peer and local issuer references;
- object and contract digests;
- policy and work-order identifiers;
- capability components and budgets;
- state transitions and ambiguous outcomes;
- processor, runner, sandbox, and verifier identities;
- export, deletion, recovery, key change, and policy change.

It excludes prompts, message bodies, source, filenames, paths, credentials, and
raw secrets. Private object correlation uses keyed local commitments where a
plain low-entropy hash would leak content.

The daemon writes records append-only and hash-links them, making accidental or
out-of-domain modification locally tamper-evident. A local signature in the
same personal-user security domain cannot prevent a same-UID attacker from
rewriting the log or truncating its tail. Stronger integrity requires periodic
checkpoints in an HSM, TPM monotonic facility, or independent configured
witness. Exported audit claims use DSSE/in-toto rather than a second custom
signature format.

Audit insertion and authorization/effect state change share a transaction or a
write-ahead protocol that cannot perform an unrecorded effect.

### 15.4 Telemetry

Telemetry is disabled by default. When enabled it uses OpenTelemetry and a
public low-cardinality <code>axon.*</code> attribute schema. It never exports
task objectives, prompts, content, artifact bytes, filenames, host paths,
policy details, peer-provided trace parents, credentials, or keys.

Peer trace context is an untrusted span link, not an automatically trusted
parent. Experimental GenAI semantic conventions stay behind a pinned
compatibility option. Telemetry is operational sampling, never audit evidence.

### 15.5 Export, deletion, and recovery

Users can export their peer records, contracts, original input Parts, output
Artifacts, evidence, outcomes, and public audit summaries in documented
standard formats. A hosted deployment cannot withhold export.

Deletion semantics distinguish payload deletion from required integrity
metadata. The UI states what remains and why. Secure deletion claims are
limited by filesystem, SSD, snapshot, backup, and replica behavior.

Backups are encrypted and versioned. Restoring old state cannot silently resume
automatic effects.

Before a transaction that issues or consumes authority, the daemon reserves a
new monotonic state generation in the OS keystore, TPM, HSM, or configured
external checkpoint and commits that generation in the database transaction.
A crash between the two may conservatively force recovery, but cannot make an
older database appear current. Startup compares the external checkpoint with
the database before accepting sessions or work.

The supported backup format excludes the live external checkpoint. An official
restore therefore enters recovery, invalidates pending/claimed work and
automatic policy, and requires operator review and re-pairing when identity
freshness cannot be established. If a platform keystore cannot protect an
independent generation, Axon reports rollback detection as unavailable and
does not support restoration of reusable authority on that profile.

## 16. Public interfaces and adapters

### 16.1 Network interface

The canonical agent network interface is A2A. Axon publishes an Agent Card and
implements only the operations required by the pinned profile. MCP may be a
convenience adapter for a local agent, but it is not Axon’s network
interoperability or authority model.

A2A parsing and validation are independent of any particular official SDK.
Axon tests with at least two SDKs and preserves unknown standard fields when
safe.

### 16.2 Local interfaces

The daemon exposes separate local surfaces:

- an OS-protected user/admin socket for pairing, policy, approval, recovery,
  and audit;
- a narrow adapter/worker socket for task input, progress, result submission,
  and evidence references.

The worker surface cannot pair peers, create standing policy, approve a
contract, issue a work order, sign requester outcome, or export unrelated
content.

On Unix, peer credentials and file permissions bind the caller process and
user. Isolated deployments use distinct service identities. Other platforms
need an equivalent authenticated local IPC mechanism before support is
advertised.

In the personal profile, same-UID socket access is convenience authentication,
not proof of user intent; same-UID processes are in the profile’s TCB. The
isolated profile places authority/admin methods behind a separate service
identity and an OS-mediated local user-presence/authorization mechanism. Worker
descriptors remain process- and work-order-bound in both profiles.

The local control API uses a versioned OpenAPI 3.1 description and RFC 9457
Problem Details where A2A errors do not apply. Generated TypeScript and Python
clients are published. Custom errors do not leak whether a hidden path, secret,
policy rule, or internal peer exists.

### 16.3 Adapter contract

An adapter:

- declares its processor and plaintext handling;
- receives a task-bound input manifest, never the database or full session;
- cannot access raw processor credentials;
- emits bounded progress and result artifacts;
- cannot select a new recipient or network destination;
- cannot convert text into authority;
- survives cancellation and deadline enforcement by the trusted gateway;
- is tested for passive arrival and duplicate delivery.

Two production-real adapters are Phase 1 gates. A demo echo adapter does not
count.

### 16.4 Operator commands

The initial command groups are:

~~~text
axon init
axon demo review
axon serve
axon endpoint check
axon pair diagnose
axon pair create|accept|list|remove
axon peer show
axon review
axon task inbox|show|approve|deny|watch|cancel
axon outcome accept|reject|dispute
axon evidence validate|export
axon processor add|list|test
axon policy show
axon doctor
~~~

Phase 2 may add narrowly scoped <code>policy allow|revoke</code> and verifier
commands. Relay, directory, organization, and apply commands are not reserved
until those designs pass their release gates.

## 17. Open-source product and operations

### 17.1 Open-source covenant

The complete secure connection path is open source and self-hostable:

- A2A profile and Axon extensions;
- daemon and direct transport;
- pairing, policy, work-order, worker, and evidence engines;
- official adapters and generated clients;
- schemas, golden vectors, threat model, and conformance suite;
- migration, backup, export, and recovery tooling.

The proposed project license is Apache-2.0, subject to a dedicated maintainer
licensing decision before Phase 1. The repository must contain an OSI-approved
license before any “open source” release claim.

A hosted service may charge for operation, availability, managed runners,
organization integrations, support, and compliance packaging. It does not
provide a stronger protocol, exclusive cross-domain connectivity, restricted
export, or essential security controls unavailable to self-hosters.

### 17.2 Required project foundations

Before the first public release the repository contains:

- LICENSE;
- GOVERNANCE.md and MAINTAINERS.md;
- CONTRIBUTING.md and CODE_OF_CONDUCT.md;
- SECURITY.md with private vulnerability reporting and response targets;
- compatibility and deprecation policy;
- public extension registry and ADR process;
- signed releases, SBOMs, and dependency provenance;
- reproducible-build documentation and published conformance results.

Security-sensitive changes require review from maintainers who did not author
the change. Cryptographic, identity, authorization, sandbox, and evidence
changes include updated threat cases and vectors.

### 17.3 Operations

The default install has:

- no mandatory cloud control plane;
- no telemetry;
- local encrypted state;
- secure generated configuration;
- explicit listen addresses;
- automatic local database migrations with rollback-tested backups;
- a health report that separates availability from security posture.

<code>axon doctor</code> reports certificate expiry, unexpected key/card
changes, keystore quality, database encryption, retention, socket exposure,
processor disclosure, sandbox capabilities, version support, pending recovery,
and whether any proxy can read plaintext.

## 18. Versioning and compatibility

A2A, Axon extensions, evidence predicates, policy records, and local APIs are
versioned independently.

Rules:

- the Agent Card advertises exact required and optional Axon extension
  versions;
- required-version negotiation is authenticated and downgrade-resistant;
- unsupported required semantics fail before a contract can be accepted;
- readers reject unknown safety-critical enum values and preserve
  non-critical unknown standard fields;
- writers do not emit a new version until the peer advertises it;
- database migrations are forward tested and restore tested;
- deprecation includes at least one stable release overlap unless an active
  vulnerability requires immediate disablement.

There is no opportunistic compatibility mode that removes mutual
authentication, signatures, extension validation, evidence requirements, or
local authorization.

## 19. Implementation plan

### Phase 0 — Standards and security feasibility

Deliver:

- pin A2A 1.0 and its HTTP+JSON binding;
- publish the exact mapping for Agent Card, Message, Task, Part, Artifact,
  extension negotiation, nonblocking operations, status/history decisions,
  polling, cancellation, errors, and lifecycle;
- obtain a project-controlled extension namespace;
- define JSON Schemas and RFC 8785/DSSE golden vectors for contract, decision,
  ordered input manifest, identity/key binding, passive delivery,
  result-manifest, evidence reference, verifier summary, and outcome;
- define the in-toto/DSSE signer and identity profile, evidence payload types,
  SARIF 2.1.0 Errata 01 profile, and public-hash rules;
- select reviewed TLS, X.509, DSSE, storage-encryption, and keystore libraries;
- prototype retry-safe personal pairing and mutual TLS on two machines;
- define full-request Content-Digest/deduplication vectors and tombstone
  lifetime;
- select and publish the concrete Linux namespace/seccomp/cgroup sandbox
  launcher and profile;
- prototype the passive receive path, clean worker, and durable processor
  sub-attempt;
- validate the named OpenCode/local-model and Codex adapters;
- define trusted-time and external database-generation behavior;
- prototype the risk card with non-expert users;
- publish the threat model, standards disposition ADRs, and open-source
  foundations.

Gate:

- an A2A Message, server-created Task, status Message, and output Artifact
  survive a round trip through both adapters without semantic loss;
- contract signatures and digests match independent implementations;
- same-request retry returns the identical server-generated Task identifier,
  while any covered-value change is rejected;
- unsupported or downgraded security profiles fail closed;
- receiving every supported A2A object provably invokes no model, tool, file,
  URL, credential, or arbitrary reply;
- maintainers explicitly approve the small Axon extension surface.

### Phase 1 — Direct evidence-backed code review

Deliver:

- <code>axond</code>, CLI, local inbox/risk card, encrypted SQLite-backed state,
  OS keystore integration, outbox, inbox, dedupe, and audit;
- personal and isolated profiles;
- invitation, pair, re-pair, key-change suspension, and removal;
- direct A2A over TLS 1.3 with mutual authentication;
- <code>code_review.v1</code> using bounded text inputs;
- proposal, decision, work order, clean attempt, result, evidence-validation,
  and outcome states;
- local and explicitly configured remote processor support with durable
  ambiguous-call handling;
- text summary, SARIF findings, canonical result manifest, and DSSE/in-toto
  evidence;
- signed native Linux packages, user/system services, and the normative worker
  sandbox;
- export, retention, externally checkpointed official-restore behavior, and
  <code>axon doctor</code>;
- maintained OpenCode/local-model and Codex adapters and conformance fixtures;
- the same-host <code>axon demo review</code> evaluation path.

Gate:

- two independent, directly reachable fresh machines with documented
  processors already configured complete fresh Axon setup and the full loop in
  under ten minutes without an Axon account or organization IdP;
- the reviewer uses the isolated service profile for the security gate;
- the same-host evaluation path completes in under five minutes and is visibly
  labeled as lower assurance;
- network, daemon, database, adapter, and worker crash tests show no lost
  durable receipt, duplicate attempt, plaintext persistence, or false success;
- the worker has no host workspace, generic network, arbitrary tool, ambient
  secret, or host mutation;
- SVG, Markdown, Mermaid, and Graphviz inputs remain escaped source and cause no
  renderer, DOM, external fetch, or OS preview;
- a requester independently validates every signed subject and records an
  outcome;
- usability testing shows users can distinguish receipt, approval, completion,
  evidence validation, semantic verification, and acceptance.

**The first public product release ends here.**

### Phase 2 — Repeatable bounded local work

Candidate deliverables:

- deterministic standing policy ceilings outside the receive path;
- immutable read-only repository snapshots;
- only after immutable snapshots pass their gate, named verifier profiles with
  strong sandbox probing;
- JUnit compatibility importer and additional standard reports;
- private stage-write overlays and patch output, still without host apply;
- independent verifier adapters and richer evidence trust policy.

Gate:

- every automatic attempt is reproducibly explained by one exact local rule;
- run does not imply apply, network, secrets, or arbitrary command selection;
- path, hardlink, symlink, race, resource, crash, and parser tests pass on every
  advertised backend.

### Phase 3 — Optional transport and change expansion

Candidate deliverables require separate ADRs and demand evidence:

- a self-hostable opaque store-and-forward provider using mandatory MLS;
- a hardened SLIM provider if its maturity and conformance are sufficient;
- bounded standard binary artifact profiles;
- separately authorized host apply with true compare-and-swap semantics;
- additional task profiles proven by real cross-organization use.

Gate for any relay:

- the relay cannot decrypt content or forge authenticated membership;
- removal, rekey, replay, rollback, metadata leakage, durability, malicious
  member, and crash behavior pass the provider conformance suite;
- direct transport remains supported;
- there is no nested cryptography or competing membership state.

Gate for apply:

- workers still cannot mutate the host;
- the trusted applier checks exact bases and operations atomically;
- crash after effect start cannot be reported as clean failure or retried
  blindly.

### Phase 4 — Managed organizations and groups

Only after demonstrated demand:

- SPIFFE trust-domain federation;
- OIDC/WebAuthn local authority and SCIM lifecycle input;
- central policy, audit export, visible recovery, and compliance controls;
- private directory/federation;
- multi-party connections and MLS membership governance.

Managed work does not fork the base protocol or close essential features.
Groups require formal modeling and independent protocol review before release.

## 20. Verification plan

### 20.1 Standards and interoperability

- A2A conformance for Agent Card, operations, objects, lifecycle, and errors.
- Agent Card advertises mTLS, required extensions, HTTP+JSON, authenticated
  extended-card support, and disabled streaming/push exactly as the v1 profile
  requires.
- Request and response extension headers and Message/Artifact extension URI
  lists agree on SendMessage, GetTask, ListTasks, CancelTask, and
  GetExtendedAgentCard; missing required semantics fail before lookup or Task
  creation.
- Cross-peer GetTask/ListTasks/CancelTask/outcome references reveal no Task
  existence or content.
- Round trips through at least two independent SDKs/adapters.
- Golden vectors for every Axon schema, canonical digest, DSSE signature, and
  in-toto statement.
- Reject duplicate JSON keys, invalid UTF-8, non-I-JSON numbers, unknown
  critical fields, and version downgrade.
- Preserve exact bytes covered by signatures or attestations through parse and
  export.

### 20.2 Pairing and transport

- Entropy, expiry, attempt-limit, transactional consumption, exact-transcript
  retry, changed-transcript rejection, redaction, and QR/file invitation tests.
- Active MITM, wrong certificate, changed certificate, wrong trust domain,
  expired certificate, revoked peer, and unexpected Agent Card tests.
- Reject TLS below 1.3, 0-RTT, redirects, plaintext, anonymous clients, invalid
  chains/pins, and insecure proxy configuration.
- Fragmentation, slow body, oversized headers/body, queue saturation, rate
  limit, and decompression tests.
- Outbox/inbox crash at every transaction boundary.
- Same peer/Message ID/full-body-and-profile digest replays the saved response
  with the identical Task ID; any body, version, extension, interface, tenant,
  media type, or covered-header change conflicts.
- Replay tombstones outlive the maximum retry plus contract-expiry horizon.
- No claim of store-and-forward while a direct endpoint is offline.

### 20.3 Passive arrival and authority

- Every inbound A2A operation proves no model, approval decision, tool, file,
  process, URL, callback, credential, arbitrary recipient, or host mutation.
- Fixed submission response is schema-bound, body-independent, and effect-free.
- Agent Card skills, aliases, objectives, metadata, filenames, URLs, and
  unknown extensions cannot affect policy.
- Contract identity equals authenticated origin/local performer, and every
  worker byte maps to exactly one signed Message-Part manifest entry.
- Unmanifested, duplicate, kind-changed, or digest-changed Parts fail before
  work.
- Remote origin, local issuer, executor, and capability remain distinct.
- Work order binds exact task, revision, input, vector, budgets, processor,
  executor, and nonce.
- Claim and budget reservation are atomic.
- Crash-after-start becomes ambiguous and never auto-retries.
- Remote cancellation acts only when explicitly caveated.
- CancelTask without a caveat returns TaskNotCancelableError, and
  TASK_STATE_AUTH_REQUIRED is unreachable in v1.

### 20.4 Content and parser safety

- Boundary tests for bytes, nesting, item count, recursion, Unicode, duplicate
  keys, filenames, media types, and report complexity.
- URLs never trigger DNS, HTTP, file, data, or custom-scheme access.
- SVG is never placed in a DOM, decoded, rendered, rasterized, previewed, or
  externally resolved; the UI shows escaped source.
- Markdown, Mermaid, and Graphviz have the same inert-source guarantee.
- SARIF/JUnit/import parsers run with strict limits, never fetch schema or
  artifact URIs, and preserve original bytes.
- Unsupported and binary content cannot reach a model or OS preview service.

### 20.5 Worker and sandbox

- Empty environment, descriptor inheritance, process identity, scratch cleanup,
  output gate, deadline, cost, and resource tests.
- Processor broker permits only the selected service and exact input manifest.
- Processor calls are durably prepared; uncertain transmission becomes
  ambiguous and never auto-retries without proven provider idempotency.
- Worker cannot reach host workspace, generic network, raw credentials, or
  unrelated tasks.
- Later snapshot tests cover symlink, hardlink, mount, rename, inode reuse,
  path alias, TOCTOU, and non-atomic reads.
- Later overlay/apply tests cover base mismatch, concurrent modification,
  partial failure, crash, and rollback.
- Sandbox feature probing fails closed on every advertised platform.

### 20.6 Evidence and outcomes

- Validate DSSE payload type, exact bytes, signer purpose, chain, time,
  revocation, and subject digests.
- Result-manifest ordering, digest, slot mapping, and atomic completion match
  independent golden vectors.
- Evidence result and disclosure are orthogonal; redaction cannot hide failure
  or satisfy a visible-pass requirement.
- Self, independent, and hardware trust labels derive only from local policy.
- SLSA is emitted only for matching build semantics and makes no unsupported
  level claim.
- Outcome binds the exact accepted contract and canonical result manifest.
- Personal portable validation proves continuity only to the exported pairing
  root; managed identity and trusted-time claims require their configured
  chains/checkpoints.
- Public Sigstore interaction is impossible without explicit approval.
- Private low-entropy content hashes do not leak through telemetry or audit.

### 20.7 Privacy, storage, and recovery

- Database, WAL, temporary file, backup, log, panic, and crash-dump scans find
  no task plaintext or credential material.
- Keystore denial and rollback/restore cases fail safely.
- External state generation and backward-clock cases enter recovery before any
  session or work-order issuance.
- Retention and deletion behavior matches the UI and exported policy.
- Telemetry is off by default and its enabled schema contains no content.
- Every plaintext proxy and processor appears in <code>axon doctor</code>.
- Restored state cannot silently resume automatic work.

### 20.8 Product verification

- Fresh-install time-to-first-complete-task under ten minutes.
- Independent users understand pairing without certificate terminology.
- Risk-card tests show comprehension of exact data disclosure and capability.
- Users distinguish durable receipt, local approval, producer completion,
  evidence validation, optional semantic verification, and requester
  acceptance.
- Two real adapters complete the same code-review fixture.
- Maintainers dogfood Axon for review of Axon changes before Phase 1 release.

## 21. Decision gates for deferred features

A deferred feature enters implementation only when an ADR answers:

1. Which observed user problem requires it?
2. Which existing standard or implementation was evaluated?
3. Why can the current A2A/direct/local-authority design not satisfy the need?
4. What new trusted code, metadata, parser, authority, and recovery surface is
   introduced?
5. What secure failure behavior and downgrade rule apply?
6. How is the feature self-hosted and interoperable?
7. What conformance, fuzz, fault, and adversarial tests gate release?
8. How can an operator disable or remove it without losing base Axon use?

This gate applies especially to relays, MLS groups, directories, rich media,
large artifacts, secret brokerage, network egress, host apply, delegation,
managed recovery, and public transparency.

## 22. References

- A2A 1.0 Protocol specification:
  <https://a2a-protocol.org/latest/specification/>
- BCP 14 requirements language, RFC 2119 and RFC 8174:
  <https://www.rfc-editor.org/rfc/rfc2119>
  <https://www.rfc-editor.org/rfc/rfc8174>
- TLS 1.3, RFC 8446:
  <https://www.rfc-editor.org/rfc/rfc8446>
- Internet X.509 PKI profile, RFC 5280:
  <https://www.rfc-editor.org/rfc/rfc5280>
- JWS, RFC 7515:
  <https://www.rfc-editor.org/rfc/rfc7515>
- JWK thumbprints, RFC 7638:
  <https://www.rfc-editor.org/rfc/rfc7638>
- Ed25519, RFC 8032:
  <https://www.rfc-editor.org/rfc/rfc8032>
- EdDSA for JOSE, RFC 8037:
  <https://www.rfc-editor.org/rfc/rfc8037>
- Internet X.509 timestamp protocol, RFC 3161:
  <https://www.rfc-editor.org/rfc/rfc3161>
- HTTP Content-Digest, RFC 9530:
  <https://www.rfc-editor.org/rfc/rfc9530>
- Bearer authorization syntax and handling, RFC 6750:
  <https://www.rfc-editor.org/rfc/rfc6750>
- UUIDs, RFC 9562:
  <https://www.rfc-editor.org/rfc/rfc9562>
- RFC 3339 date and time:
  <https://www.rfc-editor.org/rfc/rfc3339>
- I-JSON, RFC 7493:
  <https://www.rfc-editor.org/rfc/rfc7493>
- JSON Canonicalization Scheme, RFC 8785:
  <https://www.rfc-editor.org/rfc/rfc8785>
- Problem Details for HTTP APIs, RFC 9457:
  <https://www.rfc-editor.org/rfc/rfc9457>
- JSON Schema Draft 2020-12:
  <https://json-schema.org/draft/2020-12>
- DSSE:
  <https://github.com/secure-systems-lab/dsse>
- in-toto Attestation Framework:
  <https://github.com/in-toto/attestation>
- SLSA Provenance:
  <https://slsa.dev/spec/>
- SARIF 2.1.0 Plus Errata 01:
  <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os.html>
- Sigstore bundle format:
  <https://docs.sigstore.dev/about/bundle/>
- Git bundle format:
  <https://git-scm.com/docs/bundle-format>
- Git format-patch:
  <https://git-scm.com/docs/git-format-patch>
- Messaging Layer Security, RFC 9420:
  <https://www.rfc-editor.org/rfc/rfc9420>
- MLS architecture, RFC 9750:
  <https://www.rfc-editor.org/rfc/rfc9750>
- SPIFFE X.509-SVID:
  <https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/>
- OpenID Connect:
  <https://openid.net/developers/how-connect-works/>
- SCIM, RFC 7644:
  <https://www.rfc-editor.org/rfc/rfc7644>
- Linux <code>openat2</code>:
  <https://man7.org/linux/man-pages/man2/openat2.2.html>
- Linux Landlock:
  <https://docs.kernel.org/userspace-api/landlock.html>
- OpenTelemetry semantic conventions:
  <https://opentelemetry.io/docs/specs/semconv/>
- AGNTCY SLIM specification:
  <https://spec.slim.agntcy.org/>
- IETF MIMI working group:
  <https://datatracker.ietf.org/wg/mimi/>

## 23. Final product boundary

Axon is the open secure A2A gateway, local authority boundary, and portable
evidence loop.

It succeeds by making one difficult path exceptionally clear:

~~~text
authenticated request
-> inert durable task
-> explicit local decision
-> bounded clean execution
-> standard evidence
-> independently checkable outcome
~~~

It does not become outstanding by owning every surrounding layer. Agent
semantics stay A2A. Direct transport stays TLS. Later group security stays MLS.
Software findings stay SARIF. Evidence stays DSSE/in-toto. Source formats stay
Git. SVG stays text. Local authority and honest product UX are where Axon earns
its name.

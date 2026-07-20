# Security policy

Akson is a security product in pre-release development. Until the first
release, the code in this repository has **no supported versions** and must
not be deployed.

## Reporting a vulnerability

Report vulnerabilities privately — do not open a public issue:

- Preferred: GitHub private vulnerability reporting on this repository
  ("Report a vulnerability" under the Security tab).
- Alternatively: email <pouriya@zarbafian.com> with subject
  `[akson security]`.

You will receive an acknowledgment within **7 days** and a triage decision
within **14 days**. Please include reproduction steps and the commit hash.
Coordinated disclosure is appreciated; we will credit reporters unless they
prefer otherwise.

## Scope

In scope once releases exist: the daemon (`aksond`), CLI, pairing and
transport, contract/authority/evidence engines, worker sandbox, official
adapters, and the published schemas and vectors.

Design-level threat assumptions are documented in the
[design](design/2026-07-16-threads-enterprise-agent-communication.md)
(section 6) — reports that show a violated invariant from that section are
especially valuable.

## Security-sensitive changes

Changes to cryptography, identity, authorization, sandboxing, or evidence
require review by a maintainer who did not author the change, plus updated
threat cases and test vectors (see GOVERNANCE.md).

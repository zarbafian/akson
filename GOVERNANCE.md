# Governance

## Maintainers

| Name | Role |
|---|---|
| Pouriya Zarbafian (@zarbafian) | Founding maintainer |

While the project has a single maintainer, the design's requirement that
security-sensitive changes be reviewed by a non-author maintainer cannot be
met; until a second maintainer joins, such changes must instead pass the full
conformance and adversarial test suites and be flagged
`security-review-pending` in the changelog. Adding maintainers is an explicit
goal before the first stable release.

## Decisions

- Product and security decisions with lasting consequences are recorded as
  ADRs in `spec/adr/` (process described there).
- The design document is normative; changing a normative statement requires a
  dated revision of the design plus an ADR when standards disposition is
  affected.
- Akson-specific wire formats are added only under the rule in design §3.1
  (documented standards gap, versioned schema, golden vectors, security
  review, two independent adapters).

## Releases

Releases are signed, include SBOMs and dependency provenance, and follow the
compatibility rules in design §18. There are no releases yet.

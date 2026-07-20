# Akson extension registry

The versioned JSON Schemas (Draft 2020-12) for every Akson extension object
(design §3.2). One file per schema version; published schemas are immutable —
a change is a new version. The ordered input manifest is embedded in the
contract schema rather than standing alone.

| Schema | Object | Design |
|---|---|---|
| `contract.v1.schema.json` | task contract revision + input manifest | §10.2 |
| `decision.v1.schema.json` | accept / reject / revision-request | §10.2 |
| `key-binding.v1.schema.json` | purpose-bound verification keys at pairing | §8.1, §8.2 |
| `delivery.v1.schema.json` | passive-delivery durable receipt | §9.2 |
| `result-manifest.v1.schema.json` | canonical result manifest | §14.1 |
| `evidence-reference.v1.schema.json` | pointer to one DSSE evidence envelope | §3.2 |
| `verifier-summary.v1.schema.json` | named-verifier check result | §14.2 |
| `outcome.v1.schema.json` | requester accepted/rejected/disputed | §14.5 |

Validation rules the schemas cannot express (input-manifest uniqueness and
exact-Part binding, result-manifest array ordering, identity-equals-origin)
are enforced in code and tested in the owning crates. Instances must pass
strict I-JSON parsing (`akson-ext::ijson`) before schema validation.

## Namespace and media types

Extension URIs require a project-controlled HTTPS namespace (design §3.1, a
Phase 0 release gate). That gate is **met**: the project controls `akson.cc`,
and every `$id` and extension URI is built from `https://akson.cc/ext`.

Payload media types are a **separate, unmet** gate. Owning a domain confers no
IANA registration, so they remain in the unregistered `application/vnd.akson-dev.*`
tree until design §14.2's registration completes. No stable release may ship
while `MEDIA_TYPES_ARE_PROVISIONAL` is true.

Both are defined in one place — `crates/akson-ext/src/namespace.rs`.

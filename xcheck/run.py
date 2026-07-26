#!/usr/bin/env python3
"""Independent cross-checker for the golden vectors under spec/vectors/.

Re-derives every expected value with implementations that share no code with
the Rust workspace (rfc8785, jwcrypto, cryptography) and fails on any
mismatch. Run: python xcheck/run.py spec/vectors
"""

import base64
import hashlib
import json
import pathlib
import sys

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator
from jwcrypto import jwk

# Set by main() from the vectors root; schema vectors validate instances
# against the real registry files in spec/ext/.
SCHEMA_DIR = pathlib.Path("spec/ext")

FAILURES = []


def fail(name: str, message: str) -> None:
    FAILURES.append(f"{name}: {message}")


def expect_eq(name: str, what: str, actual, expected) -> None:
    if actual != expected:
        fail(name, f"{what} differs\n  actual:   {actual!r}\n  expected: {expected!r}")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def check_jcs(name: str, case: dict) -> None:
    canonical = rfc8785.dumps(case["input"]["value"])
    expect_eq(name, "canonical", canonical.decode("utf-8"), case["expected"]["canonical"])
    expect_eq(
        name,
        "sha256",
        hashlib.sha256(canonical).hexdigest(),
        case["expected"]["sha256_hex"],
    )


def check_thumbprint(name: str, case: dict) -> None:
    inp = case["input"]
    if "jwk" in inp:
        key = jwk.JWK(**inp["jwk"])
    else:
        x = b64url(bytes.fromhex(inp["public_key_hex"]))
        expect_eq(name, "jwk x", x, case["expected"]["jwk_x"])
        key = jwk.JWK(kty="OKP", crv="Ed25519", x=x)
    expect_eq(name, "thumbprint", key.thumbprint(), case["expected"]["thumbprint"])


def pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (
        len(payload_type),
        payload_type.encode(),
        len(payload),
        payload,
    )


def check_dsse(name: str, case: dict) -> None:
    inp, exp = case["input"], case["expected"]
    payload = inp["payload_utf8"].encode("utf-8")
    p = pae(inp["payload_type"], payload)
    expect_eq(name, "PAE", p.decode("utf-8"), exp["pae_utf8"])
    expect_eq(name, "payload b64", base64.b64encode(payload).decode(), exp["payload_base64"])

    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(inp["private_key_hex"]))
    pk_raw = bytes.fromhex(inp["public_key_hex"])
    expect_eq(name, "key pair", sk.public_key().public_bytes_raw().hex(), pk_raw.hex())

    # Ed25519 is deterministic: re-signing must reproduce the frozen bytes.
    expect_eq(name, "signature", base64.b64encode(sk.sign(p)).decode(), exp["sig_base64"])
    Ed25519PublicKey.from_public_bytes(pk_raw).verify(
        base64.b64decode(exp["sig_base64"]), p
    )

    key = jwk.JWK(kty="OKP", crv="Ed25519", x=b64url(pk_raw))
    expect_eq(name, "keyid", key.thumbprint(), exp["keyid"])


def _ijson_int(token: str):
    value = int(token)
    if abs(value) > (2**53 - 1):
        raise ValueError("safe range")
    return value


def _ijson_float(token: str):
    value = float(token)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("safe range")
    if value.is_integer() and abs(value) > (2**53 - 1):
        raise ValueError("safe range")
    return value


def _ijson_valid(data: bytes):
    """Independent I-JSON judgment for the cross-checkable cases (duplicate
    keys, safe-integer range, invalid UTF-8, syntax). Depth/node limits and
    lone-surrogate handling are Rust-only unit tests, not in this family."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False

    def object_pairs(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError("duplicate")
            seen.add(key)
        return dict(pairs)

    try:
        json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_int=_ijson_int,
            parse_float=_ijson_float,
        )
    except (json.JSONDecodeError, ValueError):
        return False
    return True


def check_ijson(name: str, case: dict) -> None:
    inp = case["input"]
    if "json_utf8" in inp:
        data = inp["json_utf8"].encode("utf-8")
    else:
        data = base64.b64decode(inp["json_base64"])
    expect_eq(name, "validity", _ijson_valid(data), case["expected"]["valid"])


def check_jws(name: str, case: dict) -> None:
    """Independent Agent Card JWS (A2A §8.4, design §10.1 EdDSA profile).

    Rebuilds the whole signature from the card and the seed: RFC 8785 over the
    card minus `signatures` for the payload, an {alg,typ,kid} protected header
    (kid = RFC 7638 thumbprint), and a deterministic Ed25519 signature over
    `BASE64URL(protected) "." BASE64URL(payload)`.
    """
    inp, exp = case["input"], case["expected"]
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(inp["private_key_hex"]))
    pk_raw = bytes.fromhex(inp["public_key_hex"])
    expect_eq(name, "key pair", sk.public_key().public_bytes_raw().hex(), pk_raw.hex())

    kid = jwk.JWK(kty="OKP", crv="Ed25519", x=b64url(pk_raw)).thumbprint()
    expect_eq(name, "kid", kid, exp["kid"])

    card = {k: v for k, v in inp["card"].items() if k != "signatures"}
    payload = rfc8785.dumps(card)
    expect_eq(name, "payload_jcs", payload.decode("utf-8"), exp["payload_jcs"])

    header = {"alg": "EdDSA", "typ": "JOSE", "kid": kid}
    protected = b64url(rfc8785.dumps(header))
    expect_eq(name, "protected", protected, exp["protected"])

    signing_input = protected.encode() + b"." + b64url(payload).encode()
    signature = b64url(sk.sign(signing_input))
    expect_eq(name, "signature", signature, exp["signature"])

    # The frozen signature must verify under the public key.
    Ed25519PublicKey.from_public_bytes(pk_raw).verify(
        base64.urlsafe_b64decode(exp["signature"] + "=="), signing_input
    )


def check_delivery(name: str, case: dict) -> None:
    """Independent reliable-delivery primitives (design §9.2): RFC 9530
    Content-Digest and the HMAC-SHA256 keyed covered-value commitment."""
    import hmac

    inp, exp = case["input"], case["expected"]
    if "content_digest" in exp:
        body = inp["body_utf8"].encode("utf-8")
        digest = "sha-256=:%s:" % base64.b64encode(hashlib.sha256(body).digest()).decode()
        expect_eq(name, "content_digest", digest, exp["content_digest"])
        return

    # Covered-value commitment: normalize the extension set, canonicalize, HMAC.
    c = dict(inp["covered"])
    c["extensions"] = sorted(set(c["extensions"]))
    if c.get("tenant") is None:
        c.pop("tenant", None)
    canonical = rfc8785.dumps(c)
    expect_eq(name, "canonical", canonical.decode("utf-8"), exp["canonical"])
    key = bytes.fromhex(inp["commitment_key_hex"])
    commitment = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    expect_eq(name, "commitment", commitment, exp["commitment_hex"])


def _intro_canonical(transcript: dict) -> bytes:
    """The bytes every introduction proof signs (ADR-0015): the RFC 8785
    canonical JSON of the transcript with the domain field inside — the one
    canonicalization, nothing else to agree on."""
    t = dict(transcript)
    t["domain"] = "akson-introduction-v1"
    return rfc8785.dumps(t)


def check_introduction_transcript(name: str, case: dict) -> None:
    """Transcript signing bytes for one role; digest + Ed25519 PoP over them."""
    inp, exp = case["input"], case["expected"]
    canonical = _intro_canonical(inp["transcript"])
    expect_eq(name, "canonical", canonical.decode("utf-8"), exp["canonical"])
    expect_eq(name, "digest", hashlib.sha256(canonical).hexdigest(), exp["digest_hex"])
    if "signature_b64url" in exp:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(inp["private_key_hex"]))
        expect_eq(name, "pop signature", b64url(sk.sign(canonical)), exp["signature_b64url"])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(inp["public_key_hex"])).verify(
            b64url_decode(exp["signature_b64url"]), canonical
        )


def check_introduction_hello(name: str, case: dict) -> None:
    """Flight 1's exact wire bytes: the field set and order are the frozen
    fact (protocol_version, token_version, target_root, claimed_root, nonce);
    a plain compact JSON serialization in that order must reproduce them."""
    h, exp = case["input"]["hello"], case["expected"]
    wire = json.dumps(
        {
            "protocol_version": h["protocol_version"],
            "token_version": h["token_version"],
            "target_root": h["target_root"],
            "claimed_root": h["claimed_root"],
            "nonce": h["nonce"],
        },
        separators=(",", ":"),
    )
    expect_eq(name, "hello wire", wire, exp["wire"])
    expect_eq(name, "hello round-trip", json.loads(exp["wire"]), h)


def check_introduction_proof(name: str, case: dict) -> None:
    """One role's full proof body (IntroMaterial): rebuild the key-binding
    record, its RFC 8785 digest, the digest-bound transcript bytes, the card
    JWS, and every proof-of-possession signature from the seeds alone."""
    inp, exp = case["input"], case["expected"]
    material = exp["material"]

    # Keys: seed -> Ed25519 pair, RFC 7638 thumbprint via jwcrypto.
    keys = {}
    for purpose, seed_hex in inp["keys"].items():
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
        x = b64url(sk.public_key().public_bytes_raw())
        keys[purpose] = {
            "sk": sk,
            "jwk": {"crv": "Ed25519", "kty": "OKP", "x": x},
            "thumbprint": jwk.JWK(kty="OKP", crv="Ed25519", x=x).thumbprint(),
        }

    # The key-binding record, exactly as the signer builds it: the claimed TLS
    # certificate is the signer's side of the transcript.
    t = inp["transcript"]
    signer_tls = t["dialer_tls_sha256"] if inp["role"] == "dialer" else t["responder_tls_sha256"]
    validity = inp["validity"]
    key_binding = {
        "schema_version": 1,
        "subject": inp["subject"],
        "tls_certificate_sha256": signer_tls,
        "keys": {
            purpose: {
                "jwk": k["jwk"],
                "thumbprint": k["thumbprint"],
                "generation": validity["generation"],
                "not_before": validity["not_before"],
                "not_after": validity["not_after"],
            }
            for purpose, k in keys.items()
        },
    }
    expect_eq(name, "key binding", key_binding, material["key_binding"])
    kb_digest = hashlib.sha256(rfc8785.dumps(key_binding)).hexdigest()
    expect_eq(name, "key binding digest", kb_digest, exp["key_binding_sha256"])

    # The digest-bound transcript bytes every proof signs.
    bound = dict(t)
    bound["key_binding_sha256"] = kb_digest
    canonical = _intro_canonical(bound)
    expect_eq(name, "transcript canonical", canonical.decode("utf-8"), exp["transcript_canonical"])
    expect_eq(
        name,
        "transcript digest",
        hashlib.sha256(canonical).hexdigest(),
        exp["transcript_digest_hex"],
    )

    # Proof of possession by every advertised key over exactly those bytes.
    for purpose, k in keys.items():
        expect_eq(
            name,
            f"proof {purpose}",
            b64url(k["sk"].sign(canonical)),
            material["proofs"].get(purpose),
        )
    expect_eq(name, "proof purposes", sorted(material["proofs"]), sorted(keys))

    # The extended card: the input card plus one root JWS (same construction
    # as the jws/ family: JCS payload, {alg,typ,kid} protected header).
    card_key = keys["agent-card"]
    payload = rfc8785.dumps(inp["card"])
    protected = b64url(
        rfc8785.dumps({"alg": "EdDSA", "typ": "JOSE", "kid": card_key["thumbprint"]})
    )
    signing_input = protected.encode() + b"." + b64url(payload).encode()
    signature = b64url(card_key["sk"].sign(signing_input))
    expect_eq(
        name,
        "extended card",
        {**inp["card"], "signatures": [{"protected": protected, "signature": signature}]},
        material["extended_card"],
    )


def check_introduction_refusal(name: str, case: dict) -> None:
    """Refusal wire shapes (ADR-0015 error matrix): the RFC 9457 problem body
    is exactly {type, title, status} in that order, no detail. The
    indistinguishability of every pre-verification trigger is asserted by the
    Rust test driving the real handler (aksond/tests/introduce_e2e.rs)."""
    p, exp = case["input"]["problem"], case["expected"]
    body = json.dumps(
        {"type": p["type"], "title": p["title"], "status": p["status"]},
        separators=(",", ":"),
    )
    expect_eq(name, "problem body", body, exp["body"])
    expect_eq(name, "status", p["status"], exp["status"])
    expect_eq(name, "content type", exp["content_type"], "application/problem+json")


def check_introduction(name: str, case: dict) -> None:
    """Independent introduction vectors (ADR-0015), dispatched by input shape:
    transcript bytes per role, the hello wire shape, both proof bodies, and
    the refusal shapes."""
    inp = case["input"]
    if "hello" in inp:
        check_introduction_hello(name, case)
    elif "keys" in inp:
        check_introduction_proof(name, case)
    elif "problem" in inp:
        check_introduction_refusal(name, case)
    else:
        check_introduction_transcript(name, case)


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def decode_token(s: str):
    """Independent ADR-0013 decoder: bech32m, HRP akson, version+32-byte key.
    Returns (version, key_bytes) or raises ValueError with the refusal class."""
    if len(s) > 90:
        raise ValueError("too-long")
    # ASCII only, and ASCII case rules only: Unicode case folding (e.g. the
    # Kelvin sign lowercasing to 'k') must not admit a token Rust refuses.
    if not s.isascii():
        raise ValueError("bad-char")
    if any(c.islower() for c in s) and any(c.isupper() for c in s):
        raise ValueError("mixed-case")
    s = s.lower()
    sep = s.rfind("1")
    if sep < 0:
        raise ValueError("bad-hrp")
    hrp, rest = s[:sep], s[sep + 1 :]
    if len(rest) < 6:
        raise ValueError("bad-checksum")
    try:
        data = [BECH32_CHARSET.index(c) for c in rest]
    except ValueError as e:
        raise ValueError("bad-char") from e
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 0x2BC830A3:
        raise ValueError("bad-checksum")
    if hrp != "akson":
        raise ValueError("bad-hrp")
    acc, bits, out = 0, 0, bytearray()
    for g in data[:-6]:
        acc = (acc << 5) | g
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc & ((1 << bits) - 1)) != 0:
        raise ValueError("bad-length")
    if len(out) != 33:
        raise ValueError("bad-length")
    if out[0] != 0x01:
        raise ValueError("unknown-version")
    return out[0], bytes(out[1:])


def check_token(name: str, case: dict) -> None:
    """Independent identity-token decoding (ADR-0013)."""
    for c in case["cases"]:
        cname = f"{name}/{c['name']}"
        if c.get("rust_only"):
            continue  # e.g. curve-point checks outside this decoder's scope
        raw = c["input"]
        if c["expect"] == "presentation":
            token, _, hint = raw.rpartition("@")
            if not token:
                token, hint = raw, None
            expect_eq(cname, "hint", hint or None, c.get("hint"))
            if c.get("token_expect") == "valid":
                decode_token(token)
            continue
        try:
            version, key = decode_token(raw)
        except ValueError as e:
            expect_eq(cname, "refusal", c["expect"], "error")
            expect_eq(cname, "error class", str(e), c["error"])
            continue
        expect_eq(cname, "validity", c["expect"], "valid")
        expect_eq(cname, "version", version, c["version"])
        expect_eq(cname, "root key", key.hex(), c["root_key_hex"])


COORD_CURSOR_DOMAIN = "akson-coord-events-v1:"


def _coord_stage_reference(staging: dict) -> dict:
    """Independent ADR-0016 §4 derivation: the staged reference is a function of
    the content — SHA-256 over the RFC 8785 canonical JSON of the payload digest,
    the recipient label, and the task type; the reference is `stage-` plus the
    digest's first 32 hex characters. Nothing here is client-chosen."""
    payload = staging["payload_utf8"].encode("utf-8")
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    canonical = rfc8785.dumps(
        {
            "payload_sha256": payload_sha256,
            "performer": staging["performer"],
            "task_type": staging["task_type"],
        }
    )
    staged_digest = hashlib.sha256(canonical).hexdigest()
    return {
        "payload_sha256": payload_sha256,
        "canonical": canonical.decode("utf-8"),
        "staged_digest": staged_digest,
        "stage_ref": "stage-" + staged_digest[:32],
    }


def _coord_cursor(seq: int) -> str:
    return b64url(f"{COORD_CURSOR_DOMAIN}{seq}".encode("utf-8"))


def check_coordination(name: str, case: dict) -> None:
    """Independent coordination-surface vectors (ADR-0016), dispatched by input
    shape: the staged reference derivation and its idempotency, the opaque event
    cursor, each op's frozen request wire and reply field set, and every refusal
    body."""
    inp, exp = case["input"], case["expected"]

    # A request's wire form: `{"op": …}` plus that op's arguments, compact, in the
    # frozen field order.
    if "request" in inp:
        expect_eq(
            name,
            "request wire",
            json.dumps(inp["request"], separators=(",", ":")),
            exp["request_wire"],
        )
        expect_eq(name, "request round-trip", json.loads(exp["request_wire"]), inp["request"])

    # The staged reference derivation.
    if "payload_utf8" in inp:
        derived = _coord_stage_reference(inp)
        for field in ("payload_sha256", "canonical", "staged_digest", "stage_ref"):
            expect_eq(name, field, derived[field], exp[field])

    # Idempotency: identical content ⇒ identical reference; different bytes ⇒ not.
    if "stagings" in inp:
        refs = [_coord_stage_reference(s)["stage_ref"] for s in inp["stagings"]]
        expect_eq(name, "stage refs", refs, exp["stage_refs"])
        i, j = exp["same_reference"]
        expect_eq(name, f"stagings {i} and {j} share a reference", refs[i], refs[j])
        i, j = exp["distinct_reference"]
        if refs[i] == refs[j]:
            fail(name, f"stagings {i} and {j} must NOT share a reference")

    # The opaque cursor: base64url over the feed's domain plus the sequence.
    if "seqs" in inp:
        expect_eq(
            name,
            "cursors",
            [_coord_cursor(s) for s in inp["seqs"]],
            exp["cursors"],
        )
        expect_eq(name, "cursor domain", COORD_CURSOR_DOMAIN, exp["domain"])
        for bogus in exp["refused"]:
            try:
                text = b64url_decode(bogus).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue  # not even base64url/UTF-8 — refused
            if text.startswith(COORD_CURSOR_DOMAIN):
                fail(name, f"cursor {bogus!r} should not decode into this feed")

    # A reply's shape: the field set is the stable contract, and the canonical
    # bytes pin it.
    if "result" in inp:
        canonical = rfc8785.dumps(inp["result"])
        expect_eq(name, "result keys", sorted(inp["result"]), exp["result_keys"])
        expect_eq(name, "canonical", canonical.decode("utf-8"), exp["canonical"])
        expect_eq(
            name,
            "canonical sha256",
            hashlib.sha256(canonical).hexdigest(),
            exp["canonical_sha256"],
        )
        if "event_keys" in exp:
            for event in inp["result"]["events"]:
                expect_eq(name, "event keys", sorted(event), exp["event_keys"])
            expect_eq(
                name,
                "event kinds",
                [e["kind"] for e in inp["result"]["events"]],
                exp["kinds"],
            )
            # Every event carries the cursor that resumes AFTER it, and
            # `next_cursor` is the last one.
            expect_eq(
                name,
                "next_cursor",
                inp["result"]["events"][-1]["cursor"],
                inp["result"]["next_cursor"],
            )
        if "section_headings" in exp:
            expect_eq(
                name,
                "card headings",
                [s["heading"] for s in inp["result"]["sections"]],
                exp["section_headings"],
            )
            expect_eq(name, "card sentence", inp["result"]["sentence"], exp["sentence"])
            # The card the operator read names the exact digest the receipt binds,
            # and never the payload bytes.
            staged_as = [
                line.split(":", 1)[1].strip()
                for section in inp["result"]["sections"]
                for line in section["lines"]
                if line.startswith("staged as:")
            ]
            expect_eq(name, "card names the digest", staged_as, [inp["result"]["staged_digest"]])

        # Where the bytes got to (ADR-0016 §2, slice 3). The timestamp and the
        # one-line reason are instance values; the field set and the state
        # vocabulary are the contract.
        if "egress_keys" in exp:
            expect_eq(name, "egress keys", sorted(inp["result"]["egress"]), exp["egress_keys"])
            if "egress_states" in exp:
                if inp["result"]["egress"]["state"] not in exp["egress_states"]:
                    fail(name, "the example egress state is not in the frozen vocabulary")
        if "verification_states" in exp:
            v = inp["result"]["verification"]
            if v["state"] not in exp["verification_states"]:
                fail(name, "the example verification state is not in the frozen vocabulary")
            # A coordination dispatch is not a contract, so these are permanently
            # null — never "awaiting".
            for field in ("result_manifest_digest", "outcome_state"):
                if v[field] is not None:
                    fail(name, f"{field} must be null for a coordination dispatch")

    # The coordination dispatch envelope: independently re-derive the digest
    # chain the receiver checks, and re-validate the envelope against the
    # published schema — including that a contract term cannot be smuggled in.
    if "envelope" in inp:
        env = inp["envelope"]
        derived = _coord_stage_reference(inp)
        expect_eq(name, "envelope payload digest", env["payload_sha256"], derived["payload_sha256"])
        expect_eq(name, "envelope staged digest", env["staged_digest"], derived["staged_digest"])
        expect_eq(name, "envelope recipient label", env["recipient_label"], inp["performer"])
        expect_eq(name, "envelope task type", env["task_type"], inp["task_type"])
        expect_eq(name, "envelope keys", sorted(env), exp["envelope_keys"])
        canonical = rfc8785.dumps(env)
        expect_eq(name, "envelope canonical", canonical.decode("utf-8"), exp["envelope_canonical"])
        expect_eq(
            name,
            "envelope canonical sha256",
            hashlib.sha256(canonical).hexdigest(),
            exp["envelope_canonical_sha256"],
        )
        schema = json.loads((SCHEMA_DIR / "coord-dispatch.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        if list(validator.iter_errors(env)):
            fail(name, "the frozen envelope does not conform to coord-dispatch.v1")
        for member in exp["forbidden_members"]:
            if member in env:
                fail(name, f"{member} is a contract term the operator never consented to")
            if not list(validator.iter_errors({**env, member: "x"})):
                fail(name, f"coord-dispatch.v1 must refuse a smuggled {member}")

    # A refusal: the RFC 9457 body is exactly these members in this order.
    if "problem" in inp:
        p = inp["problem"]
        body = json.dumps(p, separators=(",", ":"))
        expect_eq(name, "problem body", body, exp["body"])
        expect_eq(name, "status", p["status"], exp["status"])
        expect_eq(name, "problem round-trip", json.loads(exp["body"]), p)
        if "op" in exp:
            # A 501 must NAME the op, so "not built" never reads as "not allowed".
            if exp["op"] not in p.get("detail", ""):
                fail(name, f"the 501 detail must name {exp['op']!r}")


def check_schema(name: str, case: dict) -> None:
    inp, exp = case["input"], case["expected"]
    schema_path = SCHEMA_DIR / f"{inp['schema']}.v{inp['version']}.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(inp["value"]))
    expect_eq(name, "validity", not errors, exp["valid"])
    if exp["valid"]:
        canonical = rfc8785.dumps(inp["value"])
        expect_eq(
            name,
            "canonical sha256",
            hashlib.sha256(canonical).hexdigest(),
            exp["canonical_sha256"],
        )


CHECKERS = {
    "jcs": check_jcs,
    "thumbprint": check_thumbprint,
    "dsse": check_dsse,
    "jws": check_jws,
    "delivery": check_delivery,
    "introduction": check_introduction,
    "token": check_token,
    "schema": check_schema,
    "coordination": check_coordination,
    "ijson": check_ijson,
}


def main() -> int:
    global SCHEMA_DIR
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "spec/vectors")
    SCHEMA_DIR = root.parent / "ext"
    count = 0
    for path in sorted(root.rglob("*.json")):
        family = path.relative_to(root).parts[0]
        checker = CHECKERS.get(family)
        if checker is None:
            fail(str(path), f"no checker registered for family {family!r}")
            continue
        case = json.loads(path.read_text())
        expected_name = f"{family}/{path.stem}"
        if case.get("name") != expected_name:
            fail(str(path), f"vector name {case.get('name')!r} != {expected_name!r}")
        checker(case.get("name", str(path)), case)
        count += 1

    if FAILURES:
        print(f"xcheck: {len(FAILURES)} failure(s) across {count} vector(s)")
        for f in FAILURES:
            print(f"  FAIL {f}")
        return 1
    if count == 0:
        print(f"xcheck: no vectors found under {root}")
        return 1
    print(f"xcheck: {count} vectors OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

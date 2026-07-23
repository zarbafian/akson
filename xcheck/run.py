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


def check_introduction(name: str, case: dict) -> None:
    """Independent introduction-transcript bytes (ADR-0015): the signing bytes
    are exactly the RFC 8785 canonical JSON of the transcript with the domain
    field inside; digest + Ed25519 proof of possession over them."""
    inp, exp = case["input"], case["expected"]
    transcript = dict(inp["transcript"])
    transcript["domain"] = "akson-introduction-v1"
    canonical = rfc8785.dumps(transcript)
    expect_eq(name, "canonical", canonical.decode("utf-8"), exp["canonical"])
    expect_eq(name, "digest", hashlib.sha256(canonical).hexdigest(), exp["digest_hex"])
    if "signature_b64url" in exp:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(inp["private_key_hex"]))
        expect_eq(name, "pop signature", b64url(sk.sign(canonical)), exp["signature_b64url"])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(inp["public_key_hex"])).verify(
            b64url_decode(exp["signature_b64url"]), canonical
        )


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

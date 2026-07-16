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
from jwcrypto import jwk

FAILURES = []


def fail(name: str, message: str) -> None:
    FAILURES.append(f"{name}: {message}")


def expect_eq(name: str, what: str, actual, expected) -> None:
    if actual != expected:
        fail(name, f"{what} differs\n  actual:   {actual!r}\n  expected: {expected!r}")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


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


CHECKERS = {"jcs": check_jcs, "thumbprint": check_thumbprint, "dsse": check_dsse}


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "spec/vectors")
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

#!/usr/bin/env python3
"""Hold docs/ to the code and the specs, so the site cannot rot quietly.

The site's pages hand-copy operation names, counts, media types, timeouts and
version strings out of the sources. That is how a false claim survives: the
source changes, the prose does not, and nobody notices because nothing fails.
This script makes that failure loud.

Two jobs, run in order:

  1. GENERATED BLOCKS. Every claim that is mechanically derivable lives inside a
     marked region of the HTML:

         <!--gen:coord-op-count-->eight<!--/gen:coord-op-count-->

     `--write` fills those regions from the sources of truth. With no flag the
     script regenerates them in memory and compares — a divergence is a failure
     naming the block, the file, the expected text and the text on the page.
     Hand-editing a generated region fails just as loudly as source drift.

  2. FREE CLAIMS AND LINKS. Facts that read better inside a sentence than inside
     a block are asserted by presence: the script computes the truth and greps
     the pages for it. Then every internal href/src is resolved against the tree
     and every page is checked for balanced tags.

Sources of truth, in the order the script trusts them:

  crates/aksond/src/socket.rs      ControlRequest — the wire `op` names
  crates/aksond/src/control.rs     ControlOp::required_surface — op -> surface
  crates/aksond/src/a2a_client.rs  the four per-stage carriage timeouts
  crates/akson-store/src/lib.rs    the three egress states
  spec/ext/coord-dispatch.v1.schema.json   the envelope's members
  spec/vectors/coordination/*.json         the frozen wire, as a second opinion
  Cargo.toml                       the workspace version

Usage:  harness/check-docs.py            # check; non-zero on drift
        harness/check-docs.py --write    # regenerate the blocks in place
"""

from __future__ import annotations

import html
import json
import re
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

# Tags that never close in HTML5, so a balance check must not wait for them.
VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}

NUMBER_WORDS = {
    1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
    7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
}


# --------------------------------------------------------------------------
# Reading the sources of truth
# --------------------------------------------------------------------------


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def snake(camel: str) -> str:
    """serde's `rename_all = "snake_case"` on an enum variant."""
    out = []
    for i, ch in enumerate(camel):
        if ch.isupper() and i:
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def control_request_ops() -> dict[str, str]:
    """Variant -> wire `op` name, from ControlRequest's serde derivation.

    The enum carries `#[serde(tag = "op", rename_all = "snake_case")]`, so the
    wire name is the snake_cased variant unless an explicit `#[serde(rename)]`
    overrides it (`CoordWhoAmI` does — `coord_whoami`, not `coord_who_am_i`).
    """
    src = read(ROOT / "crates" / "aksond" / "src" / "socket.rs")
    body = between(src, "pub enum ControlRequest {", "\n}\n")
    ops: dict[str, str] = {}
    pending_rename: str | None = None
    depth = 0
    for line in body.splitlines():
        stripped = line.strip()
        m = re.match(r'#\[serde\(rename\s*=\s*"([^"]+)"\)\]', stripped)
        if m and depth == 0:
            pending_rename = m.group(1)
            continue
        if depth == 0:
            m = re.match(r"([A-Z][A-Za-z0-9]*)\s*(\{|\(|,)", stripped)
            if m:
                variant = m.group(1)
                ops[variant] = pending_rename or snake(variant)
                pending_rename = None
        depth += line.count("{") + line.count("(") - line.count("}") - line.count(")")
        depth = max(depth, 0)
    if len(ops) < 20:
        die(f"parsed only {len(ops)} ControlRequest variants — the parser is wrong")
    return ops


def arms(body: str, target_prefix: str, lhs_prefix: str) -> list[tuple[list[str], str, str]]:
    """Split a `match` body into (left-hand names, right-hand name, raw lhs).

    Every arm ends at its right-hand `Prefix::Name`, so the text since the
    previous one is that arm's pattern. This survives block-bodied arms
    (`=> { ControlOp::X }`), which a `[^{}]` regex does not.
    """
    flat = re.sub(r"\s+", " ", body)
    parts = re.split(rf"{target_prefix}::([A-Za-z0-9]+)", flat)
    out = []
    for i in range(1, len(parts), 2):
        lhs = parts[i - 1]
        names = re.findall(rf"{lhs_prefix}::([A-Za-z0-9]+)", lhs)
        out.append((names, parts[i], lhs))
    return out


def variant_to_control_op() -> dict[str, str]:
    """ControlRequest variant -> ControlOp, from `impl ControlRequest::op`."""
    src = read(ROOT / "crates" / "aksond" / "src" / "socket.rs")
    body = between(src, "pub fn op(&self) -> ControlOp {", "\n    }\n")
    out: dict[str, str] = {}
    for names, target, _lhs in arms(body, "ControlOp", "ControlRequest"):
        for v in names:
            out[v] = target
    if len(out) < 20:
        die(f"parsed only {len(out)} op() arms — the parser is wrong")
    return out


def control_op_surfaces() -> dict[str, str]:
    """ControlOp -> surface, from `required_surface`. `_ =>` is the default."""
    src = read(ROOT / "crates" / "aksond" / "src" / "control.rs")
    body = between(src, "pub fn required_surface(self) -> Surface {", "\n    }\n")
    out: dict[str, str] = {}
    default = None
    for names, surface, lhs in arms(body, "Surface", "ControlOp"):
        if not names:
            if re.search(r"_\s*=>\s*$", lhs):
                default = surface.lower()
            continue
        for op in names:
            out[op] = surface.lower()
    if default is None:
        die("required_surface has no `_ =>` default arm — the parser is wrong")
    # Everything ControlOp declares that the match did not name falls to default.
    decl = read(ROOT / "crates" / "aksond" / "src" / "control.rs")
    enum_body = between(decl, "pub enum ControlOp {", "\n}\n")
    for line in enum_body.splitlines():
        m = re.match(r"\s{4}([A-Z][A-Za-z0-9]*),\s*$", line)
        if m:
            out.setdefault(m.group(1), default)
    return out


def registry() -> dict[str, str]:
    """The whole control registry: wire `op` name -> surface."""
    wire = control_request_ops()
    to_op = variant_to_control_op()
    surfaces = control_op_surfaces()
    out: dict[str, str] = {}
    for variant, op_name in wire.items():
        control_op = to_op.get(variant)
        if control_op is None:
            die(f"ControlRequest::{variant} has no arm in op() — cannot place it")
        surface = surfaces.get(control_op)
        if surface is None:
            die(f"ControlOp::{control_op} has no required_surface — cannot place it")
        out[op_name] = surface
    return out


def ops_on(surface: str) -> list[str]:
    """Wire op names on `surface`, in ControlRequest declaration order."""
    return [op for op, s in registry().items() if s == surface]


def envelope_schema() -> dict:
    return json.loads(read(ROOT / "spec" / "ext" / "coord-dispatch.v1.schema.json"))


def vector(name: str) -> dict:
    return json.loads(read(ROOT / "spec" / "vectors" / "coordination" / f"{name}.json"))


def workspace_version() -> str:
    src = read(ROOT / "Cargo.toml")
    body = between(src, "[workspace.package]", "\n[")
    m = re.search(r'^version\s*=\s*"([^"]+)"', body, re.M)
    if not m:
        die("no version in [workspace.package]")
    return m.group(1)


def carriage_timeouts() -> dict[str, int]:
    """The four per-stage ceilings on the outbound POST, in seconds."""
    src = read(ROOT / "crates" / "aksond" / "src" / "a2a_client.rs")
    want = {
        "resolve": "RESOLVE_TIMEOUT",
        "connect": "CONNECT_TIMEOUT",
        "handshake": "HANDSHAKE_TIMEOUT",
        "exchange": "EXCHANGE_TIMEOUT",
    }
    out = {}
    for label, const in want.items():
        m = re.search(
            rf"const {const}: Duration = Duration::from_secs\((\d+)\)", src
        )
        if not m:
            die(f"{const} not found in a2a_client.rs")
        out[label] = int(m.group(1))
    return out


def egress_states() -> list[str]:
    src = read(ROOT / "crates" / "akson-store" / "src" / "lib.rs")
    out = []
    for const in ("COORD_EGRESS_PENDING", "COORD_EGRESS_SENT", "COORD_EGRESS_FAILED"):
        m = re.search(rf'pub const {const}: &str = "([a-z]+)";', src)
        if not m:
            die(f"{const} not found in akson-store")
        out.append(m.group(1))
    return out


def between(text: str, start: str, end: str) -> str:
    i = text.find(start)
    if i < 0:
        die(f"marker not found in source: {start!r}")
    i += len(start)
    j = text.find(end, i)
    if j < 0:
        die(f"end marker not found in source: {end!r}")
    return text[i:j]


def die(msg: str) -> None:
    print(f"check-docs: FATAL — {msg}", file=sys.stderr)
    sys.exit(2)


# --------------------------------------------------------------------------
# The prose the generator owns
# --------------------------------------------------------------------------
#
# Names and counts come from the sources above. The one-line purposes are
# editorial, so they live here — keyed by the name the source produces. A new op
# or a new envelope member therefore fails this script with "no description",
# which is the point: the registry cannot grow without the site being told.

COORD_OP_PURPOSE = {
    "coord_whoami": (
        "This endpoint's identity and the protocol/feature versions — the driver's own "
        "handshake. Narrower than admin's <code>who_am_i</code> on purpose: no "
        "<code>data_dir</code>, no <code>receive_addr</code>."
    ),
    "peer_show": (
        "One named peer's verified identity tuple and card claims. It answers about the "
        "peer asked for and never enumerates; an unknown or malformed label gets the same "
        "<code>404 unknown-peer</code>."
    ),
    "stage": (
        "Inert, idempotent staging of outbound bytes. Nothing starts, no authority is "
        "minted, no socket opens. The same bytes return the same reference and write no "
        "second record."
    ),
    "stage_show": (
        "A staged payload's status and digests, plus its consent once an operator has "
        "minted one."
    ),
    "dispatch": (
        "The one op with an effect. One-shot: it spends a consent receipt it cannot create, "
        "commits the dispatch, and carries the bytes to the pinned recipient."
    ),
    "task_status": (
        "Whether a dispatch this surface committed was acknowledged. Scoped to those "
        "dispatches — an inbound task in the operator's inbox is the same "
        "<code>404 unknown-task</code>."
    ),
    "events_read": (
        "The durable cursored coordination feed. Cursors are opaque: one that did not come "
        "from a reply is refused <code>400 bad-cursor</code>."
    ),
    "capability_evidence": (
        "A DSSE-signed in-toto Statement of what this endpoint can federate with a peer, "
        "signed with the same <code>evidence</code> key result evidence uses."
    ),
}

ENVELOPE_MEMBER_WHY = {
    "schema_version": "So a receiver refuses rather than guesses.",
    "protocol": "The coordination protocol this envelope belongs to; a receiver that does not speak it refuses.",
    "task_type": "Consented to — the byom-owned type, carried uninterpreted.",
    "recipient_label": (
        "Consented to, <strong>and</strong> one of the three preimages of the staged digest: "
        "without it the receiver could check the bytes but not the digest the consent binds."
    ),
    "recipient_root": "So a misrouted disclosure is refused even over a good channel.",
    "sender_root": "So a claimed sender can never differ from the pinned one.",
    "payload_sha256": "The payload, by the digest the receiver recomputes over what it actually read.",
    "staged_digest": "The exact value the consent receipt binds.",
    "consent_receipt": (
        "The identity of the authorization — the id only, never the sealed body, and it "
        "confers nothing on the receiver."
    ),
}

CARRIAGE_STAGE_LABEL = {
    "resolve": "name resolution",
    "connect": "the TCP connect",
    "handshake": "the TLS handshake",
    "exchange": "the request/response exchange",
}

EGRESS_STATE_MEANING = {
    "pending": (
        "Committed, nothing acknowledged. The schema <strong>default</strong>, so a crash "
        "between the commit and the send is honest by construction rather than by "
        "remembering to write something."
    ),
    "sent": (
        "The pinned recipient echoed this exact staged digest. <strong>Terminal</strong> — "
        "and the only state that claims delivery."
    ),
    "failed": (
        "Attempted and refused, or timed out. Retryable: re-presenting the same "
        "<code>execution_key</code> re-attempts carriage and spends nothing."
    ),
}


# --------------------------------------------------------------------------
# The generated blocks
# --------------------------------------------------------------------------


def word(n: int) -> str:
    return NUMBER_WORDS.get(n, str(n))


def code_list(items: list[str], conjunction: str = "and") -> str:
    tagged = [f"<code>{html.escape(i)}</code>" for i in items]
    if len(tagged) == 1:
        return tagged[0]
    return ", ".join(tagged[:-1]) + f" {conjunction} " + tagged[-1]


def gen_coord_op_count() -> str:
    return word(len(ops_on("coord")))


def gen_coord_op_names() -> str:
    return code_list(ops_on("coord"))


def gen_coord_op_rows() -> str:
    rows = []
    for op in ops_on("coord"):
        why = COORD_OP_PURPOSE.get(op)
        if why is None:
            die(
                f"the coordination registry has `{op}` but this script has no description "
                f"for it — add one to COORD_OP_PURPOSE in harness/check-docs.py"
            )
        rows.append(
            f"  <tr><td><code>{html.escape(op)}</code></td><td>{why}</td></tr>"
        )
    return "\n" + "\n".join(rows) + "\n"


def gen_admin_op_count() -> str:
    return word(len(ops_on("admin")))


def gen_worker_op_count() -> str:
    return word(len(ops_on("worker")))


def gen_worker_op_names() -> str:
    return code_list(ops_on("worker"))


def gen_envelope_member_count() -> str:
    return word(len(envelope_schema()["properties"]))


def gen_envelope_members() -> str:
    return code_list(list(envelope_schema()["properties"]), conjunction="and")


def gen_envelope_member_rows() -> str:
    schema = envelope_schema()
    required = set(schema.get("required", []))
    rows = []
    for member in schema["properties"]:
        why = ENVELOPE_MEMBER_WHY.get(member)
        if why is None:
            die(
                f"the envelope schema has member `{member}` but this script has no reason "
                f"for it — add one to ENVELOPE_MEMBER_WHY in harness/check-docs.py"
            )
        mark = "" if member in required else " <em>(optional)</em>"
        rows.append(
            f"  <tr><td><code>{html.escape(member)}</code>{mark}</td><td>{why}</td></tr>"
        )
    return "\n" + "\n".join(rows) + "\n"


def gen_carriage_timeouts() -> str:
    t = carriage_timeouts()
    parts = [f"{CARRIAGE_STAGE_LABEL[k]} {t[k]}s" for k in
             ("resolve", "connect", "handshake", "exchange")]
    return ", ".join(parts[:-1]) + ", and " + parts[-1]


def gen_carriage_total() -> str:
    return str(sum(carriage_timeouts().values()))


def gen_egress_state_rows() -> str:
    rows = []
    for state in egress_states():
        meaning = EGRESS_STATE_MEANING.get(state)
        if meaning is None:
            die(
                f"akson-store declares egress state `{state}` but this script has no "
                f"meaning for it — add one to EGRESS_STATE_MEANING in harness/check-docs.py"
            )
        rows.append(
            f"  <tr><td><code>{html.escape(state)}</code></td><td>{meaning}</td></tr>"
        )
    return "\n" + "\n".join(rows) + "\n"


def gen_egress_states() -> str:
    return code_list(egress_states(), conjunction="or")


def gen_version() -> str:
    return html.escape(workspace_version())


def gen_envelope_media_type() -> str:
    return html.escape(vector("dispatch-envelope")["expected"]["envelope_media_type"])


def gen_consent_transcript() -> str:
    """The `akson stage show` / `akson stage consent` session, rendered from the
    golden vectors through the CLI's own print sequence.

    A hand-typed transcript is the purest form of a claim outrunning its
    evidence: it looks like observed output and is answerable to nothing. This
    one is built from `stage-show-staged` and `stage-consent` in the order
    `stage_show` and `stage_consent` in crates/akson-cli/src/main.rs print their
    fields, so a change to either the reply shape or the risk card shows up here.
    """
    show = vector("stage-show-staged")["input"]["result"]
    consent = vector("stage-consent")["input"]["result"]
    ref = show["stage_ref"]

    def esc(s: object) -> str:
        return html.escape(str(s), quote=False)

    out = [f"$ akson stage show {esc(ref)}"]
    out.append(esc(ref))
    out.append(f"  status:     {esc(show['status'])}")
    out.append(f"  task type:  {esc(show['task_type'])}")
    out.append(f"  recipient:  {esc(show['performer'] or '(none)')}")
    out.append(f"  bytes:      {esc(show['byte_length'])}")
    out.append(f"  payload:    sha256:{esc(show['payload_sha256'])}")
    out.append(f"  staged as:  {esc(show['staged_digest'])}")
    if show["consent"] is None:
        out.append(f"  consent:    none — `akson stage consent {esc(ref)}`")
    else:
        out.append(
            f"  consent:    {esc(show['consent']['consent_receipt'])} (one-shot, unconsumed)"
        )

    out.append("")
    out.append(f'$ akson stage consent {esc(consent["stage_ref"])}')
    out.append(f'<span class="hi">{esc(consent["sentence"])}</span>')
    out.append("")
    for section in consent["sections"]:
        out.append(esc(section["heading"]))
        for line in section["lines"]:
            out.append(f"  {esc(line)}")
    out.append("")
    out.append(f"consent receipt: {esc(consent['consent_receipt'])}")
    out.append(f"  binds:      {esc(consent['staged_digest'])}")
    out.append(f"  uses:       {esc(consent['uses'])}/{esc(consent['max_uses'])}")
    return "\n".join(out)


def gen_staged_digest_example() -> str:
    """The staged-digest derivation, taken verbatim from its golden vector.

    Shown as the single line RFC 8785 actually produces — pretty-printing it
    would imply whitespace that is not in the bytes being hashed.
    """
    v = vector("dispatch-envelope")["expected"]
    digest, ref = v["staged_digest"], v["stage_ref"]
    width = max(len(digest), len(ref))
    return (
        "the three fields, canonicalized — RFC 8785 emits one line, no whitespace\n"
        f"  {html.escape(v['canonical'], quote=False)}\n"
        "\n"
        f"sha256 of those bytes   {html.escape(digest).ljust(width)}   "
        "the staged digest — what the consent binds\n"
        f"its first 128 bits      {html.escape(ref).ljust(width)}   "
        "the stage_ref the driver is handed"
    )


def gen_envelope_forbidden() -> str:
    """The contract terms the golden vector proves the envelope refuses.

    `additionalProperties: false` is the mechanism; these are the names the
    vector actually presents to it, so the page's claim is the one that is tested.
    """
    forbidden = vector("dispatch-envelope")["expected"]["forbidden_members"]
    schema = envelope_schema()
    overlap = set(forbidden) & set(schema["properties"])
    if overlap:
        die(
            f"the vector calls {sorted(overlap)} forbidden but the schema now defines "
            f"them as members — one of the two moved"
        )
    return code_list(forbidden)


BLOCKS = {
    "coord-op-count": gen_coord_op_count,
    "coord-op-names": gen_coord_op_names,
    "coord-op-rows": gen_coord_op_rows,
    "admin-op-count": gen_admin_op_count,
    "worker-op-count": gen_worker_op_count,
    "worker-op-names": gen_worker_op_names,
    "envelope-member-count": gen_envelope_member_count,
    "envelope-members": gen_envelope_members,
    "envelope-member-rows": gen_envelope_member_rows,
    "envelope-media-type": gen_envelope_media_type,
    "envelope-forbidden": gen_envelope_forbidden,
    "consent-transcript": gen_consent_transcript,
    "staged-digest-example": gen_staged_digest_example,
    "carriage-timeouts": gen_carriage_timeouts,
    "carriage-total": gen_carriage_total,
    "egress-states": gen_egress_states,
    "egress-state-rows": gen_egress_state_rows,
    "version": gen_version,
}

BLOCK_RE = re.compile(r"<!--gen:([a-z0-9-]+)-->(.*?)<!--/gen:\1-->", re.S)


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    checked: int = 0

    def fail(self, msg: str) -> None:
        self.failures.append(msg)

    def ok(self, n: int = 1) -> None:
        self.checked += n


def first_difference(page_text: str, source_text: str) -> tuple[str, str]:
    """The first line where two versions of a block diverge, trimmed to one screen.

    A multi-row table block is long; quoting its head tells you it is stale but
    not which row moved, which is exactly the thing worth knowing.
    """
    mine = page_text.strip().splitlines() or [""]
    theirs = source_text.strip().splitlines() or [""]
    for i in range(max(len(mine), len(theirs))):
        a = mine[i] if i < len(mine) else "(nothing — the page block is shorter)"
        b = theirs[i] if i < len(theirs) else "(nothing — the source block is shorter)"
        if a != b:
            return a.strip()[:220], b.strip()[:220]
    return mine[0].strip()[:220], theirs[0].strip()[:220]


def pages() -> list[Path]:
    return sorted(DOCS.rglob("*.html"))


def rel(p: Path) -> str:
    return str(p.relative_to(ROOT))


def check_blocks(rep: Report, write: bool) -> None:
    seen: set[str] = set()
    for page in pages():
        text = read(page)
        changed = False

        def sub(m: re.Match) -> str:
            nonlocal changed
            name, current = m.group(1), m.group(2)
            seen.add(name)
            gen = BLOCKS.get(name)
            if gen is None:
                rep.fail(
                    f"{rel(page)}: <!--gen:{name}--> is not a block this script knows how "
                    f"to generate (known: {', '.join(sorted(BLOCKS))})"
                )
                return m.group(0)
            want = gen()
            rep.ok()
            if want != current:
                if write:
                    changed = True
                    return f"<!--gen:{name}-->{want}<!--/gen:{name}-->"
                mine, theirs = first_difference(current, want)
                rep.fail(
                    f"{rel(page)}: generated block `{name}` is stale.\n"
                    f"        the page says:   {mine}\n"
                    f"        the source says: {theirs}\n"
                    f"        fix: harness/check-docs.py --write"
                )
            return m.group(0)

        new = BLOCK_RE.sub(sub, text)
        if write and changed:
            page.write_text(new, encoding="utf-8")
            print(f"  rewrote {rel(page)}")

    unused = set(BLOCKS) - seen
    if unused:
        rep.fail(
            "these generated blocks exist in this script but appear on no page, so "
            "nothing is being held to them: " + ", ".join(sorted(unused))
        )


def check_free_claims(rep: Report) -> None:
    """Facts that read better in a sentence than in a block: assert by presence.

    Each entry is (what it is, the exact string that must appear, where).
    """
    version = workspace_version()
    coord = ops_on("coord")
    worker = ops_on("worker")
    states = egress_states()
    schema = envelope_schema()
    env_vec = vector("dispatch-envelope")["expected"]
    who_vec = vector("coord-whoami")["input"]["result"]

    # A second, independent opinion on the same facts: the frozen golden vectors
    # are re-derived by xcheck/ from the wire, so a code change that the vectors
    # did not follow is caught here rather than on a page.
    if who_vec["features"] != coord:
        rep.fail(
            "the registry and the golden vector disagree about the coordination ops.\n"
            f"        crates/aksond (ControlRequest + required_surface): {coord}\n"
            f"        spec/vectors/coordination/coord-whoami.json features: {who_vec['features']}"
        )
    else:
        rep.ok()

    if sorted(schema["properties"]) != env_vec["envelope_keys"]:
        rep.fail(
            "the envelope schema and its golden vector disagree about the members.\n"
            f"        spec/ext/coord-dispatch.v1.schema.json: {sorted(schema['properties'])}\n"
            f"        spec/vectors/coordination/dispatch-envelope.json: {env_vec['envelope_keys']}"
        )
    else:
        rep.ok()

    if sorted(schema["required"]) != sorted(schema["properties"]):
        rep.fail(
            "every envelope member used to be required; the site says so. "
            f"required={sorted(schema['required'])} properties={sorted(schema['properties'])}"
        )
    else:
        rep.ok()

    if schema.get("additionalProperties") is not False:
        rep.fail(
            "the site says the envelope's `additionalProperties` is false, so a contract "
            "term cannot be added later. The schema no longer says that."
        )
    else:
        rep.ok()

    # The release page's central claim — "this is a prerelease because the media
    # types are provisional" — is true only while this flag is. Flip it and the
    # page is asserting a gate that no longer refuses anything.
    namespace = read(ROOT / "crates" / "akson-ext" / "src" / "namespace.rs")
    provisional = re.search(
        r"MEDIA_TYPES_ARE_PROVISIONAL: bool = (true|false)", namespace
    )
    if provisional is None:
        rep.fail("MEDIA_TYPES_ARE_PROVISIONAL not found in akson-ext/src/namespace.rs")
    elif provisional.group(1) != "true":
        rep.fail(
            "MEDIA_TYPES_ARE_PROVISIONAL is now false, so the media types are no longer "
            "provisional — docs/release/index.html still says that gate is what refuses a "
            "stable tag, and docs/coordination/index.html still calls the envelope's media "
            "type unregistered. Both need rewriting, not regenerating."
        )
    else:
        rep.ok()

    protocol = schema["properties"]["protocol"]["const"]

    required: list[tuple[str, str, Path]] = [
        ("the workspace version", version, DOCS / "index.html"),
        ("the workspace version", version, DOCS / "release" / "index.html"),
        ("the workspace version", version, DOCS / "coordination" / "index.html"),
        ("the coordination protocol name", protocol, DOCS / "coordination" / "index.html"),
        ("the envelope media type", env_vec["envelope_media_type"],
         DOCS / "coordination" / "index.html"),
        ("the payload media type", env_vec["payload_media_type"],
         DOCS / "coordination" / "index.html"),
        ("the staged-digest preimage member name", "performer",
         DOCS / "coordination" / "index.html"),
        ("the coordination socket's admission variable", "AKSON_COORD_UID",
         DOCS / "coordination" / "index.html"),
        ("the coordination socket's admission variable", "AKSON_COORD_UID",
         DOCS / "guide" / "index.html"),
        ("the unregistered media-type tree", "vnd.akson-dev", DOCS / "release" / "index.html"),
    ]
    for op in coord:
        required.append((f"the coordination op `{op}`", op, DOCS / "coordination" / "index.html"))
    for state in states:
        required.append(
            (f"the egress state `{state}`", state, DOCS / "coordination" / "index.html")
        )
    for op in worker:
        required.append((f"the worker op `{op}`", op, DOCS / "internals" / "index.html"))

    for what, needle, page in required:
        if not page.exists():
            rep.fail(f"{rel(page)}: missing, but {what} must appear on it")
            continue
        if needle not in read(page):
            rep.fail(
                f"{rel(page)}: {what} is {needle!r} in the source, and that string does "
                f"not appear on the page"
            )
        else:
            rep.ok()

    # Claims that must NOT appear: retired facts the site once stated.
    forbidden: list[tuple[str, str, str]] = [
        (
            "same UID only",
            "admission became per-socket when coord.sock landed, so no page may say the "
            "daemon admits only its own UID universally",
            "docs",
        ),
    ]
    for needle, why, _scope in forbidden:
        for page in pages():
            if needle in read(page):
                rep.fail(f"{rel(page)}: says {needle!r} — {why}")
            else:
                rep.ok()


def check_links(rep: Report) -> None:
    """Every internal href/src resolves to something in docs/, and fragments exist."""
    ids: dict[Path, set[str]] = {}
    for page in pages():
        ids[page] = set(re.findall(r'\bid="([^"]+)"', read(page)))

    href_re = re.compile(r'\b(?:href|src)="([^"]*)"')
    for page in pages():
        for raw in href_re.findall(read(page)):
            link = html.unescape(raw)
            if not link or link.startswith(("http://", "https://", "mailto:", "data:", "//")):
                continue
            path_part, _, frag = link.partition("#")
            if not path_part:
                if frag and frag not in ids[page]:
                    rep.fail(f"{rel(page)}: #{frag} — no element with that id on this page")
                else:
                    rep.ok()
                continue
            base = DOCS if path_part.startswith("/") else page.parent
            target = (base / path_part.lstrip("/")).resolve()
            try:
                target.relative_to(DOCS.resolve())
            except ValueError:
                rep.fail(f"{rel(page)}: {link} escapes docs/")
                continue
            if target.is_dir():
                target = target / "index.html"
            if not target.exists():
                rep.fail(f"{rel(page)}: {link} -> {target} does not exist")
                continue
            if frag:
                if target.suffix != ".html":
                    rep.fail(f"{rel(page)}: {link} has a fragment but the target is not HTML")
                    continue
                if frag not in ids.get(target, set(re.findall(r'\bid="([^"]+)"', read(target)))):
                    rep.fail(f"{rel(page)}: {link} — no element with id {frag!r} in the target")
                    continue
            rep.ok()

    # The sitemap must list exactly the indexable pages, and nothing that 404s.
    sitemap = DOCS / "sitemap.xml"
    listed = set(re.findall(r"<loc>https://akson\.cc/([^<]*)</loc>", read(sitemap)))
    on_disk = set()
    for page in pages():
        if page.name != "index.html":
            continue
        r = page.relative_to(DOCS).parent.as_posix()
        on_disk.add("" if r == "." else r + "/")
    if listed != on_disk:
        rep.fail(
            "docs/sitemap.xml does not list exactly the site's index pages.\n"
            f"        only in sitemap: {sorted(listed - on_disk) or 'none'}\n"
            f"        only on disk:    {sorted(on_disk - listed) or 'none'}"
        )
    else:
        rep.ok()


class Balance(HTMLParser):
    def __init__(self, name: str) -> None:
        super().__init__(convert_charrefs=True)
        self.name = name
        self.stack: list[tuple[str, int]] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack:
            self.errors.append(f"line {self.getpos()[0]}: </{tag}> with nothing open")
            return
        if self.stack[-1][0] != tag:
            open_tag, line = self.stack[-1]
            self.errors.append(
                f"line {self.getpos()[0]}: </{tag}> closes <{open_tag}> opened on line {line}"
            )
            # Recover if it matches something further down, so one slip does not
            # cascade into a hundred bogus errors.
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i][0] == tag:
                    del self.stack[i:]
                    return
            return
        self.stack.pop()


SVG_RE = re.compile(r'<svg[^>]*\bviewBox="([\d.\s-]+)"(.*?)</svg>', re.S)
COORD_RE = re.compile(r'\b(x|y|x1|y1|x2|y2|cx|cy)="(-?[\d.]+)"')
RECT_RE = re.compile(r'<rect\b[^>]*>')
ATTR_RE = re.compile(r'\b(x|y|width|height)="(-?[\d.]+)"')
POINTS_RE = re.compile(r'\bpoints="([\d.,\s-]+)"')


def check_svg_bounds(rep: Report) -> None:
    """Every diagram element sits inside its own viewBox.

    These figures are hand-written SVG. A box or an arrowhead nudged past the
    viewBox is clipped in the browser and silent everywhere else — the drawing
    just quietly loses a piece. The tolerance is generous because `text` is
    positioned by its anchor and legitimately extends past it.
    """
    slack = 4.0
    for page in pages():
        for i, (vb, body) in enumerate(SVG_RE.findall(read(page)), start=1):
            nums = [float(n) for n in vb.split()]
            if len(nums) != 4:
                rep.fail(f"{rel(page)}: svg #{i} has a malformed viewBox {vb!r}")
                continue
            minx, miny, w, h = nums
            maxx, maxy = minx + w, miny + h
            bad: list[str] = []

            def note(kind: str, x: float, y: float) -> None:
                if not (minx - slack <= x <= maxx + slack and miny - slack <= y <= maxy + slack):
                    bad.append(f"{kind} at ({x:g},{y:g})")

            for tag in RECT_RE.findall(body):
                a = {k: float(v) for k, v in ATTR_RE.findall(tag)}
                if {"x", "y", "width", "height"} <= a.keys():
                    note("rect corner", a["x"] + a["width"], a["y"] + a["height"])
            for pts in POINTS_RE.findall(body):
                vals = [float(v) for v in pts.replace(",", " ").split()]
                for j in range(0, len(vals) - 1, 2):
                    note("polygon point", vals[j], vals[j + 1])
            # Line/circle anchors, taken pairwise as they appear on each element.
            for element in re.findall(r"<(?:line|circle|ellipse)\b[^>]*>", body):
                found = dict(COORD_RE.findall(element))
                for xk, yk in (("x1", "y1"), ("x2", "y2"), ("cx", "cy")):
                    if xk in found and yk in found:
                        note("line end", float(found[xk]), float(found[yk]))
            if bad:
                rep.fail(
                    f"{rel(page)}: svg #{i} (viewBox {vb}) draws outside itself, so the "
                    f"browser clips it: " + "; ".join(sorted(set(bad))[:6])
                )
            else:
                rep.ok()


def check_html(rep: Report) -> None:
    for page in pages():
        text = read(page)
        parser = Balance(rel(page))
        parser.feed(text)
        parser.close()
        for err in parser.errors:
            rep.fail(f"{rel(page)}: {err}")
        for tag, line in parser.stack:
            rep.fail(f"{rel(page)}: <{tag}> opened on line {line} is never closed")
        if not parser.errors and not parser.stack:
            rep.ok()
        if "<title>" not in text and page.name == "index.html":
            rep.fail(f"{rel(page)}: no <title>")
        # Self-contained: the CSP-free Pages host still must not reach out.
        for m in re.finditer(r'\b(?:src|href)="(https?://[^"]+)"', text):
            url = m.group(1)
            if re.search(r'\brel="(stylesheet|preconnect|preload)"', text[max(0, m.start() - 120):m.start()]):
                rep.fail(f"{rel(page)}: external asset {url}")
        if re.search(r"<script[^>]+\bsrc=\"https?://", text):
            rep.fail(f"{rel(page)}: external script")


def main() -> int:
    write = "--write" in sys.argv[1:]
    rep = Report()

    print("docs: generated blocks vs. the sources of truth")
    check_blocks(rep, write)
    if write:
        # A rewrite invalidates the counts above; re-check so the exit code means
        # "the tree is now consistent", not "it was consistent before I wrote".
        rep = Report()
        check_blocks(rep, False)

    print("docs: free claims vs. the sources of truth")
    check_free_claims(rep)

    print("docs: internal links, fragments, and the sitemap")
    check_links(rep)

    print("docs: HTML is balanced and self-contained")
    check_html(rep)

    print("docs: hand-written diagrams stay inside their viewBox")
    check_svg_bounds(rep)

    print()
    if rep.failures:
        for f in rep.failures:
            print(f"  FAIL  {f}")
        print(f"\ndocs check: {len(rep.failures)} FAILED, {rep.checked} passed")
        return 1
    print(f"docs check: {rep.checked} claims and links verified against the sources")
    return 0


if __name__ == "__main__":
    sys.exit(main())

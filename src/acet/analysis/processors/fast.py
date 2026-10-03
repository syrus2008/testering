"""FAST@1 processors: HashFacts, PEFacts, StringFacts (spec §14). Deterministic (D0)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from acet.analysis.pe import pe_facts
from acet.engines.worker import WorkerContext

MAX_STRINGS = 20000
MIN_LEN = 5
MAX_LEN = 256
_ASCII = re.compile(rb"[\x20-\x7e]{%d,%d}" % (MIN_LEN, MAX_LEN))
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,%d}" % (MIN_LEN, MAX_LEN))


def hash_facts(ctx: WorkerContext) -> dict[str, Any]:
    path = ctx.artifact_path(0)
    data = path.read_bytes()
    ctx.heartbeat()
    facts: dict[str, Any] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "size_bytes": len(data),
    }
    if facts["sha256"] != ctx.inputs[0].sha256:
        ctx.error("input bytes do not match the requested artifact hash")
    try:
        import tlsh  # optional (spec: "TLSH si disponible")

        value = tlsh.hash(data)
        facts["tlsh"] = {"state": "MEASURED" if value and value != "TNULL" else "UNSUPPORTED", "value": value or None}
    except ImportError:
        facts["tlsh"] = {"state": "NOT_MEASURED", "value": None, "reason": "tlsh module unavailable"}
    return facts


def pe_facts_processor(ctx: WorkerContext) -> dict[str, Any]:
    data = ctx.artifact_path(0).read_bytes()
    facts = pe_facts(data)
    if facts.get("format_state") == "MEASURED":
        partial = [k for k, v in facts.items() if isinstance(v, dict) and v.get("state") == "PARTIAL"]
        for fam in partial:
            ctx.warn(f"PE family {fam} partially parsed")
        ctx.count("pe_families", len([v for v in facts.values() if isinstance(v, dict)]))
    return facts


def string_facts(ctx: WorkerContext) -> dict[str, Any]:
    data = ctx.artifact_path(0).read_bytes()
    found: list[dict[str, Any]] = []
    truncated = False
    for enc, rx in (("ascii", _ASCII), ("utf16le", _UTF16)):
        for m in rx.finditer(data):
            if len(found) >= MAX_STRINGS:
                truncated = True
                break
            raw = m.group(0)
            s = raw.decode("ascii") if enc == "ascii" else raw.decode("utf-16-le")
            found.append({"offset": m.start(), "encoding": enc, "value": s})
    uniq = sorted({f["value"] for f in found})
    ctx.count("strings", len(found))
    return {
        "count": len(found),
        "unique_count": len(uniq),
        "truncated": truncated,
        "min_length": MIN_LEN,
        "set_sha256": hashlib.sha256("\n".join(uniq).encode("utf-8")).hexdigest(),
        # Strings can contain user names/paths: exports treat them as sensitive (ACET-PRI-002).
        "sensitive": True,
        "strings": found,
    }

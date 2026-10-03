"""Analysis context stratification (spec §67, ACET-SCI-001..003)."""

from __future__ import annotations

from typing import Any


def _bucket(n: int | None, edges: tuple[tuple[int, str], ...]) -> str:
    if n is None:
        return "UNKNOWN"
    for limit, name in edges:
        if n <= limit:
            return name
    return "XL"


def analysis_context(
    pe: dict[str, Any] | None,
    features: dict[str, Any] | None,
    size_bytes: int | None,
    export: dict[str, Any] | None = None,
) -> dict[str, Any]:
    hdr = (pe or {}).get("headers", {}).get("value") or {}
    secs = (pe or {}).get("sections", {}).get("value") or []
    text_entropy = max((s["entropy"] or 0 for s in secs if s.get("characteristics", 0) & 0x20000000), default=None)
    funcs = (features or {}).get("functions") or []
    named = sum(1 for f in funcs if f["identity"]["name"])
    return {
        "format": hdr.get("magic"),
        "architecture": {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(hdr.get("machine", 0)),
        "compiler_family_hint": ((export or {}).get("program") or {}).get("compiler"),
        "compiler_version_hint": None,
        "optimization_hint": None,
        "linkage": "dynamic" if ((pe or {}).get("imports", {}).get("value") or {}).get("dlls") else "static-or-none",
        "symbols_present": (named / len(funcs) > 0.5) if funcs else None,
        "packing_indicators": None if text_entropy is None else text_entropy > 7.2,
        "virtualization_indicators": None,
        "function_count_bucket": _bucket(len(funcs) if features else None, ((100, "S"), (1000, "M"), (10000, "L"))),
        "binary_size_bucket": _bucket(size_bytes, ((1 << 20, "S"), (16 << 20, "M"), (128 << 20, "L"))),
        "extraction_quality": (features or {}).get("extraction_quality", {}).get("code_coverage_ratio"),
        "provider_versions": (features or {}).get("engine_version"),
    }


CONTEXT_KEY_FIELDS = ("format", "architecture", "compiler_family_hint", "function_count_bucket", "packing_indicators")


def context_key(ctx: dict[str, Any]) -> str:
    return "|".join(f"{k}={ctx.get(k)}" for k in CONTEXT_KEY_FIELDS)

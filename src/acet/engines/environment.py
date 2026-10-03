"""Provider detection and capability model (spec §18, ACC-033).

Detection is static (paths, versions read from files). Nothing here runs an
analysed artifact. A detected provider that is not in a validated Engine Pack is
reported ``verified=False`` ("UNVERIFIED ENGINE", §77).
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acet.domain.enums import Capability


@dataclass
class ProviderInfo:
    provider_id: str
    available: bool
    version: str | None = None
    location: str | None = None
    capabilities: tuple[Capability, ...] = ()
    verified: bool = False
    reason: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "available": self.available,
            "version": self.version,
            "capabilities": [c.value for c in self.capabilities],
            "verified": self.verified,
            "reason": self.reason,
        }


@dataclass
class EngineEnvironment:
    providers: dict[str, ProviderInfo]
    engine_pack_id: str | None = None

    def available(self, provider_id: str) -> bool:
        p = self.providers.get(provider_id)
        return bool(p and p.available)

    @property
    def capabilities(self) -> set[Capability]:
        out: set[Capability] = set()
        for p in self.providers.values():
            if p.available:
                out |= set(p.capabilities)
        return out

    def manifest(self) -> dict[str, Any]:
        return {
            "id": self.engine_pack_id or "local-detected",
            "providers": {k: v.to_dict() for k, v in sorted(self.providers.items())},
        }


def ghidra_dir(overrides: dict[str, str] | None = None) -> Path | None:
    o = overrides or {}
    for cand in (o.get("ghidra"), os.environ.get("ACET_GHIDRA_DIR"), os.environ.get("GHIDRA_INSTALL_DIR")):
        if cand and (Path(cand) / "support").is_dir():
            return Path(cand)
    return None


def _ghidra_version(d: Path) -> str | None:
    props = d / "Ghidra" / "application.properties"
    try:
        m = re.search(r"^application\.version=(.+)$", props.read_text(encoding="utf-8"), re.MULTILINE)
        return m.group(1).strip() if m else None
    except OSError:
        return None


def _module_version(name: str) -> str | None:
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:
        return None


def _binexport_extension(gdir: Path | None) -> Path | None:
    candidates: list[Path] = []
    if gdir is not None:
        candidates.append(gdir / "Ghidra" / "Extensions")
    home = Path.home()
    candidates += list(home.glob(".ghidra/.ghidra_*/Extensions")) + list(
        Path(os.environ.get("APPDATA", home)).glob("ghidra/ghidra_*/Extensions")
    )
    for c in candidates:
        if (c / "BinExport").is_dir():
            return c / "BinExport"
    return None


def detect(overrides: dict[str, str] | None = None, *, pack_id: str | None = None) -> EngineEnvironment:
    o = overrides or {}
    providers: dict[str, ProviderInfo] = {}
    gdir = ghidra_dir(o)
    java = shutil.which("java") or (os.environ.get("JAVA_HOME") and str(Path(os.environ["JAVA_HOME"]) / "bin" / "java"))
    if gdir and java:
        providers["ghidra"] = ProviderInfo(
            "ghidra", True, _ghidra_version(gdir), str(gdir), (Capability.DISASSEMBLY, Capability.FUNCTION_EXTRACTION)
        )
    elif os.environ.get("ACET_GHIDRA_REPLAY_DIR"):
        providers["ghidra"] = ProviderInfo(
            "ghidra",
            True,
            "replay",
            os.environ["ACET_GHIDRA_REPLAY_DIR"],
            (Capability.DISASSEMBLY, Capability.FUNCTION_EXTRACTION),
            verified=False,
            reason="golden replay provider (recorded exports); not a live engine",
            extra={"replay": True},
        )
    else:
        providers["ghidra"] = ProviderInfo(
            "ghidra", False, reason="Ghidra install not found" if not gdir else "Java runtime not found"
        )
    live_ghidra = providers["ghidra"].available and not providers["ghidra"].extra.get("replay")
    gdf = importlib.util.find_spec("ghidriff") is not None and (
        importlib.util.find_spec("pyghidra") is not None or importlib.util.find_spec("pyhidra") is not None
    )
    providers["ghidriff"] = ProviderInfo(
        "ghidriff",
        gdf and live_ghidra,
        _module_version("ghidriff"),
        None,
        (Capability.STRUCTURAL_DIFF,),
        reason=None if gdf and live_ghidra else "ghidriff/pyghidra or a live Ghidra unavailable",
    )
    be = _binexport_extension(gdir)
    providers["binexport"] = ProviderInfo(
        "binexport",
        bool(be and gdir),
        None,
        str(be) if be else None,
        (Capability.STRUCTURAL_DIFF,),
        reason=None if be else "BinExport Ghidra extension not installed",
    )
    bd = o.get("bindiff") or os.environ.get("ACET_BINDIFF") or shutil.which("bindiff")
    providers["bindiff"] = ProviderInfo(
        "bindiff",
        bool(bd),
        None,
        bd,
        (Capability.STRUCTURAL_DIFF,),
        reason=None if bd else "bindiff executable not found",
    )
    qpy = o.get("qbindiff") or os.environ.get("ACET_QBINDIFF_PYTHON")
    qver = None
    if qpy and Path(qpy).is_file():
        venv = Path(qpy).absolute().parent.parent  # do not resolve: venv python is a symlink
        dist = sorted(venv.glob("lib/python*/site-packages/qbindiff-*.dist-info")) + sorted(
            venv.glob("Lib/site-packages/qbindiff-*.dist-info")
        )
        qver = dist[0].name.split("-")[1] if dist else None
    qb = qver is not None
    providers["qbindiff"] = ProviderInfo(
        "qbindiff",
        qb and providers["binexport"].available,
        qver,
        qpy,
        (Capability.PROGRAMMABLE_DIFF,),
        reason=None if qb else "isolated QBinDiff interpreter not configured",
        extra={"experimental": True},
    )
    ida = o.get("ida") or os.environ.get("IDADIR")
    providers["diaphora"] = ProviderInfo(
        "diaphora",
        False,
        None,
        ida,
        (Capability.STRUCTURAL_DIFF,),
        reason="external IDA-based provider: detection only (ADR-0009)" + ("; IDA detected" if ida else ""),
    )
    providers["acet"] = ProviderInfo(
        "acet",
        True,
        _acet_version(),
        sys.executable,
        (Capability.SEMANTIC_FEATURES, Capability.REPORT_EXPORT),
        verified=True,
    )
    return EngineEnvironment(providers, pack_id)


def _acet_version() -> str:
    import acet

    return acet.__version__

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


def _venv_dist_version(python: str, dist_name: str) -> str | None:
    """Version of ``dist_name`` installed in the virtual environment of ``python``, read from
    its dist-info directory (no code from that environment is executed)."""
    exe_dir = Path(python).absolute().parent  # do not resolve: venv python is a symlink
    norm = dist_name.replace("-", "_").lower()
    # venv (bin/python, Scripts/python.exe) or embeddable CPython of an Engine Pack (python.exe at the root).
    found = sorted(exe_dir.parent.glob("lib/python*/site-packages/*.dist-info"))
    for root in (exe_dir.parent, exe_dir):
        found += sorted(root.glob("Lib/site-packages/*.dist-info"))
    for d in found:
        name, _, ver = d.name[: -len(".dist-info")].rpartition("-")
        if name.replace("-", "_").lower() == norm:
            return ver
    return None


def _java_release_version(home: Path) -> str | None:
    """JDK version from its ``release`` file (no process is started)."""
    try:
        for line in (home / "release").read_text(encoding="utf-8").splitlines():
            if line.startswith("JAVA_VERSION="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        return None
    return None


def _java(o: dict[str, str]) -> ProviderInfo:
    """Java for Ghidra. An Engine Pack's private runtime is used exclusively when the pack has one
    (never JAVA_HOME / PATH); a system Java is only a developer fallback when no pack runtime is set."""
    exe_name = "java.exe" if os.name == "nt" else "java"
    if o.get("java"):
        home = Path(o["java"])
        if (home / "bin" / exe_name).is_file():
            return ProviderInfo("java", True, _java_release_version(home), str(home), extra={"source": "engine-pack"})
        return ProviderInfo("java", False, reason="the Engine Pack's private Java runtime is missing")
    found = shutil.which("java") or (
        os.environ.get("JAVA_HOME") and str(Path(os.environ["JAVA_HOME"]) / "bin" / exe_name)
    )
    if found and Path(found).is_file():
        home = Path(found).resolve().parent.parent
        return ProviderInfo("java", True, _java_release_version(home), str(home), extra={"source": "system"})
    return ProviderInfo("java", False, reason="no Java runtime (install the Engine Pack)")


def detect(overrides: dict[str, str] | None = None, *, pack_id: str | None = None) -> EngineEnvironment:
    o = overrides or {}
    providers: dict[str, ProviderInfo] = {}
    gdir = ghidra_dir(o)
    providers["java"] = _java(o)
    java = providers["java"].available
    if gdir and java:
        providers["ghidra"] = ProviderInfo(
            "ghidra", True, _ghidra_version(gdir), str(gdir), (Capability.DISASSEMBLY, Capability.FUNCTION_EXTRACTION)
        )
    elif gdir:
        # A configured live Ghidra that cannot run is reported as such: the replay provider
        # never silently substitutes for a live engine.
        providers["ghidra"] = ProviderInfo("ghidra", False, reason="Java runtime not found")
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
        providers["ghidra"] = ProviderInfo("ghidra", False, reason="Ghidra install not found")
    live_ghidra = providers["ghidra"].available and not providers["ghidra"].extra.get("replay")
    # Ghidriff runs in its own interpreter (the Engine Pack's, ACET_GHIDRIFF_PYTHON). Only a
    # development checkout may fall back to the current interpreter: a frozen ACET build
    # does not contain ghidriff.
    gpy = o.get("ghidriff") or os.environ.get("ACET_GHIDRIFF_PYTHON")
    if gpy:
        gver = _venv_dist_version(gpy, "ghidriff") if Path(gpy).is_file() else None
        gdf = gver is not None and _venv_dist_version(gpy, "pyghidra") is not None
    elif not getattr(sys, "frozen", False) and pack_id is None:
        # Developer checkout without an Engine Pack only: a pack is self-contained and never mixes
        # in engines from the interpreter ACET happens to run on.
        gpy, gver = sys.executable, _module_version("ghidriff")
        gdf = importlib.util.find_spec("ghidriff") is not None and (
            importlib.util.find_spec("pyghidra") is not None or importlib.util.find_spec("pyhidra") is not None
        )
    else:
        gver, gdf = None, False
    providers["ghidriff"] = ProviderInfo(
        "ghidriff",
        gdf and live_ghidra,
        gver,
        gpy if gdf else None,
        (Capability.STRUCTURAL_DIFF,),
        reason=None if gdf and live_ghidra else "ghidriff/pyghidra interpreter or a live Ghidra unavailable",
    )
    be = _binexport_extension(gdir)
    be_ver = (
        (be / "ACET_VERSION").read_text(encoding="utf-8").strip() if be and (be / "ACET_VERSION").is_file() else None
    )
    providers["binexport"] = ProviderInfo(
        "binexport",
        bool(be and gdir),
        be_ver,
        str(be) if be else None,
        (Capability.STRUCTURAL_DIFF,),
        reason=None if be else "BinExport Ghidra extension not installed",
    )
    bd = o.get("bindiff") or os.environ.get("ACET_BINDIFF") or shutil.which("bindiff")
    providers["bindiff"] = ProviderInfo(
        "bindiff",
        bool(bd),
        _bindiff_version(bd),
        bd,
        (Capability.STRUCTURAL_DIFF,),
        reason=None if bd else "bindiff executable not found",
    )
    qpy = o.get("qbindiff") or os.environ.get("ACET_QBINDIFF_PYTHON")
    qver = _venv_dist_version(qpy, "qbindiff") if qpy and Path(qpy).is_file() else None
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
    from acet.platform.engine_packs import provider_status

    for info in providers.values():
        if info.available and not info.extra.get("replay"):
            status = provider_status(info.provider_id, info.version)
            info.verified = status == "validated"
            info.extra["compatibility"] = status
    providers["acet"] = ProviderInfo(
        "acet",
        True,
        _acet_version(),
        sys.executable,
        (Capability.SEMANTIC_FEATURES, Capability.REPORT_EXPORT),
        verified=True,
    )
    return EngineEnvironment(providers, pack_id)


_VERSION_CACHE: dict[tuple[str, float], str | None] = {}


def _bindiff_version(path: str | None) -> str | None:
    """Run the provider's own ``--version`` (a provider, never an analysed artifact); cached by mtime."""
    if not path or not Path(path).is_file():
        return None
    key = (path, Path(path).stat().st_mtime)
    if key not in _VERSION_CACHE:
        import subprocess

        try:
            out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15).stdout
            m = re.search(r"BinDiff\s+(\S+)", out)
            _VERSION_CACHE[key] = m.group(1) if m else None
        except (OSError, subprocess.TimeoutExpired):
            _VERSION_CACHE[key] = None
    return _VERSION_CACHE[key]


def _acet_version() -> str:
    import acet

    return acet.__version__

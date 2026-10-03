"""Processor registry and analysis profiles (spec §14, §15, §118, ACET-ANA-001, ACET-GHD-004).

A processor's identity is ``id@version``. Changing behaviour means bumping the
version, which invalidates (STALE) only that processor's results and their
descendants (ACET-ANA-003). Profiles are versioned: any parameter change
creates a new profile version (ACET-ANA-001).
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acet.domain.canonical import canonical_hash
from acet.domain.enums import Capability, DeterminismClass
from acet.domain.error_codes import AcetError

PE_FORMATS = ("PE32", "PE32+")


@dataclass(frozen=True)
class ProcessorSpec:
    id: str
    version: str
    scope: str  # "artifact" | "pair"
    entry: str  # "module:function" run inside the worker
    determinism: DeterminismClass
    depends_on: tuple[str, ...] = ()
    optional_deps: tuple[str, ...] = ()
    provider: str | None = None  # external engine needed, if any
    capabilities: tuple[Capability, ...] = ()
    formats: tuple[str, ...] | None = None  # None = any format
    heavy: bool = False
    experimental: bool = False
    feature_schema_version: int = 1
    disk_factor: float = 2.0  # estimate: output bytes ≈ factor × input bytes (calibrable)
    default_timeout_s: float = 600.0

    @property
    def key(self) -> str:
        return f"{self.id}@{self.version}"


D0, D1, D2, D3 = DeterminismClass.D0, DeterminismClass.D1, DeterminismClass.D2, DeterminismClass.D3

PROCESSORS: dict[str, ProcessorSpec] = {
    p.id: p
    for p in (
        ProcessorSpec("acet.hash", "1", "artifact", "acet.analysis.processors.fast:hash_facts", D0, disk_factor=0.01),
        ProcessorSpec(
            "acet.pe",
            "1",
            "artifact",
            "acet.analysis.processors.fast:pe_facts_processor",
            D0,
            formats=PE_FORMATS,
            disk_factor=0.5,
        ),
        ProcessorSpec("acet.strings", "1", "artifact", "acet.analysis.processors.fast:string_facts", D0, disk_factor=2),
        ProcessorSpec(
            "ghidra.extract",
            "1",
            "artifact",
            "acet.engines.ghidra:extract",
            D1,
            provider="ghidra",
            capabilities=(Capability.DISASSEMBLY, Capability.FUNCTION_EXTRACTION),
            formats=PE_FORMATS,
            heavy=True,
            disk_factor=40,
            default_timeout_s=1800,
        ),
        ProcessorSpec(
            "acet.features",
            "1",
            "artifact",
            "acet.analysis.processors.features:normalized_view",
            D0,
            depends_on=("ghidra.extract",),
            formats=PE_FORMATS,
            disk_factor=2,
        ),
        ProcessorSpec(
            "ghidriff.diff",
            "1",
            "pair",
            "acet.engines.ghidriff:diff",
            D1,
            provider="ghidriff",
            capabilities=(Capability.STRUCTURAL_DIFF,),
            formats=PE_FORMATS,
            heavy=True,
            disk_factor=60,
            default_timeout_s=3600,
        ),
        ProcessorSpec(
            "acet.featurematch",
            "2",
            "pair",
            "acet.matching.featurematch:match",
            D0,
            depends_on=("acet.features",),
            formats=PE_FORMATS,
            disk_factor=2,
        ),
        ProcessorSpec(
            "binexport.export",
            "1",
            "artifact",
            "acet.engines.bindiff:export",
            D1,
            provider="binexport",
            capabilities=(Capability.STRUCTURAL_DIFF,),
            formats=PE_FORMATS,
            heavy=True,
            disk_factor=40,
            default_timeout_s=1800,
        ),
        ProcessorSpec(
            "bindiff.diff",
            "1",
            "pair",
            "acet.engines.bindiff:diff",
            D1,
            provider="bindiff",
            depends_on=("binexport.export",),
            capabilities=(Capability.STRUCTURAL_DIFF,),
            formats=PE_FORMATS,
            heavy=True,
            disk_factor=10,
        ),
        ProcessorSpec(
            "qbindiff.diff",
            "1",
            "pair",
            "acet.engines.qbindiff_provider:diff",
            D2,
            provider="qbindiff",
            depends_on=("binexport.export",),
            capabilities=(Capability.PROGRAMMABLE_DIFF,),
            formats=PE_FORMATS,
            heavy=True,
            experimental=True,
            disk_factor=10,
        ),
        ProcessorSpec(
            "acet.consensus",
            "2",
            "pair",
            "acet.matching.consensus:consensus_processor",
            D0,
            depends_on=("acet.features",),
            optional_deps=("acet.featurematch", "ghidriff.diff", "bindiff.diff", "qbindiff.diff"),
            formats=PE_FORMATS,
            disk_factor=2,
        ),
    )
}


def resolve_entry(processor_id: str, version: str) -> Callable[[Any], Any]:
    spec = PROCESSORS.get(processor_id)
    if spec is None or spec.version != version:
        raise AcetError("ACET-UPD-001", f"processor {processor_id}@{version} not provided by this ACET")
    module, _, fn = spec.entry.partition(":")
    obj: Callable[[Any], Any] = getattr(importlib.import_module(module), fn)
    return obj


GHIDRA_ANALYZERS_DEFAULT: dict[str, bool] = {
    # ACET-GHD-004: the analyzer selection is part of the profile and of its hash.
    "Decompiler Parameter ID": False,
    "Decompiler Switch Analysis": True,
    "Aggressive Instruction Finder": False,
    "Windows x86 PE Exception Handling": True,
    "PDB Universal": False,  # symbols are optional enrichment (ACET-SYM-001); no remote fetch
}


@dataclass(frozen=True)
class Profile:
    name: str
    version: int
    processors: tuple[str, ...]
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> str:
        return f"{self.name}@{self.version}"

    def as_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            # Processor *implementation* versions are not profile parameters: they are tracked per
            # result (cache key, STALE). The profile identity is its processors + parameters (ACET-ANA-001).
            "processors": list(self.processors),
            "config": self.config,
        }

    @property
    def config_hash(self) -> str:
        return canonical_hash(self.as_json())

    def processor_config(self, processor_id: str) -> dict[str, Any]:
        cfg: dict[str, Any] = dict(self.config.get("processors", {}).get(processor_id, {}))
        return cfg


_FAST = ("acet.hash", "acet.pe", "acet.strings")
_STD = (*_FAST, "ghidra.extract", "acet.features", "ghidriff.diff", "acet.featurematch", "acet.consensus")
_DEEP = (*_STD, "binexport.export", "bindiff.diff", "qbindiff.diff")
_GHIDRA_CFG = {"analyzers": GHIDRA_ANALYZERS_DEFAULT, "soft_timeout_s": 1500, "hard_timeout_s": 1800}
_QBD_CFG = {"max_functions": 5000, "max_memory_bytes": 4 * 1024**3}  # conservative; calibrable (ACET-QBD-001)

PROFILES: dict[str, Profile] = {
    p.ref: p
    for p in (
        Profile("FAST", 1, _FAST),
        Profile("STANDARD", 1, _STD, {"processors": {"ghidra.extract": _GHIDRA_CFG}}),
        Profile("DEEP", 1, _DEEP, {"processors": {"ghidra.extract": _GHIDRA_CFG, "qbindiff.diff": _QBD_CFG}}),
        Profile(
            "RESEARCH",
            1,
            _DEEP,
            {
                "processors": {"ghidra.extract": _GHIDRA_CFG, "qbindiff.diff": _QBD_CFG},
                "keep_intermediates": True,
                "determinism_repeats": 2,
            },
        ),
        # v2 audit (ACET-BDF-001): BinDiff is official in DEEP@2 and optional in STANDARD@2 when installed.
        Profile(
            "STANDARD",
            2,
            (*_STD, "binexport.export", "bindiff.diff"),
            {"processors": {"ghidra.extract": _GHIDRA_CFG}, "optional_providers": ["binexport", "bindiff"]},
        ),
        Profile("DEEP", 2, _DEEP, {"processors": {"ghidra.extract": _GHIDRA_CFG, "qbindiff.diff": _QBD_CFG}}),
    )
}

# Processors whose absence must not degrade the run beyond missing_evidence (ACET-ANA-002).
OPTIONAL_PROCESSORS = frozenset({"ghidriff.diff", "binexport.export", "bindiff.diff", "qbindiff.diff", "acet.strings"})


def get_profile(ref: str) -> Profile:
    if "@" not in ref:
        candidates = sorted((p for p in PROFILES.values() if p.name == ref.upper()), key=lambda p: p.version)
        if candidates:
            return candidates[-1]
    p = PROFILES.get(ref.upper())
    if p is None:
        raise AcetError("ACET-PROF-001", f"unknown analysis profile {ref!r}; known: {sorted(PROFILES)}")
    return p

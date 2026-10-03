from __future__ import annotations

import ast
import json
import uuid
from pathlib import Path

import pytest

from acet.domain.cache import cache_key
from acet.domain.canonical import CanonicalJsonError, canonical_hash, canonical_json
from acet.domain.enums import ComponentPresence, ComponentRole, FailureFamily, OperationOutcome
from acet.domain.error_codes import CATALOG, AcetError, classify_exception
from acet.domain.fingerprint import ComponentEntry, build_fingerprint
from acet.domain.ids import is_sha256, is_uuid7, uuid7
from acet.domain.product_profile import ProductProfile
from acet.domain.state_machines import ALL_MACHINES, ANALYSIS_RUN, ARTIFACT, JOB, DomainTransitionError
from acet.domain.timeutil import TimePrecision, parse_external_timestamp

SRC = Path(__file__).resolve().parents[2] / "src" / "acet"
A = "a" * 64
B = "b" * 64


def test_uuid7_format_and_monotonic():
    ids = [uuid7() for _ in range(5000)]
    assert all(is_uuid7(i) for i in ids)
    assert ids == sorted(ids, key=lambda s: uuid.UUID(s).int)
    assert len(set(ids)) == len(ids)


def test_sha256_validation():
    assert is_sha256(A)
    assert not is_sha256(A.upper())
    assert not is_sha256(A[:-1])


@pytest.mark.acceptance("ACC-067")
def test_canonical_json_is_stable():
    a = {"b": 1, "a": [True, None, "é"], "c": {"y": 2, "x": 1}}
    b = {"c": {"x": 1, "y": 2}, "a": [True, None, "é"], "b": 1}
    assert canonical_json(a) == canonical_json(b) == b'{"a":[true,null,"\xc3\xa9"],"b":1,"c":{"x":1,"y":2}}'
    # NFC normalization: decomposed é == precomposed é
    assert canonical_hash({"k": "é"}) == canonical_hash({"k": "é"})


def test_canonical_json_rejects_floats_and_unknown_types():
    with pytest.raises(CanonicalJsonError):
        canonical_json({"x": 0.1})
    with pytest.raises(CanonicalJsonError):
        canonical_json({"x": object()})
    with pytest.raises(CanonicalJsonError):
        canonical_json({1: "x"})


@pytest.mark.acceptance("ACC-113")
def test_fingerprint_ignores_order_and_counts_duplicates():
    e1 = ComponentEntry(ComponentRole.KERNEL_DRIVER, A)
    e2 = ComponentEntry(ComponentRole.USER_MODULE, B)
    assert build_fingerprint([e1, e2]) == build_fingerprint([e2, e1])
    assert build_fingerprint([e1, e1, e2]) != build_fingerprint([e1, e2])
    assert build_fingerprint([e1]) != build_fingerprint([ComponentEntry(ComponentRole.OTHER, A)])
    with pytest.raises(ValueError):
        build_fingerprint([])


def test_fingerprint_matches_spec_formula():
    e = ComponentEntry(ComponentRole.KERNEL_DRIVER, A)
    expected = canonical_hash([{"role": "KERNEL_DRIVER", "artifact_sha256": A, "purpose": "primary", "ordinal": 0}])
    assert build_fingerprint([e]) == expected


def test_cache_key_depends_on_every_component():
    base = cache_key("ghidra.extract", "1.0", [A, B], A, 1)
    assert base == cache_key("ghidra.extract", "1.0", [A, B], A, 1)
    assert base != cache_key("ghidra.extract", "1.1", [A, B], A, 1)
    assert base != cache_key("ghidra.extract", "1.0", [B, A], A, 1)
    assert base != cache_key("ghidra.extract", "1.0", [A, B], B, 1)
    assert base != cache_key("ghidra.extract", "1.0", [A, B], A, 2)


@pytest.mark.acceptance("ACC-104")
def test_illegal_transition_rejected():
    ARTIFACT.walk(["HASHING", "COPYING", "VERIFYING", "AVAILABLE", "CORRUPTED"])
    with pytest.raises(DomainTransitionError):
        ARTIFACT.check("DISCOVERED", "AVAILABLE")
    with pytest.raises(DomainTransitionError):
        ANALYSIS_RUN.check("RUNNING", "COMPLETED")  # must go through VALIDATING
    with pytest.raises(DomainTransitionError):
        JOB.check("COMPLETED", "RUNNING")


def test_terminal_states_have_no_exit():
    for sm in ALL_MACHINES:
        assert sm.initial in sm.states
        for t in sm.terminal:
            assert not sm.allowed(t), (sm.name, t)


def test_error_catalog_complete_and_mapped():
    spec_codes = {
        "ACET-IMP-001",
        "ACET-IMP-002",
        "ACET-IMP-003",
        "ACET-STO-001",
        "ACET-STO-002",
        "ACET-DB-001",
        "ACET-DB-002",
        "ACET-GHD-001",
        "ACET-GHD-002",
        "ACET-GHD-003",
        "ACET-DIF-001",
        "ACET-DIF-002",
        "ACET-JOB-001",
        "ACET-JOB-002",
        "ACET-PACK-001",
        "ACET-UPD-001",
        "ACET-SEC-001",
        "ACET-REP-001",
    }
    assert spec_codes <= set(CATALOG)
    for spec in CATALOG.values():
        assert spec.summary and spec.impact and spec.action
        assert isinstance(spec.family, FailureFamily)
        assert isinstance(spec.outcome, OperationOutcome)


@pytest.mark.acceptance("ACC-102", "ACC-103")
def test_every_exception_maps_to_family_and_outcome():
    for exc in (
        ValueError("x"),
        FileNotFoundError(),
        PermissionError(),
        KeyError("k"),
        DomainTransitionError("JOB", "A", "B"),
        AcetError("ACET-STO-002"),
    ):
        err = classify_exception(exc)
        assert isinstance(err.family, FailureFamily)
        assert isinstance(err.outcome, OperationOutcome)
    assert classify_exception(KeyError("k")).outcome is OperationOutcome.INTERNAL_INVARIANT_VIOLATION
    assert AcetError("NOPE-999").code == "ACET-INT-001"


def test_external_timestamp_parsing():
    assert parse_external_timestamp("2026") == ("2026", TimePrecision.YEAR)
    assert parse_external_timestamp("2026-09") == ("2026-09", TimePrecision.MONTH)
    assert parse_external_timestamp("2026-09-01") == ("2026-09-01", TimePrecision.DAY)
    assert parse_external_timestamp("2026-09-01T12:00:00+02:00") == ("2026-09-01T10:00:00Z", TimePrecision.SECOND)
    with pytest.raises(ValueError):
        parse_external_timestamp("2026-09-01T12:00:00")  # naive: timezone unknown


@pytest.mark.acceptance("ACC-097")
def test_product_profile_is_declarative_only():
    ok = ProductProfile.parse({"schema_version": 2, "product_name": "X", "expected_roles": ["KERNEL_DRIVER"]})
    assert ok.expected_roles == (ComponentRole.KERNEL_DRIVER,)
    for bad in (
        {"schema_version": 2, "product_name": "X", "script": "import os"},
        {"schema_version": 2, "product_name": "X", "version_extractors": [{"fn": lambda: 1}]},
        {"schema_version": 3, "product_name": "X"},
        {"schema_version": 2, "product_name": "X", "expected_roles": ["NOT_A_ROLE"]},
        {"schema_version": 2, "product_name": "X", "expected_roles": "KERNEL_DRIVER"},
    ):
        with pytest.raises(AcetError) as ei:
            ProductProfile.parse(bad)
        assert ei.value.code == "ACET-PROF-001"


@pytest.mark.acceptance("ACC-047", "ACC-017")
def test_unobserved_expected_component_is_unknown_not_absent():
    prof = ProductProfile.parse(
        {"schema_version": 2, "product_name": "X", "expected_roles": ["KERNEL_DRIVER", "SERVICE"]}
    )
    res = prof.completeness({ComponentRole.KERNEL_DRIVER})
    assert res == {
        ComponentRole.KERNEL_DRIVER: ComponentPresence.PRESENT,
        ComponentRole.SERVICE: ComponentPresence.UNKNOWN,
    }
    assert "ABSENT" not in {v.value for v in ComponentPresence}


def _imports(path: Path) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_domain_is_pure_and_headless():
    """ACET-ARCH-001: no Qt anywhere outside acet.ui; the domain does no storage I/O."""
    for py in SRC.rglob("*.py"):
        if "ui" in py.relative_to(SRC).parts:
            continue
        assert not any(m.startswith("PySide6") for m in _imports(py)), py
    for py in (SRC / "domain").rglob("*.py"):
        assert not ({"sqlite3", "shutil", "subprocess"} & _imports(py)), py


@pytest.mark.acceptance("ACC-041")
def test_core_has_no_product_specific_branch():
    """ACET-PROD-003: no hard-coded anti-cheat product in the Core."""
    banned = ("battleye", "easyanticheat", "easy anti-cheat", "vanguard", "eac.sys", "bedaisy")
    for py in SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8").lower()
        for word in banned:
            assert word not in text, f"{word!r} in {py}"


@pytest.mark.acceptance("ACC-004")
def test_no_execution_primitives_in_core():
    """ACET-SEC-001 / INV-003 (static half): import paths never spawn processes or load code.
    Engine adapters (acet.engines, acet.jobs) will spawn *providers*, never artifacts."""
    banned_modules = {"subprocess", "ctypes", "importlib.machinery", "runpy", "multiprocessing"}
    for py in SRC.rglob("*.py"):
        rel = py.relative_to(SRC).parts
        if rel[0] in ("engines", "jobs"):
            continue
        mods = _imports(py)
        assert not (mods & banned_modules), (py, mods & banned_modules)
        text = py.read_text(encoding="utf-8")
        for call in ("os.system(", "os.startfile(", "os.exec", "os.spawn", "eval(", "exec("):
            assert call not in text, (py, call)


def test_json_schemas_are_valid_json():
    root = Path(__file__).resolve().parents[2] / "schemas" / "v1"
    files = list(root.glob("*.schema.json"))
    assert files
    for f in files:
        doc = json.loads(f.read_text(encoding="utf-8"))
        assert doc["$schema"].startswith("https://json-schema.org/")
        assert doc.get("$id") and doc.get("title")

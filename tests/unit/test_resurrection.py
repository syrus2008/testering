"""resurrect@2 decision rule: graded claims, contradictions veto, uniqueness (ACET-LIN-002)."""

from __future__ import annotations

import copy
from typing import Any

from acet.lineage.resurrection import Assessment, Context, assess, resolve


def feat(
    *,
    nhash: str = "h-A",
    count: int = 35,
    mnemonics: dict[str, int] | None = None,
    cfg: tuple[str | None, int, int, int] = ("cfg-A", 6, 8, 4),
    consts: list[int] | None = None,
    strings: list[str] | None = None,
    name: str | None = None,
    name_source: str = "DEFAULT",
) -> dict[str, Any]:
    return {
        "entry": 0x1000,
        "size": count * 3,
        "instruction": {
            "normalized_hash": nhash,
            "count": count,
            "mnemonics": mnemonics or {"MOV": 10, "XOR": 6, "IMUL": 4, "CALL": 3, "CMP": 4, "JNZ": 4, "ADD": 4},
        },
        "cfg": {"hash": cfg[0], "blocks": cfg[1], "edges": cfg[2], "cyclomatic": cfg[3]},
        "callgraph": {"callers": [0x2000], "callees": [0x3000], "imports": [], "callee_names": []},
        "data": {"constants": consts if consts is not None else [0xA5C3, 0x9E3779B9, 0x1F2E], "strings": strings or []},
        "identity": {"name": name, "name_source": name_source},
    }


CTX = Context(old_caller_lineages=frozenset({"L-run"}), new_caller_lineages=frozenset({"L-run"}))
NO_CTX = Context(old_caller_lineages=frozenset({"L-run"}), new_caller_lineages=frozenset({"L-flush"}))


def test_identical_function_back_in_its_old_context_is_confirmed():
    a = assess(feat(), feat(), CTX)
    assert a.status == "CONFIRMED" and a.code == "exact" and {"context", "data"} <= set(a.supports)


def test_recompiled_function_needs_converging_families():
    recompiled = feat(
        nhash="h-A2",
        count=38,
        mnemonics={"MOV": 11, "XOR": 6, "IMUL": 4, "CALL": 3, "CMP": 4, "JNZ": 4, "ADD": 5, "PUSH": 1},
        cfg=("cfg-A2", 6, 8, 4),
    )
    a = assess(feat(), recompiled, CTX)
    assert a.status == "CONFIRMED" and a.code == "similar" and {"context", "data"} <= set(a.supports)
    # Same code change, but the data references are gone: only code + context remain → hypothesis.
    a = assess(feat(), {**recompiled, "data": {"constants": [], "strings": []}}, CTX)
    assert a.status == "CANDIDATE"


def test_lookalike_is_never_merged():
    # Same normalized code (normalization strips constants) and same callee, different constants.
    lookalike = feat(consts=[0x3C5A, 0x7F4A7C15, 0x2E1F])
    a = assess(feat(), lookalike, CTX)
    assert a.status == "REJECTED" and "data" in a.contradicts
    # Even with identical code AND constants, a function nothing that used to call it calls
    # (a copied routine) is at most a hypothesis.
    a = assess(feat(), feat(), NO_CTX)
    assert a.status == "CANDIDATE" and "context" not in a.supports


def test_name_contradiction_vetoes():
    a = assess(
        feat(name="audit_record", name_source="IMPORTED"), feat(name="trace_record", name_source="IMPORTED"), CTX
    )
    assert a.status == "REJECTED" and "name" in a.contradicts
    # Tool default names (FUN_xxx) are not evidence either way.
    a = assess(feat(name="FUN_1000"), feat(name="FUN_2000"), CTX)
    assert a.status == "CONFIRMED" and "name" not in a.supports + a.contradicts


def test_trivial_code_is_not_code_evidence():
    stub = feat(count=5, consts=[1, 2])
    a = assess(stub, copy.deepcopy(stub), CTX)
    assert a.code is None and a.status == "CANDIDATE"


def test_rollback_event_supports_but_never_suffices():
    changed = feat(nhash="other", mnemonics={"PUSH": 9, "POP": 9, "RET": 1}, cfg=("x", 1, 0, 1), consts=[])
    rb = Context(rollback_event="evt-1")
    assert assess(feat(), changed, rb).status == "REJECTED"
    similar_no_data = feat(nhash="h-A2", consts=[])
    ctx_rb = Context(
        old_caller_lineages=frozenset({"L-run"}), new_caller_lineages=frozenset({"L-run"}), rollback_event="evt-1"
    )
    assert assess(feat(consts=[]), similar_no_data, CTX).status == "CANDIDATE"
    assert assess(feat(consts=[]), similar_no_data, ctx_rb).status == "CONFIRMED"


def test_ambiguous_pairings_are_not_confirmed():
    def conf(score: float) -> Assessment:
        return Assessment(status="CONFIRMED", score=score, code="exact", supports=["context", "data"])

    # Two returning functions claim the same historical lineage with nearly equal scores.
    out = resolve({("R1", "L"): conf(0.97), ("R2", "L"): conf(0.95)})
    assert list(out) == [("R1", "L")] and out[("R1", "L")].status == "CANDIDATE"
    # A clear winner stays confirmed; the loser gets no claim on that lineage.
    out = resolve({("R1", "L"): conf(0.99), ("R2", "L"): conf(0.80)})
    assert out == {("R1", "L"): out[("R1", "L")]} and out[("R1", "L")].status == "CONFIRMED"
    # Rejected pairings never take a slot.
    rej = Assessment(status="REJECTED", score=1.0, code="exact")
    assert resolve({("R1", "L"): rej}) == {}

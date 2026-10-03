"""ACET built-in feature matcher (engine ``acet.featurematch@1``).

Deterministic (D0). Produces the normalized matcher DTO consumed by consensus.
Its raw score is engine-internal (a fixed, calibrable weighting of its own
families); consensus never averages engines (ACET-MAT-002). Engine decisions are
classes, not probabilities (ADR-0008).
"""

from __future__ import annotations

import math
from typing import Any

from acet.engines.worker import WorkerContext

ENGINE = "acet.featurematch"
ENGINE_VERSION = "2"
WEIGHTS = {"instruction": 0.35, "cfg": 0.25, "callgraph": 0.15, "data-reference": 0.15, "identity": 0.10}  # calibrable
STRONG, PROBABLE, MARGIN = 0.85, 0.60, 0.05  # calibrable


def _cos(a: dict[str, int], b: dict[str, int]) -> float:
    keys = set(a) | set(b)
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def _ratio(x: float, y: float) -> float:
    return 1.0 - abs(x - y) / max(x, y, 1)


def _jac(a: set[Any], b: set[Any]) -> float | None:
    if not a and not b:
        return None
    return len(a & b) / len(a | b)


def family_scores(lf: dict[str, Any], r: dict[str, Any], matched: dict[int, int]) -> dict[str, float | None]:
    li, ri = lf["instruction"], r["instruction"]
    if li["normalized_hash"] and li["normalized_hash"] == ri["normalized_hash"]:
        ins = 1.0
    else:
        ins = _cos(li["mnemonics"], ri["mnemonics"]) * _ratio(li["count"], ri["count"]) ** 0.5
    lc, rc = lf["cfg"], r["cfg"]
    cfg = (
        1.0
        if lc["hash"] and lc["hash"] == rc["hash"]
        else (
            _ratio(lc["blocks"], rc["blocks"])
            + _ratio(lc["edges"], rc["edges"])
            + _ratio(lc["cyclomatic"], rc["cyclomatic"])
        )
        / 3
        * 0.9
    )
    lg, rg = lf["callgraph"], r["callgraph"]
    targets = set(matched.values())
    lset = {matched[c] for c in lg["callees"] if c in matched}
    rset = {c for c in rg["callees"] if c in targets}
    cg_sets = _jac(
        lset | {f"imp:{x}" for x in lg["imports"]} | {f"n:{x}" for x in lg["callee_names"]},
        rset | {f"imp:{x}" for x in rg["imports"]} | {f"n:{x}" for x in rg["callee_names"]},
    )
    deg = (_ratio(len(lg["callees"]), len(rg["callees"])) + _ratio(len(lg["callers"]), len(rg["callers"]))) / 2
    cg = deg if cg_sets is None else (cg_sets + deg) / 2
    data = _jac(
        set(lf["data"]["strings"]) | {str(c) for c in lf["data"]["constants"]},
        set(r["data"]["strings"]) | {str(c) for c in r["data"]["constants"]},
    )
    ln, rn = lf["identity"]["name"], r["identity"]["name"]
    ident = None if not (ln and rn) else (1.0 if ln == rn else 0.0)
    return {
        "instruction": round(ins, 4),
        "cfg": round(cfg, 4),
        "callgraph": round(cg, 4),
        "data-reference": None if data is None else round(data, 4),
        "identity": ident,
    }


def raw_score(fam: dict[str, float | None]) -> float:
    num = sum(WEIGHTS[k] * v for k, v in fam.items() if v is not None)
    den = sum(WEIGHTS[k] for k, v in fam.items() if v is not None)
    return round(num / den, 4) if den else 0.0


def _evidence(fam: dict[str, float | None]) -> list[dict[str, Any]]:
    return [{"family": k, "score": v, "supports": v >= 0.5} for k, v in sorted(fam.items()) if v is not None]


def _compatible(lf: dict[str, Any], r: dict[str, Any]) -> bool:
    a, b = int(lf["instruction"]["count"]), int(r["instruction"]["count"])
    return bool(min(a, b) * 3 >= max(a, b) or abs(a - b) <= 4)


def match_features(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    L = {f["entry"]: f for f in left["functions"]}
    R = {f["entry"]: f for f in right["functions"]}
    matched: dict[int, int] = {}
    pairs: dict[int, dict[str, Any]] = {}

    # 1) EXACT: unique normalized hash on both sides (rule normalized-hash-unique@1)
    def index(fs: dict[int, dict[str, Any]]) -> dict[str, list[int]]:
        out: dict[str, list[int]] = {}
        for e, f in fs.items():
            if f["instruction"]["normalized_hash"]:
                out.setdefault(f["instruction"]["normalized_hash"], []).append(e)
        return out

    li, ri = index(L), index(R)
    for h, ls in sorted(li.items()):
        rs = ri.get(h, [])
        if len(ls) == 1 and len(rs) == 1 and L[ls[0]]["instruction"]["count"] >= 3:
            matched[ls[0]] = rs[0]
    # 2) identity: same non-default symbol name
    rnames = {f["identity"]["name"]: e for e, f in R.items() if f["identity"]["name"]}
    for e, f in sorted(L.items()):
        n = f["identity"]["name"]
        if e not in matched and n and n in rnames and rnames[n] not in matched.values():
            matched[e] = rnames[n]
    exact_rule = {
        e for e in matched if L[e]["instruction"]["normalized_hash"] == R[matched[e]]["instruction"]["normalized_hash"]
    }

    candidates: dict[int, list[tuple[int, float]]] = {}
    for rnd in (1, 2):  # round 2 benefits from call-graph propagation of round-1 matches
        free_l = [e for e in sorted(L) if e not in matched]
        free_r = {e for e in R if e not in matched.values()}
        scored: list[tuple[float, int, int, dict[str, float | None]]] = []
        for le in free_l:
            row = []
            for re_ in sorted(free_r):
                if not _compatible(L[le], R[re_]):
                    continue
                fam = family_scores(L[le], R[re_], matched)
                s = raw_score(fam)
                row.append((re_, s))
                scored.append((s, le, re_, fam))
            candidates[le] = sorted(row, key=lambda x: (-x[1], x[0]))[:3]
        threshold = STRONG if rnd == 1 else PROBABLE
        used_r: set[int] = set()
        for s, le, re_, _fam in sorted(scored, key=lambda x: (-x[0], x[1], x[2])):
            if s < threshold or le in matched or re_ in used_r or re_ in matched.values():
                continue
            matched[le] = re_
            used_r.add(re_)

    for le, re_ in sorted(matched.items()):
        fam = family_scores(L[le], R[re_], matched)
        s = 1.0 if le in exact_rule else raw_score(fam)
        alts = [c for c in candidates.get(le, []) if c[0] != re_]
        if le in exact_rule:
            decision = "EXACT"
        elif alts and s - alts[0][1] < MARGIN and s < STRONG:
            decision = "AMBIGUOUS"
        elif s >= STRONG:
            decision = "STRONG"
        elif s >= PROBABLE:
            decision = "PROBABLE"
        else:
            decision = "UNRESOLVED"
        pairs[le] = {
            "left": le,
            "right": re_,
            "raw_score": s,
            "decision": decision,
            "rule": "normalized-hash-unique@1" if le in exact_rule else None,
            "evidence": _evidence(fam),
            "alternatives": [[a, b] for a, b in alts[:2]],
        }
    unmatched_left = []
    for e in sorted(L):
        if e in matched:
            continue
        cands = sorted(
            ((re_, raw_score(family_scores(L[e], R[re_], matched))) for re_ in R if _compatible(L[e], R[re_])),
            key=lambda x: (-x[1], x[0]),
        )[:3]
        unmatched_left.append({"left": e, "candidates": [[a, b] for a, b in cands]})
    mr = set(matched.values())
    unmatched_right = []
    for e in sorted(R):
        if e in mr:
            continue
        cands = sorted(
            ((le, raw_score(family_scores(L[le], R[e], matched))) for le in L if _compatible(L[le], R[e])),
            key=lambda x: (-x[1], x[0]),
        )[:3]
        unmatched_right.append({"right": e, "candidates": [[a, b] for a, b in cands]})
    return {
        "engine": ENGINE,
        "engine_version": ENGINE_VERSION,
        "families_used": ["identity", "instruction", "cfg", "callgraph", "data-reference"],
        "pairs": [pairs[k] for k in sorted(pairs)],
        "unmatched_left": unmatched_left,
        "unmatched_right": unmatched_right,
    }


def match(ctx: WorkerContext) -> dict[str, Any]:
    lay = ctx.layout()["derived"]
    left = ctx.derived(lay.index("acet.features@left"))
    right = ctx.derived(lay.index("acet.features@right"))
    res = match_features(left, right)
    ctx.count("pairs", len(res["pairs"]))
    return res

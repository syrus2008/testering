"""Consensus by evidence families (spec §21, ACET-MAT-002/003, ACC-015/049). Rules ``consensus@1``.

* Engines sharing an evidence family are NOT independent: diversity counts
  distinct supporting families, reported separately from the engine count.
* No arithmetic mean of engine scores. Raw engine outputs are untouched.
* Output classes, never probabilities, unless a validated calibration for the
  context is provided (ADR-0008) — V1 consensus is uncalibrated.
* An unmatched function is UNRESOLVED (``right: null``), never "new".
"""

from __future__ import annotations

from typing import Any

from acet.engines.worker import WorkerContext

RULES = "consensus@1"
RANK = {"EXACT": 5, "STRONG": 4, "PROBABLE": 3, "AMBIGUOUS": 2, "CONFLICT": 1, "UNRESOLVED": 0, "ABSTAIN": 0}
STRENGTH = {
    "EXACT": "HIGH",
    "STRONG": "HIGH",
    "PROBABLE": "MEDIUM",
    "AMBIGUOUS": "LOW",
    "CONFLICT": "LOW",
    "UNRESOLVED": "LOW",
    "ABSTAIN": "UNKNOWN",
}
ALL_FAMILIES = ["identity", "instruction", "cfg", "callgraph", "data-reference", "semantic", "historical-lineage"]


def _supporting(p: dict[str, Any]) -> set[str]:
    return {e["family"] for e in p.get("evidence", []) if e.get("supports")}


def consensus(
    left_feat: dict[str, Any], right_feat: dict[str, Any], matchers: list[dict[str, Any]], expected_engines: list[str]
) -> dict[str, Any]:
    engines = [m["engine"] for m in matchers]
    measured_families = sorted({f for m in matchers for f in m.get("families_used", [])})
    missing_engines = sorted(set(expected_engines) - set(engines))
    missing_families = [f for f in ALL_FAMILIES if f not in measured_families]
    proposals: dict[int, list[tuple[str, dict[str, Any]]]] = {}
    explicit_unmatched: dict[int, list[str]] = {}
    left_candidates: dict[int, set[tuple[int, float]]] = {}
    for m in matchers:
        for u in m.get("unmatched_left", []):
            for c in u.get("candidates", []):
                if c[1] is not None:
                    left_candidates.setdefault(u["left"], set()).add((c[0], c[1]))
    for m in matchers:
        for p in m["pairs"]:
            if p["decision"] in ("UNRESOLVED", "ABSTAIN") or p.get("right") is None:
                continue
            proposals.setdefault(p["left"], []).append((m["engine"], p))
        for u in m.get("unmatched_left", []):
            explicit_unmatched.setdefault(u["left"], []).append(m["engine"])

    out: list[dict[str, Any]] = []
    claimed: dict[int, list[int]] = {}
    for f in left_feat["functions"]:
        le = f["entry"]
        props = proposals.get(le, [])
        if not props:
            out.append(
                {
                    "left": le,
                    "right": None,
                    "decision": "UNRESOLVED",
                    "strength_class": "LOW",
                    "evidence_diversity": 0,
                    "engine_count": 0,
                    "supporting_evidence": [],
                    "contradicting_evidence": [
                        {"engine": e, "claim": "no counterpart"} for e in sorted(explicit_unmatched.get(le, []))
                    ],
                    "missing_evidence": missing_families,
                    "notes": ["no engine proposed a counterpart"],
                    "candidates": [
                        list(c) for c in sorted(left_candidates.get(le, set()), key=lambda x: (-x[1], x[0]))[:3]
                    ],
                }
            )
            continue
        by_right: dict[int, list[tuple[str, dict[str, Any]]]] = {}
        for eng, p in props:
            by_right.setdefault(p["right"], []).append((eng, p))

        def support(r: int, by_right: dict[int, list[tuple[str, dict[str, Any]]]] = by_right) -> tuple[int, int, int]:
            fams = set().union(*(_supporting(p) for _, p in by_right[r]))
            return len(fams), len(by_right[r]), max(RANK[p["decision"]] for _, p in by_right[r])

        ranked = sorted(by_right, key=lambda r: (support(r), -r), reverse=True)
        best = ranked[0]
        fams = sorted(set().union(*(_supporting(p) for _, p in by_right[best])))
        diversity, n_eng, best_rank = support(best)
        contra = [
            {"engine": eng, "right": r, "families": sorted(_supporting(p)), "decision": p["decision"]}
            for r in ranked[1:]
            for eng, p in by_right[r]
        ]
        contra += [{"engine": e, "claim": "no counterpart"} for e in sorted(explicit_unmatched.get(le, []))]
        strong_contra = [r for r in ranked[1:] if support(r)[0] >= 2]
        notes: list[str] = []
        if strong_contra:
            decision = "CONFLICT"
        elif len(ranked) > 1 and support(ranked[1])[:2] == (diversity, n_eng):
            decision = "AMBIGUOUS"
        elif any(p["decision"] == "EXACT" for _, p in by_right[best]):
            decision = "EXACT"
        elif any(p["decision"] == "AMBIGUOUS" for _, p in by_right[best]) and n_eng == 1:
            decision = "AMBIGUOUS"
        elif diversity >= 3 and not contra:
            decision = "STRONG"
        elif diversity >= 2 or best_rank >= RANK["STRONG"]:
            decision = "PROBABLE"
        else:
            decision = "UNRESOLVED"
            notes.append("single weak evidence family")
        claimed.setdefault(best, []).append(le)
        out.append(
            {
                "left": le,
                "right": best,
                "decision": decision,
                "strength_class": STRENGTH[decision],
                "evidence_diversity": diversity,
                "engine_count": n_eng,
                "supporting_evidence": [
                    {
                        "engine": eng,
                        "decision": p["decision"],
                        "raw_score": p.get("raw_score"),
                        "families": sorted(_supporting(p)),
                        "rule": p.get("rule"),
                    }
                    for eng, p in sorted(by_right[best], key=lambda x: x[0])
                ],
                "supporting_families": fams,
                "contradicting_evidence": contra,
                "missing_evidence": missing_families,
                "alternatives": [a for _, p in by_right[best] for a in p.get("alternatives", [])][:3],
                "notes": notes,
            }
        )
    # Several lefts claiming the same right: merge candidates, never silently dropped.
    for r, ls in claimed.items():
        if len(ls) > 1:
            for item in out:
                if item["right"] == r:
                    item["merge_candidate"] = True
                    if item["decision"] in ("PROBABLE", "STRONG"):
                        item["decision"], item["strength_class"] = "AMBIGUOUS", "LOW"
                        item["notes"].append("right function claimed by several left functions")
    taken = {i["right"] for i in out if i["right"] is not None}
    unmatched_right = []
    for f in right_feat["functions"]:
        if f["entry"] in taken:
            continue
        cands = sorted(
            {
                tuple(c)
                for m in matchers
                for u in m.get("unmatched_right", [])
                if u["right"] == f["entry"]
                for c in u.get("candidates", [])
            },
            key=lambda x: (-x[1], x[0]),
        )[:3]
        unmatched_right.append(
            {
                "right": f["entry"],
                "decision": "UNRESOLVED",
                "candidates": [list(c) for c in cands],
                "notes": ["unmatched is not new (spec §2)"],
            }
        )
    counts: dict[str, int] = {}
    for i in out:
        counts[i["decision"]] = counts.get(i["decision"], 0) + 1
    return {
        "rules": RULES,
        "calibration_profile_id": None,
        "probability_available": False,
        "engines": sorted(engines),
        "missing_engines": missing_engines,
        "measured_families": measured_families,
        "matches": out,
        "unmatched_right": unmatched_right,
        "decision_counts": dict(sorted(counts.items())),
    }


def consensus_processor(ctx: WorkerContext) -> dict[str, Any]:
    lay = ctx.layout()["derived"]
    left = ctx.derived(lay.index("acet.features@left"))
    right = ctx.derived(lay.index("acet.features@right"))
    matchers = [ctx.derived(i) for i, name in enumerate(lay) if not name.startswith("acet.features")]
    expected = list(ctx.config.get("expected_engines", ["acet.featurematch", "ghidriff"]))
    res = consensus(left, right, matchers, expected)
    ctx.count("matches", len(res["matches"]))
    return res

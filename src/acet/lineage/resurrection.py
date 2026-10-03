"""Resurrection of a lineage (rule ``resurrect@2``, spec §22, ACET-LIN-002).

A function that disappeared from a product may come back. Re-attaching it to its historical
lineage is a strong claim: a wrong re-attachment silently merges two different functions'
histories (a purity error), which is worse than leaving history fragmented. The rule therefore
grades the claim instead of thresholding one score:

* ``CONFIRMED`` — the returning function continues the *historical* lineage. Requires
  independent evidence families that converge, no contradicting family, and a unique
  (mutual-best, separated) pairing.
* ``CANDIDATE`` — a recorded hypothesis: a *new* lineage linked to the historical one by a
  ``RESURRECTED_CANDIDATE`` link. Nothing is merged.
* ``REJECTED`` — no claim (a contradiction, or not enough resemblance).

Independent families (engines/features sharing a family are not independent, §21):

=========  ===========================================================================
code       ``exact``: identical normalized instructions, non-trivial size;
           ``similar``: matcher instruction+CFG score at or above the STRONG class
data       strings/constants of a non-trivial set: Jaccard ≥ DATA_SUPPORT (supports),
           both sides non-trivial and Jaccard < DATA_CONTRADICT (contradicts)
context    at least one *caller* of the returning function belongs to a lineage that called
           the function at its last appearance (callees alone are weak: shared helpers)
name       real symbol names (not tool defaults): equal supports, different contradicts
rollback   a recorded external ROLLBACK event between disappearance and return
           (supporting only; never sufficient alone, events are capped evidence)
=========  ===========================================================================

Confirmation requires caller ``context`` (a returning function that nothing that used to call
it calls is, at best, a hypothesis: identical code and data are not rare — a copied routine with
the same constants is indistinguishable by content alone), plus ``code=exact`` (context is
then the second family), or ``code=similar`` and one more supporting family. Candidate: ``code`` in {exact, similar} or the matcher's raw score at or
above ``RESURRECT_MIN``, or data *and* context both supporting (the code changed too much to
be compared, but the function is plausibly the same). Any contradiction rejects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from acet.matching.featurematch import STRONG, family_scores, raw_score

RULE = "resurrect@2"
RESURRECT_MIN = 0.75  # matcher raw score for a candidate (calibrable; unchanged from resurrect@1)
MIN_EXACT_INSNS = 8  # identical code shorter than this is too common to identify a function
DATA_MIN_ITEMS = 2
DATA_SUPPORT = 0.8
DATA_CONTRADICT = 0.3
MARGIN = 0.05  # best pairing must beat the runner-up by this much to be confirmed
DEFAULT_NAME_SOURCES = {"DEFAULT", None, ""}


@dataclass(frozen=True)
class Context:
    """Neighbourhood facts the lineage builder computes (lineage ids, not addresses)."""

    old_caller_lineages: frozenset[str] = frozenset()
    new_caller_lineages: frozenset[str] = frozenset()
    rollback_event: str | None = None  # id of a qualifying ROLLBACK event, if any


@dataclass
class Assessment:
    status: str  # CONFIRMED | CANDIDATE | REJECTED
    score: float
    code: str | None  # exact | similar | None
    supports: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def evidence(self) -> dict[str, Any]:
        return {
            "rule": RULE,
            "status": self.status,
            "matcher_score": self.score,
            "code": self.code,
            "supporting_families": sorted(self.supports),
            "contradicting_families": sorted(self.contradicts),
            "reasons": self.reasons,
        }


def _data_items(f: dict[str, Any]) -> set[str]:
    return set(f["data"]["strings"]) | {str(c) for c in f["data"]["constants"]}


def _real_name(f: dict[str, Any]) -> str | None:
    ident = f.get("identity") or {}
    return ident.get("name") if ident.get("name_source") not in DEFAULT_NAME_SOURCES else None


def assess(old: dict[str, Any], new: dict[str, Any], ctx: Context) -> Assessment:
    """Grade the claim "``new`` is ``old`` back again" from two feature records."""
    fam = family_scores(old, new, {})
    score = raw_score(fam)
    a = Assessment(status="REJECTED", score=score, code=None)

    li, ri = old["instruction"], new["instruction"]
    trivial = min(int(li["count"]), int(ri["count"])) < MIN_EXACT_INSNS
    if trivial:
        # Stubs, thunks and accessors look alike everywhere: no code evidence either way.
        a.reasons.append(f"trivial code ({li['count']}/{ri['count']} instructions): code not used as evidence")
    elif li["normalized_hash"] and li["normalized_hash"] == ri["normalized_hash"]:
        a.code = "exact"
    else:
        code_score = (0.35 * float(fam["instruction"] or 0) + 0.25 * float(fam["cfg"] or 0)) / 0.60
        if code_score >= STRONG:
            a.code = "similar"
        else:
            a.reasons.append(f"code differs (instruction+cfg {code_score:.2f} < {STRONG})")

    od, nd = _data_items(old), _data_items(new)
    if len(od) >= DATA_MIN_ITEMS and len(nd) >= DATA_MIN_ITEMS:
        jac = len(od & nd) / len(od | nd)
        if jac >= DATA_SUPPORT:
            a.supports.append("data")
        elif jac < DATA_CONTRADICT:
            a.contradicts.append("data")
            a.reasons.append(f"data references differ (Jaccard {jac:.2f})")
    on, nn = _real_name(old), _real_name(new)
    if on and nn:
        (a.supports if on == nn else a.contradicts).append("name")
    shared = ctx.old_caller_lineages & ctx.new_caller_lineages
    if shared:
        a.supports.append("context")
    elif ctx.old_caller_lineages and ctx.new_caller_lineages:
        a.reasons.append("no caller continuity")
    if ctx.rollback_event:
        a.supports.append("rollback")

    if a.contradicts:
        return a  # REJECTED: never propose what an independent family contradicts
    others = len(a.supports)
    if "context" in a.supports and ((a.code == "exact" and others >= 1) or (a.code == "similar" and others >= 2)):
        a.status = "CONFIRMED"
    elif a.code is not None or score >= RESURRECT_MIN or {"data", "context"} <= set(a.supports):
        a.status = "CANDIDATE"
    return a


def resolve(pairs: dict[tuple[str, str], Assessment]) -> dict[tuple[str, str], Assessment]:
    """Keep at most one claim per returning function and per historical lineage.

    ``pairs`` maps (new function id, old lineage id) → assessment. A CONFIRMED claim survives
    only if it is the mutual best by score with a margin over every runner-up on both sides;
    otherwise it is downgraded to CANDIDATE (the ambiguity is itself recorded)."""
    live = {k: v for k, v in pairs.items() if v.status != "REJECTED"}
    out: dict[tuple[str, str], Assessment] = {}
    used_new: set[str] = set()
    used_old: set[str] = set()
    rank = {"CONFIRMED": 2, "CANDIDATE": 1}
    for (nf, ol), a in sorted(live.items(), key=lambda kv: (-rank[kv[1].status], -kv[1].score, kv[0])):
        if nf in used_new or ol in used_old:
            continue
        if a.status == "CONFIRMED":
            rivals = [v.score for (n2, o2), v in live.items() if (n2 == nf) != (o2 == ol)]
            if rivals and a.score - max(rivals) < MARGIN:
                a.status = "CANDIDATE"
                a.reasons.append(f"ambiguous: a rival pairing scores within {MARGIN}")
        out[(nf, ol)] = a
        used_new.add(nf)
        used_old.add(ol)
    return out

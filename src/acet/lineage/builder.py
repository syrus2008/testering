"""Function lineage across builds (spec §22, ACET-LIN-001/002, ACC-018/019).

A lineage run is an Analysis Run (scope ``lineage``) over an ordered build
sequence of one product. It reads consensus results of consecutive build pairs
and writes assignments bound to the run. Previous runs are never modified;
adding a build creates a new lineage run that carries the previous assignments
forward (copy, no re-matching) and only computes the new transition.

Relations:
* CONTINUATION — EXACT/STRONG consensus with identical normalized code
* MODIFIED — STRONG/PROBABLE consensus with changed code
* SPLIT_PARENT — a left function continues and an unmatched right function's best
  candidate is that same left function (lineage_link SPLIT_PARENT)
* MERGE_PARENT — several left functions claim the same right function
* DISAPPEARED — the lineage has no instance in this build (marker on last instance)
* RESURRECTED_CANDIDATE — an unmatched right function equals (normalized hash) the last
  instance of a lineage that disappeared earlier
* UNRESOLVED — unmatched right function: a new lineage with unresolved origin (never "new")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import acet
from acet.application.workspace import Workspace
from acet.domain.canonical import canonical_hash, stable_json
from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.domain.timeutil import utc_now_iso
from acet.storage import repositories as repo

RULES = "lineage@1"
JOIN_DECISIONS = ("EXACT", "STRONG", "PROBABLE")
SPLIT_MIN = 0.40  # calibrable
MERGE_MIN = 0.60  # calibrable
RESURRECT_MIN = 0.75  # calibrable


@dataclass
class LineageSummary:
    run_id: str
    builds: list[str]
    lineages: int
    relations: dict[str, int]
    carried_forward: int
    missing_pairs: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "builds": self.builds,
            "lineages": self.lineages,
            "relations": self.relations,
            "carried_forward": self.carried_forward,
            "missing_pairs": [list(p) for p in self.missing_pairs],
        }


def _advance(tx: Any, run_id: str, *states: str) -> None:
    from acet.domain.state_machines import ANALYSIS_RUN

    cur = tx.execute("SELECT status FROM analysis_run WHERE id=?", (run_id,)).fetchone()["status"]
    for st in states:
        cur = ANALYSIS_RUN.check(cur, st)
    tx.execute("UPDATE analysis_run SET status=? WHERE id=?", (cur, run_id))


def ordered_builds(ws: Workspace, product_id: str) -> list[str]:
    """Order: first observation date, then release label, then causal creation order (ACET-TIME-001)."""
    rows = ws.db.conn.execute(
        "SELECT b.id, (SELECT min(observed_at) FROM observation o WHERE o.build_id=b.id) AS first_obs,"
        " r.version_label, b.rowid AS rid FROM build b LEFT JOIN release r ON r.id=b.release_id"
        " WHERE b.product_id=? AND b.deleted_at IS NULL",
        (product_id,),
    ).fetchall()
    return [r["id"] for r in sorted(rows, key=lambda r: (r["first_obs"] or "9999", r["version_label"] or "", r["rid"]))]


def latest_compare_run(ws: Workspace, left: str, right: str) -> str | None:
    row = ws.db.conn.execute(
        "SELECT id FROM analysis_run WHERE scope_type='compare' AND scope_id=? AND status IN ('COMPLETED',"
        "'COMPLETED_PARTIAL') ORDER BY seq DESC LIMIT 1",
        (f"{left}:{right}",),
    ).fetchone()
    return None if row is None else str(row["id"])


def _continuations(rows: list[Any], nxt: dict[str, str]) -> list[tuple[str, str]]:
    return [
        (r["left_function_id"], r["right_function_id"])
        for r in rows
        if r["left_function_id"] and r["right_function_id"] in nxt and r["decision"] in JOIN_DECISIONS
    ]


_FEAT_CACHE: dict[str, dict[int, dict[str, Any]]] = {}


def _features_by_fn(ws: Workspace, tx: Any, fn_ids: list[str]) -> dict[str, dict[str, Any]]:
    """function_instance id → its normalized feature record (from the derived result that produced it)."""
    out: dict[str, dict[str, Any]] = {}
    if not fn_ids:
        return out
    for fid in fn_ids:
        row = tx.execute(
            "SELECT fi.address, dr.output_relpath FROM function_instance fi JOIN derived_result dr"
            " ON dr.id=fi.derived_result_id WHERE fi.id=?",
            (fid,),
        ).fetchone()
        if row is None:
            continue
        rel = row["output_relpath"]
        if rel not in _FEAT_CACHE:
            data = json.loads((ws.path / rel / "result.json").read_text(encoding="utf-8"))
            _FEAT_CACHE[rel] = {f["entry"]: f for f in data["functions"]}
        f = _FEAT_CACHE[rel].get(int(row["address"]))
        if f is not None:
            out[fid] = f
    return out


def _component_role(ws: Workspace, build_id: str, sha: str) -> str:
    row = ws.db.conn.execute(
        "SELECT c.role FROM component c JOIN component_artifact ca ON ca.component_id=c.id"
        " WHERE c.build_id=? AND ca.artifact_sha256=? LIMIT 1",
        (build_id, sha),
    ).fetchone()
    return str(row["role"]) if row else "OTHER"


def build_lineage(
    ws: Workspace, product_id: str, builds: list[str] | None = None, *, incremental: bool = True
) -> LineageSummary:
    ws.require_writable()
    builds = builds or ordered_builds(ws, product_id)
    if len(builds) < 2:
        raise AcetError("ACET-NOTFOUND-001", "lineage needs at least two builds with compare runs")
    conn = ws.db.conn
    prev = conn.execute(
        "SELECT id, input_hashes_json FROM analysis_run WHERE scope_type='lineage' AND scope_id=? AND status='COMPLETED'"
        " ORDER BY seq DESC LIMIT 1",
        (product_id,),
    ).fetchone()
    prev_builds: list[str] = json.loads(prev["input_hashes_json"])["builds"] if prev else []
    reuse = incremental and prev is not None and builds[: len(prev_builds)] == prev_builds
    start_index = len(prev_builds) - 1 if reuse else 0

    run_id = uuid7()
    profile_cfg = {"name": "LINEAGE", "version": 1, "rules": RULES}
    with ws.db.transaction() as tx:
        prof = tx.execute(
            "SELECT id FROM analysis_profile WHERE config_hash=?", (canonical_hash(profile_cfg),)
        ).fetchone()
        prof_id = prof["id"] if prof else uuid7()
        if not prof:
            tx.execute(
                "INSERT INTO analysis_profile(id, name, version, config_json, config_hash) VALUES (?,?,?,?,?)",
                (prof_id, "LINEAGE", 1, stable_json(profile_cfg).decode(), canonical_hash(profile_cfg)),
            )
        tx.execute(
            "INSERT INTO analysis_run(id, scope_type, scope_id, profile_id, status, started_at, input_hashes_json,"
            " acet_version, seq, resolved_config_json, resolved_config_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                "lineage",
                product_id,
                prof_id,
                "CREATED",
                utc_now_iso(),
                stable_json({"builds": builds, "compare_runs": {}}).decode(),
                acet.__version__,
                repo.next_seq(tx),
                stable_json(profile_cfg).decode(),
                canonical_hash(profile_cfg),
            ),
        )
        _advance(tx, run_id, "PLANNING", "QUEUED", "RUNNING")

    # state: function_instance_id -> lineage_id for the latest processed build
    current: dict[str, str] = {}
    disappeared: dict[str, tuple[str, str | None]] = {}  # lineage -> (last fn id, normalized hash)
    relations: dict[str, int] = {}
    carried = 0
    lineages: set[str] = set()

    def bump(rel: str) -> None:
        relations[rel] = relations.get(rel, 0) + 1

    with ws.db.transaction() as tx:
        if reuse:
            rows = tx.execute("SELECT * FROM lineage_assignment WHERE analysis_run_id=?", (prev["id"],)).fetchall()
            for r in rows:
                tx.execute(
                    "INSERT INTO lineage_assignment(id, lineage_id, function_instance_id, analysis_run_id, relation,"
                    " strength, status, build_id, component_role, evidence_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        uuid7(),
                        r["lineage_id"],
                        r["function_instance_id"],
                        run_id,
                        r["relation"],
                        r["strength"],
                        "CARRIED_FORWARD",
                        r["build_id"],
                        r["component_role"],
                        r["evidence_json"],
                    ),
                )
                carried += 1
                lineages.add(r["lineage_id"])
                bump(r["relation"])
                if r["build_id"] == builds[start_index]:
                    if r["relation"] == "DISAPPEARED":
                        h = tx.execute(
                            "SELECT normalized_hash FROM function_instance WHERE id=?", (r["function_instance_id"],)
                        ).fetchone()
                        disappeared[r["lineage_id"]] = (r["function_instance_id"], h["normalized_hash"] if h else None)
                    else:
                        current[r["function_instance_id"]] = r["lineage_id"]
            for r in tx.execute("SELECT * FROM lineage_link WHERE analysis_run_id=?", (prev["id"],)).fetchall():
                tx.execute(
                    "INSERT INTO lineage_link(id, analysis_run_id, parent_lineage_id, child_lineage_id, relation,"
                    " build_id, evidence_json) VALUES (?,?,?,?,?,?,?)",
                    (
                        uuid7(),
                        run_id,
                        r["parent_lineage_id"],
                        r["child_lineage_id"],
                        r["relation"],
                        r["build_id"],
                        r["evidence_json"],
                    ),
                )
            # lineages that disappeared earlier stay eligible for resurrection
            for r in tx.execute(
                "SELECT la.lineage_id, la.function_instance_id, fi.normalized_hash FROM lineage_assignment la"
                " JOIN function_instance fi ON fi.id=la.function_instance_id"
                " WHERE la.analysis_run_id=? AND la.relation='DISAPPEARED'",
                (prev["id"],),
            ).fetchall():
                if r["lineage_id"] not in current.values():
                    disappeared.setdefault(r["lineage_id"], (r["function_instance_id"], r["normalized_hash"]))

        def new_lineage(role: str, label: str | None) -> str:
            lid = uuid7()
            tx.execute(
                "INSERT INTO lineage(id, product_id, created_by_run_id, status, component_role, label)"
                " VALUES (?,?,?,?,?,?)",
                (lid, product_id, run_id, "ACTIVE", role, label),
            )
            lineages.add(lid)
            return lid

        def assign(
            lid: str, fid: str, rel: str, build: str, role: str, strength: float | None, ev: dict[str, Any]
        ) -> None:
            tx.execute(
                "INSERT INTO lineage_assignment(id, lineage_id, function_instance_id, analysis_run_id, relation, strength,"
                " status, build_id, component_role, evidence_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (uuid7(), lid, fid, run_id, rel, strength, "ASSIGNED", build, role, stable_json(ev).decode()),
            )
            bump(rel)

        def link(parent: str, child: str, rel: str, build: str, ev: dict[str, Any]) -> None:
            tx.execute(
                "INSERT INTO lineage_link(id, analysis_run_id, parent_lineage_id, child_lineage_id, relation,"
                " build_id, evidence_json) VALUES (?,?,?,?,?,?,?)",
                (uuid7(), run_id, parent, child, rel, build, stable_json(ev).decode()),
            )

        if not reuse:
            first = builds[0]
            for c in repo.build_artifacts(tx, first):
                for f in tx.execute(
                    "SELECT fi.id, fi.name FROM function_instance fi JOIN derived_result dr ON"
                    " dr.id=fi.derived_result_id WHERE fi.artifact_sha256=? AND dr.state IN"
                    " ('CURRENT','INCOMPLETE')",
                    (c["sha256"],),
                ).fetchall():
                    lid = new_lineage(c["role"], f["name"])
                    assign(lid, f["id"], "UNRESOLVED", first, c["role"], None, {"origin": "first build in sequence"})
                    current[f["id"]] = lid

        missing: list[tuple[str, str]] = []
        compare_runs: dict[str, str] = {}
        for left_b, right_b in zip(builds[start_index:], builds[start_index + 1 :], strict=False):
            crun = latest_compare_run(ws, left_b, right_b)
            nxt: dict[str, str] = {}
            if crun is None:
                missing.append((left_b, right_b))
                continue
            compare_runs[f"{left_b}:{right_b}"] = crun
            rows = tx.execute("SELECT * FROM consensus_match WHERE analysis_run_id=?", (crun,)).fetchall()
            claims: dict[str, list[Any]] = {}
            for r in rows:
                if r["left_function_id"] and r["right_function_id"] and r["decision"] in (*JOIN_DECISIONS, "AMBIGUOUS"):
                    claims.setdefault(r["right_function_id"], []).append(r)
            continued_left: set[str] = set()
            for rf, cl in sorted(claims.items()):
                role = _component_role(ws, right_b, cl[0]["right_artifact_sha256"])
                parents = [c for c in cl if c["left_function_id"] in current]
                if not parents:
                    continue
                if len(parents) > 1 and all(json.loads(p["evidence_json"]).get("merge_candidate") for p in parents):
                    lid = new_lineage(role, None)
                    for p in parents:
                        link(
                            current[p["left_function_id"]],
                            lid,
                            "MERGE_PARENT",
                            right_b,
                            {"consensus_id": p["id"], "decision": p["decision"]},
                        )
                        continued_left.add(p["left_function_id"])
                    assign(
                        lid,
                        rf,
                        "MERGE_PARENT",
                        right_b,
                        role,
                        None,
                        {"parents": [current[p["left_function_id"]] for p in parents], "compare_run": crun},
                    )
                    nxt[rf] = lid
                    continue
                best = max(parents, key=lambda p: (p["decision"] in JOIN_DECISIONS, p["evidence_diversity"]))
                if best["decision"] not in JOIN_DECISIONS:
                    continue
                lid = current[best["left_function_id"]]
                hashes = tx.execute(
                    "SELECT id, normalized_hash FROM function_instance WHERE id IN (?,?)",
                    (best["left_function_id"], rf),
                ).fetchall()
                hs = {h["id"]: h["normalized_hash"] for h in hashes}
                same = hs.get(best["left_function_id"]) is not None and hs.get(best["left_function_id"]) == hs.get(rf)
                rel = "CONTINUATION" if same else "MODIFIED"
                assign(
                    lid,
                    rf,
                    rel,
                    right_b,
                    role,
                    None,
                    {
                        "consensus_id": best["id"],
                        "decision": best["decision"],
                        "evidence_diversity": best["evidence_diversity"],
                        "compare_run": crun,
                    },
                )
                nxt[rf] = lid
                continued_left.add(best["left_function_id"])
            # right functions without a parent: split child, resurrection, or unresolved origin
            lfeat = _features_by_fn(ws, tx, [r["left_function_id"] for r in rows if r["left_function_id"]])
            rfeat = _features_by_fn(ws, tx, [r["right_function_id"] for r in rows if r["right_function_id"]])
            left_addr = {lfeat[f]["entry"]: f for f in lfeat}
            right_addr = {rfeat[f]["entry"]: f for f in rfeat}
            parent_of_right = {rf: lf for lf, rf in _continuations(rows, nxt)}
            for r in rows:
                rf = r["right_function_id"]
                if rf is None or rf in nxt or rf not in rfeat:
                    continue
                if r["left_function_id"] is not None and r["decision"] in JOIN_DECISIONS:
                    continue
                role = _component_role(ws, right_b, r["right_artifact_sha256"])
                ev = json.loads(r["evidence_json"])
                me = rfeat[rf]
                lid = new_lineage(role, None)
                split_parent = None
                # split@1: called by the MODIFIED continuation R1 of a left function L that is a candidate
                for cand_addr, score in ev.get("candidates") or []:
                    lf = left_addr.get(cand_addr)
                    if lf is None or score is None or score < SPLIT_MIN:
                        continue
                    callers = {right_addr.get(c) for c in me["callgraph"]["callers"]}
                    for r1 in callers:
                        if r1 is not None and parent_of_right.get(r1) == lf and nxt.get(r1) is not None:
                            split_parent = (current[lf], score, r1)
                            break
                    if split_parent:
                        break
                resurrect = None
                if split_parent is None:
                    from acet.matching.featurematch import family_scores, raw_score

                    best = None
                    for old_lid, (old_fid, _h) in sorted(disappeared.items()):
                        old = _features_by_fn(ws, tx, [old_fid]).get(old_fid)
                        if old is None:
                            continue
                        sc = raw_score(family_scores(old, me, {}))
                        if sc >= RESURRECT_MIN and (best is None or sc > best[1]):
                            best = (old_lid, sc)
                    resurrect = best
                if split_parent is not None:
                    link(
                        split_parent[0],
                        lid,
                        "SPLIT_PARENT",
                        right_b,
                        {"rule": "split@1", "candidate_score": split_parent[1], "called_by": split_parent[2]},
                    )
                    assign(lid, rf, "SPLIT_PARENT", right_b, role, None, {"parent": split_parent[0]})
                elif resurrect is not None:
                    link(
                        resurrect[0],
                        lid,
                        "RESURRECTED_CANDIDATE",
                        right_b,
                        {"rule": "resurrect@1", "similarity": resurrect[1]},
                    )
                    assign(
                        lid,
                        rf,
                        "RESURRECTED_CANDIDATE",
                        right_b,
                        role,
                        None,
                        {"previous_lineage": resurrect[0], "similarity": resurrect[1]},
                    )
                    disappeared.pop(resurrect[0], None)
                else:
                    assign(
                        lid, rf, "UNRESOLVED", right_b, role, None, {"note": "origin unresolved; not classified new"}
                    )
                nxt[rf] = lid
            # merge@1: an unresolved left L2 whose candidate R is the MODIFIED continuation of a sibling L1
            for r in rows:
                l2 = r["left_function_id"]
                if l2 is None or r["right_function_id"] is not None or l2 not in current or l2 in continued_left:
                    continue
                f2 = lfeat.get(l2)
                if f2 is None:
                    continue
                for cand_addr, score in json.loads(r["evidence_json"]).get("candidates") or []:
                    target = right_addr.get(cand_addr)
                    l1 = parent_of_right.get(target) if target else None
                    if target is None or l1 is None or score is None or score < MERGE_MIN or l1 not in lfeat:
                        continue
                    f1 = lfeat[l1]
                    siblings = (
                        bool(set(f1["callgraph"]["callers"]) & set(f2["callgraph"]["callers"]))
                        or f2["entry"] in f1["callgraph"]["callees"]
                        or f1["entry"] in f2["callgraph"]["callees"]
                    )
                    grew = rfeat[target]["size"] > f1["size"]
                    if siblings and grew:
                        role = _component_role(ws, right_b, r["left_artifact_sha256"])
                        link(
                            current[l2],
                            nxt[target],
                            "MERGE_PARENT",
                            right_b,
                            {"rule": "merge@1", "candidate_score": score, "sibling_of": l1},
                        )
                        assign(
                            current[l2],
                            target,
                            "MERGE_PARENT",
                            right_b,
                            role,
                            None,
                            {"merged_into_lineage": nxt[target], "candidate_score": score},
                        )
                        continued_left.add(l2)
                        break
            for fid, lid in current.items():
                if fid not in continued_left and lid not in nxt.values():
                    role_row = tx.execute("SELECT artifact_sha256 FROM function_instance WHERE id=?", (fid,)).fetchone()
                    role = _component_role(ws, left_b, role_row["artifact_sha256"]) if role_row else "OTHER"
                    if any(c["left_function_id"] == fid for c in rows):
                        assign(lid, fid, "DISAPPEARED", right_b, role, None, {"last_seen_build": left_b})
                        h = tx.execute("SELECT normalized_hash FROM function_instance WHERE id=?", (fid,)).fetchone()
                        disappeared[lid] = (fid, h["normalized_hash"] if h else None)
            current = nxt
        tx.execute(
            "UPDATE analysis_run SET finished_at=?, input_hashes_json=?, missing_evidence_json=? WHERE id=?",
            (
                utc_now_iso(),
                stable_json({"builds": builds, "compare_runs": compare_runs}).decode(),
                stable_json([{"pair": list(p), "reason": "no completed compare run"} for p in missing]).decode(),
                run_id,
            ),
        )
        _advance(tx, run_id, "VALIDATING", "COMPLETED_PARTIAL" if missing else "COMPLETED")
        repo.audit(tx, "lineage.build", "analysis_run", run_id, {"builds": len(builds), "carried": carried})
    return LineageSummary(run_id, builds, len(lineages), dict(sorted(relations.items())), carried, missing)


def lineage_history(ws: Workspace, lineage_id: str, run_id: str | None = None) -> list[dict[str, Any]]:
    conn = ws.db.conn
    if run_id is None:
        row = conn.execute(
            "SELECT analysis_run_id FROM lineage_assignment WHERE lineage_id=? ORDER BY rowid DESC LIMIT 1",
            (lineage_id,),
        ).fetchone()
        run_id = row["analysis_run_id"] if row else None
    rows = conn.execute(
        "SELECT la.build_id, la.relation, la.status, fi.address, fi.name, fi.artifact_sha256 FROM lineage_assignment la"
        " JOIN function_instance fi ON fi.id=la.function_instance_id WHERE la.lineage_id=? AND la.analysis_run_id=?"
        " ORDER BY la.rowid",
        (lineage_id, run_id),
    ).fetchall()
    return [dict(r) for r in rows]

"""Analysis orchestrator: DAG planning, cache, single-flight, supervised execution (spec §15, §27, §101).

Transaction boundaries (ACET-TXN-001): workers run with no DB transaction open;
results are validated, then registered in short transactions. Derived outputs
are moved into ``derived/<processor>/<version>/<cache_key>/`` with an atomic
directory rename only after validation (INV-009, ACC-142).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import acet
from acet.analysis.registry import OPTIONAL_PROCESSORS, PROCESSORS, ProcessorSpec, Profile, get_profile
from acet.application.builds import verify_build_artifacts
from acet.application.workspace import Workspace
from acet.domain.cache import cache_key
from acet.domain.canonical import canonical_hash, stable_hash, stable_json
from acet.domain.enums import JobPriority, OperationOutcome
from acet.domain.error_codes import AcetError
from acet.domain.ids import uuid7
from acet.domain.state_machines import ANALYSIS_RUN
from acet.domain.timeutil import utc_now_iso
from acet.engines.environment import EngineEnvironment, detect
from acet.jobs import store as jobs
from acet.jobs.completion import CompletionState, LogRule, validate_completion
from acet.jobs.locks import single_flight
from acet.jobs.power import keep_awake
from acet.jobs.resources import ResourcePolicy, disk_preflight
from acet.jobs.supervisor import Limits, run_supervised
from acet.storage import repositories as repo
from acet.storage.content_store import sha256_file
from acet.storage.db import Database

log = logging.getLogger(__name__)

FaultHook = Callable[[str], None]
SRC_ROOT = Path(acet.__file__).resolve().parents[1]


def _noop(_: str) -> None:
    return None


@dataclass
class Node:
    key: str
    spec: ProcessorSpec
    artifacts: tuple[str, ...]  # 1 (artifact scope) or 2 (pair: left, right)
    deps: list[str] = field(default_factory=list)
    optional_deps: list[str] = field(default_factory=list)
    skip: OperationOutcome | None = None
    skip_reason: str | None = None


@dataclass
class NodeResult:
    outcome: OperationOutcome
    derived_result_id: str | None = None
    output_dir: Path | None = None
    output_sha256: str | None = None
    reason: str | None = None
    cache_hit: bool = False


@dataclass
class RunSummary:
    run_id: str
    job_id: str
    status: str
    coverage: float | None
    nodes: dict[str, str]
    missing_evidence: list[dict[str, Any]]
    cache_hits: int
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "job_id": self.job_id,
            "status": self.status,
            "coverage": self.coverage,
            "nodes": self.nodes,
            "missing_evidence": self.missing_evidence,
            "cache_hits": self.cache_hits,
            "warnings": self.warnings,
        }


# --------------------------------------------------------------------------- planning
def artifact_formats(ws: Workspace, shas: Sequence[str]) -> dict[str, str]:
    q = ",".join("?" * len(shas))
    return {
        r["sha256"]: r["format"]
        for r in ws.db.conn.execute(f"SELECT sha256, format FROM artifact WHERE sha256 IN ({q})", tuple(shas))
    }


def pair_components(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> tuple[list[tuple[str, str]], list[str]]:
    """Pair components of two builds by role, then file label. Unpaired ≠ new (they are reported)."""
    pairs: list[tuple[str, str]] = []
    notes: list[str] = []
    roles = sorted({c["role"] for c in left} | {c["role"] for c in right})
    for role in roles:
        lc = sorted((c for c in left if c["role"] == role), key=lambda c: (c["label"] or "").lower())
        rc = sorted((c for c in right if c["role"] == role), key=lambda c: (c["label"] or "").lower())
        used_r: set[int] = set()
        rest_l = []
        for c in lc:
            j = next(
                (
                    i
                    for i, d in enumerate(rc)
                    if i not in used_r and (d["label"] or "").lower() == (c["label"] or "").lower()
                ),
                None,
            )
            if j is None:
                rest_l.append(c)
            else:
                used_r.add(j)
                pairs.append((c["sha256"], rc[j]["sha256"]))
        rest_r = [d for i, d in enumerate(rc) if i not in used_r]
        for a, b in zip(rest_l, rest_r, strict=False):
            pairs.append((a["sha256"], b["sha256"]))
        for c in rest_l[len(rest_r) :]:
            notes.append(f"left component {role}:{c['label']} has no counterpart (UNKNOWN, not removed)")
        for c in rest_r[len(rest_l) :]:
            notes.append(f"right component {role}:{c['label']} has no counterpart (UNKNOWN, not new)")
    return sorted(set(pairs)), notes


def plan(
    profile: Profile,
    artifacts: Sequence[str],
    pairs: Sequence[tuple[str, str]],
    formats: dict[str, str],
    env: EngineEnvironment,
) -> list[Node]:
    nodes: dict[str, Node] = {}
    order = _topo([PROCESSORS[p] for p in profile.processors])
    in_profile = set(profile.processors)
    for spec in order:
        targets: list[tuple[str, ...]] = [(a,) for a in artifacts] if spec.scope == "artifact" else list(pairs)
        for t in targets:
            key = f"{spec.key}:{'|'.join(x[:16] for x in t)}"
            node = Node(key, spec, t)
            for dep in spec.depends_on:
                if dep not in in_profile:
                    continue
                d = PROCESSORS[dep]
                node.deps += (
                    [f"{d.key}:{x[:16]}" for x in t]
                    if d.scope == "artifact"
                    else [f"{d.key}:{'|'.join(x[:16] for x in t)}"]
                )
            for dep in spec.optional_deps:
                # ACET-DET-001 / ACC-138: D3 (non-reproducible) outputs never feed stable inference unless
                # the profile explicitly opts in (Research use, results then marked experimental).
                if PROCESSORS[dep].determinism.value == "D3" and not profile.config.get("allow_d3"):
                    continue
                if dep in in_profile:
                    d = PROCESSORS[dep]
                    node.optional_deps += (
                        [f"{d.key}:{x[:16]}" for x in t]
                        if d.scope == "artifact"
                        else [f"{d.key}:{'|'.join(x[:16] for x in t)}"]
                    )
            if spec.formats is not None and any(formats.get(x) not in spec.formats for x in t):
                node.skip, node.skip_reason = OperationOutcome.SKIPPED_INCOMPATIBLE, "input format not supported"
            elif spec.provider and not env.available(spec.provider):
                node.skip = OperationOutcome.SKIPPED_UNSUPPORTED
                node.skip_reason = env.providers[spec.provider].reason or "provider unavailable"
            elif spec.scope == "pair" and spec.heavy and t[0] == t[1]:
                node.skip, node.skip_reason = OperationOutcome.SKIPPED_POLICY, "identical bytes on both sides"
            nodes[key] = node
    return list(nodes.values())


def _topo(specs: list[ProcessorSpec]) -> list[ProcessorSpec]:
    by_id = {s.id: s for s in specs}
    out: list[ProcessorSpec] = []
    seen: set[str] = set()

    def visit(s: ProcessorSpec, stack: tuple[str, ...]) -> None:
        if s.id in seen:
            return
        if s.id in stack:
            raise AcetError("ACET-INT-001", f"processor dependency cycle at {s.id}")
        for d in (*s.depends_on, *s.optional_deps):
            if d in by_id:
                visit(by_id[d], (*stack, s.id))
        seen.add(s.id)
        out.append(s)

    for s in specs:
        visit(s, ())
    return out


# --------------------------------------------------------------------------- stale propagation
def mark_stale(db: Database) -> int:
    """Processor version changed ⇒ its results and all descendants become STALE (ACC-013).
    Nothing is deleted; STALE stays readable (§27)."""
    changed = 0
    with db.transaction() as tx:
        frontier: list[str] = []
        for pid, spec in PROCESSORS.items():
            rows = tx.execute(
                "SELECT id FROM derived_result WHERE processor_id=? AND processor_version<>? AND state='CURRENT'",
                (pid, spec.version),
            ).fetchall()
            for r in rows:
                tx.execute(
                    "UPDATE derived_result SET state='STALE', stale_reason=? WHERE id=?",
                    (f"processor {pid} is now version {spec.version}", r["id"]),
                )
                frontier.append(r["id"])
        while frontier:
            nxt: list[str] = []
            for did in frontier:
                for r in tx.execute(
                    "SELECT dr.id FROM derived_input di JOIN derived_result dr ON dr.id=di.derived_result_id"
                    " WHERE di.input_kind='derived' AND di.input_ref=? AND dr.state='CURRENT'",
                    (did,),
                ).fetchall():
                    tx.execute(
                        "UPDATE derived_result SET state='STALE', stale_reason=? WHERE id=?",
                        (f"upstream result {did} is stale", r["id"]),
                    )
                    nxt.append(r["id"])
            changed += len(frontier)
            frontier = nxt
        if changed:
            repo.audit(tx, "derived.stale", None, None, {"count": changed})
    return changed


# --------------------------------------------------------------------------- orchestrator
class Orchestrator:
    def __init__(
        self,
        ws: Workspace,
        *,
        env: EngineEnvironment | None = None,
        policy: ResourcePolicy | None = None,
        fault: FaultHook = _noop,
        allow_keep_awake: bool = False,
    ) -> None:
        self.ws = ws
        self.env = env or detect()
        self.policy = policy or ResourcePolicy()
        self.fault = fault
        self.allow_keep_awake = allow_keep_awake

    # -- run lifecycle ------------------------------------------------------
    def _set_run(self, run_id: str, dst: str, **fields: Any) -> None:
        with self.ws.db.transaction() as tx:
            cur = tx.execute("SELECT status FROM analysis_run WHERE id=?", (run_id,)).fetchone()
            ANALYSIS_RUN.check(cur["status"], dst)
            sets = {"status": dst, **fields}
            tx.execute(
                f"UPDATE analysis_run SET {', '.join(f'{k}=?' for k in sets)} WHERE id=?", (*sets.values(), run_id)
            )

    def _network_enabled(self) -> bool:
        from acet.application.settings import get_setting

        return bool(get_setting(self.ws, "network.enabled"))

    def _engine_pack_id(self) -> str:
        manifest = self.env.manifest()
        mhash = canonical_hash(manifest)
        with self.ws.db.transaction() as tx:
            row = tx.execute("SELECT id FROM engine_pack WHERE manifest_hash=?", (mhash,)).fetchone()
            if row:
                return str(row["id"])
            eid = uuid7()
            tx.execute(
                "INSERT INTO engine_pack(id, name, version, manifest_json, manifest_hash) VALUES (?,?,?,?,?)",
                (eid, manifest["id"], acet.__version__, stable_json(manifest).decode(), mhash),
            )
            return eid

    def _profile_id(self, profile: Profile) -> str:
        with self.ws.db.transaction() as tx:
            row = tx.execute("SELECT id FROM analysis_profile WHERE config_hash=?", (profile.config_hash,)).fetchone()
            if row:
                return str(row["id"])
            pid = uuid7()
            tx.execute(
                "INSERT INTO analysis_profile(id, name, version, config_json, config_hash) VALUES (?,?,?,?,?)",
                (pid, profile.name, profile.version, stable_json(profile.as_json()).decode(), profile.config_hash),
            )
            return pid

    def create_run(self, scope_type: str, scope_id: str, profile: Profile, artifacts: Sequence[str]) -> str:
        self.ws.require_writable()
        rid = uuid7()
        resolved = {
            "profile": profile.as_json(),
            "engines": self.env.manifest(),
            "acet_version": acet.__version__,
            "resource_policy": {"heavy_workers": self.policy.heavy_workers, "light_workers": self.policy.light_workers},
        }
        pid, eid = self._profile_id(profile), self._engine_pack_id()
        with self.ws.db.transaction() as tx:
            tx.execute(
                "INSERT INTO analysis_run(id, scope_type, scope_id, profile_id, engine_pack_id, status, started_at,"
                " resolved_config_json, resolved_config_hash, input_hashes_json, acet_version, seq)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    rid,
                    scope_type,
                    scope_id,
                    pid,
                    eid,
                    ANALYSIS_RUN.initial,
                    utc_now_iso(),
                    stable_json(resolved).decode(),
                    stable_hash(resolved),
                    stable_json(sorted(set(artifacts))).decode(),
                    acet.__version__,
                    repo.next_seq(tx),
                ),
            )
            repo.audit(tx, "analysis.create", "analysis_run", rid, {"scope_type": scope_type, "profile": profile.ref})
        return rid

    def execute(
        self,
        run_id: str,
        nodes: list[Node],
        profile: Profile,
        *,
        job_id: str | None = None,
        warnings: list[str] | None = None,
    ) -> RunSummary:
        db = self.ws.db
        warnings = list(warnings or [])
        run = db.conn.execute("SELECT status FROM analysis_run WHERE id=?", (run_id,)).fetchone()
        if run["status"] == "CREATED":
            self._set_run(run_id, "PLANNING")
            self._set_run(run_id, "QUEUED")
        if job_id is None:
            job_id = jobs.create_job(
                db, "analysis", {"run_id": run_id}, priority=JobPriority.NORMAL, analysis_run_id=run_id
            )
        mark_stale(db)
        if jobs.get_job(db, job_id)["state"] == "QUEUED":  # type: ignore[index]
            jobs.transition(db, job_id, "PREPARING")
            # ACC-031: heavy work refuses to start without enough disk.
            heavy_bytes = sum(self._estimate(n) for n in nodes if n.spec.heavy and n.skip is None)
            try:
                disk_preflight(self.ws.path / "temp", heavy_bytes, self.policy)
            except AcetError:
                jobs.transition(db, job_id, "FAILED_PERMANENT", error_code="ACET-IMP-003")
                if db.conn.execute("SELECT status FROM analysis_run WHERE id=?", (run_id,)).fetchone()[0] != "RUNNING":
                    self._set_run(run_id, "RUNNING")
                self._set_run(run_id, "FAILED", finished_at=utc_now_iso())
                raise
            jobs.transition(db, job_id, "RUNNING")
        if db.conn.execute("SELECT status FROM analysis_run WHERE id=?", (run_id,)).fetchone()[0] != "RUNNING":
            self._set_run(run_id, "RUNNING")

        done: dict[str, NodeResult] = {}
        prior = db.conn.execute(
            "SELECT node_key, status, derived_result_id, outcome, cache_hit FROM processor_run WHERE analysis_run_id=?",
            (run_id,),
        ).fetchall()
        for r in prior:  # resume: nodes already settled for this run are not re-recorded
            if r["node_key"] and r["status"] in ("COMPLETED", "PARTIAL") and r["derived_result_id"]:
                dr = db.conn.execute("SELECT * FROM derived_result WHERE id=?", (r["derived_result_id"],)).fetchone()
                done[r["node_key"]] = NodeResult(
                    OperationOutcome(r["outcome"]),
                    dr["id"],
                    self.ws.path / dr["output_relpath"],
                    dr["output_sha256"],
                    cache_hit=bool(r["cache_hit"]),
                )
        cancelled = paused = False
        with keep_awake(self.allow_keep_awake and any(n.spec.heavy for n in nodes)):
            for i, node in enumerate(nodes):
                if node.key in done:
                    continue
                state = jobs.get_job(db, job_id)["state"]  # type: ignore[index]
                if state == "CANCELLING":
                    cancelled = True
                    break
                if state == "PAUSING":
                    paused = True
                    break
                self.fault(f"node:{node.key}")
                done[node.key] = self._run_node(run_id, job_id, node, profile, done)
                jobs.checkpoint(
                    db,
                    job_id,
                    {"completed": sorted(done)},
                    stage=node.spec.key,
                    progress=round((i + 1) / max(1, len(nodes)), 4),
                )
        if cancelled:
            jobs.transition(db, job_id, "CANCELLED")
            self._set_run(run_id, "CANCELLED", finished_at=utc_now_iso())
            return self._summary(run_id, job_id, "CANCELLED", nodes, done, warnings)
        if paused:
            jobs.transition(db, job_id, "PAUSED")
            return self._summary(run_id, job_id, "RUNNING", nodes, done, warnings)

        jobs.transition(db, job_id, "POST_PROCESSING")
        self._set_run(run_id, "VALIDATING")
        applicable = [
            n for n in nodes if n.skip not in (OperationOutcome.SKIPPED_INCOMPATIBLE, OperationOutcome.SKIPPED_POLICY)
        ]
        # Provider-side refusals (memory gate, known limitation) keep the run usable but are visible (ACC-080).
        ok = [
            n
            for n in applicable
            if done[n.key].outcome in (OperationOutcome.SUCCESS, OperationOutcome.SUCCESS_WITH_WARNINGS)
        ]
        coverage = round(len(ok) / len(applicable), 4) if applicable else None
        missing = self._missing(nodes, done)
        required_failed = [m for m in missing if m["processor"].split("@")[0] not in OPTIONAL_PROCESSORS]
        produced = [
            n
            for n in applicable
            if done[n.key].outcome
            in (OperationOutcome.SUCCESS, OperationOutcome.SUCCESS_WITH_WARNINGS, OperationOutcome.PARTIAL)
        ]
        if applicable and not produced:
            status = "FAILED"
        elif missing:
            status = "COMPLETED_PARTIAL"
        else:
            status = "COMPLETED"
        if required_failed and status == "COMPLETED_PARTIAL":
            warnings.append(
                "required evidence missing: " + ", ".join(sorted({m["processor"] for m in required_failed}))
            )
        cov_by: dict[str, dict[str, int]] = {}
        for n in nodes:
            c = cov_by.setdefault(n.spec.key, {})
            o = done[n.key].outcome.value
            c[o] = c.get(o, 0) + 1
        self._set_run(
            run_id,
            status,
            finished_at=utc_now_iso(),
            coverage=coverage,
            missing_evidence_json=stable_json(missing).decode(),
            coverage_json=stable_json(cov_by).decode(),
            warnings_json=stable_json(warnings).decode(),
        )
        jobs.transition(db, job_id, "COMPLETED")
        with db.transaction() as tx:
            repo.audit(tx, "analysis.finish", "analysis_run", run_id, {"status": status, "coverage": coverage})
        return self._summary(run_id, job_id, status, nodes, done, warnings)

    def _summary(
        self, run_id: str, job_id: str, status: str, nodes: list[Node], done: dict[str, NodeResult], warnings: list[str]
    ) -> RunSummary:
        cov = self.ws.db.conn.execute("SELECT coverage FROM analysis_run WHERE id=?", (run_id,)).fetchone()["coverage"]
        return RunSummary(
            run_id,
            job_id,
            status,
            cov,
            {k: v.outcome.value for k, v in done.items()},
            self._missing(nodes, done),
            sum(1 for v in done.values() if v.cache_hit),
            warnings,
        )

    @staticmethod
    def _missing(nodes: list[Node], done: dict[str, NodeResult]) -> list[dict[str, Any]]:
        out = []
        for n in nodes:
            r = done.get(n.key)
            if r is None or r.outcome in (OperationOutcome.SUCCESS, OperationOutcome.SUCCESS_WITH_WARNINGS):
                continue
            if n.skip in (OperationOutcome.SKIPPED_INCOMPATIBLE, OperationOutcome.SKIPPED_POLICY):
                continue  # planned skips (format, identical bytes) are not missing evidence
            out.append(
                {
                    "processor": n.spec.key,
                    "inputs": list(n.artifacts),
                    "outcome": r.outcome.value,
                    "reason": r.reason,
                    "capabilities": [c.value for c in n.spec.capabilities],
                    "experimental": n.spec.experimental,
                }
            )
        return out

    def _estimate(self, node: Node) -> int:
        size = 0
        for sha in node.artifacts:
            row = self.ws.db.conn.execute("SELECT size_bytes FROM artifact WHERE sha256=?", (sha,)).fetchone()
            size += int(row["size_bytes"]) if row else 0
        return int(size * node.spec.disk_factor)

    # -- one node -------------------------------------------------------------
    def _record_pr(
        self,
        run_id: str,
        node: Node,
        *,
        status: str,
        outcome: OperationOutcome,
        input_hash: str,
        config_hash: str,
        key: str,
        derived_id: str | None = None,
        cache_hit: bool = False,
        **extra: Any,
    ) -> str:
        prid = extra.pop("prid", None) or uuid7()
        now = utc_now_iso()
        with self.ws.db.transaction() as tx:
            tx.execute(
                "INSERT INTO processor_run(id, analysis_run_id, processor_id, processor_version, input_hash, config_hash,"
                " cache_key, status, started_at, finished_at, outcome, failure_family, determinism_class,"
                " derived_result_id, node_key, termination, completion_state, warnings_json, metrics_json, error_code,"
                " cache_hit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    prid,
                    run_id,
                    node.spec.id,
                    node.spec.version,
                    input_hash,
                    config_hash,
                    key,
                    status,
                    extra.get("started_at", now),
                    now,
                    outcome.value,
                    extra.get("failure_family"),
                    node.spec.determinism.value,
                    derived_id,
                    node.key,
                    extra.get("termination"),
                    extra.get("completion_state"),
                    stable_json(extra.get("warnings", [])).decode(),
                    stable_json(extra.get("metrics", {})).decode(),
                    extra.get("error_code"),
                    int(cache_hit),
                ),
            )
        return prid

    def _run_node(
        self, run_id: str, job_id: str, node: Node, profile: Profile, done: dict[str, NodeResult]
    ) -> NodeResult:
        nohash = "0" * 64
        if node.skip is not None:
            self._record_pr(
                run_id,
                node,
                status="SKIPPED",
                outcome=node.skip,
                input_hash=nohash,
                config_hash=nohash,
                key=nohash,
                warnings=[node.skip_reason or ""],
            )
            return NodeResult(node.skip, reason=node.skip_reason)
        for d in node.deps:
            r = done.get(d)
            if r is None or r.derived_result_id is None:
                reason = f"dependency {d.split(':')[0]} unavailable"
                self._record_pr(
                    run_id,
                    node,
                    status="SKIPPED",
                    outcome=OperationOutcome.SKIPPED_UNSUPPORTED,
                    input_hash=nohash,
                    config_hash=nohash,
                    key=nohash,
                    warnings=[reason],
                )
                return NodeResult(OperationOutcome.SKIPPED_UNSUPPORTED, reason=reason)
        derived_deps = [d for d in [*node.deps, *node.optional_deps] if done.get(d) and done[d].derived_result_id]
        inputs: list[dict[str, Any]] = [
            {"kind": "artifact", "sha256": sha, "path": str(self.ws.store.path_for(sha))} for sha in node.artifacts
        ]
        layout = {
            "artifacts": ["left", "right"] if node.spec.scope == "pair" else ["subject"],
            "derived": [
                d.split(":")[0].split("@")[0] + ("@" + _side(node, d) if node.spec.scope == "pair" else "")
                for d in derived_deps
            ],
        }
        for d in derived_deps:
            r = done[d]
            assert r.output_dir is not None and r.output_sha256 is not None
            inputs.append(
                {
                    "kind": "derived",
                    "sha256": r.output_sha256,
                    "path": str(r.output_dir / "result.json"),
                    "_id": r.derived_result_id,
                }
            )
        cfg = {**profile.processor_config(node.spec.id), "_layout": layout}
        if node.spec.id == "qbindiff.diff":
            for side, sha in zip(("left", "right"), node.artifacts, strict=True):
                fr = done.get(f"{PROCESSORS['acet.features'].key}:{sha[:16]}")
                if fr is not None and fr.output_dir is not None:
                    data = json.loads((fr.output_dir / "result.json").read_text(encoding="utf-8"))
                    cfg[f"_function_count_{side}"] = int(data.get("function_count", 0))
        if node.spec.id == "acet.consensus":
            engine_names = {
                "acet.featurematch": "acet.featurematch",
                "ghidriff.diff": "ghidriff",
                "bindiff.diff": "bindiff",
                "qbindiff.diff": "qbindiff",
            }
            cfg["expected_engines"] = sorted(engine_names[p] for p in profile.processors if p in engine_names)
        config_hash = stable_hash(cfg)
        input_hashes = [i["sha256"] for i in inputs]
        input_hash = canonical_hash(input_hashes)
        key = cache_key(node.spec.id, node.spec.version, input_hashes, config_hash, node.spec.feature_schema_version)

        with single_flight(self.ws.db, key):
            hit = self._cache_lookup(key)
            if hit is not None:
                self._record_pr(
                    run_id,
                    node,
                    status="COMPLETED",
                    outcome=hit.outcome,
                    input_hash=input_hash,
                    config_hash=config_hash,
                    key=key,
                    derived_id=hit.derived_result_id,
                    cache_hit=True,
                )
                self._ingest(run_id, node, hit, None)
                return hit
            return self._execute_worker(run_id, job_id, node, profile, inputs, cfg, config_hash, input_hash, key)

    def _cache_lookup(self, key: str) -> NodeResult | None:
        row = self.ws.db.conn.execute(
            "SELECT * FROM derived_result WHERE cache_key=? AND state='CURRENT'", (key,)
        ).fetchone()
        if row is None:
            return None
        out_dir = self.ws.path / row["output_relpath"]
        res = out_dir / "result.json"
        if not res.is_file() or sha256_file(res)[0] != row["output_sha256"]:
            with self.ws.db.transaction() as tx:  # corrupted cache entry is never a hit (INV-010)
                tx.execute("UPDATE derived_result SET state='CORRUPTED' WHERE id=?", (row["id"],))
            return None
        return NodeResult(OperationOutcome.SUCCESS, row["id"], out_dir, row["output_sha256"], cache_hit=True)

    def _execute_worker(
        self,
        run_id: str,
        job_id: str,
        node: Node,
        profile: Profile,
        inputs: list[dict[str, Any]],
        cfg: dict[str, Any],
        config_hash: str,
        input_hash: str,
        key: str,
    ) -> NodeResult:
        prid = uuid7()
        started = utc_now_iso()
        stage = self.ws.path / "temp" / "runs" / prid
        out_dir = stage / "out"
        out_dir.mkdir(parents=True)
        request = {
            "protocol_version": 1,
            "job_id": prid,
            "processor": {"id": node.spec.id, "version": node.spec.version},
            "inputs": [{k: v for k, v in i.items() if not k.startswith("_")} for i in inputs],
            "config": cfg,
            "output_dir": str(out_dir),
        }
        (stage / "request.json").write_text(json.dumps(request, indent=2), encoding="utf-8")
        timeout = float(cfg.get("hard_timeout_s", node.spec.default_timeout_s))
        limits = Limits(
            soft_timeout_s=float(cfg.get("soft_timeout_s", timeout * 0.9)),
            hard_timeout_s=timeout,
            heartbeat_timeout_s=float(cfg.get("heartbeat_timeout_s", 300)),
            memory_limit_bytes=cfg.get("max_memory_bytes"),
        )
        cancel = threading.Event()
        watcher_stop = threading.Event()
        watcher = threading.Thread(target=self._watch_job, args=(job_id, cancel, watcher_stop), daemon=True)
        watcher.start()
        log_dir = self.ws.path / "logs" / "processor_runs" / prid
        env = {
            "PYTHONPATH": os.pathsep.join(filter(None, [str(SRC_ROOT), os.environ.get("PYTHONPATH")])),
            "ACET_CORRELATION": f"ws={self.ws.id} run={run_id} job={job_id} pr={prid}",
            "ACET_NO_NETWORK": "0" if self._network_enabled() else "1",
        }  # ACET-OBS-001
        for k in ("ACET_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "ACET_GHIDRA_REPLAY_DIR"):
            if os.environ.get(k):
                env[k] = os.environ[k]
        gh = self.env.providers.get("ghidra")
        if gh and gh.location and not gh.extra.get("replay"):
            env["ACET_GHIDRA_DIR"] = str(gh.location)
        for pid_, info in self.env.providers.items():
            if info.available and info.location:
                env[f"ACET_PROVIDER_{pid_.upper()}"] = str(info.location)
        try:
            proc = run_supervised(
                [sys.executable, "-m", "acet.engines.worker", str(stage / "request.json")],
                workdir=stage,
                log_dir=log_dir,
                limits=limits,
                env=env,
                heartbeat_file=out_dir / ".heartbeat",
                cancel_event=cancel,
                graceful_stop_file=out_dir / ".stop",
            )
        finally:
            watcher_stop.set()
        self.fault(f"after_worker:{node.key}")
        verdict = validate_completion(proc, out_dir, expected_outputs=["result.json"], log_rules=_log_rules(node.spec))
        metrics = proc.to_metrics()
        determinism: dict[str, Any] | None = None
        if verdict.state is CompletionState.COMPLETE and int(profile.config.get("determinism_repeats", 1)) > 1:
            determinism = self._determinism_check(node, stage, request, limits, env, out_dir)
            metrics["determinism"] = determinism
        common: dict[str, Any] = dict(
            prid=prid,
            started_at=started,
            termination=proc.termination.value,
            completion_state=verdict.state.value,
            metrics=metrics,
            warnings=verdict.reasons,
        )
        if verdict.state is CompletionState.INVALID:
            code = "ACET-JOB-001" if proc.hung else ("ACET-GHD-002" if proc.termination.value == "timeout" else None)
            self._record_pr(
                run_id,
                node,
                status="FAILED",
                outcome=verdict.outcome,
                input_hash=input_hash,
                config_hash=config_hash,
                key=key,
                failure_family="ENGINE",
                error_code=code,
                **common,
            )
            shutil.rmtree(stage, ignore_errors=True)
            return NodeResult(verdict.outcome, reason="; ".join(verdict.reasons[:3]))
        if verdict.outcome is OperationOutcome.CANCELLED:
            shutil.rmtree(stage, ignore_errors=True)
            return NodeResult(OperationOutcome.CANCELLED, reason="cancelled")
        skipped = _skipped(out_dir)
        if skipped is not None:
            status, reason, code = skipped
            outcome = (
                OperationOutcome.SKIPPED_POLICY if status == "SKIPPED_POLICY" else OperationOutcome.SKIPPED_INCOMPATIBLE
            )
            self._record_pr(
                run_id,
                node,
                status=status,
                outcome=outcome,
                input_hash=input_hash,
                config_hash=config_hash,
                key=key,
                error_code=code,
                **{**common, "warnings": [reason]},
            )
            shutil.rmtree(stage, ignore_errors=True)
            return NodeResult(outcome, reason=f"{status}: {reason}")
        # Promote: atomic rename of the validated output directory into the derived store.
        drid = uuid7()
        # One directory per attempt under the cache key: nothing is ever overwritten (INV-011).
        final_rel = Path("derived") / node.spec.id / node.spec.version / key / drid
        final = self.ws.path / final_rel
        final.parent.mkdir(parents=True, exist_ok=True)
        for leftover in out_dir.glob("*.tmp"):
            leftover.unlink()
        (out_dir / ".heartbeat").unlink(missing_ok=True)
        (out_dir / ".stop").unlink(missing_ok=True)
        os.replace(out_dir, final)
        shutil.rmtree(stage, ignore_errors=True)
        out_sha = sha256_file(final / "result.json")[0]
        state = "CURRENT" if verdict.state is CompletionState.COMPLETE else "INCOMPLETE"
        outcome = OperationOutcome.SUCCESS if state == "CURRENT" else OperationOutcome.PARTIAL
        if determinism is not None and not determinism["match"] and node.spec.determinism.value in ("D0", "D1"):
            outcome = OperationOutcome.SUCCESS_WITH_WARNINGS
        prid_rec = self._record_pr(
            run_id,
            node,
            status="COMPLETED" if state == "CURRENT" else "PARTIAL",
            outcome=outcome,
            input_hash=input_hash,
            config_hash=config_hash,
            key=key,
            **common,
        )
        with self.ws.db.transaction() as tx:
            tx.execute(
                "INSERT INTO derived_result(id, cache_key, processor_id, processor_version, determinism_class, state,"
                " output_relpath, output_sha256, produced_by_processor_run_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    drid,
                    key,
                    node.spec.id,
                    node.spec.version,
                    node.spec.determinism.value,
                    state,
                    final_rel.as_posix(),
                    out_sha,
                    prid_rec,
                    utc_now_iso(),
                ),
            )
            for i, inp in enumerate(inputs):
                tx.execute(
                    "INSERT INTO derived_input(derived_result_id, ordinal, input_kind, input_ref) VALUES (?,?,?,?)",
                    (drid, i, inp["kind"], inp.get("_id") or inp["sha256"]),
                )
            tx.execute("UPDATE processor_run SET derived_result_id=? WHERE id=?", (drid, prid_rec))
        res = NodeResult(outcome, drid, final, out_sha, reason="; ".join(verdict.reasons[:3]) or None)
        self._ingest(run_id, node, res, prid_rec)
        return res

    def _determinism_check(
        self, node: Node, stage: Path, request: dict[str, Any], limits: Limits, env: dict[str, str], first_out: Path
    ) -> dict[str, Any]:
        """RESEARCH profile: repeat and compare (ACC-136/137, ACET-DET-001)."""
        rep = stage / "repeat"
        rep_out = rep / "out"
        rep_out.mkdir(parents=True)
        req2 = {**request, "output_dir": str(rep_out)}
        (rep / "request.json").write_text(json.dumps(req2), encoding="utf-8")
        run_supervised(
            [sys.executable, "-m", "acet.engines.worker", str(rep / "request.json")],
            workdir=rep,
            log_dir=rep / "logs",
            limits=limits,
            env=env,
        )
        a, b = first_out / "result.json", rep_out / "result.json"
        if not b.is_file():
            return {"repeats": 2, "match": False, "reason": "repeat produced no result"}
        same_bytes = sha256_file(a)[0] == sha256_file(b)[0]
        same_canon = stable_hash(json.loads(a.read_text(encoding="utf-8"))) == stable_hash(
            json.loads(b.read_text(encoding="utf-8"))
        )
        return {
            "repeats": 2,
            "class": node.spec.determinism.value,
            "bit_identical": same_bytes,
            "canonical_identical": same_canon,
            "match": same_bytes if node.spec.determinism.value == "D0" else same_canon,
        }

    def _watch_job(self, job_id: str, cancel: threading.Event, stop: threading.Event) -> None:
        db = Database(self.ws.db.path)
        try:
            while not stop.wait(0.25):
                row = db.conn.execute("SELECT state FROM job WHERE id=?", (job_id,)).fetchone()
                if row and row["state"] == "CANCELLING":
                    cancel.set()
                    return
        finally:
            db.close()

    def _ingest(self, run_id: str, node: Node, res: NodeResult, prid: str | None) -> None:
        from acet.analysis.ingest import ingest_result

        ingest_result(self.ws, run_id, node.spec, node.artifacts, res.derived_result_id, res.output_dir, prid)


def _skipped(out_dir: Path) -> tuple[str, str, str | None] | None:
    try:
        data = json.loads((out_dir / "result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) and data.get("skipped") in (
        "SKIPPED_POLICY",
        "SKIPPED_INCOMPATIBLE",
        "SKIPPED_KNOWN_LIMITATION",
    ):
        return str(data["skipped"]), str(data.get("reason")), data.get("code")
    return None


def _side(node: Node, dep_key: str) -> str:
    short = dep_key.split(":", 1)[1]
    if "|" in short:
        return "pair"
    return "left" if node.artifacts[0][:16] == short else "right"


def _log_rules(spec: ProcessorSpec) -> list[LogRule]:
    from acet.engines.quirks import log_rules_for

    return log_rules_for(spec.provider or spec.id)


# --------------------------------------------------------------------------- use cases
def _check_artifacts(ws: Workspace, build_ids: Sequence[str]) -> list[str]:
    shas: list[str] = []
    for b in build_ids:
        shas += verify_build_artifacts(ws, b)  # ACC-008: integrity gate before analysis
    return sorted(set(shas))


def environment_for(ws: Workspace) -> EngineEnvironment:
    """Engines for new runs: the workspace's pinned Engine Pack if any, else local detection (ACET-UPD-002)."""
    from acet.application.settings import get_setting
    from acet.platform.engine_packs import provider_overrides, resolve_pinned

    pack = resolve_pinned(get_setting(ws, "engines.pinned_pack"))
    if pack is None:
        return detect()
    return detect(provider_overrides(pack), pack_id=f"{pack['id']}@{pack['version']}")


def analyze_build(
    ws: Workspace,
    build_id: str,
    profile_ref: str = "FAST@1",
    *,
    env: EngineEnvironment | None = None,
    fault: FaultHook = _noop,
) -> RunSummary:
    profile = get_profile(profile_ref)
    orch = Orchestrator(ws, env=env or environment_for(ws), fault=fault)
    _require_mandatory(profile, orch.env)
    shas = _check_artifacts(ws, [build_id])
    nodes = plan(profile, shas, [], artifact_formats(ws, shas), orch.env)
    run_id = orch.create_run("build", build_id, profile, shas)
    return orch.execute(run_id, nodes, profile)


def compare_builds(
    ws: Workspace,
    left: str,
    right: str,
    profile_ref: str = "STANDARD@1",
    *,
    env: EngineEnvironment | None = None,
    fault: FaultHook = _noop,
) -> RunSummary:
    profile = get_profile(profile_ref)
    orch = Orchestrator(ws, env=env or environment_for(ws), fault=fault)
    _require_mandatory(profile, orch.env)
    shas = _check_artifacts(ws, [left, right])
    lc, rc = repo.build_artifacts(ws.db.conn, left), repo.build_artifacts(ws.db.conn, right)
    pairs, notes = pair_components(lc, rc)
    nodes = plan(profile, shas, pairs, artifact_formats(ws, shas), orch.env)
    run_id = orch.create_run("compare", f"{left}:{right}", profile, shas)
    return orch.execute(run_id, nodes, profile, warnings=notes)


def _require_mandatory(profile: Profile, env: EngineEnvironment) -> None:
    """Ghidra is mandatory for STANDARD/DEEP (§90): refuse clearly instead of a meaningless run."""
    if "ghidra.extract" in profile.processors and not env.available("ghidra"):
        raise AcetError("ACET-GHD-001", f"profile {profile.ref} needs Ghidra; use FAST@1 or install the Engine Pack")


def resume(ws: Workspace, job_id: str, *, env: EngineEnvironment | None = None, fault: FaultHook = _noop) -> RunSummary:
    """Resume an INTERRUPTED/PAUSED/FAILED_RETRYABLE job (ACC-010). Completed nodes are not redone."""
    job = jobs.get_job(ws.db, job_id)
    if job is None or not job["analysis_run_id"]:
        raise AcetError("ACET-NOTFOUND-001", f"analysis job {job_id}")
    run = ws.db.conn.execute("SELECT * FROM analysis_run WHERE id=?", (job["analysis_run_id"],)).fetchone()
    profile = get_profile(
        json.loads(run["resolved_config_json"])["profile"]["name"]
        + "@"
        + str(json.loads(run["resolved_config_json"])["profile"]["version"])
    )
    orch = Orchestrator(ws, env=env, fault=fault)
    if job["state"] == "INTERRUPTED":
        jobs.transition(ws.db, job_id, "RECOVERING")
        jobs.transition(ws.db, job_id, "QUEUED", attempts=int(job["attempts"]) + 1)
    elif job["state"] == "PAUSED":
        jobs.transition(ws.db, job_id, "RESUMING")
        jobs.transition(ws.db, job_id, "RUNNING")
    elif job["state"] == "FAILED_RETRYABLE":
        jobs.transition(ws.db, job_id, "QUEUED", attempts=int(job["attempts"]) + 1)
    else:
        raise AcetError("ACET-DOM-001", f"job in state {job['state']} cannot be resumed")
    if run["status"] == "INTERRUPTED":
        orch._set_run(run["id"], "RECOVERING")
        orch._set_run(run["id"], "QUEUED")
    shas = json.loads(run["input_hashes_json"])
    if run["scope_type"] == "compare":
        left, right = run["scope_id"].split(":")
        pairs, notes = pair_components(repo.build_artifacts(ws.db.conn, left), repo.build_artifacts(ws.db.conn, right))
    else:
        pairs, notes = [], []
    nodes = plan(profile, shas, pairs, artifact_formats(ws, shas), orch.env)
    return orch.execute(run["id"], nodes, profile, job_id=job_id, warnings=notes)

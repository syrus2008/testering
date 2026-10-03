"""Import pipeline (spec §11, transaction boundaries §101).

DISCOVER → PREVIEW → VALIDATE → HASH → COPY → VERIFY → CLASSIFY → COMMIT

* Hash/copy/verify run outside any DB transaction (ACET-TXN-001).
* Nothing becomes visible before the single COMMIT transaction (ACC-007, INV-009).
  Blobs copied before a failed commit are detected by reconcile as orphans (ACC-082).
* An existing artifact's bytes are never re-copied (ACET-IMP-003, ACC-005).
* An existing build fingerprint is never silently duplicated (ACET-IMP-004, ACC-006).
* Near-duplicates only warn (ACET-IMP-005).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from acet.application.workspace import Workspace
from acet.domain.enums import (
    ArtifactFormat,
    BuildStatus,
    ComponentPresence,
    ComponentRole,
    ConfidenceClass,
    IntegrityState,
    ObservationSourceType,
)
from acet.domain.error_codes import AcetError
from acet.domain.fingerprint import ComponentEntry, assign_ordinals, build_fingerprint
from acet.domain.ids import uuid7
from acet.domain.product_profile import ProductProfile
from acet.domain.timeutil import TimePrecision, parse_external_timestamp, utc_now_iso
from acet.ingest.classify import Classification, classify_file
from acet.ingest.discover import discover
from acet.storage import repositories as repo
from acet.storage.content_store import sha256_file

NEAR_DUPLICATE_THRESHOLD = 0.5  # calibrable

FaultHook = Callable[[str], None]


class DuplicatePolicy(StrEnum):
    CANCEL = "cancel"
    ADD_OBSERVATION = "add-observation"


@dataclass(frozen=True)
class PlannedFile:
    path: Path
    sha256: str
    size_bytes: int
    classification: Classification
    role: ComponentRole
    role_confidence: ConfidenceClass


@dataclass
class ImportRequest:
    paths: list[Path]
    product: str
    release_label: str | None = None
    channel: str | None = None
    observed_at: str | None = None
    source_type: ObservationSourceType = ObservationSourceType.USER_IMPORT
    source_label: str | None = None
    on_duplicate: DuplicatePolicy = DuplicatePolicy.CANCEL
    role_overrides: Mapping[str, ComponentRole] = field(default_factory=dict)  # by file name


@dataclass
class ImportResult:
    build_id: str
    build_fingerprint: str
    observation_id: str
    created_build: bool
    new_artifacts: list[str]
    reused_artifacts: list[str]
    status: BuildStatus
    completeness: dict[str, str]
    warnings: list[str]
    files: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "build_id": self.build_id,
            "build_fingerprint": self.build_fingerprint,
            "observation_id": self.observation_id,
            "created_build": self.created_build,
            "new_artifacts": self.new_artifacts,
            "reused_artifacts": self.reused_artifacts,
            "status": self.status.value,
            "completeness": self.completeness,
            "warnings": self.warnings,
            "files": self.files,
        }


def _noop(_: str) -> None:
    return None


def plan_files(paths: Iterable[Path], overrides: Mapping[str, ComponentRole]) -> tuple[list[PlannedFile], list[str]]:
    """DISCOVER + HASH + CLASSIFY, reading sources only."""
    disc = discover(paths)
    if not disc.files:
        raise AcetError("ACET-IMP-001", "no files found")
    planned: list[PlannedFile] = []
    for p in disc.files:
        try:
            sha, size = sha256_file(p)
            cls = classify_file(p)
        except OSError as exc:
            raise AcetError("ACET-IMP-001", f"{type(exc).__name__}: {p.name}") from exc
        role, conf = cls.role, cls.confidence
        if p.name in overrides:
            role, conf = overrides[p.name], ConfidenceClass.HIGH
        planned.append(PlannedFile(p, sha, size, cls, role, conf))
    return planned, disc.warnings


def import_build(ws: Workspace, req: ImportRequest, *, fault: FaultHook = _noop) -> ImportResult:
    ws.require_writable()
    conn = ws.db.conn

    # VALIDATE (metadata)
    product = repo.find_product(conn, req.product)
    if product is None:
        raise AcetError("ACET-NOTFOUND-001", f"product {req.product!r}")
    profile = ProductProfile.parse(repo.loads(product["profile_json"]))
    observed_at: str | None = None
    precision = TimePrecision.UNKNOWN
    if req.observed_at:
        try:
            observed_at, precision = parse_external_timestamp(req.observed_at)
        except ValueError as exc:
            raise AcetError("ACET-IMP-005", f"observed_at: {exc}") from exc

    # DISCOVER / HASH / CLASSIFY
    fault("discover")
    planned, warnings = plan_files(req.paths, req.role_overrides)
    fault("hashed")

    entries = [ComponentEntry(f.role, f.sha256) for f in planned]
    fingerprint = build_fingerprint(entries)

    existing = repo.build_by_fingerprint(conn, fingerprint)
    if existing is not None and req.on_duplicate is DuplicatePolicy.CANCEL:
        raise AcetError(
            "ACET-IMP-004",
            "identical build fingerprint already exists",
            data={"build_id": existing["id"], "options": ["add-observation", "open", "cancel"]},
        )

    # Near duplicate warning (never merges).
    shas = {f.sha256 for f in planned}
    if existing is None:
        for b in conn.execute(
            "SELECT id FROM build WHERE product_id=? AND deleted_at IS NULL", (product["id"],)
        ).fetchall():
            other = {r["sha256"] for r in repo.build_artifacts(conn, b["id"])}
            jac = len(shas & other) / len(shas | other) if shas | other else 0.0
            if jac >= NEAR_DUPLICATE_THRESHOLD:
                warnings.append(
                    f"near-duplicate of build {b['id']} (shared artifacts {len(shas & other)}/{len(shas | other)})"
                )

    # COPY + VERIFY (outside DB transaction). Missing blobs are (re)stored even if
    # the artifact row exists — this repairs dangling references with identical bytes.
    by_sha = {f.sha256: f for f in planned}
    needed = sum(f.size_bytes for f in by_sha.values() if not ws.store.exists(f.sha256))
    ws.store.preflight(needed)
    new_artifacts: list[str] = []
    reused: list[str] = []
    for sha, f in sorted(by_sha.items()):
        res = ws.store.put_file(f.path, source_sha256=sha)
        (new_artifacts if res.created else reused).append(sha)
        fault(f"copied:{sha}")
    fault("before_commit")

    present = {f.role for f in planned}
    completeness = profile.completeness(present)
    if not profile.expected_roles:
        status = BuildStatus.UNASSESSED
    elif all(v is ComponentPresence.PRESENT for v in completeness.values()):
        status = BuildStatus.COMPLETE
    else:
        status = BuildStatus.PARTIAL
    archs = {
        f.classification.arch
        for f in planned
        if f.classification.format in (ArtifactFormat.PE32, ArtifactFormat.PE32_PLUS)
    }
    build_arch = next(iter(archs)) if len(archs) == 1 else None

    now = utc_now_iso()
    obs_id = uuid7()
    with ws.db.transaction() as tx:
        for sha, f in sorted(by_sha.items()):
            row = tx.execute("SELECT integrity_state FROM artifact WHERE sha256=?", (sha,)).fetchone()
            if row is None:
                tx.execute(
                    "INSERT INTO artifact(sha256, size_bytes, mime_hint, format, arch, store_relpath, imported_at,"
                    " integrity_state) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        sha,
                        f.size_bytes,
                        f.classification.mime_hint,
                        f.classification.format.value,
                        f.classification.arch,
                        ws.store.relpath_for(sha),
                        now,
                        IntegrityState.AVAILABLE.value,
                    ),
                )
            elif row["integrity_state"] == IntegrityState.CORRUPTED.value and ws.store.verify(sha):
                tx.execute(
                    "UPDATE artifact SET integrity_state=? WHERE sha256=?", (IntegrityState.AVAILABLE.value, sha)
                )
                repo.audit(tx, "artifact.repaired", "artifact", sha, {})

        if existing is not None:
            build_id = str(existing["id"])
            created = False
        else:
            build_id = uuid7()
            created = True
            release_id = (
                repo.get_or_create_release(tx, product["id"], req.release_label, req.channel)
                if req.release_label
                else None
            )
            tx.execute(
                "INSERT INTO build(id, product_id, release_id, build_fingerprint, arch, platform, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (build_id, product["id"], release_id, fingerprint, build_arch, "windows", status.value, now),
            )
            labels: dict[tuple[str, str], list[str]] = {}
            for f in sorted(planned, key=lambda x: x.path.name):
                labels.setdefault((f.role.value, f.sha256), []).append(f.path.name)
            conf_by = {(f.role.value, f.sha256): f.role_confidence for f in planned}
            for o in assign_ordinals(entries):
                cid = uuid7()
                key = (o.role.value, o.artifact_sha256)
                label = labels[key][o.ordinal] if o.ordinal < len(labels[key]) else None
                tx.execute(
                    "INSERT INTO component(id, build_id, role, role_confidence, label, ordinal) VALUES (?,?,?,?,?,?)",
                    (cid, build_id, o.role.value, conf_by[key].value, label, o.ordinal),
                )
                tx.execute(
                    "INSERT INTO component_artifact(component_id, artifact_sha256, purpose) VALUES (?,?,?)",
                    (cid, o.artifact_sha256, o.purpose),
                )
        source_label = req.source_label or (Path(req.paths[0]).name if req.paths else None)
        tx.execute(
            "INSERT INTO observation(id, build_id, observed_at, time_precision, source_type, source_label, imported_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (obs_id, build_id, observed_at, precision.value, req.source_type.value, source_label, now),
        )
        repo.audit(
            tx,
            "import",
            "build",
            build_id,
            {
                "observation_id": obs_id,
                "created_build": created,
                "new_artifacts": len(new_artifacts),
                "reused_artifacts": len(reused),
            },
        )
        fault("in_commit")

    return ImportResult(
        build_id=build_id,
        build_fingerprint=fingerprint,
        observation_id=obs_id,
        created_build=created,
        new_artifacts=new_artifacts,
        reused_artifacts=reused,
        status=BuildStatus(existing["status"]) if existing else status,
        completeness={k.value: v.value for k, v in completeness.items()},
        warnings=warnings,
        files=[
            {
                "name": f.path.name,
                "sha256": f.sha256,
                "size_bytes": f.size_bytes,
                "role": f.role.value,
                "role_confidence": f.role_confidence.value,
                "format": f.classification.format.value,
            }
            for f in planned
        ],
    )

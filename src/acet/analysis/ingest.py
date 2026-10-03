"""Index validated derived results into queryable tables (function_instance, matcher_result, consensus).

Called after a derived result is registered (or on a cache hit). Idempotent per
derived result for facts; matcher/consensus rows are bound to the analysis run
(INTERPRETATION is per run, ACET-LIN-001).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from acet.analysis.registry import ProcessorSpec
from acet.application.workspace import Workspace

Handler = Callable[[Workspace, str, ProcessorSpec, tuple[str, ...], str, Path, "str | None"], None]


def _handlers() -> dict[str, Handler]:
    from acet.matching import store as mstore

    return {
        "acet.features": mstore.ingest_functions,
        "acet.featurematch": mstore.ingest_matcher,
        "ghidriff.diff": mstore.ingest_matcher,
        "bindiff.diff": mstore.ingest_matcher,
        "qbindiff.diff": mstore.ingest_matcher,
        "acet.consensus": mstore.ingest_consensus,
    }


def ingest_result(
    ws: Workspace,
    run_id: str,
    spec: ProcessorSpec,
    artifacts: tuple[str, ...],
    derived_result_id: str | None,
    output_dir: Path | None,
    processor_run_id: str | None,
) -> None:
    if derived_result_id is None or output_dir is None:
        return
    handler = _handlers().get(spec.id)
    if handler is not None:
        handler(ws, run_id, spec, artifacts, derived_result_id, output_dir, processor_run_id)

"""Completion validation (ACET-ENG-001/002/003, INV-014, ACC-051/053/143).

An exit code of 0 is never sufficient. The verdict combines: termination,
exit code, the provider's completion manifest (schema-valid), presence and
checksums of every expected output, structured error counters, and versioned
provider log rules. Providers cannot declare themselves reliable.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from acet.domain.enums import OperationOutcome
from acet.domain.jsonschema import SchemaValidationError, validate_named
from acet.jobs.supervisor import ProcessResult, Termination

MANIFEST_NAME = "completion-manifest.json"


class CompletionState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INVALID = "invalid"


@dataclass(frozen=True)
class LogRule:
    """A versioned provider log rule: a validation mechanism, not a scientific fact (ACET-ENG-003)."""

    rule_id: str
    pattern: str
    effect: CompletionState  # PARTIAL or INVALID
    description: str


@dataclass
class Verdict:
    state: CompletionState
    outcome: OperationOutcome
    reasons: list[str] = field(default_factory=list)
    manifest: dict[str, Any] | None = None
    matched_rules: list[str] = field(default_factory=list)


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _worst(a: CompletionState, b: CompletionState) -> CompletionState:
    order = [CompletionState.COMPLETE, CompletionState.PARTIAL, CompletionState.INVALID]
    return max(a, b, key=order.index)


def validate_completion(
    proc: ProcessResult,
    output_dir: Path,
    *,
    expected_outputs: Sequence[str],
    log_rules: Sequence[LogRule] = (),
) -> Verdict:
    reasons: list[str] = []
    state = CompletionState.COMPLETE
    manifest: dict[str, Any] | None = None

    if proc.cancelled:
        return Verdict(CompletionState.INVALID, OperationOutcome.CANCELLED, ["cancelled"])
    if proc.termination is not Termination.NORMAL:
        reasons.append(f"termination={proc.termination.value}")
        state = CompletionState.PARTIAL
    if proc.exit_code != 0:
        reasons.append(f"exit_code={proc.exit_code}")
        state = _worst(state, CompletionState.PARTIAL)

    mpath = output_dir / MANIFEST_NAME
    if not mpath.is_file():
        reasons.append("completion manifest missing")
        state = CompletionState.INVALID
    else:
        try:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
            validate_named(manifest, "completion-manifest")
        except (json.JSONDecodeError, SchemaValidationError, UnicodeDecodeError) as exc:
            reasons.append(f"completion manifest invalid: {exc}")
            state = CompletionState.INVALID
            manifest = None
    if manifest is not None:
        declared = CompletionState(manifest["completion_state"])
        state = _worst(state, declared)
        if declared is not CompletionState.COMPLETE:
            reasons.append(f"provider declared {declared.value}")
        if manifest["termination"] != "normal":
            reasons.append(f"manifest termination={manifest['termination']}")
            state = _worst(state, CompletionState.PARTIAL)
        if manifest["engine_reported_errors"] > 0:
            reasons.append(f"engine reported {manifest['engine_reported_errors']} error(s)")
            state = _worst(state, CompletionState.PARTIAL)
        checks: dict[str, str] = manifest["output_checksums"]
        for name in expected_outputs:
            p = output_dir / name
            if not p.is_file():
                reasons.append(f"expected output missing: {name}")
                state = CompletionState.INVALID
            elif name not in checks:
                reasons.append(f"no checksum declared for {name}")
                state = CompletionState.INVALID
            elif _sha(p) != checks[name]:
                reasons.append(f"checksum mismatch: {name}")
                state = CompletionState.INVALID
        missing_decl = set(manifest["expected_outputs"]) - set(manifest["present_outputs"])
        if missing_decl:
            reasons.append(f"provider reports missing outputs {sorted(missing_decl)}")
            state = _worst(state, CompletionState.PARTIAL)
    for leftover in output_dir.glob("*.tmp"):
        reasons.append(f"temporary file present: {leftover.name}")  # ACC-095: never valid output

    matched: list[str] = []
    if log_rules:
        text = b""
        for p in (proc.stdout_path, proc.stderr_path):
            if p.is_file():
                text += p.read_bytes()
        decoded = text.decode("utf-8", "replace")
        for rule in log_rules:
            if re.search(rule.pattern, decoded, re.MULTILINE):
                matched.append(rule.rule_id)
                reasons.append(f"log rule {rule.rule_id}: {rule.description}")
                state = _worst(state, rule.effect)

    outcome = {
        CompletionState.COMPLETE: OperationOutcome.SUCCESS,
        CompletionState.PARTIAL: OperationOutcome.PARTIAL,
        CompletionState.INVALID: OperationOutcome.RETRYABLE_FAILURE
        if proc.termination in (Termination.CRASH, Termination.TIMEOUT)
        else OperationOutcome.PERMANENT_FAILURE,
    }[state]
    if proc.hung:
        outcome = OperationOutcome.RETRYABLE_FAILURE
    return Verdict(state, outcome, reasons, manifest, matched)

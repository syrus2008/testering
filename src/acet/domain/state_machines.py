"""Canonical state machines (§25, §99) with explicit transition tables.

ACET-CLOSE-005: every transition not listed raises ``DomainTransitionError``
and must not be persisted. Persistence code calls ``machine.check(src, dst)``
*before* writing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field


class DomainTransitionError(Exception):
    def __init__(self, machine: str, src: str, dst: str) -> None:
        super().__init__(f"illegal {machine} transition {src} -> {dst}")
        self.machine = machine
        self.src = src
        self.dst = dst


@dataclass(frozen=True)
class StateMachine:
    name: str
    initial: str
    transitions: Mapping[str, frozenset[str]]
    terminal: frozenset[str] = field(default_factory=frozenset)

    @property
    def states(self) -> frozenset[str]:
        out = set(self.transitions)
        for targets in self.transitions.values():
            out |= targets
        return frozenset(out)

    def allowed(self, src: str) -> frozenset[str]:
        return self.transitions.get(src, frozenset())

    def can(self, src: str, dst: str) -> bool:
        return dst in self.allowed(src)

    def check(self, src: str, dst: str) -> str:
        if not self.can(src, dst):
            raise DomainTransitionError(self.name, src, dst)
        return dst

    def walk(self, path: Iterable[str]) -> str:
        """Validate a whole path starting from ``initial``; return final state."""
        state = self.initial
        for nxt in path:
            state = self.check(state, nxt)
        return state


def _sm(name: str, initial: str, edges: Mapping[str, Iterable[str]], terminal: Iterable[str] = ()) -> StateMachine:
    return StateMachine(
        name=name,
        initial=initial,
        transitions={k: frozenset(v) for k, v in edges.items()},
        terminal=frozenset(terminal),
    )


ARTIFACT = _sm(
    "ARTIFACT",
    "DISCOVERED",
    {
        "DISCOVERED": ["HASHING"],
        "HASHING": ["COPYING", "QUARANTINED"],
        "COPYING": ["VERIFYING", "QUARANTINED"],
        "VERIFYING": ["AVAILABLE", "QUARANTINED"],
        "AVAILABLE": ["CORRUPTED", "ORPHANED"],
        # A corrupted blob can be repaired by re-importing identical bytes.
        "CORRUPTED": ["AVAILABLE", "QUARANTINED"],
        "ORPHANED": ["QUARANTINED", "AVAILABLE"],
        "QUARANTINED": ["PURGED", "AVAILABLE"],
    },
    terminal=["PURGED"],
)

ANALYSIS_RUN = _sm(
    "ANALYSIS_RUN",
    "CREATED",
    {
        "CREATED": ["PLANNING", "CANCELLED"],
        "PLANNING": ["QUEUED", "FAILED", "CANCELLED"],
        "QUEUED": ["RUNNING", "CANCELLED", "INTERRUPTED"],
        "RUNNING": ["VALIDATING", "FAILED", "CANCELLED", "INTERRUPTED"],
        "VALIDATING": ["COMPLETED", "COMPLETED_PARTIAL", "FAILED", "INTERRUPTED"],
        "INTERRUPTED": ["RECOVERING"],
        "RECOVERING": ["QUEUED", "FAILED"],
    },
    terminal=["COMPLETED", "COMPLETED_PARTIAL", "FAILED", "CANCELLED"],
)

DERIVED_RESULT = _sm(
    "DERIVED_RESULT",
    "BUILDING",
    {
        "BUILDING": ["VALIDATING"],
        "VALIDATING": ["CURRENT", "INCOMPLETE", "FAILED"],
        "CURRENT": ["STALE", "CORRUPTED"],
        "STALE": ["REBUILDING", "CORRUPTED"],
        "REBUILDING": ["CURRENT", "FAILED"],
    },
)

UPDATE = _sm(
    "UPDATE",
    "AVAILABLE",
    {
        "AVAILABLE": ["DOWNLOADING", "FAILED"],
        "DOWNLOADING": ["DOWNLOADED", "FAILED"],
        "DOWNLOADED": ["VERIFYING", "FAILED"],
        "VERIFYING": ["VERIFIED", "FAILED"],
        "VERIFIED": ["STAGING", "FAILED"],
        "STAGING": ["STAGED", "FAILED"],
        "STAGED": ["APPLYING", "FAILED"],
        "APPLYING": ["VALIDATING", "ROLLBACK"],
        "VALIDATING": ["COMMITTED", "ROLLBACK"],
        "ROLLBACK": ["ROLLED_BACK", "RECOVERY_REQUIRED"],
    },
    terminal=["COMMITTED", "FAILED", "ROLLED_BACK", "RECOVERY_REQUIRED"],
)

JOB = _sm(
    "JOB",
    "QUEUED",
    {
        "QUEUED": ["PREPARING", "CANCELLING", "BLOCKED_DEPENDENCY", "INTERRUPTED"],
        "BLOCKED_DEPENDENCY": ["QUEUED", "CANCELLING", "FAILED_PERMANENT"],
        "PREPARING": ["RUNNING", "CANCELLING", "FAILED_RETRYABLE", "FAILED_PERMANENT", "INTERRUPTED"],
        "RUNNING": [
            "PAUSING",
            "POST_PROCESSING",
            "CANCELLING",
            "FAILED_RETRYABLE",
            "FAILED_PERMANENT",
            "INTERRUPTED",
            "HUNG",
        ],
        "PAUSING": ["PAUSED", "RUNNING", "CANCELLING", "INTERRUPTED"],
        "PAUSED": ["RESUMING", "CANCELLING", "INTERRUPTED"],
        "RESUMING": ["RUNNING", "FAILED_RETRYABLE", "INTERRUPTED"],
        "POST_PROCESSING": ["COMPLETED", "FAILED_RETRYABLE", "FAILED_PERMANENT", "INTERRUPTED"],
        "HUNG": ["CANCELLING", "FAILED_RETRYABLE"],  # ACET-JOB-003: HUNG -> controlled stop
        "CANCELLING": ["CANCELLED"],
        "FAILED_RETRYABLE": ["QUEUED", "FAILED_PERMANENT"],
        "INTERRUPTED": ["RECOVERING"],
        "RECOVERING": ["QUEUED", "FAILED_PERMANENT"],
    },
    terminal=["COMPLETED", "CANCELLED", "FAILED_PERMANENT"],
)

ALL_MACHINES: tuple[StateMachine, ...] = (ARTIFACT, ANALYSIS_RUN, DERIVED_RESULT, UPDATE, JOB)

"""Robust historical baselines (spec §24). Profile ``baseline-robust@1`` (thresholds calibrable).

Per product + component role + metric: median and MAD of past values. A value
is NORMAL / UNUSUAL / EXTREME by robust z-score; with too little history the
class is UNKNOWN (never NORMAL by default). Distributions are never shared
across products.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from enum import StrEnum

PROFILE = "baseline-robust@1"
MIN_HISTORY = 5
UNUSUAL_Z = 3.5
EXTREME_Z = 7.0


class BaselineClass(StrEnum):
    NORMAL = "NORMAL"
    UNUSUAL = "UNUSUAL"
    EXTREME = "EXTREME"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class BaselineResult:
    cls: BaselineClass
    n: int
    median: float | None
    mad: float | None
    robust_z: float | None
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "class": self.cls.value,
            "n": self.n,
            "median": self.median,
            "mad": self.mad,
            "robust_z": self.robust_z,
            "reason": self.reason,
            "profile": PROFILE,
        }


def classify(value: float | None, history: list[float]) -> BaselineResult:
    if value is None:
        return BaselineResult(BaselineClass.UNKNOWN, len(history), None, None, None, "value not measured")
    if len(history) < MIN_HISTORY:
        return BaselineResult(
            BaselineClass.UNKNOWN,
            len(history),
            None,
            None,
            None,
            f"insufficient history ({len(history)} < {MIN_HISTORY})",
        )
    med = statistics.median(history)
    mad = statistics.median(abs(x - med) for x in history)
    z = (0.0 if value == med else float("inf")) if mad == 0 else 0.6745 * (value - med) / mad
    az = abs(z)
    cls = (
        BaselineClass.NORMAL if az < UNUSUAL_Z else (BaselineClass.UNUSUAL if az < EXTREME_Z else BaselineClass.EXTREME)
    )
    return BaselineResult(cls, len(history), round(med, 6), round(mad, 6), None if z == float("inf") else round(z, 4))


def percentiles(history: list[float]) -> dict[str, float] | None:
    if len(history) < 2:
        return None
    qs = statistics.quantiles(history, n=20, method="inclusive")
    return {"p5": qs[0], "p50": statistics.median(history), "p95": qs[-1]}

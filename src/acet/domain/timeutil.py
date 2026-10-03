"""Time handling (ACET-TIME-002): persisted system timestamps are UTC ISO-8601."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum


class TimePrecision(StrEnum):
    """Precision of an externally sourced timestamp such as ``observed_at``."""

    EXACT = "EXACT"
    SECOND = "SECOND"
    MINUTE = "MINUTE"
    HOUR = "HOUR"
    DAY = "DAY"
    MONTH = "MONTH"
    YEAR = "YEAR"
    UNKNOWN = "UNKNOWN"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_external_timestamp(value: str) -> tuple[str, TimePrecision]:
    """Parse a user supplied ``observed_at`` and return (normalized, precision).

    Accepted forms: ``YYYY``, ``YYYY-MM``, ``YYYY-MM-DD`` or a full ISO-8601
    datetime. Datetimes with an offset are converted to UTC; naive datetimes are
    rejected because their timezone is unknown and guessing would be an
    inference presented as a fact.
    """
    v = value.strip()
    if len(v) == 4 and v.isdigit():
        return v, TimePrecision.YEAR
    if len(v) == 7 and v[4] == "-":
        datetime.strptime(v, "%Y-%m")
        return v, TimePrecision.MONTH
    if len(v) == 10:
        datetime.strptime(v, "%Y-%m-%d")
        return v, TimePrecision.DAY
    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("datetime without timezone; append 'Z' or an offset, or use a date")
    dt = dt.astimezone(UTC)
    precision = TimePrecision.SECOND if dt.microsecond == 0 else TimePrecision.EXACT
    return dt.isoformat().replace("+00:00", "Z"), precision

"""Closed vocabularies of the spec. Values are persisted; never rename a member."""

from __future__ import annotations

from enum import StrEnum


class DataCategory(StrEnum):
    """§6 — mutability class of stored data."""

    SOURCE = "SOURCE"
    FACT = "FACT"
    DERIVED = "DERIVED"
    INTERPRETATION = "INTERPRETATION"
    HUMAN = "HUMAN"


class ComponentRole(StrEnum):
    """§13."""

    KERNEL_DRIVER = "KERNEL_DRIVER"
    SERVICE = "SERVICE"
    USER_MODULE = "USER_MODULE"
    EXECUTABLE = "EXECUTABLE"
    LAUNCHER = "LAUNCHER"
    CONFIGURATION = "CONFIGURATION"
    DATA = "DATA"
    OTHER = "OTHER"


class ConfidenceClass(StrEnum):
    """Strength classes shown before empirical calibration (ACET-BEN-003, ADR-0008)."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class BuildStatus(StrEnum):
    """ACET-IMP-006: a build may be PARTIAL; missing components are UNKNOWN."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNASSESSED = "UNASSESSED"


class ComponentPresence(StrEnum):
    PRESENT = "PRESENT"
    UNKNOWN = "UNKNOWN"  # never "ABSENT" by implication (ACET-IMP-006, ACC-047)


class IntegrityState(StrEnum):
    """Artifact state machine (§99) as persisted in ``artifact.integrity_state``."""

    DISCOVERED = "DISCOVERED"
    HASHING = "HASHING"
    COPYING = "COPYING"
    VERIFYING = "VERIFYING"
    AVAILABLE = "AVAILABLE"
    CORRUPTED = "CORRUPTED"
    ORPHANED = "ORPHANED"
    QUARANTINED = "QUARANTINED"
    PURGED = "PURGED"


class ArtifactFormat(StrEnum):
    PE32 = "PE32"
    PE32_PLUS = "PE32+"
    UNKNOWN_BINARY = "UNKNOWN_BINARY"
    TEXT = "TEXT"
    UNKNOWN = "UNKNOWN"


class ObservationSourceType(StrEnum):
    USER_IMPORT = "USER_IMPORT"
    ARCHIVE = "ARCHIVE"
    ACETPACK = "ACETPACK"
    OTHER = "OTHER"


class OperationOutcome(StrEnum):
    """§95 — closed taxonomy of operation results (ACET-CLOSE-002)."""

    SUCCESS = "SUCCESS"
    SUCCESS_WITH_WARNINGS = "SUCCESS_WITH_WARNINGS"
    PARTIAL = "PARTIAL"
    SKIPPED_UNSUPPORTED = "SKIPPED_UNSUPPORTED"
    SKIPPED_INCOMPATIBLE = "SKIPPED_INCOMPATIBLE"
    SKIPPED_POLICY = "SKIPPED_POLICY"
    ABSTAIN = "ABSTAIN"
    CANCELLED = "CANCELLED"
    INTERRUPTED = "INTERRUPTED"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    PERMANENT_FAILURE = "PERMANENT_FAILURE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    SECURITY_REJECTION = "SECURITY_REJECTION"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    INTERNAL_INVARIANT_VIOLATION = "INTERNAL_INVARIANT_VIOLATION"


class FailureFamily(StrEnum):
    """§96 — closed taxonomy of failure causes (ACET-CLOSE-003)."""

    INPUT = "INPUT"
    FORMAT = "FORMAT"
    STORAGE = "STORAGE"
    DATABASE = "DATABASE"
    ENGINE = "ENGINE"
    PROTOCOL = "PROTOCOL"
    RESOURCE = "RESOURCE"
    TIMEOUT = "TIMEOUT"
    CANCELLATION = "CANCELLATION"
    OS = "OS"
    SECURITY = "SECURITY"
    INTEGRITY = "INTEGRITY"
    COMPATIBILITY = "COMPATIBILITY"
    CONFIGURATION = "CONFIGURATION"
    NETWORK = "NETWORK"
    UPDATE = "UPDATE"
    MIGRATION = "MIGRATION"
    EXPORT = "EXPORT"
    INTERNAL = "INTERNAL"


class MeasurementState(StrEnum):
    """§97. UNKNOWN is never mapped to 0 (ACET-DATA-002, ACET-CHG-001)."""

    MEASURED = "MEASURED"
    NOT_MEASURED = "NOT_MEASURED"
    UNSUPPORTED = "UNSUPPORTED"
    INCOMPATIBLE = "INCOMPATIBLE"
    PARTIAL = "PARTIAL"
    UNRELIABLE = "UNRELIABLE"
    OUT_OF_DISTRIBUTION = "OUT_OF_DISTRIBUTION"


class InferenceState(StrEnum):
    """§97."""

    CONFIRMED_BY_RULE = "CONFIRMED_BY_RULE"
    STRONG = "STRONG"
    PROBABLE = "PROBABLE"
    AMBIGUOUS = "AMBIGUOUS"
    CONFLICTING = "CONFLICTING"
    UNRESOLVED = "UNRESOLVED"
    ABSTAIN = "ABSTAIN"


class MatchState(StrEnum):
    """§20 — matcher/consensus decision states."""

    EXACT = "EXACT"
    STRONG = "STRONG"
    PROBABLE = "PROBABLE"
    AMBIGUOUS = "AMBIGUOUS"
    CONFLICT = "CONFLICT"
    UNRESOLVED = "UNRESOLVED"
    ABSTAIN = "ABSTAIN"


class LineageRelation(StrEnum):
    """§22."""

    CONTINUATION = "CONTINUATION"
    MODIFIED = "MODIFIED"
    SPLIT_PARENT = "SPLIT_PARENT"
    MERGE_PARENT = "MERGE_PARENT"
    DISAPPEARED = "DISAPPEARED"
    RESURRECTED_CANDIDATE = "RESURRECTED_CANDIDATE"
    UNRESOLVED = "UNRESOLVED"


class EvidenceFamily(StrEnum):
    """§21 — engines sharing a family are NOT independent evidence."""

    IDENTITY = "identity"
    INSTRUCTION = "instruction"
    CFG = "cfg"
    CALLGRAPH = "callgraph"
    DATA_REFERENCE = "data-reference"
    SEMANTIC = "semantic"
    HISTORICAL_LINEAGE = "historical-lineage"


class ChangeDimension(StrEnum):
    """§23 — dimensions stay separate; no global score (ACC-016)."""

    BINARY = "BINARY"
    BUILD = "BUILD"
    STRUCTURAL = "STRUCTURAL"
    SEMANTIC = "SEMANTIC"
    DEPLOYMENT = "DEPLOYMENT"
    ECOSYSTEM = "ECOSYSTEM"
    ANALYSIS_RELIABILITY = "ANALYSIS_RELIABILITY"


class CacheState(StrEnum):
    """§27."""

    CURRENT = "CURRENT"
    STALE = "STALE"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


class SourceClass(StrEnum):
    """§83 — external event source classes."""

    OFFICIAL = "OFFICIAL"
    RESEARCH = "RESEARCH"
    COMMUNITY = "COMMUNITY"
    LOCAL_NOTE = "LOCAL_NOTE"


class DeterminismClass(StrEnum):
    """§118."""

    D0 = "D0"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"


class Capability(StrEnum):
    """§18 — the UI depends on capabilities, never engine names (ACC-033)."""

    DISASSEMBLY = "DISASSEMBLY"
    FUNCTION_EXTRACTION = "FUNCTION_EXTRACTION"
    STRUCTURAL_DIFF = "STRUCTURAL_DIFF"
    PROGRAMMABLE_DIFF = "PROGRAMMABLE_DIFF"
    SEMANTIC_FEATURES = "SEMANTIC_FEATURES"
    REPORT_EXPORT = "REPORT_EXPORT"


class JobPriority(StrEnum):
    """ACET-JOB-004."""

    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    INTERACTIVE = "INTERACTIVE"


class SystemHealth(StrEnum):
    """§28 top-bar state."""

    READY = "READY"
    DEGRADED = "DEGRADED"
    ACTION_REQUIRED = "ACTION_REQUIRED"

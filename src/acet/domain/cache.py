"""Analysis cache key (ACET-ANA-004, PROP-004, INV-010)."""

from __future__ import annotations

from collections.abc import Sequence

from acet.domain.canonical import canonical_hash
from acet.domain.ids import require_sha256


def cache_key(
    processor_id: str,
    processor_version: str,
    ordered_input_hashes: Sequence[str],
    config_hash: str,
    feature_schema_version: int,
) -> str:
    """SHA256(processor_id + processor_version + ordered_input_hashes + config_hash + feature_schema_version).

    Encoded as canonical JSON of an ordered array to make concatenation
    unambiguous (``"ab"+"c"`` vs ``"a"+"bc"``). Input order is significant by
    definition ("ordered_input_hashes").
    """
    for h in ordered_input_hashes:
        require_sha256(h)
    require_sha256(config_hash)
    return canonical_hash(
        [processor_id, processor_version, list(ordered_input_hashes), config_hash, int(feature_schema_version)]
    )

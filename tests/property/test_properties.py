"""Property-based tests (spec §103)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from acet.domain.cache import cache_key
from acet.domain.enums import ComponentRole
from acet.domain.fingerprint import ComponentEntry, build_fingerprint
from acet.domain.state_machines import ALL_MACHINES, DomainTransitionError
from acet.storage.content_store import ContentStore, sha256_file

shas = st.binary(min_size=0, max_size=64).map(lambda b: hashlib.sha256(b).hexdigest())
entries = st.builds(ComponentEntry, st.sampled_from(list(ComponentRole)), shas, st.sampled_from(["primary", "pdb"]))


@pytest.mark.acceptance("ACC-113")
@given(st.lists(entries, min_size=1, max_size=12), st.randoms())
def test_prop002_fingerprint_permutation_invariant(items, rnd):
    shuffled = list(items)
    rnd.shuffle(shuffled)
    assert build_fingerprint(items) == build_fingerprint(shuffled)


@given(st.binary(max_size=4096), st.integers(min_value=0, max_value=4095))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_prop001_hash_determinism(tmp_path: Path, data: bytes, flip: int):
    p = tmp_path / "f"
    p.write_bytes(data)
    assert sha256_file(p)[0] == hashlib.sha256(data).hexdigest()
    if data:
        i = flip % len(data)
        mutated = data[:i] + bytes([data[i] ^ 0x01]) + data[i + 1 :]
        p.write_bytes(mutated)
        assert sha256_file(p)[0] != hashlib.sha256(data).hexdigest()


@given(st.lists(st.binary(max_size=256), min_size=1, max_size=5), st.integers(min_value=1, max_value=4))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=30)
def test_prop003_import_idempotence_blob_count(tmp_path_factory, payloads, repeats):
    root = tmp_path_factory.mktemp("ws")
    store = ContentStore(root)
    src = root / "src"
    src.mkdir()
    files = []
    for i, data in enumerate(payloads):
        f = src / f"f{i}"
        f.write_bytes(data)
        files.append(f)
    for _ in range(repeats):
        for f in files:
            store.put_file(f)
    assert sum(1 for _ in store.iter_blobs()) == len(set(payloads))


@given(st.text(min_size=1), st.text(min_size=1), st.lists(shas, max_size=4), shas, st.integers(0, 10))
def test_prop004_cache_key_idempotence(pid, ver, inputs, cfg, fsv):
    assert cache_key(pid, ver, inputs, cfg, fsv) == cache_key(pid, ver, list(inputs), cfg, fsv)


@given(st.data())
def test_prop005_state_safety(data):
    sm = data.draw(st.sampled_from(ALL_MACHINES))
    all_states = sorted(sm.states)
    state = sm.initial
    for _ in range(data.draw(st.integers(1, 30))):
        nxt = data.draw(st.sampled_from(all_states))
        if sm.can(state, nxt):
            state = sm.check(state, nxt)
        else:
            with pytest.raises(DomainTransitionError):
                sm.check(state, nxt)
            # state unchanged after a refused transition
    assert state in sm.states

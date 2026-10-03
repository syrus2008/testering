"""Adapter normalization on real recorded provider outputs, PE facts, gates (spec §17, §69, §70, §72)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from acet.analysis.pe import pe_facts
from acet.engines import bindiff, ghidriff, qbindiff_provider
from acet.engines.quirks import applicable_limitations, load_known_limitations
from acet.matching.consensus import consensus
from acet.matching.featurematch import match_features

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "datasets" / "demo"
GT = json.loads((DEMO / "ground_truth.json").read_text(encoding="utf-8"))
V1 = GT["functions"]["guardcore.dll"]["v1"]
V2 = GT["functions"]["guardcore.dll"]["v2"]


def test_ghidriff_normalization_on_real_output():
    g = DEMO / "golden" / "ghidriff"
    d = json.loads((g / "guardcore-v1-v2.ghidriff.json").read_text())
    m = json.loads((g / "guardcore-v1-v2.ghidriff.matches.json").read_text())
    res = ghidriff.normalize(d, m, "ghidriff-1.0.0")
    by_left = {p["left"]: p for p in res["pairs"]}
    assert by_left[V1["mem_compare"]]["decision"] == "EXACT"
    assert by_left[V1["mem_compare"]]["evidence"][0]["family"] == "instruction"
    assert by_left[V1["GuardInit"]]["evidence"][0]["family"] == "identity"  # exported symbol
    assert {u["left"] for u in res["unmatched_left"]}  # deleted functions are explicit claims
    assert all(p["correlators"] for p in res["pairs"])  # raw correlator names preserved


def test_bindiff_normalization_on_real_output(tmp_path):
    db = tmp_path / "r.BinDiff"
    shutil.copyfile(DEMO / "golden" / "bindiff" / "guardcore-v1-v2.BinDiff", db)
    res = bindiff.normalize(db, "bindiff-8")
    by_left = {p["left"]: p for p in res["pairs"]}
    assert by_left[V1["mem_compare"]]["decision"] == "EXACT"
    assert by_left[V1["crc32"]]["right"] == V2["crc32"]
    assert by_left[V1["GuardInit"]]["evidence"][0]["family"] == "identity"
    assert all("raw_confidence" in p and "algorithm" in p for p in res["pairs"])  # ACC-048
    assert bindiff.families_for("function: address sequence") == ()


@pytest.mark.acceptance("ACC-072")
def test_qbindiff_memory_gate():
    assert qbindiff_provider.gate(100, 200, 5000) is None
    assert "exceeds validated budget" in qbindiff_provider.gate(10, 6000, 5000)  # type: ignore[operator]
    assert qbindiff_provider.gate(None, 10, 5000) is None


@pytest.mark.acceptance("ACC-074")
def test_known_limitations_registry():
    kls = load_known_limitations()
    assert {k.provider_id for k in kls} >= {"bindiff", "binexport", "qbindiff", "ghidra"}
    assert applicable_limitations("bindiff", "8")
    assert any(k.matches_log("sqlite: database or disk is full") for k in applicable_limitations("bindiff", None))


def _features(version: str, comp: str = "52c429bbf5e77c79e5bdf39868fb20084694579ca800dbb2895fdf7292d0ab5e"):
    from acet.analysis.processors.features import featurize

    return featurize(json.loads((DEMO / "golden" / "ghidra" / f"{comp}.json").read_text()))


def test_featurematch_and_consensus_on_golden_exports():
    left = _features("v1")
    right = _features("v2", "93525c344299cd35de42c8be8439ba2a54f877ea5c1f8ab00d85fdb2e052941a")
    fm = match_features(left, right)
    pairs = {p["left"]: p for p in fm["pairs"]}
    assert pairs[V1["xor_obfuscate"]]["right"] == V2["obfuscate_buffer"]
    assert pairs[V1["xor_obfuscate"]]["decision"] == "EXACT"
    truth = {
        p["left"]: p["right"]
        for t in GT["transitions"]
        if t["component"] == "guardcore.dll" and t["from"] == "v1"
        for p in t["pairs"]
    }
    wrong = [p for p in fm["pairs"] if p["left"] in truth and truth[p["left"]] != p["right"]]
    assert not wrong
    c = consensus(left, right, [fm], ["acet.featurematch", "ghidriff"])
    assert c["missing_engines"] == ["ghidriff"] and c["probability_available"] is False
    assert all("raw_score" in s for m in c["matches"] for s in m.get("supporting_evidence", []))


def test_consensus_never_averages_and_detects_conflict():
    feats = {"functions": [{"entry": 1}, {"entry": 2}]}
    right = {"functions": [{"entry": 10}, {"entry": 20}]}
    a = {
        "engine": "a",
        "families_used": ["instruction"],
        "pairs": [
            {
                "left": 1,
                "right": 10,
                "raw_score": 0.9,
                "decision": "STRONG",
                "evidence": [
                    {"family": "instruction", "score": 0.9, "supports": True},
                    {"family": "cfg", "score": 0.9, "supports": True},
                ],
            }
        ],
        "unmatched_left": [],
    }
    b = {
        "engine": "b",
        "families_used": ["cfg"],
        "pairs": [
            {
                "left": 1,
                "right": 20,
                "raw_score": 0.95,
                "decision": "STRONG",
                "evidence": [
                    {"family": "cfg", "score": 0.95, "supports": True},
                    {"family": "callgraph", "score": 0.9, "supports": True},
                ],
            }
        ],
        "unmatched_left": [],
    }
    c = consensus(feats, right, [a, b], ["a", "b"])
    m1 = next(m for m in c["matches"] if m["left"] == 1)
    assert m1["decision"] == "CONFLICT" and m1["contradicting_evidence"]
    assert "score" not in m1 and "probability" not in json.dumps(m1)  # no fused score (ACC-016/028)
    same_family = {
        "engine": "c",
        "families_used": ["instruction"],
        "pairs": [
            {
                "left": 2,
                "right": 20,
                "raw_score": 0.99,
                "decision": "STRONG",
                "evidence": [{"family": "instruction", "score": 0.99, "supports": True}],
            }
        ],
        "unmatched_left": [],
    }
    same_family2 = {**same_family, "engine": "d"}
    c2 = consensus(feats, right, [same_family, same_family2], ["c", "d"])
    m2 = next(m for m in c2["matches"] if m["left"] == 2)
    assert m2["engine_count"] == 2 and m2["evidence_diversity"] == 1  # same family ≠ independent (ACC-049)


@pytest.mark.parametrize("v", ["v1", "v2", "v3"])
def test_pe_facts_on_real_demo_binaries(v):
    for name in ("guardcore.dll", "guardsvc.exe"):
        facts = pe_facts((DEMO / "builds" / v / name).read_bytes())
        assert facts["format_state"] == "MEASURED"
        assert all(fam["state"] in ("MEASURED", "NOT_MEASURED") for k, fam in facts.items() if isinstance(fam, dict))
        secs = {s["name"]: s for s in facts["sections"]["value"]}
        assert ".text" in secs and 0 < secs[".text"]["entropy"] <= 8
        assert facts["load_config"]["value"]["present"] is False or facts["load_config"]["value"]["size"]
        assert facts["rich_header"]["value"]["present"] is False  # lld-link writes no Rich header


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=3583), st.binary(min_size=1, max_size=16))
def test_pe_parser_never_crashes_on_mutations(pos, patch):
    data = bytearray((DEMO / "builds" / "v1" / "guardcore.dll").read_bytes())
    data[pos : pos + len(patch)] = patch
    facts = pe_facts(bytes(data))
    assert facts["format_state"] in ("MEASURED", "UNSUPPORTED")


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=2048))
def test_pe_parser_on_random_bytes(data):
    assert pe_facts(b"MZ" + data)["format_state"] in ("MEASURED", "UNSUPPORTED")


def test_asn1_reader_basics():
    from acet.analysis import asn1

    der = bytes.fromhex("300d06092a864886f70d01070205 00".replace(" ", ""))
    t = asn1.read_tlv(der, 0)
    kids = t.children()
    assert asn1.oid(kids[0]) == "1.2.840.113549.1.7.2"
    with pytest.raises(asn1.Asn1Error):
        asn1.read_tlv(b"\x30\x84\xff\xff\xff\xff", 0)

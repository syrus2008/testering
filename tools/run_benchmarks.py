"""Regenerate the committed benchmark results (benchmarks/*.json) from the real pipeline.

Usage:
  python tools/run_benchmarks.py                     # golden replay (recorded real Ghidra exports)
  ACET_GHIDRA_DIR=... python tools/run_benchmarks.py --live

Writes benchmarks/demo-STANDARD@1-{replay,live}.json (Benchmark Lab on datasets/demo) and
benchmarks/resurrection-STANDARD@1-{replay,live}.json (lineage scenarios on datasets/resurrection).
Baselines (benchmarks/baselines/) are never updated here: accepting a new baseline is a reviewed
copy, so a regression cannot silently become the reference.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
TOLERANCES = {"precision": 0.02, "recall": 0.03, "false_new_rate": 0.02}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Regenerate benchmark results.")
    ap.add_argument("--live", action="store_true", help="use the live Engine Pack (ACET_GHIDRA_DIR)")
    args = ap.parse_args(argv)
    mode = "live" if args.live else "replay"
    if args.live:
        if not os.environ.get("ACET_GHIDRA_DIR"):
            print("--live needs ACET_GHIDRA_DIR", file=sys.stderr)
            return 2
        os.environ.pop("ACET_GHIDRA_REPLAY_DIR", None)
    os.environ.setdefault("ACET_HOME", tempfile.mkdtemp(prefix="acet-bench-home-"))

    from acet.application.workspace import create_workspace
    from acet.benchmark import scenarios
    from acet.benchmark.runner import run_benchmark
    from acet.engines.environment import detect

    def ws(name: str):  # type: ignore[no-untyped-def]
        return create_workspace(name, Path(tempfile.mkdtemp(prefix="acet-bench-")))

    demo = ROOT / "datasets" / "demo"
    if not args.live:
        os.environ["ACET_GHIDRA_REPLAY_DIR"] = str(demo / "golden" / "ghidra")
    env = detect()
    engines = (
        f"live: Ghidra {env.providers['ghidra'].version}"
        + (f" + ghidriff {env.providers['ghidriff'].version}" if env.available("ghidriff") else "")
        if args.live
        else "replay: recorded Ghidra exports, no ghidriff"
    )
    w = ws("demo")
    res = run_benchmark(w, demo, "STANDARD@1", env=env)
    w.close()
    out = {
        "dataset": "acet-demo@1",
        "profile": "STANDARD@1",
        "engines": engines,
        "summary": res["summary"],
        "tolerances": TOLERANCES,
    }
    out["summary"].pop("performance", None)
    (ROOT / "benchmarks" / f"demo-STANDARD@1-{mode}.json").write_text(json.dumps(out, indent=2) + "\n")
    print("demo", json.dumps(out["summary"]["lineage"]))

    corpus = ROOT / "datasets" / "resurrection"
    if not args.live:
        os.environ["ACET_GHIDRA_REPLAY_DIR"] = str(corpus / "golden" / "ghidra")
    results = {}
    for scen in scenarios.load(corpus)["scenarios"]:
        w = ws(scen)
        r = scenarios.run_scenario(w, corpus, scen)
        w.close()
        results[scen] = {"relations": r["relations"], "lineage": r["lineage"]}
        print(scen, json.dumps(r["lineage"]))
    report = {
        "dataset": "acet-resurrection@1",
        "profile": "STANDARD@1",
        "engines": engines,
        "lineage_rules": "lineage@2 (resurrect@2)",
        "scenarios": results,
    }
    (ROOT / "benchmarks" / f"resurrection-STANDARD@1-{mode}.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Record golden Ghidra exports for a dataset (input of the golden replay provider used by CI).

Usage: ACET_GHIDRA_DIR=... python tools/record_golden.py <dataset dir> [--out <dir>]

Imports every file under <dataset>/builds/*/ into a throw-away workspace, runs the real
``ghidra.extract`` processor through the normal orchestrator (STANDARD profile) and writes each
export to <dataset>/golden/ghidra/<artifact sha256>.json. Refuses to run without a live Ghidra:
a golden file is only ever a recording of the real engine.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main(argv: list[str] | None = None) -> int:
    from acet.analysis.orchestrator import analyze_build
    from acet.analysis.results import derived_for_artifact
    from acet.application.products import create_product
    from acet.application.workspace import create_workspace
    from acet.engines.environment import detect
    from acet.ingest.importer import DuplicatePolicy, ImportRequest, import_build

    ap = argparse.ArgumentParser(description="Record golden Ghidra exports for a dataset.")
    ap.add_argument("dataset", type=Path)
    ap.add_argument("--out", type=Path, help="default: <dataset>/golden/ghidra")
    args = ap.parse_args(argv)
    env = detect()
    gh = env.providers["ghidra"]
    if not gh.available or gh.extra.get("replay"):
        print("a live Ghidra is required (ACET_GHIDRA_DIR)", file=sys.stderr)
        return 2
    out = args.out or args.dataset / "golden" / "ghidra"
    out.mkdir(parents=True, exist_ok=True)
    ws = create_workspace("golden", Path(tempfile.mkdtemp(prefix="acet-golden-")))
    try:
        pid = create_product(ws, "golden recording")
        for build_dir in sorted(p for p in (args.dataset / "builds").iterdir() if p.is_dir()):
            res = import_build(
                ws,
                ImportRequest(
                    [build_dir], pid, release_label=build_dir.name, on_duplicate=DuplicatePolicy.ADD_OBSERVATION
                ),
            )
            run = analyze_build(ws, res.build_id, "STANDARD@1", env=env)
            for f in res.files:
                data = derived_for_artifact(ws, "ghidra.extract", f["sha256"])
                if data is None:
                    print(f"no Ghidra export for {build_dir.name}/{f['name']} (run {run.status})", file=sys.stderr)
                    return 1
                (out / f"{f['sha256']}.json").write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
                print(f"{build_dir.name}/{f['name']}: {len(data['functions'])} functions ({data['engine_version']})")
    finally:
        ws.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

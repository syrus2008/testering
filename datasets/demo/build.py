"""Rebuild the ACET demo dataset with clang + lld-link (reproducible flags, no timestamps).

Usage: python datasets/demo/build.py   (requires clang and lld-link)
Produces builds/v{1,2,3}/{guardcore.dll,guardsvc.exe}, maps/*.map and ground_truth.json.
The map files carry the names used as ground truth; they are never given to analyzers (ACET-BEN-001).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = "x86_64-pc-windows-msvc"
CFLAGS = ["--target=" + TARGET, "-O1", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-nostdlib",
          "-fuse-ld=lld", "-mno-stack-arg-probe"]
LDFLAGS = ["-Wl,/brepro", "-Wl,/nodefaultlib", "-Wl,/opt:noicf", "-Wl,/opt:noref"]

# Logical identity of functions across versions (ground truth relations).
RENAMES = {("v1", "v2"): {"xor_obfuscate": "obfuscate_buffer"}}
SPLITS = {("v1", "v2"): {"parse_config": ["parse_config", "parse_line"]}}
MERGES = {("v1", "v2"): {"validate_header_full": ["validate_header", "check_magic"]}}
MODIFIED = {("v1", "v2"): ["checksum32", "parse_config", "GuardScan", "parse_args"],
            ("v2", "v3"): ["policy_decide", "GuardScan", "GuardTick", "schedule_loop"]}
RESURRECTED = {("v2", "v3"): ["report_event"]}


def build(version: int) -> None:
    out = HERE / "builds" / f"v{version}"
    maps = HERE / "maps"
    out.mkdir(parents=True, exist_ok=True)
    maps.mkdir(exist_ok=True)
    common = [*CFLAGS, f"-DVERSION={version}"]
    subprocess.run(["clang", *common, "-shared", *LDFLAGS, "-Wl,/entry:_DllMainCRTStartup",
                    f"-Wl,/map:{maps / f'guardcore-v{version}.map'}", "-o", str(out / "guardcore.dll"),
                    str(HERE / "src" / "guardcore.c")], check=True)
    subprocess.run(["clang", *common, *LDFLAGS, "-Wl,/entry:mainCRTStartup", "-Wl,/subsystem:console",
                    f"-Wl,/map:{maps / f'guardsvc-v{version}.map'}", "-o", str(out / "guardsvc.exe"),
                    str(HERE / "src" / "guardsvc.c")], check=True)
    for junk in out.glob("*.lib"):
        junk.unlink()
    for junk in out.glob("*.exp"):
        junk.unlink()


def parse_map(path: Path) -> dict[str, int]:
    """lld-link map 'Publics by Value' lines: '<sec>:<off>  <name>  <Rva+Base>  <object>' (code section only)."""
    funcs: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\s*0001:[0-9a-fA-F]{8}\s+([A-Za-z_][A-Za-z0-9_]*)\s+([0-9a-fA-F]{16})\s", line)
        if m and not m.group(1).startswith("_DllMain"):
            funcs[m.group(1)] = int(m.group(2), 16)
    return funcs


def ground_truth() -> dict[str, object]:
    comps = {"guardcore.dll": "guardcore", "guardsvc.exe": "guardsvc"}
    versions = ["v1", "v2", "v3"]
    functions: dict[str, dict[str, dict[str, int]]] = {}
    for comp, stem in comps.items():
        functions[comp] = {v: parse_map(HERE / "maps" / f"{stem}-{v}.map") for v in versions}
    transitions = []
    for a, b in (("v1", "v2"), ("v2", "v3")):
        for comp in comps:
            fa, fb = functions[comp][a], functions[comp][b]
            ren = RENAMES.get((a, b), {})
            pairs = []
            for name, addr in sorted(fa.items()):
                target = ren.get(name, name)
                if target in fb and not any(name in v for v in MERGES.get((a, b), {}).values()):
                    rel = "MODIFIED" if name in MODIFIED.get((a, b), []) else "CONTINUATION"
                    pairs.append({"left": addr, "right": fb[target], "name": name, "relation": rel})
            splits = [{"left": fa[k], "rights": [fb[x] for x in v if x in fb], "name": k}
                      for k, v in SPLITS.get((a, b), {}).items() if k in fa]
            merges = [{"lefts": [fa[x] for x in v if x in fa], "right": fb[k], "name": k}
                      for k, v in MERGES.get((a, b), {}).items() if k in fb]
            mapped_right = {p["right"] for p in pairs} | {r for s in splits for r in s["rights"]} | {
                m["right"] for m in merges}
            mapped_left = {p["left"] for p in pairs} | {s["left"] for s in splits} | {
                x for m in merges for x in m["lefts"]}
            new = []
            for n, addr in sorted(fb.items()):
                if addr in mapped_right:
                    continue
                entry: dict[str, object] = {"right": addr, "name": n, "resurrected": n in RESURRECTED.get((a, b), [])}
                if entry["resurrected"]:
                    # The same logical function, last present in an earlier version (lineage continuity).
                    earlier = [v for v in versions[: versions.index(a)] if n in functions[comp][v]]
                    if earlier:
                        entry["resurrects"] = {"version": earlier[-1], "address": functions[comp][earlier[-1]][n]}
                new.append(entry)
            gone = [{"left": addr, "name": n} for n, addr in sorted(fa.items()) if addr not in mapped_left]
            transitions.append({"component": comp, "from": a, "to": b, "pairs": pairs, "splits": splits,
                                "merges": merges, "new": new, "disappeared": gone})
    return {"dataset": "acet-demo", "schema_version": 1, "license": "ACET project (original code)",
            "versions": versions, "components": list(comps), "functions": functions, "transitions": transitions}


if __name__ == "__main__":
    for v in (1, 2, 3):
        build(v)
    (HERE / "ground_truth.json").write_text(json.dumps(ground_truth(), indent=2) + "\n", encoding="utf-8")
    print("ok")

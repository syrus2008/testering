"""Build the ACET resurrection corpus with clang + lld-link (reproducible flags, no timestamps).

Usage: python datasets/resurrection/build.py   (requires clang and lld-link)

One DLL (rescore.dll), five builds:
  v1               audit_record present (called by Run)
  v2               audit_record absent
  v3_identical     audit_record back, same source and flags as v1
  v3_recompiled    audit_record back, same source, its translation unit built with -O2 -fno-omit-frame-pointer
  v3_recompiled_heavy  same, built with -O3 -march=haswell (unrolled: the code barely resembles v1)
  v3_lookalike     audit_record still absent; trace_record (similar shape, different constants,
                   called by a different export) appears

Each scenario is the sequence v1 → v2 → v3_<x>. ground_truth.json records the logical identity of
functions from the linker maps (never given to analyzers, ACET-BEN-001).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = "x86_64-pc-windows-msvc"
CFLAGS = ["--target=" + TARGET, "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-nostdlib",
          "-mno-stack-arg-probe"]
LDFLAGS = ["-fuse-ld=lld", "-shared", "-Wl,/brepro", "-Wl,/nodefaultlib", "-Wl,/opt:noicf", "-Wl,/opt:noref",
           "-Wl,/entry:_DllMainCRTStartup"]
# build → (SCEN, extra translation unit, its optimisation flags)
BUILDS = {
    "v1": (1, "audit.c", ["-O1"]),
    "v2": (2, None, []),
    "v3_identical": (3, "audit.c", ["-O1"]),
    "v3_recompiled": (3, "audit.c", ["-O2", "-fno-omit-frame-pointer"]),
    "v3_recompiled_heavy": (3, "audit.c", ["-O3", "-march=haswell"]),
    "v3_lookalike": (4, "trace.c", ["-O1"]),
}
SCENARIOS = {
    "identical": ["v1", "v2", "v3_identical"],
    "recompiled": ["v1", "v2", "v3_recompiled"],
    "recompiled_heavy": ["v1", "v2", "v3_recompiled_heavy"],
    "lookalike": ["v1", "v2", "v3_lookalike"],
}


def build(name: str) -> None:
    scen, extra, opt = BUILDS[name]
    out = HERE / "builds" / name
    obj = HERE / "obj" / name
    out.mkdir(parents=True, exist_ok=True)
    obj.mkdir(parents=True, exist_ok=True)
    (HERE / "maps").mkdir(exist_ok=True)
    objs = [obj / "core.o"]
    subprocess.run(["clang", *CFLAGS, "-O1", f"-DSCEN={scen}", "-c", str(HERE / "src" / "core.c"), "-o", str(objs[0])],
                   check=True)
    if extra:
        objs.append(obj / extra.replace(".c", ".o"))
        subprocess.run(["clang", *CFLAGS, *opt, "-c", str(HERE / "src" / extra), "-o", str(objs[1])], check=True)
    subprocess.run(["clang", *CFLAGS, *LDFLAGS, f"-Wl,/map:{HERE / 'maps' / f'{name}.map'}",
                    "-o", str(out / "rescore.dll"), *map(str, objs)], check=True)
    for junk in [*out.glob("*.lib"), *out.glob("*.exp"), *obj.glob("*.o")]:
        junk.unlink()
    obj.rmdir()


def parse_map(path: Path) -> dict[str, int]:
    funcs: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\s*0001:[0-9a-fA-F]{8}\s+([A-Za-z_][A-Za-z0-9_]*)\s+([0-9a-fA-F]{16})\s", line)
        if m and not m.group(1).startswith("_DllMain"):
            funcs[m.group(1)] = int(m.group(2), 16)
    return funcs


def ground_truth() -> dict[str, object]:
    functions = {b: parse_map(HERE / "maps" / f"{b}.map") for b in BUILDS}
    scenarios = {}
    for scen, seq in SCENARIOS.items():
        v1, v2, v3 = seq
        transitions = []
        for a, b in ((v1, v2), (v2, v3)):
            fa, fb = functions[a], functions[b]
            transitions.append({
                "from": a, "to": b,
                "pairs": [{"left": fa[n], "right": fb[n], "name": n} for n in sorted(fa) if n in fb],
                "disappeared": [{"left": fa[n], "name": n} for n in sorted(fa) if n not in fb],
                "new": [{"right": fb[n], "name": n, **({"resurrects": {"version": v1, "address": functions[v1][n]}}
                                                       if n in functions[v1] and n not in fa else {})}
                        for n in sorted(fb) if n not in fa],
            })
        scenarios[scen] = {"versions": seq, "transitions": transitions}
    return {"dataset": "acet-resurrection", "schema_version": 1, "license": "ACET project (original code)",
            "component": "rescore.dll", "functions": functions, "scenarios": scenarios}


if __name__ == "__main__":
    for b in BUILDS:
        build(b)
    (HERE / "obj").rmdir()
    (HERE / "ground_truth.json").write_text(json.dumps(ground_truth(), indent=2) + "\n", encoding="utf-8")
    print("ok")

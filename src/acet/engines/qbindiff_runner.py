"""Executed by the Engine Pack's QBinDiff interpreter (not ACET's). Argv: left.BinExport right.BinExport out.json"""

import json
import sys

from qbindiff import Program, QBinDiff
from qbindiff.features import BBlockNb, MnemonicSimple, WeisfeilerLehman
from qbindiff.types import Distance

try:
    from importlib.metadata import version

    VERSION = version("qbindiff")
except Exception:
    VERSION = "unknown"

left, right, out = sys.argv[1:4]
p1, p2 = Program.from_binexport(left), Program.from_binexport(right)
print(f"QBinDiff {VERSION}: {len(p1)} x {len(p2)} functions", flush=True)
d = QBinDiff(p1, p2, distance=Distance.canberra)
feats = [
    ("WeisfeilerLehman", WeisfeilerLehman, 1.0),
    ("MnemonicSimple", MnemonicSimple, 1.0),
    ("BBlockNb", BBlockNb, 0.5),
]
for _, cls, w in feats:
    d.register_feature_extractor(cls, w)
matches = [
    {
        "primary": int(m.primary.addr),
        "secondary": int(m.secondary.addr),
        "similarity": float(m.similarity),
        "confidence": float(m.confidence),
    }
    for m in d.compute_matching()
]
with open(out + ".tmp", "w", encoding="utf-8") as fh:
    json.dump({"version": VERSION, "features": [[n, w] for n, _, w in feats], "matches": matches}, fh)
import os  # noqa: E402

os.replace(out + ".tmp", out)
print(f"QBinDiff matches: {len(matches)}", flush=True)

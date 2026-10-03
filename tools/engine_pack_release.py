"""Reproducible Engine Pack release: assemble from a pinned recipe, sign offline, finalize, index (ADR-0013).

The signing key never has to be on the build machine:

  assemble  RECIPE OUT       download every pinned input (SHA-256 checked), lay out the pack, install the
                             Ghidriff interpreter's packages, smoke-test it, then write OUT/unsigned.zip
                             (the pack without its manifest), OUT/payload.json (the manifest to sign: every
                             file's SHA-256) and OUT/build-info.json (inputs and their verified hashes).
  sign      PAYLOAD -o M     sign the payload (Ed25519, release key) -> engine-pack.json envelope.
  finalize  ZIP M -o A       check that every member of ZIP matches the signed manifest (no extra, no missing
                             file), then append the manifest as a stored member: A is the .acetengine.
                             Deterministic: the same ZIP and manifest give the same archive on any machine.
  index     A M --url U -o I signed index for the Engine Pack Manager (archive SHA-256/size, components...).
  check     A I              exit 1 unless the archive is the one the signed index names.

Uses tools/build_engine_pack.py for the manifest, archive and index formats.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tools.build_engine_pack import MANIFEST, _manifest, _sha, index_entry, make_archive, make_index  # noqa: E402

HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


# ------------------------------------------------------------------------------------------- inputs
def _get(url: str, *, accept: str | None = None) -> urllib.request.Request:
    req = urllib.request.Request(url, headers={"User-Agent": "acet-engine-pack-build"})
    if accept:
        req.add_header("Accept", accept)
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {token}")
    return req


def download(url: str, dest: Path, attempts: int = 4) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    for i in range(attempts):
        try:
            h = hashlib.sha256()
            with urllib.request.urlopen(_get(url), timeout=120) as r, open(dest, "wb") as f:
                while chunk := r.read(1 << 20):
                    h.update(chunk)
                    f.write(chunk)
            return h.hexdigest()
        except OSError as exc:
            if i == attempts - 1:
                raise
            print(f"retry {url}: {exc}", flush=True)
            time.sleep(2 ** (i + 1))
    raise AssertionError("unreachable")


def published_sha256(spec: dict[str, Any], url: str) -> str | None:
    """The SHA-256 the publisher lists for this file (GitHub release asset digest or a .sha256 file)."""
    name = url.rsplit("/", 1)[-1]
    if "github_release" in spec:
        api = f"https://api.github.com/repos/{spec['github_release']}/releases/tags/{spec['tag']}"
        with urllib.request.urlopen(_get(api, accept="application/vnd.github+json"), timeout=60) as r:
            rel = json.load(r)
        for a in rel.get("assets", []):
            if a.get("name") == name and str(a.get("digest", "")).startswith("sha256:"):
                return str(a["digest"]).split(":", 1)[1]
        body = str(rel.get("body") or "")
        i = body.find(name)
        m = HEX64.search(body[i:] if i >= 0 else body)
        return m.group(0) if m else None
    if "url" in spec:
        with urllib.request.urlopen(_get(spec["url"]), timeout=60) as r:
            m = HEX64.search(r.read(4096).decode("ascii", "replace").lower())
        return m.group(0) if m else None
    return None


def fetch_inputs(recipe: dict[str, Any], cache: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, spec in recipe["inputs"].items():
        url = spec["url"]
        path = cache / url.rsplit("/", 1)[-1].replace("%2B", "+")
        observed = download(url, path)
        published = published_sha256(spec["published_sha256"], url) if spec.get("published_sha256") else None
        pinned = spec.get("sha256")
        if pinned and observed != pinned:
            raise SystemExit(f"{name}: SHA-256 {observed} differs from the pinned {pinned}")
        if published and observed != published:
            raise SystemExit(f"{name}: SHA-256 {observed} differs from the published {published}")
        if not pinned and not published:
            raise SystemExit(f"{name}: neither pinned nor published SHA-256: refusing an unverified input")
        verified = "pinned+published" if pinned and published else ("pinned" if pinned else "published (pin it)")
        print(f"input {name}: {observed} [{verified}]", flush=True)
        out[name] = {"url": url, "path": str(path), "sha256": observed, "verified": verified}
    return out


# ------------------------------------------------------------------------------------------- layout
def extract(
    archive: Path,
    pack: Path,
    dest: str,
    *,
    strip_root: bool = False,
    subdir: str = "",
    exclude: list[str] | None = None,
) -> int:
    """Copy the members of ``archive`` (optionally below ``subdir``, without its root folder) to ``pack/dest``,
    refusing any name the Engine Pack Manager would refuse at install time."""
    from acet.platform.engine_manager import safe_member_name

    exclude = exclude or []
    n = 0
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if strip_root:
                name = name.split("/", 1)[1] if "/" in name else ""
            if subdir:
                if not name.startswith(subdir + "/"):
                    continue
                name = name[len(subdir) + 1 :]
            if not name or any(name == e.rstrip("/") or name.startswith(e) for e in exclude):
                continue
            rel = f"{dest}/{name}"
            target = pack / rel
            if not safe_member_name(rel):
                raise SystemExit(f"unsafe member name in {archive.name}: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            n += 1
    return n


def assemble(recipe_path: Path, out: Path) -> dict[str, Any]:
    from acet.domain.jsonschema import validate_named

    recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    config = {k: recipe[k] for k in ("id", "version", "supported_acet", "platform")} | recipe["manifest"]
    validate_named({**_manifest(config), "checksums": {}, "installed_size": 0}, "engine-pack")  # before any download
    if out.exists():
        shutil.rmtree(out)
    pack = out / "pack"
    pack.mkdir(parents=True)
    inputs = fetch_inputs(recipe, out / "inputs")
    for name, spec in recipe["inputs"].items():
        src = Path(inputs[name]["path"])
        if "extract" in spec:
            x = spec["extract"]
            count = extract(src, pack, x["dest"], strip_root=x.get("strip_root", False), subdir=x.get("subdir", ""),
                            exclude=x.get("exclude", []))  # fmt: skip
            print(f"extracted {count} files of {name} into {x['dest']}", flush=True)
        if "copy_to" in spec:
            (pack / spec["copy_to"]).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, pack / spec["copy_to"])
    sp = recipe["site_packages"]
    files: list[str] = []
    for item in sp["install"]:
        if "pack_file" in item:
            f = pack / item["pack_file"]
            if _sha(f) != item["sha256"]:
                raise SystemExit(f"{item['pack_file']}: SHA-256 differs from the recipe")
            files.append(str(f))
        else:
            files.append(inputs[item["input"]]["path"])
    target = pack / sp["target"]
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--no-compile", "--no-index", "--no-build-isolation",
         "--disable-pip-version-check", "--target", str(target), *files],
        check=True,
    )  # fmt: skip
    for junk in target.rglob("__pycache__"):
        shutil.rmtree(junk)
    if sys.platform == "win32":  # the interpreter is a Windows build: smoke-test it where it can run
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        smoke = subprocess.run([str(pack / sp["interpreter"]), "-I", "-B", "-c", sp["smoke"]],
                               capture_output=True, text=True, env=env, timeout=300)  # fmt: skip
        print(smoke.stdout, smoke.stderr, flush=True)
        if smoke.returncode != 0:
            raise SystemExit("the pack interpreter cannot import its engines")
    notices = ROOT / recipe["notices"]
    (pack / "licenses").mkdir(exist_ok=True)
    shutil.copyfile(notices, pack / "licenses" / notices.name)
    files_ = [p for p in sorted(pack.rglob("*")) if p.is_file()]
    payload = {
        **_manifest(config),
        "checksums": {p.relative_to(pack).as_posix(): _sha(p) for p in files_},
        "installed_size": sum(p.stat().st_size for p in files_),
    }
    validate_named(payload, "engine-pack")
    make_archive(pack, out / "unsigned.zip")
    (out / "payload.json").write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    info = {
        "pack": f"{recipe['id']}@{recipe['version']}",
        # newline-normalised: a Windows checkout may have converted the recipe to CRLF
        "recipe_sha256": hashlib.sha256(recipe_path.read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
        "inputs": {k: {kk: v[kk] for kk in ("url", "sha256", "verified")} for k, v in inputs.items()},
        "files": len(files_),
        "installed_size": payload["installed_size"],
        "payload_sha256": _sha(out / "payload.json"),
        "unsigned_zip_sha256": _sha(out / "unsigned.zip"),
        "unsigned_zip_size": (out / "unsigned.zip").stat().st_size,
        "builder": {"python": sys.version.split()[0], "platform": sys.platform},
    }
    (out / "build-info.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(info, indent=2), flush=True)
    return info


# ------------------------------------------------------------------------------------------- sign / finalize
def sign(payload_path: Path, out: Path, secret: bytes, key_id: str) -> None:
    from acet.domain.jsonschema import validate_named
    from acet.platform.signing import sign_payload

    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    validate_named(payload, "engine-pack")
    out.write_text(json.dumps(sign_payload(payload, secret, key_id), indent=1, sort_keys=True) + "\n", encoding="utf-8")


def finalize(unsigned: Path, manifest_path: Path, archive: Path) -> dict[str, Any]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))["payload"]
    expected = dict(payload["checksums"])
    with zipfile.ZipFile(unsigned) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            want = expected.pop(info.filename, None)
            if want is None:
                raise SystemExit(f"{info.filename} is not in the signed manifest")
            h = hashlib.sha256()
            with z.open(info) as f:
                while chunk := f.read(1 << 20):
                    h.update(chunk)
            if h.hexdigest() != want:
                raise SystemExit(f"{info.filename} differs from the signed manifest")
    if expected:
        raise SystemExit(f"{len(expected)} signed files are missing, e.g. {sorted(expected)[:3]}")
    tmp = archive.with_name(archive.name + ".tmp")
    archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(unsigned, tmp)
    zi = zipfile.ZipInfo(MANIFEST, date_time=(1980, 1, 1, 0, 0, 0))
    zi.create_system = 3
    zi.external_attr = 0o100644 << 16
    zi.compress_type = zipfile.ZIP_STORED  # stored: identical bytes whatever the zlib build
    with zipfile.ZipFile(tmp, "a") as z:
        z.writestr(zi, manifest_path.read_bytes())
    os.replace(tmp, archive)
    res = {"archive": archive.name, "sha256": _sha(archive), "size": archive.stat().st_size}
    print(json.dumps(res), flush=True)
    return res


def check(archive: Path, index_path: Path) -> int:
    payload = json.loads(index_path.read_text(encoding="utf-8"))["payload"]
    sha, size = _sha(archive), archive.stat().st_size
    for e in payload["packs"]:
        if e["archive_sha256"] == sha and e["archive_size"] == size:
            print(f"OK {archive.name} is {e['id']}@{e['version']} ({sha})")
            return 0
    print(f"MISMATCH {archive.name} {sha} {size} is not in the signed index", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assemble")
    a.add_argument("recipe", type=Path)
    a.add_argument("out", type=Path)
    s = sub.add_parser("sign")
    s.add_argument("payload", type=Path)
    s.add_argument("-o", "--out", type=Path, required=True)
    f = sub.add_parser("finalize")
    f.add_argument("unsigned", type=Path)
    f.add_argument("manifest", type=Path)
    f.add_argument("-o", "--out", type=Path, required=True)
    i = sub.add_parser("index")
    i.add_argument("archive", type=Path)
    i.add_argument("manifest", type=Path)
    i.add_argument("--url", required=True)
    i.add_argument("-o", "--out", type=Path, required=True)
    for p in (s, i):
        p.add_argument("--key-file", type=Path, required=True, help="hex Ed25519 seed, kept outside the repository")
        p.add_argument("--key-id", required=True)
    c = sub.add_parser("check")
    c.add_argument("archive", type=Path)
    c.add_argument("index", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "assemble":
        assemble(args.recipe, args.out)
    elif args.cmd == "sign":
        sign(args.payload, args.out, bytes.fromhex(args.key_file.read_text(encoding="ascii").strip()), args.key_id)
    elif args.cmd == "finalize":
        finalize(args.unsigned, args.manifest, args.out)
    elif args.cmd == "index":
        secret = bytes.fromhex(args.key_file.read_text(encoding="ascii").strip())
        with zipfile.ZipFile(args.archive) as z:
            if z.read(MANIFEST) != args.manifest.read_bytes():
                raise SystemExit("the archive does not carry this manifest")
        tmpdir = args.out.parent / ".index-tmp"
        tmpdir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.manifest, tmpdir / MANIFEST)
        entry = index_entry(tmpdir, args.archive, args.url)
        shutil.rmtree(tmpdir)
        args.out.write_text(json.dumps(make_index([entry], secret, args.key_id), indent=1) + "\n", encoding="utf-8")
    else:
        return check(args.archive, args.index)
    return 0


if __name__ == "__main__":
    sys.exit(main())

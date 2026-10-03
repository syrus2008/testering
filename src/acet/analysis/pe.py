"""Static PE facts (spec §72). Pure parsing of bytes; nothing is mapped or executed.

Every family returns a ``MeasurementState``: MEASURED, NOT_MEASURED (absent
directory is still MEASURED with ``present: False``), UNSUPPORTED or PARTIAL when
the structure is malformed. Limits bound every loop so hostile inputs cannot
explode memory or time.
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections import Counter
from typing import Any

from acet.analysis import asn1

MAX_SECTIONS = 96
MAX_IMPORT_DLLS = 4096
MAX_SYMBOLS = 65536
MAX_EXPORTS = 65536
MAX_RESOURCES = 4096
MAX_RELOC_BLOCKS = 65536
MAX_TLS_CALLBACKS = 256
MAX_STR = 512

DIR_NAMES = [
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "COM_DESCRIPTOR",
    "RESERVED",
]
RESOURCE_TYPES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}
RELOC_TYPES = {0: "ABSOLUTE", 1: "HIGH", 2: "LOW", 3: "HIGHLOW", 4: "HIGHADJ", 10: "DIR64"}
DEBUG_TYPES = {
    1: "COFF",
    2: "CODEVIEW",
    3: "FPO",
    4: "MISC",
    5: "EXCEPTION",
    6: "FIXUP",
    9: "BORLAND",
    11: "CLSID",
    12: "VC_FEATURE",
    13: "POGO",
    14: "ILTCG",
    16: "REPRO",
    20: "EX_DLLCHARACTERISTICS",
}


class PeFormatError(ValueError):
    pass


def entropy(data: bytes) -> float | None:
    if not data:
        return None
    counts = Counter(data)
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in counts.values()), 4)


def _cstr(buf: bytes, off: int, limit: int = MAX_STR) -> str | None:
    if off < 0 or off >= len(buf):
        return None
    end = buf.find(b"\0", off, off + limit)
    if end < 0:
        end = min(len(buf), off + limit)
    return buf[off:end].decode("latin-1")


def _sanitize_path(p: str) -> dict[str, Any]:
    """ACET-PRI-002: PDB paths may contain user names; keep basename, flag sensitivity."""
    base = p.replace("\\", "/").rsplit("/", 1)[-1]
    lowered = p.lower()
    sensitive = any(m in lowered for m in ("\\users\\", "/users/", "/home/", "documents and settings"))
    return {"basename": base, "path_sensitive": sensitive or ("\\" in p or "/" in p)}


class PeFile:
    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PeFormatError("missing MZ header")
        (self.e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if self.e_lfanew + 24 > len(data) or data[self.e_lfanew : self.e_lfanew + 4] != b"PE\0\0":
            raise PeFormatError("missing PE signature")
        coff = self.e_lfanew + 4
        (self.machine, self.nsections, self.timestamp, _ps, _ns, self.opt_size, self.characteristics) = (
            struct.unpack_from("<HHIIIHH", data, coff)
        )
        self.opt = coff + 20
        if self.opt + 2 > len(data):
            raise PeFormatError("truncated optional header")
        (self.magic,) = struct.unpack_from("<H", data, self.opt)
        if self.magic not in (0x10B, 0x20B):
            raise PeFormatError(f"unknown optional header magic 0x{self.magic:x}")
        self.is64 = self.magic == 0x20B
        o = self.opt
        need = 112 if self.is64 else 96
        if self.opt_size < need or o + need > len(data):
            raise PeFormatError("truncated optional header")
        self.linker = (data[o + 2], data[o + 3])
        (self.size_of_code,) = struct.unpack_from("<I", data, o + 4)
        (self.entry_rva,) = struct.unpack_from("<I", data, o + 16)
        if self.is64:
            (self.image_base,) = struct.unpack_from("<Q", data, o + 24)
        else:
            (self.image_base,) = struct.unpack_from("<I", data, o + 28)
        self.section_alignment, self.file_alignment = struct.unpack_from("<II", data, o + 32)
        self.os_version = struct.unpack_from("<HH", data, o + 40)
        self.subsystem_version = struct.unpack_from("<HH", data, o + 48)
        self.size_of_image, self.size_of_headers, self.checksum = struct.unpack_from("<III", data, o + 56)
        self.subsystem, self.dll_characteristics = struct.unpack_from("<HH", data, o + 68)
        nrva_off = o + (108 if self.is64 else 92)
        (nrva,) = struct.unpack_from("<I", data, nrva_off)
        self.checksum_offset = o + 64
        self.dirs_offset = nrva_off + 4
        self.dirs: list[tuple[int, int]] = []
        for i in range(min(nrva, 16)):
            p = self.dirs_offset + 8 * i
            if p + 8 > len(data) or p + 8 > self.opt + self.opt_size:
                break
            self.dirs.append(struct.unpack_from("<II", data, p))
        self.sections: list[dict[str, Any]] = []
        sec = self.opt + self.opt_size
        for i in range(min(self.nsections, MAX_SECTIONS)):
            p = sec + 40 * i
            if p + 40 > len(data):
                raise PeFormatError("truncated section table")
            name = data[p : p + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, p + 8)
            (chars,) = struct.unpack_from("<I", data, p + 36)
            self.sections.append(
                {
                    "name": name,
                    "virtual_address": va,
                    "virtual_size": vsize,
                    "raw_size": rsize,
                    "raw_pointer": rptr,
                    "characteristics": chars,
                }
            )

    # -- address translation ------------------------------------------------
    def rva_to_off(self, rva: int) -> int | None:
        if rva < self.size_of_headers:
            return rva if rva < len(self.data) else None
        for s in self.sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["virtual_address"] <= rva < s["virtual_address"] + span:
                delta = rva - s["virtual_address"]
                if delta >= s["raw_size"]:
                    return None  # uninitialized data
                off = s["raw_pointer"] + delta
                return off if off < len(self.data) else None
        return None

    def dir(self, idx: int) -> tuple[int, int]:
        return self.dirs[idx] if idx < len(self.dirs) else (0, 0)

    def u32(self, off: int) -> int:
        return int(struct.unpack_from("<I", self.data, off)[0])

    def u16(self, off: int) -> int:
        return int(struct.unpack_from("<H", self.data, off)[0])

    def uptr(self, off: int) -> int:
        return int(struct.unpack_from("<Q" if self.is64 else "<I", self.data, off)[0])

    def str_at_rva(self, rva: int) -> str | None:
        off = self.rva_to_off(rva)
        return None if off is None else _cstr(self.data, off)

    # -- families -----------------------------------------------------------
    def headers(self) -> dict[str, Any]:
        return {
            "machine": self.machine,
            "number_of_sections": self.nsections,
            "pe_timestamp": self.timestamp,
            "characteristics": self.characteristics,
            "magic": "PE32+" if self.is64 else "PE32",
            "linker_version": f"{self.linker[0]}.{self.linker[1]}",
            "entry_point_rva": self.entry_rva,
            "image_base": self.image_base,
            "section_alignment": self.section_alignment,
            "file_alignment": self.file_alignment,
            "size_of_image": self.size_of_image,
            "size_of_headers": self.size_of_headers,
            "checksum": self.checksum,
            "subsystem": self.subsystem,
            "dll_characteristics": self.dll_characteristics,
            "os_version": f"{self.os_version[0]}.{self.os_version[1]}",
            "subsystem_version": f"{self.subsystem_version[0]}.{self.subsystem_version[1]}",
            "data_directories": {DIR_NAMES[i]: {"rva": r, "size": s} for i, (r, s) in enumerate(self.dirs) if r or s},
        }

    def section_facts(self) -> list[dict[str, Any]]:
        out = []
        for s in self.sections:
            raw = self.data[s["raw_pointer"] : s["raw_pointer"] + s["raw_size"]] if s["raw_size"] else b""
            out.append(
                {
                    **s,
                    "entropy": entropy(raw),
                    "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                    "truncated": len(raw) < s["raw_size"],
                }
            )
        return out

    def imports(self) -> dict[str, Any]:
        rva, _size = self.dir(1)
        if not rva:
            return {"present": False, "dlls": [], "imphash": None}
        off = self.rva_to_off(rva)
        if off is None:
            raise PeFormatError("import directory outside file")
        dlls: list[dict[str, Any]] = []
        total = 0
        for i in range(MAX_IMPORT_DLLS):
            p = off + 20 * i
            if p + 20 > len(self.data):
                break
            oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", self.data, p)
            if not (oft or name_rva or ft):
                break
            name = self.str_at_rva(name_rva) or "?"
            symbols = self._thunks(oft or ft, budget=MAX_SYMBOLS - total)
            total += len(symbols)
            dlls.append({"dll": name, "symbols": symbols})
        return {"present": True, "dlls": dlls, "imphash": self._imphash(dlls)}

    def _thunks(self, rva: int, *, budget: int, va_based: bool = False) -> list[str]:
        out: list[str] = []
        off = self.rva_to_off(rva - self.image_base if va_based else rva)
        if off is None:
            return out
        step = 8 if self.is64 else 4
        flag = 1 << 63 if self.is64 else 1 << 31
        for i in range(budget):
            p = off + step * i
            if p + step > len(self.data):
                break
            v = self.uptr(p)
            if v == 0:
                break
            if v & flag:
                out.append(f"#{v & 0xFFFF}")
            else:
                hint_rva = (v - self.image_base if va_based else v) & 0x7FFFFFFF
                name_off = self.rva_to_off(hint_rva)
                out.append(_cstr(self.data, name_off + 2) or "?" if name_off is not None else "?")
        return out

    @staticmethod
    def _imphash(dlls: list[dict[str, Any]]) -> str | None:
        parts = []
        for d in dlls:
            lib = d["dll"].lower()
            for ext in (".dll", ".ocx", ".sys"):
                if lib.endswith(ext):
                    lib = lib[: -len(ext)]
            parts += [f"{lib}.{s.lower()}" for s in d["symbols"]]
        return hashlib.md5(",".join(parts).encode(), usedforsecurity=False).hexdigest() if parts else None

    def delay_imports(self) -> dict[str, Any]:
        rva, _ = self.dir(13)
        if not rva:
            return {"present": False, "dlls": []}
        off = self.rva_to_off(rva)
        if off is None:
            raise PeFormatError("delay import directory outside file")
        dlls = []
        for i in range(MAX_IMPORT_DLLS):
            p = off + 32 * i
            if p + 32 > len(self.data):
                break
            attrs, name_rva, _mod, _iat, int_rva = struct.unpack_from("<IIIII", self.data, p)
            if not (name_rva or int_rva):
                break
            va_based = not (attrs & 1)
            name_r = name_rva - self.image_base if va_based else name_rva
            dlls.append(
                {
                    "dll": self.str_at_rva(name_r) or "?",
                    "symbols": self._thunks(int_rva, budget=MAX_SYMBOLS, va_based=va_based),
                }
            )
        return {"present": True, "dlls": dlls}

    def exports(self) -> dict[str, Any]:
        rva, size = self.dir(0)
        if not rva:
            return {"present": False, "symbols": []}
        off = self.rva_to_off(rva)
        if off is None or off + 40 > len(self.data):
            raise PeFormatError("export directory outside file")
        (_c, _ts, _maj, _min, name_rva, base, nfunc, nnames, funcs, names, ords) = struct.unpack_from(
            "<IIHHIIIIIII", self.data, off
        )
        nfunc, nnames = min(nfunc, MAX_EXPORTS), min(nnames, MAX_EXPORTS)
        by_index: dict[int, str] = {}
        noff, ooff = self.rva_to_off(names), self.rva_to_off(ords)
        if noff is not None and ooff is not None:
            for i in range(nnames):
                if noff + 4 * i + 4 > len(self.data) or ooff + 2 * i + 2 > len(self.data):
                    break
                by_index[self.u16(ooff + 2 * i)] = self.str_at_rva(self.u32(noff + 4 * i)) or "?"
        syms = []
        foff = self.rva_to_off(funcs)
        if foff is not None:
            for i in range(nfunc):
                if foff + 4 * i + 4 > len(self.data):
                    break
                frva = self.u32(foff + 4 * i)
                if not frva:
                    continue
                forwarder = self.str_at_rva(frva) if rva <= frva < rva + size else None
                syms.append(
                    {
                        "ordinal": base + i,
                        "name": by_index.get(i),
                        "rva": None if forwarder else frva,
                        "forwarder": forwarder,
                    }
                )
        return {"present": True, "dll_name": self.str_at_rva(name_rva), "symbols": syms}

    def relocations(self) -> dict[str, Any]:
        rva, size = self.dir(5)
        if not rva:
            return {"present": False, "count": 0, "types": {}}
        off = self.rva_to_off(rva)
        if off is None:
            raise PeFormatError("reloc directory outside file")
        end = min(off + size, len(self.data))
        types: Counter[str] = Counter()
        blocks = 0
        p = off
        while p + 8 <= end and blocks < MAX_RELOC_BLOCKS:
            _page, bsize = struct.unpack_from("<II", self.data, p)
            if bsize < 8:
                break
            for q in range(p + 8, min(p + bsize, end) - 1, 2):
                types[RELOC_TYPES.get(self.u16(q) >> 12, "OTHER")] += 1
            p += bsize
            blocks += 1
        return {"present": True, "blocks": blocks, "count": sum(types.values()), "types": dict(sorted(types.items()))}

    def resources(self) -> dict[str, Any]:
        rva, _size = self.dir(2)
        if not rva:
            return {"present": False, "entries": []}
        base = self.rva_to_off(rva)
        if base is None:
            raise PeFormatError("resource directory outside file")
        entries: list[dict[str, Any]] = []
        visited: set[int] = set()

        def name_of(entry_name: int) -> str | int:
            if entry_name & 0x80000000:
                p = base + (entry_name & 0x7FFFFFFF)
                if p + 2 > len(self.data):
                    return "?"
                n = min(self.u16(p), 256)
                return self.data[p + 2 : p + 2 + 2 * n].decode("utf-16-le", "replace")
            return entry_name & 0xFFFF

        def walk(dir_off: int, path: list[str | int]) -> None:
            if dir_off in visited or len(path) > 3 or dir_off + 16 > len(self.data):
                return
            visited.add(dir_off)
            n_named, n_id = struct.unpack_from("<HH", self.data, dir_off + 12)
            for i in range(min(n_named + n_id, MAX_RESOURCES)):
                p = dir_off + 16 + 8 * i
                if p + 8 > len(self.data) or len(entries) >= MAX_RESOURCES:
                    return
                ename, eoff = struct.unpack_from("<II", self.data, p)
                key = name_of(ename)
                if eoff & 0x80000000:
                    walk(base + (eoff & 0x7FFFFFFF), [*path, key])
                else:
                    d = base + eoff
                    if d + 16 > len(self.data):
                        continue
                    drva, dsize = struct.unpack_from("<II", self.data, d)
                    doff = self.rva_to_off(drva)
                    blob = self.data[doff : doff + dsize] if doff is not None else b""
                    full = [*path, key]
                    t = full[0] if full else None
                    entries.append(
                        {
                            "type": RESOURCE_TYPES.get(t, t) if isinstance(t, int) else t,
                            "name": full[1] if len(full) > 1 else None,
                            "lang": full[2] if len(full) > 2 else None,
                            "size": dsize,
                            "sha256": hashlib.sha256(blob).hexdigest() if blob else None,
                            "truncated": len(blob) < dsize,
                            "_blob": blob,
                        }
                    )

        walk(base, [])
        return {"present": True, "entries": entries}

    def debug(self) -> dict[str, Any]:
        rva, size = self.dir(6)
        if not rva:
            return {"present": False, "entries": []}
        off = self.rva_to_off(rva)
        if off is None:
            raise PeFormatError("debug directory outside file")
        out = []
        for i in range(min(size // 28, 64)):
            p = off + 28 * i
            if p + 28 > len(self.data):
                break
            _c, ts, _ma, _mi, typ, dsize, _drva, dptr = struct.unpack_from("<IIHHIIII", self.data, p)
            entry: dict[str, Any] = {"type": DEBUG_TYPES.get(typ, typ), "timestamp": ts, "size": dsize}
            if typ == 2 and dptr + 24 <= len(self.data) and self.data[dptr : dptr + 4] == b"RSDS":
                g = self.data[dptr + 4 : dptr + 20]
                guid = (
                    f"{struct.unpack_from('<I', g, 0)[0]:08X}-{struct.unpack_from('<H', g, 4)[0]:04X}-"
                    f"{struct.unpack_from('<H', g, 6)[0]:04X}-{g[8:10].hex().upper()}-{g[10:16].hex().upper()}"
                )
                (age,) = struct.unpack_from("<I", self.data, dptr + 20)
                pdb = _cstr(self.data, dptr + 24) or ""
                entry["codeview"] = {"format": "RSDS", "guid": guid, "age": age, "pdb": _sanitize_path(pdb)}
            out.append(entry)
        return {"present": True, "entries": out}

    def load_config(self) -> dict[str, Any]:
        rva, _ = self.dir(10)
        if not rva:
            return {"present": False}
        off = self.rva_to_off(rva)
        if off is None or off + 4 > len(self.data):
            raise PeFormatError("load config outside file")
        size = self.u32(off)
        res: dict[str, Any] = {"present": True, "size": size}
        layout = (
            {"security_cookie": (0x58, 8), "guard_cf_function_count": (0x88, 8), "guard_flags": (0x90, 4)}
            if self.is64
            else {
                "security_cookie": (0x3C, 4),
                "se_handler_count": (0x44, 4),
                "guard_cf_function_count": (0x54, 4),
                "guard_flags": (0x58, 4),
            }
        )
        for k, (fo, w) in layout.items():
            if fo + w <= size and off + fo + w <= len(self.data):
                res[k] = int.from_bytes(self.data[off + fo : off + fo + w], "little")
            else:
                res[k] = None  # not present in this load-config version: unknown, not 0
        gf = res.get("guard_flags")
        res["cfg_instrumented"] = None if gf is None else bool(gf & 0x100)
        res["security_cookie_present"] = None if res["security_cookie"] is None else res["security_cookie"] != 0
        return res

    def tls(self) -> dict[str, Any]:
        rva, _ = self.dir(9)
        if not rva:
            return {"present": False, "callback_count": 0}
        off = self.rva_to_off(rva)
        if off is None:
            raise PeFormatError("TLS directory outside file")
        cb_va_off = off + (24 if self.is64 else 12)
        if cb_va_off + (8 if self.is64 else 4) > len(self.data):
            raise PeFormatError("truncated TLS directory")
        cb_va = self.uptr(cb_va_off)
        count = 0
        if cb_va:
            arr = self.rva_to_off(cb_va - self.image_base)
            step = 8 if self.is64 else 4
            while arr is not None and count < MAX_TLS_CALLBACKS and arr + step * (count + 1) <= len(self.data):
                if self.uptr(arr + step * count) == 0:
                    break
                count += 1
        # Metadata only (§72): callbacks are counted, never resolved or followed.
        return {"present": True, "callback_count": count}

    def overlay(self) -> dict[str, Any]:
        end = max([s["raw_pointer"] + s["raw_size"] for s in self.sections if s["raw_size"]] or [self.size_of_headers])
        sec_off, sec_size = self.dir(4)  # security dir uses a file offset
        regions = [(end, len(self.data))]
        if sec_off and sec_off >= end:
            regions = [(end, sec_off), (sec_off + sec_size, len(self.data))]
        parts = [(a, b) for a, b in regions if b > a]
        if not parts:
            return {"present": False}
        blob = b"".join(self.data[a:b] for a, b in parts)
        return {
            "present": True,
            "offset": parts[0][0],
            "size": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "entropy": entropy(blob),
        }

    def rich_header(self) -> dict[str, Any]:
        """Toolchain hints (Build dimension). Never used as identity."""
        stub = self.data[: self.e_lfanew]
        idx = stub.find(b"Rich")
        if idx < 0 or idx + 8 > len(stub):
            return {"present": False}
        key = stub[idx + 4 : idx + 8]
        dec = bytearray()
        p = idx - 4
        while p >= 0x40:
            dec[:0] = bytes(a ^ b for a, b in zip(stub[p : p + 4], key, strict=True))
            if dec[:4] == b"DanS":
                break
            p -= 4
        else:
            return {"present": True, "valid": False}
        entries = []
        for q in range(16, len(dec), 8):
            comp, count = struct.unpack_from("<II", dec, q)
            entries.append({"product_id": comp >> 16, "build": comp & 0xFFFF, "count": count})
        return {"present": True, "valid": True, "entries": entries}

    # -- Authenticode -------------------------------------------------------
    def authenticode_digest(self, algo: str) -> str:
        """PE Authenticode image hash (excludes checksum, security dir entry and cert table)."""
        h = hashlib.new(algo)
        sec_entry = self.dirs_offset + 8 * 4
        sec_off, sec_size = self.dir(4)
        h.update(self.data[: self.checksum_offset])
        h.update(self.data[self.checksum_offset + 4 : sec_entry])
        tail_start = sec_entry + 8
        if sec_off and sec_off + sec_size <= len(self.data):
            h.update(self.data[tail_start:sec_off])
            h.update(self.data[sec_off + sec_size :])
        else:
            h.update(self.data[tail_start:])
        return h.hexdigest()

    def authenticode(self) -> dict[str, Any]:
        off, size = self.dir(4)
        if not off:
            return {"present": False}
        if off + 8 > len(self.data) or off + size > len(self.data):
            return {"present": True, "parse_state": "PARTIAL", "error": "certificate table outside file"}
        length, rev, ctype = struct.unpack_from("<IHH", self.data, off)
        res: dict[str, Any] = {
            "present": True,
            "revision": rev,
            "certificate_type": ctype,
            "chain_status": "NOT_MEASURED",  # needs OS trust store; never assumed valid
            "chain_status_reason": "chain verification requires platform trust APIs (roadmap)",
        }
        if ctype != 2:
            res["parse_state"] = "UNSUPPORTED"
            return res
        try:
            res.update(_parse_pkcs7(self.data[off + 8 : off + min(length, size)]))
            res["parse_state"] = "MEASURED"
        except (asn1.Asn1Error, IndexError, ValueError) as exc:
            res["parse_state"] = "PARTIAL"
            res["error"] = f"pkcs7: {exc}"
            return res
        algo = res.get("indirect_digest_algorithm")
        if algo in ("sha1", "sha256", "sha384", "sha512", "md5"):
            computed = self.authenticode_digest(algo)
            res["image_digest_matches"] = computed == res.get("indirect_digest")
        else:
            res["image_digest_matches"] = None
        return res


def _parse_pkcs7(blob: bytes) -> dict[str, Any]:
    ci = asn1.read_tlv(blob, 0)
    kids = ci.children()
    if asn1.OID_NAMES.get(asn1.oid(kids[0])) != "signedData":
        raise ValueError("not signedData")
    sd = kids[1].children()[0].children()
    out: dict[str, Any] = {"digest_algorithms": []}
    for alg in sd[1].children():
        out["digest_algorithms"].append(asn1.OID_NAMES.get(asn1.oid(alg.children()[0]), asn1.oid(alg.children()[0])))
    encap = sd[2].children()
    if asn1.OID_NAMES.get(asn1.oid(encap[0])) == "spcIndirectDataContent":
        spc = encap[1].children()[0].children()
        digest_info = spc[1].children()
        a = asn1.oid(digest_info[0].children()[0])
        out["indirect_digest_algorithm"] = asn1.OID_NAMES.get(a, a)
        out["indirect_digest"] = digest_info[1].value.hex()
    certs: list[dict[str, Any]] = []
    signer_infos = None
    for el in sd[3:]:
        if el.tag == 0xA0:
            for cert in el.children():
                tbs = cert.children()[0].children()
                i = 1 if tbs[0].tag == 0xA0 else 0
                certs.append(
                    {
                        "serial": tbs[i].value.hex(),
                        "issuer": asn1.name_attrs(tbs[i + 2]),
                        "subject": asn1.name_attrs(tbs[i + 4]),
                    }
                )
        elif el.tag == 0x31:
            signer_infos = el
    out["certificate_count"] = len(certs)
    if signer_infos is not None and signer_infos.children():
        si = signer_infos.children()[0].children()
        serial = si[1].children()[1].value.hex()
        signer = next((c for c in certs if c["serial"] == serial), None)
        out["signer"] = None if signer is None else {"subject": signer["subject"], "issuer": signer["issuer"]}
        a = asn1.oid(si[2].children()[0])
        out["signer_digest_algorithm"] = asn1.OID_NAMES.get(a, a)
        timestamp = None
        for el in si[3:]:
            if el.tag == 0xA1:  # unsigned attributes
                for attr in el.children():
                    name = asn1.OID_NAMES.get(asn1.oid(attr.children()[0]))
                    if name in ("countersignature", "rfc3161Timestamp"):
                        timestamp = name
        out["timestamp"] = {"present": timestamp is not None, "kind": timestamp}
    return out


def parse_version_info(blob: bytes) -> dict[str, Any]:
    """VS_VERSIONINFO → metadata (non-identity, §72)."""
    out: dict[str, Any] = {"strings": {}}

    def node(p: int, end: int, depth: int) -> int:
        if depth > 6 or p + 6 > end:
            return end
        length: int
        vlen: int
        vtype: int
        length, vlen, vtype = struct.unpack_from("<HHH", blob, p)
        if length < 6:
            return end
        nend = int(min(p + length, end))
        q = p + 6
        kend = q
        while kend + 1 < nend and blob[kend : kend + 2] != b"\0\0":
            kend += 2
        key = blob[q:kend].decode("utf-16-le", "replace")
        q = (kend + 2 + 3) & ~3
        if key == "VS_VERSION_INFO" and vlen >= 52 and q + 52 <= nend:
            ms, ls = struct.unpack_from("<II", blob, q + 8)
            out["fixed_file_version"] = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
            q = (q + vlen + 3) & ~3
        elif vtype == 1 and vlen and depth >= 3:
            val = blob[q : min(q + 2 * vlen, nend)].decode("utf-16-le", "replace").rstrip("\0")
            out["strings"][key[:64]] = val[:MAX_STR]
            q = (q + 2 * vlen + 3) & ~3
        else:
            q = (q + vlen + 3) & ~3
        while q + 6 <= nend:
            nq = node(q, nend, depth + 1)
            if nq <= q:
                break
            q = (nq + 3) & ~3
        return nend

    node(0, len(blob), 0)
    return out


def _family(fn: Any) -> dict[str, Any]:
    try:
        return {"state": "MEASURED", "value": fn()}
    except (PeFormatError, struct.error, IndexError, ValueError) as exc:
        return {"state": "PARTIAL", "value": None, "error": f"{type(exc).__name__}: {exc}"}


def pe_facts(data: bytes) -> dict[str, Any]:
    try:
        pe = PeFile(data)
    except (PeFormatError, struct.error) as exc:
        return {"format_state": "UNSUPPORTED", "reason": str(exc)}
    res = _family(pe.resources)
    version: dict[str, Any] = {"state": "NOT_MEASURED", "value": None}
    if res["state"] == "MEASURED":
        for e in res["value"]["entries"]:
            if e["type"] == "VERSION" and e["_blob"]:
                version = _family(lambda b=e["_blob"]: parse_version_info(b))
                break
        for e in res["value"]["entries"]:
            e.pop("_blob", None)
    return {
        "format_state": "MEASURED",
        "headers": _family(pe.headers),
        "sections": _family(pe.section_facts),
        "imports": _family(pe.imports),
        "delay_imports": _family(pe.delay_imports),
        "exports": _family(pe.exports),
        "relocations": _family(pe.relocations),
        "resources": res,
        "debug": _family(pe.debug),
        "load_config": _family(pe.load_config),
        "tls": _family(pe.tls),
        "authenticode": _family(pe.authenticode),
        "version_info": version,
        "overlay": _family(pe.overlay),
        "rich_header": _family(pe.rich_header),
    }

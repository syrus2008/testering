"""Minimal DER reader used to extract Authenticode facts. Read-only, bounded, never trusts lengths."""

from __future__ import annotations

from dataclasses import dataclass


class Asn1Error(ValueError):
    pass


@dataclass(frozen=True)
class Tlv:
    tag: int
    start: int  # offset of the tag byte
    hdr: int  # header length
    length: int
    data: bytes  # whole buffer

    @property
    def value(self) -> bytes:
        return self.data[self.start + self.hdr : self.start + self.hdr + self.length]

    @property
    def end(self) -> int:
        return self.start + self.hdr + self.length

    @property
    def raw(self) -> bytes:
        return self.data[self.start : self.end]

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list[Tlv]:
        out: list[Tlv] = []
        pos = self.start + self.hdr
        while pos < self.end:
            t = read_tlv(self.data, pos, self.end)
            out.append(t)
            pos = t.end
        return out


def read_tlv(buf: bytes, pos: int, limit: int | None = None) -> Tlv:
    limit = len(buf) if limit is None else limit
    if pos + 2 > limit:
        raise Asn1Error("truncated header")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise Asn1Error("high tag numbers unsupported")
    first = buf[pos + 1]
    if first < 0x80:
        length, hdr = first, 2
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + 2 + n > limit:
            raise Asn1Error("bad length")
        length = int.from_bytes(buf[pos + 2 : pos + 2 + n], "big")
        hdr = 2 + n
    if pos + hdr + length > limit:
        raise Asn1Error("length exceeds buffer")
    return Tlv(tag, pos, hdr, length, buf)


def oid(t: Tlv) -> str:
    if t.tag != 0x06:
        raise Asn1Error("not an OID")
    v = t.value
    if not v:
        raise Asn1Error("empty OID")
    parts = [v[0] // 40, v[0] % 40]
    acc = 0
    for b in v[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(acc)
            acc = 0
    return ".".join(map(str, parts))


def text(t: Tlv) -> str:
    if t.tag == 0x1E:  # BMPString
        return t.value.decode("utf-16-be", "replace")
    return t.value.decode("utf-8", "replace")


OID_NAMES = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "1.2.840.113549.2.5": "md5",
    "1.2.840.113549.1.7.2": "signedData",
    "1.3.6.1.4.1.311.2.1.4": "spcIndirectDataContent",
    "1.2.840.113549.1.9.5": "signingTime",
    "1.2.840.113549.1.9.6": "countersignature",
    "1.3.6.1.4.1.311.3.3.1": "rfc3161Timestamp",
    "2.5.4.3": "CN",
    "2.5.4.10": "O",
}


def name_attrs(name: Tlv) -> dict[str, str]:
    """X.501 Name → {"CN": ..., "O": ...}."""
    out: dict[str, str] = {}
    for rdn in name.children():
        for atv in rdn.children():
            kids = atv.children()
            if len(kids) == 2 and kids[0].tag == 0x06:
                key = OID_NAMES.get(oid(kids[0]))
                if key:
                    out[key] = text(kids[1])
    return out

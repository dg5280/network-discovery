"""Minimal DNS wire-format encode/decode (enough for mDNS discovery)."""
from __future__ import annotations

import socket
import struct

A, PTR, TXT, AAAA, SRV, ANY = 1, 12, 16, 28, 33, 255


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(names: list[str], qtype: int = PTR, unicast_response: bool = True, qid: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0, len(names), 0, 0, 0)
    qclass = 0x8001 if unicast_response else 0x0001  # top bit = "QU" (unicast response please)
    body = b"".join(encode_name(n) + struct.pack("!HH", qtype, qclass) for n in names)
    return header + body


def _read_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    while True:
        if off >= len(data) or depth > 20:
            raise ValueError("bad name")
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off, depth = ptr, depth + 1
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


def parse_message(data: bytes) -> list[dict]:
    """Return all resource records (answers + authority + additional)."""
    if len(data) < 12:
        return []
    _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    off = 12
    try:
        for _ in range(qd):
            _, off = _read_name(data, off)
            off += 4
        records = []
        for _ in range(an + ns + ar):
            name, off = _read_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            rec = {"name": name, "type": rtype, "ttl": ttl}
            if rtype == A and rdlen == 4:
                rec["value"] = socket.inet_ntoa(rdata)
            elif rtype == AAAA and rdlen == 16:
                rec["value"] = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == PTR:
                rec["value"], _ = _read_name(data, off)
            elif rtype == SRV and rdlen >= 7:
                prio, weight, port = struct.unpack("!HHH", rdata[:6])
                target, _ = _read_name(data, off + 6)
                rec["value"] = {"port": port, "target": target}
            elif rtype == TXT:
                kv, i = {}, 0
                while i < len(rdata):
                    ln = rdata[i]
                    item = rdata[i + 1:i + 1 + ln].decode("utf-8", "replace")
                    i += 1 + ln
                    if "=" in item:
                        k, v = item.split("=", 1)
                        kv[k.lower()] = v
                    elif item:
                        kv[item.lower()] = ""
                rec["value"] = kv
            else:
                rec["value"] = None
            records.append(rec)
            off += rdlen
        return records
    except (ValueError, struct.error, IndexError):
        return []

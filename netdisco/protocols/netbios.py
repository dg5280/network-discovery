"""NetBIOS node-status queries (Windows PCs, Samba/NAS). No admin rights needed."""
from __future__ import annotations

import os
import select
import socket
import struct
import time


def _encode_name(name: bytes) -> bytes:
    name = name.ljust(16, b"\x00")[:16]
    enc = bytearray()
    for b in name:
        enc.append(ord("A") + (b >> 4))
        enc.append(ord("A") + (b & 0x0F))
    return bytes([32]) + bytes(enc) + b"\x00"


NODE_STATUS_QUERY_BODY = _encode_name(b"*") + struct.pack("!HH", 0x21, 0x01)


def _parse(data: bytes) -> dict | None:
    try:
        off = 12 + 34 + 2 + 2 + 4  # header, name, type, class, ttl
        rdlen = struct.unpack("!H", data[off:off + 2])[0]
        off += 2
        num = data[off]
        off += 1
        names, workgroup = [], None
        for _ in range(num):
            raw = data[off:off + 15].decode("ascii", "replace").strip()
            suffix = data[off + 15]
            flags = struct.unpack("!H", data[off + 16:off + 18])[0]
            off += 18
            is_group = bool(flags & 0x8000)
            names.append({"name": raw, "suffix": suffix, "group": is_group})
            if is_group and suffix == 0x00 and not workgroup:
                workgroup = raw
        mac = data[off:off + 6]
        machine = next((n["name"] for n in names if n["suffix"] == 0x00 and not n["group"]), None)
        has_file_server = any(n["suffix"] == 0x20 for n in names)
        mac_s = ":".join(f"{b:02x}" for b in mac) if len(mac) == 6 and any(mac) else None
        return {"name": machine, "workgroup": workgroup, "file_server": has_file_server, "mac": mac_s}
    except (IndexError, struct.error):
        return None


def query(ips: list[str], duration: float = 2.0) -> dict[str, dict]:
    results: dict[str, dict] = {}
    if not ips:
        return results
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", 0))
        sock.setblocking(False)
    except OSError:
        return results
    for ip in ips:
        qid = int.from_bytes(os.urandom(2), "big")
        pkt = struct.pack("!HHHHHH", qid, 0x0000, 1, 0, 0, 0) + NODE_STATUS_QUERY_BODY
        try:
            sock.sendto(pkt, (ip, 137))
        except OSError:
            pass
    deadline = time.time() + duration
    while time.time() < deadline:
        r, _, _ = select.select([sock], [], [], 0.2)
        if not r:
            continue
        try:
            data, (src, _) = sock.recvfrom(2048)
        except OSError:
            continue
        info = _parse(data)
        if info and info.get("name"):
            results[src] = info
    sock.close()
    return results

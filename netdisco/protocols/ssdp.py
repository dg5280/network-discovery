"""SSDP / UPnP discovery — no admin rights needed."""
from __future__ import annotations

import re
import select
import socket
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

SSDP_ADDR = ("239.255.255.250", 1900)
MSEARCH = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: {st}\r\nUSER-AGENT: netdisco/1.0 UPnP/1.1\r\n\r\n")
SEARCH_TARGETS = ["ssdp:all", "upnp:rootdevice"]


def _parse_headers(data: bytes) -> dict:
    headers = {}
    for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def _fetch_description(url: str, ip: str) -> dict:
    """Fetch the UPnP device description XML (only from the device that advertised it)."""
    try:
        if urlparse(url).hostname != ip:
            return {}
        with urllib.request.urlopen(url, timeout=2.5) as resp:
            body = resp.read(200_000)
        root = ET.fromstring(body)
    except Exception:
        return {}
    # Strip namespaces
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    dev = root.find("device")
    if dev is None:
        return {}
    out = {}
    for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription", "deviceType"):
        el = dev.find(k)
        if el is not None and el.text:
            out[k] = el.text.strip()
    return out


def discover(duration: float = 3.5, local_ip: str | None = None, fetch: bool = True) -> dict[str, dict]:
    """Return {ip: {server, locations, types, description}}."""
    results: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if local_ip:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            except OSError:
                pass
        sock.bind(("", 0))
        sock.setblocking(False)
    except OSError:
        return results

    for st in SEARCH_TARGETS:
        for _ in range(2):
            try:
                sock.sendto(MSEARCH.format(st=st).encode(), SSDP_ADDR)
            except OSError:
                pass

    deadline = time.time() + duration
    while time.time() < deadline:
        r, _, _ = select.select([sock], [], [], 0.2)
        if not r:
            continue
        try:
            data, (src, _) = sock.recvfrom(4096)
        except OSError:
            continue
        h = _parse_headers(data)
        dev = results.setdefault(src, {"server": None, "locations": set(), "types": set(), "description": {}})
        if h.get("server"):
            dev["server"] = h["server"]
        if h.get("location"):
            dev["locations"].add(h["location"])
        st = h.get("st") or h.get("nt")
        if st and st.startswith("urn:"):
            m = re.search(r":(device|service):([^:]+):", st)
            if m:
                dev["types"].add(f"{m.group(1)}:{m.group(2)}")
    sock.close()

    if fetch:
        jobs = {ip: sorted(d["locations"])[0] for ip, d in results.items() if d["locations"]}
        with ThreadPoolExecutor(16) as ex:
            futs = {ip: ex.submit(_fetch_description, url, ip) for ip, url in jobs.items()}
            for ip, f in futs.items():
                results[ip]["description"] = f.result()
    for d in results.values():
        d["locations"] = sorted(d["locations"])
        d["types"] = sorted(d["types"])
    return results

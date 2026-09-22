"""mDNS / Bonjour (DNS-SD) discovery — no admin rights needed."""
from __future__ import annotations

import select
import socket
import struct
import time

from . import dnswire

MDNS_ADDR, MDNS_PORT = "224.0.0.251", 5353

# Service types worth asking about directly (many devices don't answer the meta-query).
COMMON_SERVICES = [
    "_services._dns-sd._udp.local",
    "_device-info._tcp.local", "_companion-link._tcp.local", "_airplay._tcp.local",
    "_raop._tcp.local", "_homekit._tcp.local", "_hap._tcp.local", "_sleep-proxy._udp.local",
    "_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local",
    "_scanner._tcp.local", "_uscan._tcp.local",
    "_googlecast._tcp.local", "_spotify-connect._tcp.local", "_sonos._tcp.local",
    "_amzn-wplay._tcp.local", "_roku-rcp._tcp.local", "_nvstream._tcp.local",
    "_smb._tcp.local", "_afpovertcp._tcp.local", "_adisk._tcp.local", "_nfs._tcp.local",
    "_ssh._tcp.local", "_sftp-ssh._tcp.local", "_workstation._tcp.local", "_http._tcp.local",
    "_rfb._tcp.local", "_rdlink._tcp.local", "_matter._tcp.local", "_matterc._udp.local",
    "_hue._tcp.local", "_miio._udp.local", "_esphomelib._tcp.local", "_axis-video._tcp.local",
    "_rtsp._tcp.local", "_onvif._tcp.local", "_androidtvremote2._tcp.local", "_meshcop._udp.local",
]


def _open_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    try:
        # Share 5353 with the OS responder so we also hear multicast answers.
        s.bind(("", MDNS_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_ADDR), socket.inet_aton("0.0.0.0"))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        # Fall back to an ephemeral port: responders then reply by unicast ("legacy" query).
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.bind(("", 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.setblocking(False)
    return s


def discover(duration: float = 4.0, local_ip: str | None = None) -> dict[str, dict]:
    """Return {ip: {services, instances, hostnames, txt, model}}."""
    results: dict[str, dict] = {}
    host_ips: dict[str, str] = {}   # hostname.local -> ip (from A records)
    try:
        sock = _open_socket()
    except OSError:
        return results
    if local_ip:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        except OSError:
            pass

    asked: set[str] = set()
    pending = list(COMMON_SERVICES)

    def send(names):
        # Keep packets small: batch a handful of questions per datagram.
        for i in range(0, len(names), 8):
            try:
                sock.sendto(dnswire.build_query(names[i:i + 8]), (MDNS_ADDR, MDNS_PORT))
            except OSError:
                pass

    send(pending)
    asked.update(pending)
    deadline = time.time() + duration
    resend_at = time.time() + 1.2

    while time.time() < deadline:
        r, _, _ = select.select([sock], [], [], 0.2)
        if r:
            try:
                data, (src, _) = sock.recvfrom(9000)
            except OSError:
                continue
            recs = dnswire.parse_message(data)
            if not recs:
                continue
            dev = results.setdefault(src, {"services": set(), "instances": set(),
                                           "hostnames": set(), "txt": {}, "model": None})
            new_types = []
            for rec in recs:
                t, name, val = rec["type"], rec["name"], rec["value"]
                if t == dnswire.PTR and name == "_services._dns-sd._udp.local" and val:
                    stype = val.lower()
                    if stype not in asked:
                        new_types.append(stype)
                elif t == dnswire.PTR and val:
                    dev["services"].add(name.lower().replace(".local", ""))
                    dev["instances"].add(val.split("._")[0])
                elif t == dnswire.SRV and val:
                    parts = name.split("._", 1)
                    if len(parts) == 2:
                        dev["instances"].add(parts[0])
                        dev["services"].add("_" + parts[1].lower().replace(".local", ""))
                    if val.get("target"):
                        dev["hostnames"].add(val["target"])
                elif t == dnswire.A and val:
                    host_ips[name] = val
                    if val == src:
                        dev["hostnames"].add(name)
                elif t == dnswire.TXT and isinstance(val, dict):
                    for k in ("model", "md", "ty", "fn", "am", "manufacturer", "usb_mfg", "usb_mdl",
                              "product", "rpmd", "note", "vendor", "mf"):
                        if val.get(k):
                            dev["txt"][k] = val[k]
            if new_types:
                asked.update(new_types)
                send(new_types)
        if resend_at and time.time() >= resend_at:
            send(list(COMMON_SERVICES))   # second round catches slow sleepers
            resend_at = 0
    sock.close()

    for dev in results.values():
        dev["model"] = dev["txt"].get("model") or dev["txt"].get("md") or dev["txt"].get("ty") \
            or dev["txt"].get("rpmd") or dev["txt"].get("usb_mdl")
        for k in ("services", "instances", "hostnames"):
            dev[k] = sorted(dev[k])
    return results

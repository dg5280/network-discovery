"""Continuous ping to every discovered device. No admin rights needed.

macOS (and Linux with ping_group_range set) allow unprivileged ICMP "datagram" sockets,
so one socket pings every device in parallel. If that isn't available we fall back to the
system ping binary, and for devices that ignore ICMP we time a TCP handshake to a port the
scan found open.
"""
from __future__ import annotations

import os
import select
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import health

# LAN thresholds (ms) — tighter than internet latency.
GREEN_MS = 30
YELLOW_MS = 100


def status_for(ms: float | None) -> str:
    if ms is None:
        return "red"
    if ms < GREEN_MS:
        return "green"
    if ms < YELLOW_MS:
        return "yellow"
    return "red"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_sweep(ips: list[str], timeout: float = 1.5) -> dict[str, float] | None:
    """Ping all ips at once over an unprivileged ICMP socket.
    Returns {ip: rtt_ms} for replies, or None if unprivileged ICMP isn't allowed here."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except (PermissionError, OSError):
        return None
    sock.setblocking(False)
    ident = os.getpid() & 0xFFFF
    sent: dict[tuple[str, int], float] = {}
    for seq, ip in enumerate(ips, start=1):
        payload = struct.pack("!d", time.time()) + b"netdisco"
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq & 0xFFFF)
        pkt = struct.pack("!BBHHH", 8, 0, _checksum(hdr + payload), ident, seq & 0xFFFF) + payload
        try:
            sock.sendto(pkt, (ip, 0))
            sent[(ip, seq & 0xFFFF)] = time.perf_counter()
        except OSError:
            pass
    results: dict[str, float] = {}
    deadline = time.perf_counter() + timeout
    while sent and time.perf_counter() < deadline:
        r, _, _ = select.select([sock], [], [], max(0.0, deadline - time.perf_counter()))
        if not r:
            break
        try:
            data, (src, _) = sock.recvfrom(2048)
        except OSError:
            continue
        now = time.perf_counter()
        if data and data[0] >> 4 == 4:          # macOS includes the IP header; Linux doesn't
            data = data[(data[0] & 0x0F) * 4:]
        if len(data) < 8 or data[0] != 0:       # 0 = echo reply
            continue
        seq = struct.unpack("!H", data[6:8])[0]  # Linux rewrites the id, so match on (src, seq)
        t0 = sent.pop((src, seq), None)
        if t0 is not None:
            results[src] = round((now - t0) * 1000, 1)
    sock.close()
    return results


class DevicePinger:
    """Pings the scanner's online devices every `interval` seconds."""

    def __init__(self, scanner, interval: float = 5.0):
        self.scanner = scanner
        self.interval = interval
        self.results: dict[str, dict] = {}     # ip -> {ms, status, method, t, loss_streak}
        self._lock = threading.Lock()
        self._icmp_ok = True
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="pinger").start()

    def snapshot(self) -> dict:
        with self._lock:
            return {"thresholds": {"green_ms": GREEN_MS, "yellow_ms": YELLOW_MS},
                    "interval": self.interval, "results": dict(self.results)}

    def clear(self):
        with self._lock:
            self.results.clear()

    def _targets(self) -> list[dict]:
        snap = self.scanner.snapshot()
        return [d for d in snap["devices"] if d.get("online") and not d.get("is_self")]

    def ping_once(self):
        devs = self._targets()
        ips = [d["ip"] for d in devs]
        if not ips:
            with self._lock:
                self.results.clear()
            return
        got = icmp_sweep(ips) if self._icmp_ok else None
        method = "icmp"
        if got is None:
            self._icmp_ok = False
            method = "ping"
            with ThreadPoolExecutor(16) as ex:
                res = dict(zip(ips, ex.map(lambda ip: health.icmp_ping(ip, count=1, timeout_s=1), ips)))
            got = {ip: r["latency_ms"] for ip, r in res.items() if r and r.get("latency_ms") is not None}

        # Devices that ignore ICMP: time a TCP handshake to a port we know is open.
        missing = [d for d in devs if d["ip"] not in got and d.get("ports")]
        tcp: dict[str, tuple[float, int]] = {}
        if missing:
            def tcp_one(d):
                r = health.tcp_ping(d["ip"], ports=tuple(d["ports"][:2]), timeout_s=1.0)
                return d["ip"], r
            with ThreadPoolExecutor(16) as ex:
                for ip, r in ex.map(tcp_one, missing):
                    if r["latency_ms"] is not None:
                        tcp[ip] = (r["latency_ms"], r["method"])

        now = time.time()
        with self._lock:
            new = {}
            for ip in ips:
                prev = self.results.get(ip, {})
                if ip in got:
                    ms, m = got[ip], method
                elif ip in tcp:
                    ms, m = tcp[ip]
                else:
                    ms, m = None, method
                streak = 0 if ms is not None else prev.get("miss_streak", 0) + 1
                new[ip] = {"ms": ms, "status": status_for(ms), "method": m, "t": now, "miss_streak": streak}
            self.results = new

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.ping_once()
            except Exception as e:
                print(f"[pinger] {e}")
            self._stop.wait(self.interval)

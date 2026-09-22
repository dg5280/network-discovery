"""Live Wi-Fi signal sampling for the survey meter.

macOS: a CoreWLAN helper subprocess reports every second.
Fallback (helper unavailable or Linux): slower sampling via system_profiler / iw.
"""
from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
import threading
import time

from . import sysinfo

HISTORY = 900  # samples kept (15 min at 1 s)

RSSI_LEVELS = [(-60, "green", "Excellent"), (-67, "green", "Good"), (-75, "yellow", "Fair"), (-200, "red", "Poor")]


def rssi_status(rssi: int | None) -> tuple[str, str]:
    if rssi is None:
        return "unknown", "No signal"
    for floor, status, label in RSSI_LEVELS:
        if rssi >= floor:
            return status, label
    return "red", "Poor"


def snr_status(snr: int | None) -> str:
    if snr is None:
        return "unknown"
    return "green" if snr >= 25 else "yellow" if snr >= 15 else "red"


class WifiLive:
    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self.samples: collections.deque = collections.deque(maxlen=HISTORY)
        self.events: collections.deque = collections.deque(maxlen=200)   # roaming / disconnects
        self.marks: list[dict] = []
        self.mode = "starting"
        self._lock = threading.Lock()
        self._proc = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        threading.Thread(target=self._run, daemon=True, name="wifi-live").start()

    def stop(self):
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()

    def _run(self):
        if sysinfo.IS_MAC and self._run_helper():
            return
        self._run_fallback()

    def _run_helper(self) -> bool:
        """Returns False if the helper never produced a usable sample (then we fall back)."""
        got_any = False
        for attempt in range(3):
            try:
                self._proc = subprocess.Popen(
                    [sys.executable, "-m", "netdisco.wifi_helper", str(self.interval)],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                    cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            except OSError:
                return got_any
            self.mode = "fast"
            for line in self._proc.stdout:
                if self._stop.is_set():
                    return True
                try:
                    s = json.loads(line)
                except ValueError:
                    continue
                if s.get("ok"):
                    got_any = True
                    self._add(s)
            if self._stop.is_set():
                return True
            if not got_any:
                return False
            time.sleep(1)  # helper died after working; restart it
        return got_any

    def _run_fallback(self):
        self.mode = "slow"
        while not self._stop.is_set():
            _, iface = sysinfo.default_route()
            w = sysinfo.wifi_info(iface, max_age=0)  # force fresh read
            s = {"t": time.time(), "ok": True, "interface": w.get("interface"),
                 "associated": w.get("rssi_dbm") is not None, "rssi_dbm": w.get("rssi_dbm"),
                 "noise_dbm": w.get("noise_dbm"), "tx_rate_mbps": w.get("tx_rate_mbps"),
                 "ssid": w.get("ssid"), "bssid": None, "channel_text": w.get("channel")}
            if w.get("is_wifi") or w.get("rssi_dbm") is not None:
                self._add(s)
            self._stop.wait(1.0 if not sysinfo.IS_MAC else 2.0)

    # ------------------------------------------------------------------ data
    def _add(self, s: dict):
        rssi, noise = s.get("rssi_dbm"), s.get("noise_dbm")
        s["snr_db"] = rssi - noise if rssi is not None and noise is not None else None
        s["status"], s["quality"] = rssi_status(rssi)
        with self._lock:
            prev = self.samples[-1] if self.samples else None
            if prev:
                if prev.get("bssid") and s.get("bssid") and prev["bssid"] != s["bssid"]:
                    self.events.append({"t": s["t"], "type": "roam", "from": prev["bssid"], "to": s["bssid"],
                                        "channel": s.get("channel")})
                if prev.get("associated") and not s.get("associated"):
                    self.events.append({"t": s["t"], "type": "disconnect"})
                if not prev.get("associated") and s.get("associated"):
                    self.events.append({"t": s["t"], "type": "connect", "ssid": s.get("ssid")})
            self.samples.append(s)

    def latest(self, max_age: float = 5.0) -> dict | None:
        with self._lock:
            if self.samples and time.time() - self.samples[-1]["t"] <= max_age:
                return dict(self.samples[-1])
        return None

    def snapshot(self, since: float = 0.0) -> dict:
        with self._lock:
            samples = [s for s in self.samples if s["t"] > since]
            return {"mode": self.mode, "interval": self.interval,
                    "current": dict(self.samples[-1]) if self.samples else None,
                    "samples": samples, "events": [e for e in self.events if e["t"] > since],
                    "marks": list(self.marks)}

    def mark(self, label: str) -> dict | None:
        """Record the signal at a named spot (average of the last 5 samples)."""
        label = (label or "").strip()[:80] or f"Spot {len(self.marks) + 1}"
        with self._lock:
            recent = [s for s in list(self.samples)[-5:] if s.get("rssi_dbm") is not None]
            if not recent:
                return None
            avg = lambda k: (round(sum(s[k] for s in recent if s.get(k) is not None) /  # noqa: E731
                                   max(1, sum(1 for s in recent if s.get(k) is not None)))
                             if any(s.get(k) is not None for s in recent) else None)
            last = recent[-1]
            m = {"label": label, "t": time.time(), "rssi_dbm": avg("rssi_dbm"), "noise_dbm": avg("noise_dbm"),
                 "snr_db": avg("snr_db"), "tx_rate_mbps": avg("tx_rate_mbps"), "min_rssi": min(s["rssi_dbm"] for s in recent),
                 "bssid": last.get("bssid"), "ssid": last.get("ssid"), "channel": last.get("channel"),
                 "band": last.get("band"), "width_mhz": last.get("width_mhz")}
            m["status"], m["quality"] = rssi_status(m["rssi_dbm"])
            self.marks.append(m)
            return m

    def clear_marks(self):
        with self._lock:
            self.marks.clear()

"""History log: remembers network problems (internet outages, router not answering, DNS failures,
Wi-Fi drops and weak signal) with when they started, how long they lasted and how bad they got.

Fed by every health check and by the per-second Wi-Fi sampler. A problem becomes an incident only
after it persists for a few checks, and ends after a couple of good checks, so one lost ping
doesn't clutter the log. Stored as JSON lines in ~/.netdisco/events.jsonl (survives restarts).
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time

# How many consecutive checks (default 5 s apart) before a condition opens / closes an incident.
OPEN_AFTER = {"red": 2, "yellow": 3}
CLOSE_AFTER = 2
GAP_S = 60            # no health check for this long (computer asleep / app stopped) = monitoring gap
MAX_KEEP = 5000       # events kept in memory; the file is compacted to this many
MAX_FILE = 4_000_000  # bytes before the file is compacted

KIND_LABELS = {"internet": "Internet", "gateway": "Router", "dns": "DNS", "wifi": "Wi-Fi", "network": "Network",
               "app": "Monitoring"}


def _fmt_ms(v):
    return f"{v:.0f} ms" if isinstance(v, (int, float)) else "—"


class EventLog:
    def __init__(self, path: str | None = None, persist: bool = True):
        if persist and path is None:
            from .sysinfo import data_dir
            path = os.path.join(data_dir(), "events.jsonl")
        self.path = path if persist else None
        self.events: dict[str, dict] = {}          # id -> event (insertion-ordered)
        self._lock = threading.Lock()
        self._cond: dict[str, dict] = {}           # condition key -> {bad, good, level, event_id, worst...}
        self._last_obs = None
        self._wifi_seen = 0.0
        self._wifi_down: dict | None = None
        self._load()

    # ---------------------------------------------------------------- storage
    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(e, dict) and e.get("id"):
                        self.events[e["id"]] = e     # later lines update earlier ones
        except OSError:
            return
        # Anything still open was interrupted when the app stopped.
        for e in self.events.values():
            if e.get("open"):
                e["open"] = False
                e["end"] = e.get("last_seen") or e["start"]
                e["detail"] = (e.get("detail") or "") + " (monitoring stopped before it ended)"
        self._trim()

    def _write(self, e: dict):
        if not self.path:
            return
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > MAX_FILE:
                self._compact()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(e, separators=(",", ":")) + "\n")
        except OSError as err:
            print(f"[events] couldn't write the history log: {err}")

    def _compact(self):
        self._trim()
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for e in self.events.values():
                fh.write(json.dumps(e, separators=(",", ":")) + "\n")
        os.replace(tmp, self.path)

    def _trim(self):
        if len(self.events) > MAX_KEEP:
            for k in list(self.events)[: len(self.events) - MAX_KEEP]:
                if not self.events[k].get("open"):
                    del self.events[k]

    # ---------------------------------------------------------------- events
    def add(self, kind: str, severity: str, title: str, detail: str = "", t: float | None = None,
            network: str | None = None, **extra) -> dict:
        """A point-in-time event (no duration)."""
        e = {"id": secrets.token_hex(6), "kind": kind, "severity": severity, "title": title, "detail": detail,
             "start": t or time.time(), "end": None, "open": False, "point": True, "network": network, **extra}
        with self._lock:
            self.events[e["id"]] = e
            self._trim()
        self._write(e)
        return e

    def _open(self, kind, severity, title, detail, t, network, metrics) -> dict:
        e = {"id": secrets.token_hex(6), "kind": kind, "severity": severity, "title": title, "detail": detail,
             "start": t, "end": None, "last_seen": t, "open": True, "point": False, "network": network, **metrics}
        self.events[e["id"]] = e
        self._trim()
        self._write(dict(e))
        return e

    def _close(self, e: dict, t: float, note: str | None = None):
        e["open"] = False
        e["end"] = t
        if note:
            e["detail"] = (e.get("detail") or "") + f" {note}"
        self._write(dict(e))

    def clear(self):
        with self._lock:
            self.events = {k: e for k, e in self.events.items() if e.get("open")}
            if self.path:
                try:
                    self._compact()
                except OSError:
                    pass

    # ---------------------------------------------------------------- health observation
    def _condition(self, key: str, level: str | None, t: float, make, metrics: dict, network: str | None):
        """Track one condition. level: None/'green' = fine, 'yellow' = degraded, 'red' = down.
        make(level) -> (kind, severity, title, detail) for the incident."""
        c = self._cond.setdefault(key, {"bad": 0, "good": 0, "event": None})
        bad = level in ("yellow", "red")
        if bad:
            c["bad"] += 1
            c["good"] = 0
        else:
            c["good"] += 1
            c["bad"] = 0
        e = c["event"]
        if e is not None:
            if bad:
                e["last_seen"] = t
                for k, v in metrics.items():                      # keep the worst values seen
                    if v is None:
                        continue
                    cur = e.get(k)
                    worse = (v < cur) if k.startswith("min_") else (v > cur)
                    if cur is None or worse:
                        e[k] = v
                if level == "red" and e["severity"] != "critical":
                    kind, sev, title, detail = make("red")
                    e.update(severity=sev, title=title, detail=detail)
                    self._write(dict(e))
            elif c["good"] >= CLOSE_AFTER:
                self._close(e, e.get("last_seen", t))
                c["event"] = None
        elif bad and c["bad"] >= OPEN_AFTER["red" if level == "red" else "yellow"]:
            kind, sev, title, detail = make(level)
            c["event"] = self._open(kind, sev, title, detail, t, network, {k: v for k, v in metrics.items() if v is not None})

    def observe(self, snap: dict):
        """Called after every health check with HealthMonitor's snapshot."""
        t = snap.get("timestamp") or time.time()
        with self._lock:
            # A long gap means the computer slept or the app was stopped: end open incidents at the last check.
            if self._last_obs and t - self._last_obs > GAP_S:
                for c in self._cond.values():
                    if c["event"] is not None:
                        self._close(c["event"], c["event"].get("last_seen", self._last_obs),
                                    "(monitoring paused — the computer may have been asleep)")
                    c.update(bad=0, good=0, event=None)
            self._last_obs = t

            ident = snap.get("identity") or {}
            net = ident.get("label")
            local = snap.get("local") or {}
            inet, gw, dns, wifi = (snap.get(k) or {} for k in ("internet", "gateway", "dns", "wifi"))

            offline = not local.get("interface") or not local.get("ip")
            # A Wi-Fi drop is already logged by the per-second sampler; don't log it twice.
            self._condition("offline", "red" if offline and self._wifi_down is None else None, t,
                            lambda lv: ("network", "critical", "Not connected to any network",
                                        "This computer had no active network connection (Wi-Fi off or out of range, cable unplugged)."),
                            {}, net)
            if offline:
                return      # everything below would just repeat "no network"

            gw_level = gw.get("status") if gw.get("target") else None
            self._condition("gateway", gw_level, t, lambda lv: (
                "gateway", "critical" if lv == "red" else "warning",
                "Router not responding" if lv == "red" else "Router slow or dropping packets",
                f"No reply from the router at {gw.get('target')}. Devices here couldn't reach anything beyond it."
                if lv == "red" else f"Round-trip time to the router ({gw.get('target')}) was high or packets were lost — "
                                    "usually Wi-Fi interference, weak signal or a busy router."),
                {"worst_ms": gw.get("latency_ms"), "max_loss": gw.get("loss_pct")}, net)

            gw_ok = gw_level == "green"
            self._condition("internet", inet.get("status"), t, lambda lv: (
                "internet", "critical" if lv == "red" else "warning",
                "Internet outage" if lv == "red" else "Internet slow or losing packets",
                ("The router answered but the internet didn't — the problem was upstream (modem, ISP or the router's WAN)."
                 if gw_ok else "The router wasn't answering either — the problem was on the local network or Wi-Fi.")
                if lv == "red" else
                (f"Latency to the internet was over {snap.get('thresholds', {}).get('latency_green_ms', 50)} ms or packets were lost"
                 + ("; the router itself was fine, so the slowdown was upstream." if gw_ok else "."))),
                {"worst_ms": inet.get("latency_ms"), "max_loss": inet.get("loss_pct")}, net)

            self._condition("dns", dns.get("status"), t, lambda lv: (
                "dns", "critical" if lv == "red" else "warning",
                "DNS failing — websites won't load by name" if lv == "red" else "DNS slow or partly failing",
                f"DNS servers: {', '.join(dns.get('servers') or []) or 'unknown'}."
                + (" The internet itself was reachable, so try other DNS servers (e.g. 1.1.1.1)." if inet.get("status") == "green" else "")),
                {"worst_ms": dns.get("worst_ms")}, net)

            if wifi.get("is_wifi") and wifi.get("rssi_dbm") is not None:
                self._condition("wifi_signal", "red" if wifi.get("status") == "red" else None, t, lambda lv: (
                    "wifi", "warning", "Weak Wi-Fi signal",
                    f"Signal dropped below {snap.get('thresholds', {}).get('rssi_yellow_dbm', -75)} dBm"
                    + (f" on “{wifi.get('ssid')}”" if wifi.get("ssid") else "") + " — expect slow speeds and drop-outs."),
                    {"min_rssi": wifi.get("rssi_dbm")}, net)

    def observe_wifi(self, wifi_live):
        """Pull roam / disconnect / connect events from the per-second Wi-Fi sampler."""
        if wifi_live is None:
            return
        try:
            evs = [e for e in list(wifi_live.events) if e["t"] > self._wifi_seen]
        except Exception:
            return
        for ev in sorted(evs, key=lambda e: e["t"]):
            self._wifi_seen = max(self._wifi_seen, ev["t"])
            if ev["type"] == "disconnect":
                with self._lock:
                    if self._wifi_down is None:
                        self._wifi_down = self._open("wifi", "critical", "Wi-Fi disconnected",
                                                     "This computer lost its Wi-Fi connection.", ev["t"], None, {})
            elif ev["type"] == "connect":
                with self._lock:
                    if self._wifi_down is not None:
                        e = self._wifi_down
                        e["last_seen"] = ev["t"]
                        self._close(e, ev["t"], f"Reconnected to “{ev['ssid']}”." if ev.get("ssid") else "Reconnected.")
                        self._wifi_down = None
            elif ev["type"] == "roam":
                self.add("wifi", "info", "Roamed to another access point",
                         f"{ev.get('from') or '?'} → {ev.get('to') or '?'}" +
                         (f" (channel {ev['channel']})" if ev.get("channel") else ""), t=ev["t"])

    def network_changed(self, old: dict | None, new: dict):
        self.add("network", "info", f"Joined {new.get('label') or 'a new network'}",
                 f"Previously on {old.get('label')}." if old and old.get("label") else "", network=new.get("label"))

    # ---------------------------------------------------------------- queries
    def query(self, since: float = 0.0, kinds: list[str] | None = None, limit: int = 1000) -> dict:
        now = time.time()
        with self._lock:
            evs = [dict(e) for e in self.events.values()
                   if (e.get("end") or (now if e.get("open") else e["start"])) >= since and (not kinds or e["kind"] in kinds)]
        evs.sort(key=lambda e: e["start"], reverse=True)
        for e in evs:
            end = e.get("end") or (now if e.get("open") else None)
            e["duration_s"] = round(end - e["start"], 1) if end and not e.get("point") else None
        return {"now": now, "events": evs[:limit], "total": len(evs), "stats": self.stats(), "labels": KIND_LABELS,
                "ongoing": [e for e in evs if e.get("open")]}

    def stats(self) -> dict:
        """Counts and downtime for the last 24 hours and 7 days."""
        now = time.time()
        out = {}
        with self._lock:
            evs = list(self.events.values())
        first = min((e["start"] for e in evs), default=None)
        for name, span in (("day", 86400), ("week", 7 * 86400)):
            since = now - span
            s = {"outages": 0, "outage_s": 0.0, "slow": 0, "wifi_drops": 0, "dns": 0, "router": 0, "incidents": 0}
            for e in evs:
                if e.get("point"):
                    continue
                end = e.get("end") or now
                if end < since:
                    continue
                dur = end - max(e["start"], since)
                s["incidents"] += 1
                if e["kind"] == "internet" and e["severity"] == "critical":
                    s["outages"] += 1
                    s["outage_s"] += dur
                elif e["kind"] == "internet":
                    s["slow"] += 1
                elif e["kind"] == "wifi" and "disconnect" in e["title"].lower() or e["kind"] == "network":
                    s["wifi_drops"] += 1
                elif e["kind"] == "dns":
                    s["dns"] += 1
                elif e["kind"] == "gateway":
                    s["router"] += 1
            s["outage_s"] = round(s["outage_s"])
            out[name] = s
        out["first_event"] = first
        return out


def to_csv(events: list[dict]) -> str:
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["start", "end", "duration_s", "type", "severity", "title", "detail", "network", "worst_ms", "max_loss_pct", "min_rssi_dbm"])
    for e in events:
        iso = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else ""  # noqa: E731
        w.writerow([iso(e["start"]), iso(e.get("end")), e.get("duration_s") or "", KIND_LABELS.get(e["kind"], e["kind"]),
                    e["severity"], e["title"], e.get("detail", ""), e.get("network") or "", e.get("worst_ms", ""),
                    e.get("max_loss", ""), e.get("min_rssi", "")])
    return buf.getvalue()

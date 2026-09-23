"""Network health checks: internet, gateway, DNS, Wi-Fi. No admin rights needed."""
from __future__ import annotations

import collections
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import sysinfo

# Thresholds (ms). Edit here to tune the traffic lights.
THRESHOLDS = {
    "latency_green_ms": 50,
    "latency_yellow_ms": 150,
    "dns_green_ms": 200,
    "dns_yellow_ms": 1000,
    "rssi_green_dbm": -67,   # stronger than this = good
    "rssi_yellow_dbm": -75,  # between yellow and green = fair; weaker = poor
}

INTERNET_TARGETS = ["1.1.1.1", "8.8.8.8"]
DNS_TEST_NAMES = ["apple.com", "google.com", "cloudflare.com"]
HISTORY_LEN = 60


# --------------------------------------------------------------------------- probes

def icmp_ping(host: str, count: int = 3, timeout_s: int = 3) -> dict | None:
    """Use the system ping binary (unprivileged on macOS & most Linux).
    Returns None if ping is unavailable or produced no parseable output."""
    if sysinfo.IS_MAC:
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-t", str(timeout_s), host]
    else:
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-w", str(timeout_s), host]
    if not sysinfo.shutil.which("ping"):
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 2).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    loss = re.search(r"([\d.]+)% packet loss", out)
    if not loss:
        return None
    rtt = re.search(r"= [\d.]+/([\d.]+)/[\d.]+", out)
    return {
        "method": "icmp",
        "loss_pct": float(loss.group(1)),
        "latency_ms": round(float(rtt.group(1)), 1) if rtt else None,
    }


def tcp_ping(host: str, ports=(443, 80, 53), timeout_s: float = 1.5) -> dict:
    """Fallback: time a TCP handshake. A refused connection still proves reachability."""
    for port in ports:
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                pass
            return {"method": f"tcp/{port}", "loss_pct": 0.0,
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
        except ConnectionRefusedError:
            return {"method": f"tcp/{port}", "loss_pct": 0.0,
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
        except OSError:
            continue
    return {"method": "tcp", "loss_pct": 100.0, "latency_ms": None}


def reach(host: str) -> dict:
    r = icmp_ping(host)
    if r is None or r["latency_ms"] is None:
        # ICMP blocked or unavailable -> try TCP before declaring it down
        t = tcp_ping(host)
        if t["latency_ms"] is not None or r is None:
            r = t
    r["target"] = host
    return r


def latency_status(r: dict) -> str:
    if r.get("latency_ms") is None or r.get("loss_pct", 100) >= 100:
        return "red"
    lat, loss = r["latency_ms"], r["loss_pct"]
    if lat >= THRESHOLDS["latency_yellow_ms"]:
        return "red"
    if lat >= THRESHOLDS["latency_green_ms"] or loss > 0:
        return "yellow"
    return "green"


def check_dns() -> dict:
    results = []

    def one(name):
        t0 = time.perf_counter()
        try:
            addrs = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
            return {"name": name, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1),
                    "address": addrs[0][4][0]}
        except OSError as e:
            return {"name": name, "ok": False, "ms": None, "error": str(e)}

    with ThreadPoolExecutor(len(DNS_TEST_NAMES)) as ex:
        results = list(ex.map(one, DNS_TEST_NAMES))
    ok = [r for r in results if r["ok"]]
    worst = max((r["ms"] for r in ok), default=None)
    if not ok:
        status, summary = "red", "Name lookups are failing"
    elif len(ok) < len(results) or (worst or 0) >= THRESHOLDS["dns_yellow_ms"]:
        status, summary = "yellow", "Some lookups failed or were slow"
    elif (worst or 0) >= THRESHOLDS["dns_green_ms"]:
        status, summary = "yellow", "Lookups are slow"
    else:
        status, summary = "green", "Lookups working"
    return {"status": status, "summary": summary, "worst_ms": worst,
            "servers": sysinfo.dns_servers(), "lookups": results}


def check_wifi(iface: str | None, live=None) -> dict:
    w = dict(sysinfo.wifi_info(iface))
    cur = live.latest() if live else None
    if cur and cur.get("associated") and (not cur.get("interface") or cur.get("interface") == iface):
        # Fresh per-second values from the live sampler beat the cached system_profiler read.
        w["is_wifi"] = True
        for k in ("rssi_dbm", "noise_dbm", "tx_rate_mbps", "bssid"):
            if cur.get(k) is not None:
                w[k] = cur[k]
        if cur.get("ssid"):
            w["ssid"], w["ssid_hidden_by_os"] = cur["ssid"], False
        if cur.get("channel"):
            w["channel"] = f"{cur['channel']} ({cur.get('band') or '?'}" + \
                (f", {cur['width_mhz']}MHz)" if cur.get("width_mhz") else ")")
    if not iface:
        w.update(status="red", summary="No active network connection")
    elif not w["is_wifi"]:
        w.update(status="green", summary="Wired connection (not using Wi-Fi)")
    elif w["rssi_dbm"] is None:
        w.update(status="green" if (w["ssid"] or w["ssid_hidden_by_os"]) else "unknown",
                 summary="Connected" if (w["ssid"] or w["ssid_hidden_by_os"]) else "Signal unknown")
    elif w["rssi_dbm"] >= THRESHOLDS["rssi_green_dbm"]:
        w.update(status="green", summary="Strong signal")
    elif w["rssi_dbm"] >= THRESHOLDS["rssi_yellow_dbm"]:
        w.update(status="yellow", summary="Fair signal")
    else:
        w.update(status="red", summary="Weak signal")
    return w


# --------------------------------------------------------------------------- monitor

def _network_changed(old: dict | None, new: dict) -> bool:
    """Compare network identities field by field, ignoring fields unknown on either side
    (macOS sometimes hides the SSID; the gateway MAC may not be in the ARP table yet)."""
    if not old:
        return False
    for k in ("ssid", "network", "gateway_mac"):
        if old.get(k) and new.get(k) and old[k] != new[k]:
            return True
    return False


class HealthMonitor:
    """Runs all checks on an interval in a background thread and keeps history."""

    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self.on_network_change = None   # callback(old_identity, new_identity)
        self.on_snapshot = None          # callback(snapshot) after every check (history log)
        self.wifi_live = None            # optional WifiLive for fresh signal readings
        self.identity: dict | None = None
        self.latest: dict = {}
        self.history = {"internet": collections.deque(maxlen=HISTORY_LEN),
                        "gateway": collections.deque(maxlen=HISTORY_LEN)}
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def run_once(self) -> dict:
        gw, iface = sysinfo.default_route()
        ip, net = sysinfo.interface_network(iface)
        with ThreadPoolExecutor(4) as ex:
            f_inet = [ex.submit(reach, t) for t in INTERNET_TARGETS]
            f_gw = ex.submit(reach, gw) if gw else None
            f_dns = ex.submit(check_dns)
            f_wifi = ex.submit(check_wifi, iface, self.wifi_live)
            inet_results = [f.result() for f in f_inet]
            gw_r = f_gw.result() if f_gw else {"target": None, "loss_pct": 100.0,
                                                 "latency_ms": None, "method": "none"}
            dns, wifi = f_dns.result(), f_wifi.result()

        reachable = [r for r in inet_results if r["latency_ms"] is not None]
        inet = min(reachable, key=lambda r: r["latency_ms"]) if reachable else inet_results[0]
        inet = dict(inet, status=latency_status(inet), all=inet_results)
        inet["summary"] = {"green": "Internet reachable", "yellow": "Internet reachable but slow or lossy",
                           "red": "Internet unreachable"}[inet["status"]]
        gw_r = dict(gw_r, status=latency_status(gw_r))
        gw_r["summary"] = ("No default gateway found" if not gw else
                           {"green": "Router responding", "yellow": "Router slow or dropping packets",
                            "red": "Router not responding"}[gw_r["status"]])

        # Network identity: which Wi-Fi / LAN are we on? Used to reset the device list on change.
        if ip and net:
            from .discovery import read_arp
            ident = {"ssid": wifi.get("ssid") if wifi.get("is_wifi") else None, "network": str(net),
                     "gateway": gw, "gateway_mac": read_arp().get(gw) if gw else None}
            ident["label"] = (f"Wi-Fi \u201c{ident['ssid']}\u201d" if ident["ssid"]
                              else f"network {net}")
            old = self.identity
            if _network_changed(old, ident):
                with self._lock:
                    self.history["internet"].clear()
                    self.history["gateway"].clear()
                if self.on_network_change:
                    try:
                        self.on_network_change(old, ident)
                    except Exception as e:
                        print(f"[health] network-change handler failed: {e}")
            if old:  # fill in fields that were unknown before
                for k, v in old.items():
                    if ident.get(k) is None and v is not None and not _network_changed(old, ident):
                        ident[k] = v
            self.identity = ident

        now = time.time()
        snap = {
            "timestamp": now,
            "local": {"ip": ip, "network": str(net) if net else None, "interface": iface,
                      "mac": sysinfo.interface_mac(iface), "hostname": socket.gethostname()},
            "internet": inet, "gateway": gw_r, "dns": dns, "wifi": wifi,
            "thresholds": THRESHOLDS, "identity": self.identity,
        }
        with self._lock:
            self.history["internet"].append({"t": now, "ms": inet["latency_ms"], "loss": inet["loss_pct"]})
            self.history["gateway"].append({"t": now, "ms": gw_r["latency_ms"], "loss": gw_r["loss_pct"]})
            self.latest = snap
        if self.on_snapshot:
            try:
                self.on_snapshot(snap)
            except Exception as e:
                print(f"[health] snapshot handler failed: {e}")
        return snap

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self.latest, history={k: list(v) for k, v in self.history.items()})

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as e:  # keep monitoring even if one pass fails
                print(f"[health] check failed: {e}")
            self._stop.wait(self.interval)

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="health").start()

    def stop(self):
        self._stop.set()

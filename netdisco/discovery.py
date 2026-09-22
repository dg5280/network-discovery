"""Device discovery: find hosts on the local subnet and identify them. No admin rights needed.

Pipeline:
  1. Sweep   – send a tiny UDP datagram to every address so the OS resolves MACs (fills the ARP table)
  2. ARP     – read the OS neighbour table for IP ↔ MAC
  3. Listen  – mDNS/Bonjour, SSDP/UPnP and NetBIOS in parallel
  4. Probe   – check a short list of telltale TCP ports on live hosts
  5. Name    – reverse DNS (routers often know DHCP hostnames)
  6. Classify
"""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

from . import classify, oui, sysinfo
from .protocols import mdns, netbios, ssdp

PROBE_PORTS = [22, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 1400, 1883, 3389, 5000, 5001,
               5357, 5900, 8000, 8008, 8009, 8060, 8080, 9100, 32400, 37777, 62078]
MAX_HOSTS = 1024


def scan_targets(ip: str, net: ipaddress.IPv4Network) -> list[str]:
    if net.num_addresses > MAX_HOSTS + 2:
        # Large network: limit to the /22 around us so a scan stays quick and polite.
        net = ipaddress.IPv4Network(f"{ip}/22", strict=False)
    return [str(h) for h in net.hosts() if str(h) != ip]


def sweep(targets: list[str]) -> None:
    """Unprivileged ARP prime: sending any packet forces the kernel to ARP for the host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    for rnd in range(2):
        for i, t in enumerate(targets):
            try:
                s.sendto(b"\x00", (t, 9))  # discard port; the payload never matters
            except OSError:
                pass
            if i % 32 == 31:
                time.sleep(0.01)  # avoid overflowing the ARP queue (macOS drops bursts)
        time.sleep(0.6)
    s.close()


def read_arp() -> dict[str, str]:
    """Return {ip: mac} for complete entries."""
    table: dict[str, str] = {}
    out = sysinfo.run(["arp", "-an"])
    for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", out):
        table[m.group(1)] = sysinfo.normalize_mac(m.group(2))
    if not table:
        out = sysinfo.run(["ip", "neigh", "show"])
        for m in re.finditer(r"^(\d+\.\d+\.\d+\.\d+) .*?lladdr ([0-9a-fA-F:]+)", out, re.M):
            table[m.group(1)] = sysinfo.normalize_mac(m.group(2))
    if not table:
        try:
            with open("/proc/net/arp") as fh:
                for line in fh.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                        table[p[0]] = sysinfo.normalize_mac(p[3])
        except OSError:
            pass
    # Drop broadcast / multicast entries
    return {ip: mac for ip, mac in table.items()
            if mac != "ff:ff:ff:ff:ff:ff" and not (int(mac.split(":")[0], 16) & 0x01)}


def probe_port(ip: str, port: int, timeout: float = 0.7) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_ports(ips: list[str]) -> dict[str, list[int]]:
    open_ports: dict[str, list[int]] = {ip: [] for ip in ips}
    with ThreadPoolExecutor(96) as ex:
        futs = {ex.submit(probe_port, ip, p): (ip, p) for ip in ips for p in PROBE_PORTS}
        for f, (ip, p) in futs.items():
            if f.result():
                open_ports[ip].append(p)
    return {ip: sorted(ps) for ip, ps in open_ports.items()}


def reverse_dns(ips: list[str], timeout: float = 3.0) -> dict[str, str]:
    names: dict[str, str] = {}

    def one(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except OSError:
            return ip, None

    ex = ThreadPoolExecutor(32)
    futs = [ex.submit(one, ip) for ip in ips]
    done, _ = wait(futs, timeout=timeout)
    for f in done:
        ip, name = f.result()
        if name and name != ip:
            names[ip] = name
    ex.shutdown(wait=False)
    return names


def _display_name(d: dict) -> str | None:
    mdns_i = (d.get("mdns") or {}).get("instances") or []
    ssdp_d = ((d.get("ssdp") or {}).get("description") or {})
    for cand in [
        (d.get("netbios") or {}).get("name"),
        next((i for i in mdns_i if not re.fullmatch(r"[0-9a-fA-F:@\-]{12,}.*", i)), None),
        ssdp_d.get("friendlyName"),
        d.get("hostname"),
        next(iter((d.get("mdns") or {}).get("hostnames") or []), None),
    ]:
        if cand:
            return re.sub(r"\.(local|lan|home|localdomain)\.?$", "", cand)
    return None


class Scanner:
    def __init__(self):
        self.devices: dict[str, dict] = {}   # key: MAC (or ip: when MAC unknown)
        self.state = {"running": False, "phase": "idle", "progress": 0, "started": None,
                      "finished": None, "error": None, "network": None, "targets": 0,
                      "network_label": None, "network_changed_at": None}
        self._lock = threading.Lock()
        self._generation = 0          # bumped on network change; stale scans are discarded
        self._restart_pending = False

    # ------------------------------------------------------------------ public
    def start(self) -> bool:
        with self._lock:
            if self.state["running"]:
                return False
            self.state.update(running=True, phase="starting", progress=0, started=time.time(), error=None)
        threading.Thread(target=self._run, daemon=True, name="scan").start()
        return True

    def reset(self, label: str | None = None):
        """Network changed: forget every device from the old network and scan the new one."""
        with self._lock:
            self._generation += 1
            self.devices.clear()
            self.state.update(network_label=label, network_changed_at=time.time(), error=None)
            running = self.state["running"]
            if running:
                self._restart_pending = True
        if not running:
            self.start()

    def snapshot(self) -> dict:
        with self._lock:
            devs = sorted(self.devices.values(), key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
            return {"state": dict(self.state), "devices": [dict(d) for d in devs]}

    # ------------------------------------------------------------------ internals
    def _phase(self, name: str, pct: int):
        with self._lock:
            self.state.update(phase=name, progress=pct)

    def _run(self):
        try:
            self._scan()
            with self._lock:
                self.state.update(phase="done", progress=100, finished=time.time())
        except Exception as e:  # surface errors in the UI instead of dying silently
            with self._lock:
                self.state.update(phase="error", error=str(e))
        finally:
            with self._lock:
                self.state["running"] = False
                restart, self._restart_pending = self._restart_pending, False
            if restart:
                self.start()

    def _scan(self):
        with self._lock:
            gen = self._generation
        gw, iface = sysinfo.default_route()
        ip, net = sysinfo.interface_network(iface)
        if not ip or not net:
            raise RuntimeError("No active IPv4 network found")
        targets = scan_targets(ip, net)
        with self._lock:
            self.state.update(network=str(net), targets=len(targets))

        # Listeners run in the background while we sweep.
        ex = ThreadPoolExecutor(3)
        f_mdns = ex.submit(mdns.discover, 5.0, ip)
        f_ssdp = ex.submit(ssdp.discover, 4.0, ip)

        self._phase("Sweeping the network", 10)
        sweep(targets)
        time.sleep(1.0)

        self._phase("Reading neighbour table", 30)
        arp = read_arp()
        arp = {a: m for a, m in arp.items() if ipaddress.IPv4Address(a) in net}

        self._phase("Listening for Bonjour & UPnP", 40)
        mdns_r = f_mdns.result()
        ssdp_r = f_ssdp.result()
        ex.shutdown(wait=False)

        live = set(arp) | {a for a in list(mdns_r) + list(ssdp_r)
                           if a != ip and ipaddress.IPv4Address(a) in net}
        if gw:
            live.add(gw)
        live = sorted(live)

        self._phase("Asking for Windows names", 55)
        nb_r = netbios.query(live)

        self._phase("Checking common ports", 65)
        ports = probe_ports(live)

        self._phase("Looking up names", 85)
        names = reverse_dns(live + [ip])

        # Re-read ARP: probing may have resolved more MACs.
        arp.update({a: m for a, m in read_arp().items() if a in live})

        now = time.time()
        found = []
        for addr in live:
            mac = arp.get(addr) or (nb_r.get(addr) or {}).get("mac")
            found.append(self._build(addr, mac, gw, mdns_r, ssdp_r, nb_r, ports, names, now, is_self=False))
        my_mac = sysinfo.interface_mac(iface)
        found.append(self._build(ip, my_mac, gw, mdns_r, ssdp_r, nb_r, {ip: []}, names, now, is_self=True))

        with self._lock:
            if gen != self._generation:
                return  # network changed mid-scan; results belong to the old network
            seen_keys = set()
            for d in found:
                key = d["mac"] or f"ip:{d['ip']}"
                seen_keys.add(key)
                prev = self.devices.get(key)
                d["first_seen"] = prev["first_seen"] if prev else now
                d["online"] = True
                self.devices[key] = d
            for key, d in self.devices.items():
                if key not in seen_keys:
                    d["online"] = False
        self._phase("Finishing", 95)

    @staticmethod
    def _build(addr, mac, gw, mdns_r, ssdp_r, nb_r, ports, names, now, is_self):
        v = oui.lookup(mac)
        d = {
            "ip": addr, "mac": mac, "vendor": v.get("vendor"), "randomized": v.get("randomized", False),
            "hostname": names.get(addr), "is_gateway": addr == gw, "is_self": is_self,
            "mdns": mdns_r.get(addr), "ssdp": ssdp_r.get(addr), "netbios": nb_r.get(addr),
            "ports": ports.get(addr, []), "last_seen": now,
        }
        d.update(classify.classify(d))
        d["name"] = _display_name(d)
        if is_self:
            d["name"] = d["name"] or socket.gethostname()
        return d

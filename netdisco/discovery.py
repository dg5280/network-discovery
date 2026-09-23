"""Device discovery: find hosts on the local subnet and identify them. No admin rights needed.

Pipeline:
  1. Sweep   – send a tiny UDP datagram to every address so the OS resolves MACs (fills the ARP table)
  2. ARP     – read the OS neighbour table for IP ↔ MAC
  3. Listen  – mDNS/Bonjour, SSDP/UPnP and NetBIOS in parallel
  4. Probe   – check a short list of telltale TCP ports on live hosts
  5. Name    – reverse DNS (routers often know DHCP hostnames)
  6. Classify

Other subnets (added by hand or from the router's route table) are behind a router, so ARP and
broadcast discovery can't see them. Those get a routed scan: ICMP sweep + TCP "is anyone there"
probe, then ports, NetBIOS (unicast), reverse DNS and — when you're signed in to the router —
MAC addresses from the router's own ARP table.
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
MAX_HOSTS = 1024          # auto-detected local network: larger ones are trimmed to the /22 around us
MAX_MANUAL_HOSTS = 4096   # subnets you add by hand: /20 at most
ALIVE_PORTS = (80, 443, 22, 445, 3389, 8080, 53, 139)
ALLOWED_NETS = [ipaddress.IPv4Network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")]


def is_private_net(net: ipaddress.IPv4Network) -> bool:
    return any(net.subnet_of(a) for a in ALLOWED_NETS)


def parse_spec(text: str) -> dict:
    """Turn what someone typed into a scan target.

    Accepts 10.0.20.0/24 · 10.0.20.0 255.255.255.0 · 10.0.20.10-10.0.20.50 · 10.0.20.10-50 · 10.0.20.7 (→ its /24).
    Returns {spec, network (IPv4Network or None for ranges), first, last, count, note}. Raises ValueError
    with a message suitable for showing to the user."""
    t = re.sub(r"\s+", " ", (text or "").strip())
    if not t:
        raise ValueError("Enter a subnet such as 10.0.20.0/24.")
    note = None
    net = None
    m = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+(?:\.\d+\.\d+\.\d+)?)", t)
    try:
        if m:
            a = ipaddress.IPv4Address(m.group(1))
            b_txt = m.group(2)
            if "." not in b_txt:                        # 10.0.20.10-50
                b_txt = ".".join(m.group(1).split(".")[:3] + [b_txt])
            b = ipaddress.IPv4Address(b_txt)
            if b < a:
                a, b = b, a
            first, last = a, b
            spec = f"{a}-{b}"
            covering = list(ipaddress.summarize_address_range(a, b))
            if len(covering) == 1:
                net, spec = covering[0], str(covering[0])
        else:
            m2 = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)(?:\s*/\s*(\d+)|\s+(\d+\.\d+\.\d+\.\d+))?", t)
            if not m2:
                raise ValueError(f"“{text}” isn't a subnet. Use a form like 10.0.20.0/24 or 10.0.20.10-10.0.20.50.")
            if m2.group(2) or m2.group(3):
                net = ipaddress.IPv4Network(f"{m2.group(1)}/{m2.group(2) or m2.group(3)}", strict=False)
            else:
                net = ipaddress.IPv4Network(f"{m2.group(1)}/24", strict=False)
                note = f"No mask given — scanning {net}."
            spec = str(net)
            first, last = net.network_address, net.broadcast_address
            if net.prefixlen < 31:
                first, last = first + 1, last - 1
    except ipaddress.AddressValueError:
        raise ValueError(f"“{text}” contains an invalid IP address.")
    except ipaddress.NetmaskValueError:
        raise ValueError(f"“{text}” has an invalid mask.")
    count = int(last) - int(first) + 1
    span = net or ipaddress.IPv4Network(f"{first}/32")
    if not (is_private_net(net) if net else (is_private_net(ipaddress.IPv4Network(f"{first}/32"))
                                               and is_private_net(ipaddress.IPv4Network(f"{last}/32")))):
        raise ValueError(f"{spec} isn't a private address range. Only home/office ranges can be scanned: "
                         "10.x, 172.16–31.x, 192.168.x (and 100.64/10).")
    if span.is_multicast or span.is_loopback:
        raise ValueError(f"{spec} can't be scanned.")
    if count > MAX_MANUAL_HOSTS:
        raise ValueError(f"{spec} has {count:,} addresses — the limit is {MAX_MANUAL_HOSTS:,} (a /20). "
                         "Add the smaller subnets you actually use instead.")
    return {"spec": spec, "network": net, "first": first, "last": last, "count": count, "note": note}


def spec_targets(p: dict) -> list[str]:
    a, b = int(p["first"]), int(p["last"])
    return [str(ipaddress.IPv4Address(i)) for i in range(a, b + 1)]


def spec_contains(p: dict, ip: str) -> bool:
    try:
        return int(p["first"]) <= int(ipaddress.IPv4Address(ip)) <= int(p["last"])
    except ValueError:
        return False


def spec_id(spec: str) -> str:
    return re.sub(r"[^\w.-]", "_", spec)


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


def icmp_alive(targets: list[str], progress=None) -> set[str]:
    """Which addresses answer ping. Two rounds (a router's first ARP for a host often eats the first ping)."""
    from . import health, pinger
    alive: set[str] = set()
    for rnd in range(2):
        todo = [t for t in targets if t not in alive]
        use_socket = True
        for i in range(0, len(todo), 256):
            chunk = todo[i:i + 256]
            errs: dict = {}
            got = pinger.icmp_sweep(chunk, timeout=1.2, send_errors=errs) if use_socket else None
            if got is not None and len([e for e in errs.values() if e in pinger.BLOCKED_ERRNOS]) > len(chunk) // 2:
                got = None          # the OS is refusing our packets (macOS Local Network privacy): use system ping
            if got is None:
                use_socket = False
                with ThreadPoolExecutor(64) as ex:
                    res = ex.map(lambda ip: (ip, health.icmp_ping(ip, count=1, timeout_s=1)), chunk)
                got = {ip: r["latency_ms"] for ip, r in res if r and r.get("latency_ms") is not None}
            alive.update(got)
            if progress:
                progress(rnd, (i + len(chunk)) / max(1, len(todo)))
    return alive


def tcp_alive(targets: list[str], ports=ALIVE_PORTS, timeout: float = 0.6) -> set[str]:
    """Hosts that ignore ping usually still answer (or refuse) a TCP connection — both prove they exist."""
    def one(ip):
        for p in ports:
            try:
                with socket.create_connection((ip, p), timeout=timeout):
                    return ip
            except ConnectionRefusedError:
                return ip
            except OSError as e:
                if getattr(e, "errno", None) in (65, 113, 51, 101):   # host/network unreachable: stop early
                    return None
        return None

    with ThreadPoolExecutor(128) as ex:
        return {ip for ip in ex.map(one, targets) if ip}


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
    """Scans one subnet. With no spec it follows this computer's current network (the "local" tab)."""

    def __init__(self, spec: str | None = None, label: str | None = None, source: str = "local",
                 tab_id: str = "local", gate: threading.Semaphore | None = None, mac_hints=None):
        self.spec = parse_spec(spec) if spec else None
        self.id, self.label, self.source = tab_id, label, source
        self.gate = gate                 # limits how many subnets scan at once
        self.mac_hints = mac_hints       # callable -> {ip: mac} (e.g. the router's ARP table)
        self.created = time.time()
        self.devices: dict[str, dict] = {}   # key: MAC (or ip: when MAC unknown)
        self.state = {"running": False, "phase": "idle", "progress": 0, "started": None,
                      "finished": None, "error": None, "network": self.spec["spec"] if self.spec else None,
                      "targets": 0, "network_label": None, "network_changed_at": None, "mode": None, "note": None}
        self._lock = threading.Lock()
        self._generation = 0          # bumped on network change; stale scans are discarded
        self._restart_pending = False

    # ------------------------------------------------------------------ public
    def start(self) -> bool:
        with self._lock:
            if self.state["running"]:
                return False
            self.state.update(running=True, phase="waiting" if self.gate else "starting", progress=0,
                              started=time.time(), error=None)
        threading.Thread(target=self._run, daemon=True, name=f"scan-{self.id}").start()
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

    def summary(self) -> dict:
        with self._lock:
            online = sum(1 for d in self.devices.values() if d.get("online"))
            return {"id": self.id, "label": self.label, "source": self.source,
                    "spec": self.spec["spec"] if self.spec else self.state.get("network"),
                    "local": self.spec is None, "state": dict(self.state),
                    "devices": len(self.devices), "online": online}

    # ------------------------------------------------------------------ internals
    def _phase(self, name: str, pct: int):
        with self._lock:
            self.state.update(phase=name, progress=pct)

    def _run(self):
        try:
            if self.gate:
                self.gate.acquire()
            try:
                self._scan()
            finally:
                if self.gate:
                    self.gate.release()
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
        if self.spec is None:
            ip, net = sysinfo.interface_network(iface)
            if not ip or not net:
                raise RuntimeError("No active IPv4 network found")
            with self._lock:
                self.state.update(network=str(net), mode="local")
            found = self._scan_local(ip, net, scan_targets(ip, net), gw, iface)
        else:
            # Is this subnet on one of our own interfaces? Then ARP + Bonjour work; otherwise it's routed.
            sp = self.spec
            mine = next((a for a in sysinfo.all_interfaces()
                         if (sp["network"] and a["network"].overlaps(sp["network"]))
                         or (not sp["network"] and (sp["first"] in a["network"] or sp["last"] in a["network"]))), None)
            targets = spec_targets(self.spec)
            if mine:
                with self._lock:
                    self.state.update(mode="local", note=f"Directly connected on {mine['iface']}")
                targets = [t for t in targets if t != mine["ip"]]
                found = self._scan_local(mine["ip"], mine["network"], targets,
                                         gw if gw and spec_contains(self.spec, gw) else None, mine["iface"],
                                         restrict=self.spec)
            else:
                with self._lock:
                    self.state.update(mode="routed", note="Routed subnet — found by ping and port checks. "
                                      "MAC addresses come from your router when you're connected to it.")
                found = self._scan_routed(targets)
        self._commit(gen, found)

    def _commit(self, gen: int, found: list[dict]):
        now = time.time()
        with self._lock:
            if gen != self._generation:
                return  # network changed mid-scan; results belong to the old network
            seen_keys = set()
            for d in found:
                key = d["mac"] or f"ip:{d['ip']}"
                if d.get("mac") and not d.get("is_self"):
                    self.devices.pop(f"ip:{d['ip']}", None)     # MAC learned since the last scan
                seen_keys.add(key)
                prev = self.devices.get(key)
                d["first_seen"] = prev["first_seen"] if prev else now
                d["online"] = True
                self.devices[key] = d
            for key, d in self.devices.items():
                if key not in seen_keys:
                    d["online"] = False
        self._phase("Finishing", 95)

    def _scan_local(self, ip, net, targets, gw, iface, restrict=None) -> list[dict]:
        with self._lock:
            self.state.update(targets=len(targets))
        inside = (lambda a: spec_contains(restrict, a)) if restrict else (lambda a: ipaddress.IPv4Address(a) in net)

        # Listeners run in the background while we sweep.
        ex = ThreadPoolExecutor(3)
        f_mdns = ex.submit(mdns.discover, 5.0, ip)
        f_ssdp = ex.submit(ssdp.discover, 4.0, ip)

        self._phase("Sweeping the network", 10)
        sweep(targets)
        time.sleep(1.0)

        self._phase("Reading neighbour table", 30)
        arp = {a: m for a, m in read_arp().items() if inside(a)}

        self._phase("Listening for Bonjour & UPnP", 40)
        mdns_r = f_mdns.result()
        ssdp_r = f_ssdp.result()
        ex.shutdown(wait=False)

        live = set(arp) | {a for a in list(mdns_r) + list(ssdp_r) if a != ip and inside(a)}
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
        if not restrict or inside(ip):
            my_mac = sysinfo.interface_mac(iface)
            found.append(self._build(ip, my_mac, gw, mdns_r, ssdp_r, nb_r, {ip: []}, names, now, is_self=True))
        return found

    def _scan_routed(self, targets: list[str]) -> list[dict]:
        with self._lock:
            self.state.update(targets=len(targets))
        self._phase("Pinging every address", 5)
        alive = icmp_alive(targets, progress=lambda rnd, f: self._phase(
            "Pinging every address" if rnd == 0 else "Pinging again (slow responders)", int(5 + 25 * (rnd + f) / 2)))
        rest = [t for t in targets if t not in alive]
        if rest and len(targets) <= MAX_HOSTS:
            self._phase("Looking for devices that ignore ping", 35)
            tcp_only = tcp_alive(rest)
            if len(tcp_only) >= 8 and len(tcp_only) >= 0.9 * len(rest):
                # Every address "answers": a firewall set to reject (or a proxy) is replying for them.
                with self._lock:
                    self.state["note"] = ("Something between you and this subnet answers for every address "
                                          "(usually a firewall rule set to reject), so only devices that reply "
                                          "to ping are listed.")
            else:
                alive |= tcp_only
        live = sorted(alive, key=lambda a: int(ipaddress.IPv4Address(a)))

        self._phase("Asking for Windows names", 55)
        nb_r = netbios.query(live) if live else {}

        self._phase("Checking common ports", 65)
        ports = probe_ports(live) if live else {}

        self._phase("Looking up names", 85)
        names = reverse_dns(live) if live else {}

        hints = {}
        if self.mac_hints:
            try:
                hints = self.mac_hints() or {}
            except Exception:
                hints = {}
        now = time.time()
        return [self._build(a, hints.get(a) or (nb_r.get(a) or {}).get("mac"), None, {}, {}, nb_r, ports, names,
                            now, is_self=False) for a in live]

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


class ScanManager:
    """One Scanner per subnet tab. The "local" tab follows this computer's network; the others are
    subnets you added (by hand or from the router's route table) and are remembered between runs."""

    MAX_TABS = 24

    def __init__(self, store: str | None = None, concurrent: int = 2, local=None, persist: bool = True,
                 scanner_cls=None):
        import os
        self.scanner_cls = scanner_cls or Scanner
        self.gate = threading.Semaphore(concurrent)
        self.local = local or Scanner(gate=None)
        self.tabs: dict[str, Scanner] = {"local": self.local}
        self.mac_hints = None           # set by the app: router ARP/lease tables
        self.persist = persist
        self.store = store or (os.path.join(sysinfo.data_dir(), "subnets.json") if persist else None)
        self._lock = threading.Lock()
        self._load()

    # persistence ------------------------------------------------------------
    def _load(self):
        import json
        if not self.store:
            return
        try:
            with open(self.store) as fh:
                saved = json.load(fh)
        except (OSError, ValueError):
            return
        for t in saved if isinstance(saved, list) else []:
            try:
                self.add(t.get("spec", ""), t.get("label"), t.get("source") or "manual", scan=False, save=False)
            except ValueError:
                continue

    def _save(self):
        import json
        import os
        if not self.store:
            return
        rows = [{"spec": t.spec["spec"], "label": t.label, "source": t.source}
                for k, t in self.tabs.items() if k != "local"]
        tmp = self.store + ".tmp"
        try:
            with open(tmp, "w") as fh:
                json.dump(rows, fh, indent=1)
            os.replace(tmp, self.store)
        except OSError as e:
            print(f"[scan] couldn't save subnets: {e}")

    # tabs -------------------------------------------------------------------
    def _hints(self):
        return self.mac_hints() if self.mac_hints else {}

    def add(self, text: str, label: str | None = None, source: str = "manual", scan: bool = True,
            save: bool = True) -> dict:
        p = parse_spec(text)
        tid = spec_id(p["spec"])
        with self._lock:
            existing = self.tabs.get(tid)
            if existing is None:
                if len(self.tabs) >= self.MAX_TABS:
                    raise ValueError(f"You can have up to {self.MAX_TABS} subnet tabs — remove one first.")
                existing = self.scanner_cls(p["spec"], label=(label or "").strip()[:60] or None, source=source, tab_id=tid,
                                   gate=self.gate, mac_hints=self._hints)
                if p["note"]:
                    existing.state["note"] = p["note"]
                self.tabs[tid] = existing
                created = True
            else:
                if label and not existing.label:
                    existing.label = label.strip()[:60]
                created = False
        if save and created:
            self._save()
        if scan:
            existing.start()
        return dict(existing.summary(), created=created, note=p["note"])

    def remove(self, tid: str) -> bool:
        if tid == "local":
            return False
        with self._lock:
            gone = self.tabs.pop(tid, None)
        if gone:
            self._save()
        return bool(gone)

    def get(self, tid: str) -> Scanner | None:
        with self._lock:
            return self.tabs.get(tid)

    def list(self) -> list[dict]:
        with self._lock:
            tabs = list(self.tabs.values())
        return [t.summary() for t in tabs]

    def covers(self, network: str) -> str | None:
        """Tab id already scanning this network (exact match, or the local tab's network)."""
        with self._lock:
            tabs = list(self.tabs.items())
        for tid, t in tabs:
            spec = t.spec["spec"] if t.spec else t.state.get("network")
            if spec == network:
                return tid
        return None

    def start(self, tid: str) -> bool:
        t = self.get(tid)
        if not t:
            raise KeyError(tid)
        return t.start()

    def start_all(self):
        with self._lock:
            tabs = list(self.tabs.values())
        for t in tabs:
            t.start()

    def all_devices(self) -> list[dict]:
        with self._lock:
            tabs = list(self.tabs.values())
        seen, out = set(), []
        for t in tabs:
            for d in t.snapshot()["devices"]:
                if d["ip"] not in seen:
                    seen.add(d["ip"])
                    out.append(d)
        return out

    # compatibility with the single-scanner API --------------------------------
    def snapshot(self) -> dict:
        return {"state": self.local.snapshot()["state"], "devices": self.all_devices()}

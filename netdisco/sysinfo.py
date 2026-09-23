"""Platform helpers: default route, interface addresses, Wi-Fi info.

macOS is the primary target; Linux fallbacks exist so the code stays portable.
Nothing here requires admin rights.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import threading
import time

IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


def run(cmd: list[str], timeout: float = 5.0) -> str:
    """Run a command and return stdout ('' on any failure)."""
    if not shutil.which(cmd[0]):
        return ""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""


# --------------------------------------------------------------------------- routing

def default_route() -> tuple[str | None, str | None]:
    """Return (gateway_ip, interface_name) for the default IPv4 route."""
    if IS_MAC:
        out = run(["route", "-n", "get", "default"])
        gw = re.search(r"gateway:\s*(\S+)", out)
        iface = re.search(r"interface:\s*(\S+)", out)
        if gw or iface:
            return (gw.group(1) if gw else None, iface.group(1) if iface else None)
    out = run(["ip", "-4", "route", "show", "default"])
    m = re.search(r"default via (\S+) dev (\S+)", out)
    if m:
        return m.group(1), m.group(2)
    # Last resort: /proc/net/route (Linux) — gateway stored as little-endian hex
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if parts[1] == "00000000" and int(parts[3], 16) & 2:
                    gw = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
                    return gw, parts[0]
    except OSError:
        pass
    return None, None


def local_ip() -> str | None:
    """IP of the interface used to reach the internet (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def interface_network(iface: str | None) -> tuple[str | None, ipaddress.IPv4Network | None]:
    """Return (local_ip, network) for an interface."""
    ip, net = None, None
    if iface and IS_MAC:
        out = run(["ifconfig", iface])
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", out)
        if m:
            ip = m.group(1)
            prefix = bin(int(m.group(2), 16)).count("1")
            net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    if ip is None and iface:
        out = run(["ip", "-o", "-4", "addr", "show", "dev", iface])
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if m:
            ip = m.group(1)
            net = ipaddress.IPv4Network(f"{ip}/{m.group(2)}", strict=False)
    if ip is None:
        ip = local_ip()
        if ip:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return ip, net


def all_interfaces() -> list[dict]:
    """Every IPv4 address on this computer: [{iface, ip, network}] (loopback excluded)."""
    rows: list[dict] = []
    if IS_MAC:
        cur = None
        for line in run(["ifconfig"]).splitlines():
            m = re.match(r"^(\S+?):\s", line)
            if m:
                cur = m.group(1)
                continue
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", line)
            if m and cur:
                prefix = bin(int(m.group(2), 16)).count("1")
                rows.append({"iface": cur, "ip": m.group(1),
                             "network": ipaddress.IPv4Network(f"{m.group(1)}/{prefix}", strict=False)})
    if not rows:
        for line in run(["ip", "-o", "-4", "addr", "show"]).splitlines():
            m = re.search(r"^\d+:\s+(\S+)\s+inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if m:
                rows.append({"iface": m.group(1).split("@")[0], "ip": m.group(2),
                             "network": ipaddress.IPv4Network(f"{m.group(2)}/{m.group(3)}", strict=False)})
    return [r for r in rows if not r["network"].is_loopback]


def local_routes() -> list[dict]:
    """IPv4 routes this computer knows (VPNs often add some). Default and host routes excluded."""
    routes: list[dict] = []
    if IS_MAC:
        for line in run(["netstat", "-rn", "-f", "inet"]).splitlines():
            p = line.split()
            if len(p) < 4 or p[0] in ("default", "Destination", "Internet:") or "!" in p[2]:
                continue
            dest, gw, flags, iface = p[0], p[1], p[2], p[3]
            if "H" in flags or "W" in flags:        # host routes / cloned ARP entries
                continue
            net = mac_netstat_dest(dest)
            if net is None:
                continue
            routes.append({"network": str(net), "via": gw if re.match(r"\d+\.\d+\.\d+\.\d+$", gw) else None,
                           "iface": iface, "type": "static" if "G" in flags else "connected"})
    else:
        for line in run(["ip", "-4", "route", "show"]).splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s*(.*)$", line)
            if not m:
                continue
            via = re.search(r"\bvia (\S+)", m.group(2))
            dev = re.search(r"\bdev (\S+)", m.group(2))
            try:
                net = ipaddress.IPv4Network(m.group(1), strict=False)
            except ValueError:
                continue
            routes.append({"network": str(net), "via": via.group(1) if via else None,
                           "iface": dev.group(1) if dev else None, "type": "static" if via else "connected"})
    return routes


def mac_netstat_dest(dest: str) -> ipaddress.IPv4Network | None:
    """macOS netstat abbreviates networks: '10.8/16', '192.168.1', '172.16.4/22', '127'."""
    base, _, plen = dest.partition("/")
    octets = base.split(".")
    if not all(o.isdigit() for o in octets) or not 1 <= len(octets) <= 4:
        return None
    prefix = int(plen) if plen.isdigit() else len(octets) * 8
    try:
        net = ipaddress.IPv4Network(".".join(octets + ["0"] * (4 - len(octets))) + f"/{prefix}", strict=False)
    except ValueError:
        return None
    if net.prefixlen == 32 or net.is_loopback or net.is_multicast or net.prefixlen == 0:
        return None
    return net


def data_dir() -> str:
    """~/.netdisco (override with NETDISCO_HOME) — created on first use."""
    import os
    d = os.environ.get("NETDISCO_HOME") or os.path.join(os.path.expanduser("~"), ".netdisco")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def interface_mac(iface: str | None) -> str | None:
    if not iface:
        return None
    out = run(["ifconfig", iface]) if IS_MAC else run(["ip", "link", "show", iface])
    m = re.search(r"(?:ether|link/ether)\s+([0-9a-fA-F:]{17})", out)
    return normalize_mac(m.group(1)) if m else None


def dns_servers() -> list[str]:
    servers: list[str] = []
    if IS_MAC:
        out = run(["scutil", "--dns"])
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)
    if not servers:
        try:
            with open("/etc/resolv.conf") as fh:
                servers = re.findall(r"^nameserver\s+(\S+)", fh.read(), re.M)
        except OSError:
            pass
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq[:4]


def normalize_mac(mac: str) -> str:
    """'a:b:c:d:e:f' -> '0a:0b:0c:0d:0e:0f' (macOS arp drops leading zeros)."""
    parts = re.split(r"[:\-]", mac.strip())
    if len(parts) != 6:
        return mac.lower()
    return ":".join(p.zfill(2) for p in parts).lower()


# --------------------------------------------------------------------------- Wi-Fi

_wifi_cache: dict = {"t": 0.0, "v": None}
_wifi_lock = threading.Lock()


def _mac_wifi_devices() -> list[str]:
    out = run(["networksetup", "-listallhardwareports"])
    devs = []
    for block in out.split("\n\n"):
        if re.search(r"Hardware Port:\s*(Wi-Fi|AirPort)", block):
            m = re.search(r"Device:\s*(\S+)", block)
            if m:
                devs.append(m.group(1))
    return devs


def _clean_ssid(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip()
    if not s or "redacted" in s.lower() or "not associated" in s.lower():
        return None
    return s


def _mac_wifi(iface: str | None) -> dict:
    wifi_devs = _mac_wifi_devices()
    info = {"interface": iface, "is_wifi": bool(iface and iface in wifi_devs),
            "ssid": None, "rssi_dbm": None, "noise_dbm": None, "channel": None,
            "phy_mode": None, "tx_rate_mbps": None, "ssid_hidden_by_os": False}
    if not info["is_wifi"]:
        return info

    # 1) ipconfig getsummary (fast; SSID may be <redacted> on macOS 14.4+)
    out = run(["ipconfig", "getsummary", iface])
    m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
    if m:
        if "redacted" in m.group(1).lower():
            info["ssid_hidden_by_os"] = True
        info["ssid"] = _clean_ssid(m.group(1))

    # 2) networksetup (older macOS)
    if not info["ssid"]:
        out = run(["networksetup", "-getairportnetwork", iface])
        m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
        if m:
            info["ssid"] = _clean_ssid(m.group(1))

    # 3) system_profiler (slow, but also gives signal/channel)
    out = run(["system_profiler", "SPAirPortDataType"], timeout=15)
    cur = re.search(r"Current Network Information:\s*\n\s*(.+?):\s*\n(.*?)(?:\n\s*Other Local Wi-Fi Networks:|\Z)",
                    out, re.S)
    if cur:
        if not info["ssid"]:
            name = cur.group(1).strip()
            if "redacted" in name.lower():
                info["ssid_hidden_by_os"] = True
            info["ssid"] = _clean_ssid(name)
        body = cur.group(2)
        m = re.search(r"Signal / Noise:\s*(-?\d+) dBm / (-?\d+) dBm", body)
        if m:
            info["rssi_dbm"], info["noise_dbm"] = int(m.group(1)), int(m.group(2))
        m = re.search(r"Channel:\s*(.+)", body)
        if m:
            info["channel"] = m.group(1).strip()
        m = re.search(r"PHY Mode:\s*(.+)", body)
        if m:
            info["phy_mode"] = m.group(1).strip()
        m = re.search(r"Transmit Rate:\s*(\d+)", body)
        if m:
            info["tx_rate_mbps"] = int(m.group(1))
    return info


def _linux_wifi(iface: str | None) -> dict:
    info = {"interface": iface, "is_wifi": False, "ssid": None, "rssi_dbm": None,
            "noise_dbm": None, "channel": None, "phy_mode": None, "tx_rate_mbps": None,
            "ssid_hidden_by_os": False}
    if iface:
        try:
            import os
            info["is_wifi"] = os.path.isdir(f"/sys/class/net/{iface}/wireless")
        except OSError:
            pass
    if not info["is_wifi"]:
        return info
    info["ssid"] = _clean_ssid(run(["iwgetid", "-r"]))
    out = run(["iw", "dev", iface, "link"])
    m = re.search(r"signal:\s*(-?\d+)", out)
    if m:
        info["rssi_dbm"] = int(m.group(1))
    if not info["ssid"]:
        m = re.search(r"SSID:\s*(.+)", out)
        if m:
            info["ssid"] = _clean_ssid(m.group(1))
    return info


def wifi_info(iface: str | None, max_age: float = 30.0) -> dict:
    """Wi-Fi details for the active interface, cached (system_profiler is slow)."""
    with _wifi_lock:
        if _wifi_cache["v"] is not None and time.time() - _wifi_cache["t"] < max_age \
                and _wifi_cache["v"].get("interface") == iface:
            return _wifi_cache["v"]
    v = _mac_wifi(iface) if IS_MAC else _linux_wifi(iface)
    with _wifi_lock:
        _wifi_cache.update(t=time.time(), v=v)
    return v

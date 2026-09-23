"""Router-side network facts: the route table (which other subnets/VLANs exist) and the
Wi-Fi networks (SSIDs) the router or access point is configured to broadcast.

Parsers for SSH output (ip route / route -n / /proc/net/route, ip addr, uci, hostapd.conf, iw)
and a defensive extractor for Synology SRM web-API responses, whose field names vary by version.

Wi-Fi passwords are never collected: the SSH script only greps whitelisted keys, and web-API
responses pass through redact() before they're kept for the "raw data" view.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import struct

from .connect.findings import finding

# --------------------------------------------------------------------------- secrets

SECRET_KEY = re.compile(r"pass|psk|secret|passphrase|wpa_key|^key\d?$|_key$|priv|token|credential|radius_key", re.I)


def redact(obj, depth: int = 0):
    """Copy of obj with anything that looks like a password or key replaced by '•••'."""
    if depth > 12:
        return obj
    if isinstance(obj, dict):
        return {k: ("•••" if SECRET_KEY.search(str(k)) and obj[k] not in (None, "", [], {}) and
                    not isinstance(obj[k], (bool, dict, list)) else redact(v, depth + 1))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, depth + 1) for v in obj]
    return obj


# --------------------------------------------------------------------------- routes

VPN_IF = re.compile(r"^(tun|tap|wg|ppp|pppoe|ipsec|l2tp|tailscale|zt|utun|gre|vti|ovpn)", re.I)
VIRTUAL_IF = re.compile(r"^(docker|br-[0-9a-f]{12}|veth|virbr|lxc|cni|flannel|cali|kube|vnet)", re.I)
SKIP_TYPES = ("local", "broadcast", "multicast", "unreachable", "prohibit", "blackhole", "throw", "nat", "anycast")
DYNAMIC_PROTOS = ("ospf", "bgp", "zebra", "rip", "bird", "isis", "eigrp", "babel", "static_bgp")


def vlan_of(iface: str | None) -> int | None:
    """eth0.20 → 20 · vlan20 → 20 · br-lan.30 → 30 · lan.40@eth0 → 40."""
    if not iface:
        return None
    base = iface.split("@")[0]
    m = re.search(r"\.(\d{1,4})$", base) or re.fullmatch(r"(?:vlan|vl|br-vlan|br_vlan|bond\d+\.)(\d{1,4})", base, re.I)
    if m:
        v = int(m.group(1))
        return v if 1 <= v <= 4094 else None
    return None


def _net(text: str) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return None


def parse_ip_route(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.split()[0] in SKIP_TYPES:
            continue
        p = line.split()
        dest = p[0]
        if dest == "default" or dest.startswith("0.0.0.0"):
            continue
        if "/" not in dest:
            if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", dest):
                continue
            dest += "/32"
        net = _net(dest)
        if net is None:
            continue
        kv = {}
        for key in ("via", "dev", "proto", "scope", "src", "metric", "table"):
            m = re.search(rf"\b{key} (\S+)", line)
            if m:
                kv[key] = m.group(1)
        rows.append({"network": str(net), "via": kv.get("via"), "iface": kv.get("dev"), "proto": kv.get("proto"),
                     "src": kv.get("src"), "metric": int(kv["metric"]) if kv.get("metric", "").isdigit() else None,
                     "table": kv.get("table") if kv.get("table") not in (None, "main") else None,
                     "scope_link": kv.get("scope") == "link"})
    return rows


def parse_route_n(text: str) -> list[dict]:
    """BusyBox / net-tools `route -n`."""
    rows = []
    for line in text.splitlines():
        p = line.split()
        if len(p) < 8 or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", p[0]) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", p[2]):
            continue
        net = _net(f"{p[0]}/{p[2]}")
        if net is None or net.prefixlen == 0:
            continue
        via = p[1] if p[1] != "0.0.0.0" else None
        rows.append({"network": str(net), "via": via, "iface": p[-1], "proto": None, "src": None,
                     "metric": int(p[4]) if p[4].isdigit() else None, "table": None, "scope_link": via is None})
    return rows


def parse_proc_route(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        p = line.split()
        if len(p) < 8:
            continue
        try:
            dest = socket.inet_ntoa(struct.pack("<I", int(p[1], 16)))
            gw = socket.inet_ntoa(struct.pack("<I", int(p[2], 16)))
            mask = socket.inet_ntoa(struct.pack("<I", int(p[7], 16)))
        except (ValueError, struct.error, OSError):
            continue
        net = _net(f"{dest}/{mask}")
        if net is None or net.prefixlen == 0:
            continue
        via = gw if gw != "0.0.0.0" else None
        rows.append({"network": str(net), "via": via, "iface": p[0], "proto": None, "src": None,
                     "metric": int(p[6]) if p[6].isdigit() else None, "table": None, "scope_link": via is None})
    return rows


def parse_addrs(text: str) -> list[dict]:
    """`ip -o -4 addr show` → the router's own address on each connected subnet."""
    rows = []
    for line in text.splitlines():
        m = re.search(r"^\d+:\s+(\S+)\s+inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            net = _net(f"{m.group(2)}/{m.group(3)}")
            if net and not net.is_loopback:
                rows.append({"iface": m.group(1).split("@")[0], "ip": m.group(2), "network": str(net)})
    return rows


def route_type(r: dict) -> str:
    iface = r.get("iface") or ""
    proto = (r.get("proto") or "").lower()
    if VPN_IF.match(iface):
        return "vpn"
    if VIRTUAL_IF.match(iface):
        return "virtual"
    if proto in DYNAMIC_PROTOS:
        return "dynamic"
    if r.get("via"):
        return "static"
    return "connected"


def is_scannable(net: ipaddress.IPv4Network) -> bool:
    from .discovery import MAX_MANUAL_HOSTS, is_private_net
    return is_private_net(net) and 1 < net.num_addresses <= MAX_MANUAL_HOSTS + 2 and not net.is_link_local


def build_networks(routes: list[dict], addrs: list[dict] | None = None, source: str = "router") -> list[dict]:
    """Merge route + address rows into one list of networks, each with what's needed to offer a scan."""
    from .discovery import is_private_net
    out: dict[str, dict] = {}
    for a in addrs or []:
        out.setdefault(a["network"], {"network": a["network"], "via": None, "iface": a["iface"], "router_ip": a["ip"],
                                      "type": None, "proto": "kernel", "metric": None, "table": None})
        out[a["network"]]["router_ip"] = a["ip"]
    for r in routes:
        net = _net(r["network"])
        if net is None or net.prefixlen >= 32 or net.is_multicast or net.is_loopback:
            continue
        row = out.setdefault(r["network"], {"network": r["network"], "router_ip": None})
        for k in ("via", "iface", "proto", "metric", "table"):
            if r.get(k) is not None and row.get(k) is None:
                row[k] = r[k]
        if r.get("src") and not row.get("router_ip"):
            row["router_ip"] = r["src"]
    rows = []
    for n, row in out.items():
        net = _net(n)
        row["type"] = route_type(row)
        row["vlan"] = vlan_of(row.get("iface"))
        row["hosts"] = max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
        row["private"] = is_private_net(net)
        row["scannable"] = is_scannable(net) and row["type"] != "virtual"
        row["source"] = source
        row["label"] = network_label(row)
        if not row["scannable"]:
            row["why_not"] = ("container/virtual network" if row["type"] == "virtual" else
                              "public address range" if not row["private"] else
                              "link-local" if net.is_link_local else
                              f"too large ({row['hosts']:,} addresses) — add the smaller subnets you use")
        rows.append(row)
    rows.sort(key=lambda r: ({"connected": 0, "static": 1, "dynamic": 2, "vpn": 3, "virtual": 4}.get(r["type"], 5),
                             int(_net(r["network"]).network_address)))
    return rows


def network_label(r: dict) -> str:
    """Short human label: 'IoT · VLAN 20', 'VLAN 30', 'Lab switch', 'wg0 · VPN', 'via 10.0.0.2'."""
    iface = (r.get("iface") or "").split("@")[0]
    name = re.sub(r"^br-", "", iface)
    parts = []
    if name and not re.fullmatch(r"(eth|lan|en|wan|bond|switch|sw)\d*([._]\d+)?|vlan\d+|br\d*", name, re.I):
        parts.append(name)
    if r.get("vlan"):
        parts.append(f"VLAN {r['vlan']}")
    if r.get("type") == "vpn":
        parts.append("VPN")
    if not parts and r.get("type") == "static" and r.get("via"):
        parts.append(f"via {r['via']}")
    return " · ".join(parts) or iface or r["network"]


def networks_from_ssh(sections: dict) -> list[dict]:
    text = sections.get("routes", "")
    routes = parse_ip_route(text)
    if not routes:
        routes = parse_route_n(text) or parse_proc_route(text)
    return build_networks(routes, parse_addrs(sections.get("addrs", "")))


def neighbors_from_ssh(sections: dict) -> dict[str, str]:
    """{ip: mac} from the router's ARP table and DHCP leases — lets routed scans show MACs."""
    out: dict[str, str] = {}
    for line in sections.get("arp", "").splitlines()[1:]:
        p = line.split()
        if len(p) >= 4 and re.fullmatch(r"[0-9a-fA-F:]{17}", p[3]) and p[3] != "00:00:00:00:00:00":
            out[p[0]] = p[3].lower()
    for line in sections.get("leases", "").splitlines():
        p = line.split()
        if len(p) >= 3 and re.fullmatch(r"[0-9a-fA-F:]{17}", p[1]) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", p[2]):
            out.setdefault(p[2], p[1].lower())
    return out


# --------------------------------------------------------------------------- SSIDs

def _band_from(text) -> str | None:
    t = str(text or "").lower()
    if not t:
        return None
    if re.search(r"6\s*g|6ghz|\b6e\b|^6$|11axe", t):
        return "6 GHz"
    if re.search(r"(^|\D)5(\.\d)?\s*g|5ghz|^a$|11a\b|11ac|^5$|5g", t):
        return "5 GHz"
    if re.search(r"2\.?4|^g$|^b$|11[bg]|^2$|2g", t):
        return "2.4 GHz"
    return None


def _band_from_channel(ch) -> str | None:
    try:
        c = int(str(ch).split()[0])
    except (ValueError, IndexError):
        return None
    if 1 <= c <= 14:
        return "2.4 GHz"
    if 32 <= c <= 177:
        return "5 GHz"
    return None


SECURITY_NAMES = [
    (r"^(none|open|off|0|disabled?)$|^$", "Open (no password)"),
    (r"owe", "Enhanced Open (OWE)"),
    (r"wep", "WEP"),
    (r"sae-mixed|wpa2.?wpa3|wpa3.?wpa2|psk2\+sae|sae\+psk|mixed.*sae|wpa3.?transition", "WPA2/WPA3"),
    (r"sae|wpa3", "WPA3"),
    (r"wpa2.*enterprise|wpa2-?eap|^wpa2$|eap2|802\.1x", "WPA2-Enterprise"),
    (r"psk-mixed|wpa.?wpa2|wpa\+wpa2|mixed", "WPA/WPA2"),
    (r"psk2|wpa2|rsn", "WPA2"),
    (r"psk|wpa", "WPA"),
]


def security_label(raw) -> str | None:
    if raw is None:
        return None
    t = str(raw).strip().lower()
    for rx, name in SECURITY_NAMES:
        if re.search(rx, t):
            return name
    return str(raw)


def security_status(label: str | None) -> str:
    if not label:
        return "unknown"
    if label.startswith("Open") or label == "WEP":
        return "red"
    if label in ("WPA", "WPA/WPA2"):
        return "yellow"
    return "green"


def parse_uci_wireless(text: str) -> list[dict]:
    """`uci show wireless` (OpenWrt) — only whitelisted keys ever reach us."""
    sections: dict[str, dict] = {}
    types: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^wireless\.([\w@\[\]-]+)=(\S+)$", line.strip())
        if m:
            types[m.group(1)] = m.group(2).strip("'\"")
            continue
        m = re.match(r"^wireless\.([\w@\[\]-]+)\.(\w+)=(.*)$", line.strip())
        if m:
            sections.setdefault(m.group(1), {})[m.group(2)] = m.group(3).strip().strip("'\"")
    radios = {k: v for k, v in sections.items() if types.get(k) == "wifi-device"}
    out = []
    for k, v in sections.items():
        if types.get(k) != "wifi-iface" or not v.get("ssid") or v.get("mode", "ap") not in ("ap", ""):
            continue
        radio = radios.get(v.get("device", ""), {})
        band = _band_from(radio.get("band") or radio.get("hwmode")) or _band_from_channel(radio.get("channel"))
        net = v.get("network", "")
        out.append({
            "ssid": v["ssid"], "band": band, "channel": radio.get("channel"),
            "security": security_label(v.get("encryption", "none")),
            "hidden": v.get("hidden") == "1", "enabled": v.get("disabled") != "1" and radio.get("disabled") != "1",
            "guest": bool(re.search(r"guest", v["ssid"] + " " + net, re.I)), "isolated": v.get("isolate") == "1",
            "network": net or None, "interface": v.get("ifname") or v.get("device"),
            "wps": v.get("wps_pushbutton") == "1", "pmf": {"0": "off", "1": "optional", "2": "required"}.get(v.get("ieee80211w", "")),
            "source": "uci",
        })
    return out


def parse_hostapd(text: str) -> list[dict]:
    """hostapd.conf (only whitelisted keys are read on the device). One file may define several BSSes."""
    out, cur, file_common = [], None, {}

    def close():
        if cur and cur.get("ssid"):
            out.append(cur)

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("## "):
            close()
            cur, file_common = None, {}
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k in ("interface", "bss"):
            close()
            cur = {"interface": v, **file_common}
            continue
        if cur is None:
            cur = {}
        if k in ("hw_mode", "channel", "ieee80211ax", "ieee80211ac", "op_class"):
            file_common[k] = v
        cur[k] = v
    close()
    rows = []
    for c in out:
        ssid = c.get("ssid")
        if not ssid and c.get("ssid2", "").startswith('"'):
            ssid = c["ssid2"].strip('"')
        mgmt = c.get("wpa_key_mgmt", "")
        wpa = c.get("wpa", "0")
        if wpa in ("0", ""):
            sec = "Open (no password)" if "OWE" not in mgmt else "Enhanced Open (OWE)"
        elif "SAE" in mgmt and "WPA-PSK" in mgmt:
            sec = "WPA2/WPA3"
        elif "SAE" in mgmt:
            sec = "WPA3"
        elif "EAP" in mgmt:
            sec = "WPA2-Enterprise" if wpa in ("2", "3") else "WPA-Enterprise"
        else:
            sec = {"1": "WPA", "2": "WPA2", "3": "WPA/WPA2"}.get(wpa, "WPA2")
        band = _band_from({"a": "5g", "g": "2.4g", "b": "2.4g", "ad": "60g"}.get(c.get("hw_mode", ""), "")) \
            or _band_from_channel(c.get("channel"))
        if c.get("op_class", "").isdigit() and 131 <= int(c["op_class"]) <= 137:
            band = "6 GHz"
        rows.append({"ssid": ssid, "band": band, "channel": c.get("channel"), "security": sec,
                     "hidden": c.get("ignore_broadcast_ssid", "0") not in ("0", ""), "enabled": c.get("disabled", "0") in ("0", ""),
                     "guest": bool(re.search(r"guest", ssid or "", re.I)), "isolated": c.get("ap_isolate") == "1",
                     "network": c.get("bridge"), "interface": c.get("interface"),
                     "wps": c.get("wps_state") in ("1", "2"),
                     "pmf": {"0": "off", "1": "optional", "2": "required"}.get(c.get("ieee80211w", "")), "source": "hostapd"})
    return rows


def ssids_from_ssh(sections: dict, radios: list[dict] | None = None) -> list[dict]:
    text = sections.get("wifi_conf", "")
    uci_part, _, host_part = text.partition("@@HOSTAPD@@")
    rows = parse_uci_wireless(uci_part) + parse_hostapd(host_part)
    # Fall back to what `iw` says the AP interfaces are broadcasting (no security info there).
    for r in radios or []:
        if r.get("ssid") and not any(x["ssid"] == r["ssid"] and (x.get("interface") in (None, r.get("interface"))) for x in rows):
            rows.append({"ssid": r["ssid"], "band": _band_from_channel(r.get("channel")), "channel": (r.get("channel") or "").split(" (")[0] or None,
                         "security": None, "hidden": False, "enabled": True, "guest": bool(re.search(r"guest", r["ssid"], re.I)),
                         "isolated": None, "network": None, "interface": r.get("interface"), "wps": None, "pmf": None, "source": "iw"})
    return merge_ssids(rows)


def merge_ssids(rows: list[dict]) -> list[dict]:
    """One row per SSID+security, listing every band it's on."""
    out: dict[tuple, dict] = {}
    for r in rows:
        key = (r["ssid"], r.get("security") or "")
        cur = out.get(key)
        if cur is None:
            cur = out[key] = dict(r, bands=[], channels=[], interfaces=[])
        for field, many in (("band", "bands"), ("channel", "channels"), ("interface", "interfaces")):
            if r.get(field) and r[field] not in cur[many]:
                cur[many].append(r[field])
        cur["enabled"] = cur.get("enabled") or r.get("enabled")
        cur["hidden"] = cur.get("hidden") or r.get("hidden")
        cur["wps"] = cur.get("wps") or r.get("wps")
        for k in ("network", "vlan", "pmf", "isolated"):
            if cur.get(k) in (None, "") and r.get(k) not in (None, ""):
                cur[k] = r[k]
    rows = list(out.values())
    for r in rows:
        r["bands"].sort()
        r["security_status"] = security_status(r.get("security"))
        r.pop("band", None)
        r.pop("channel", None)
        r.pop("interface", None)
    rows.sort(key=lambda r: (not r.get("enabled"), r.get("guest"), r["ssid"].lower()))
    return rows


def ssid_findings(ssids: list[dict]) -> list[dict]:
    fs = []
    live = [s for s in ssids if s.get("enabled")]
    for s in live:
        sec = s.get("security")
        if sec and sec.startswith("Open"):
            fs.append(finding("warning" if not s.get("guest") else "info", "wireless",
                              f"Wi-Fi “{s['ssid']}” has no password",
                              "Anyone nearby can join it and see unencrypted traffic.",
                              "Use WPA2 or WPA3 (or Enhanced Open/OWE for a public guest network) and turn on client isolation."))
        elif sec == "WEP":
            fs.append(finding("critical", "wireless", f"Wi-Fi “{s['ssid']}” uses WEP",
                              "WEP can be cracked in minutes.", "Switch to WPA2 or WPA3 now."))
        elif sec in ("WPA", "WPA/WPA2"):
            fs.append(finding("warning", "wireless", f"Wi-Fi “{s['ssid']}” allows old WPA (TKIP)",
                              f"Security: {sec}. TKIP is weak and limits speed to 54 Mb/s for devices that use it.",
                              "Set security to WPA2 (AES) or WPA2/WPA3."))
        if s.get("wps"):
            fs.append(finding("info", "wireless", f"WPS is on for “{s['ssid']}”",
                              "WPS push-button/PIN is a common way in.", "Turn WPS off unless you use it."))
        if s.get("guest") and s.get("isolated") is False:
            fs.append(finding("info", "wireless", f"Guest network “{s['ssid']}” isn't isolated",
                              "Guests may be able to reach your other devices.", "Turn on client/guest isolation."))
    hidden = [s["ssid"] for s in live if s.get("hidden")]
    if hidden:
        fs.append(finding("info", "wireless", f"Hidden network{'s' if len(hidden) > 1 else ''}: {', '.join(hidden)}",
                          "Hiding the name doesn't add security, and makes phones probe for it everywhere.",
                          "Consider broadcasting it and relying on a strong password."))
    return fs


# --------------------------------------------------------------------------- Synology SRM (web API)

IP_KEYS = ("network", "dest", "destination", "dst", "subnet", "net", "ip", "ipaddr", "ip_addr", "ipv4", "address",
           "lan_ip", "start_ip", "gateway_ip", "router_ip")
MASK_KEYS = ("netmask", "mask", "genmask", "subnet_mask", "prefix", "prefix_len", "prefixlen", "cidr", "masklen")
NAME_KEYS = ("name", "display_name", "desc", "description", "ifname", "interface", "iface", "dev", "network_name", "alias")
VLAN_KEYS = ("vlan", "vlan_id", "vlanid", "vid")
GW_KEYS = ("gateway", "gw", "nexthop", "next_hop", "via")
IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def _first(d: dict, keys):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def extract_networks(obj, api: str = "", depth: int = 0, out: list | None = None) -> list[dict]:
    """Find every (IP, mask) or CIDR in a Synology response and turn it into a network row."""
    if out is None:
        out = []
    if depth > 8:
        return out
    if isinstance(obj, dict):
        cidr = None
        for k, v in obj.items():
            if isinstance(v, str) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+/\d{1,2}", v.strip()) and k.lower() not in GW_KEYS:
                cidr = v.strip()
                break
        ip = _first(obj, IP_KEYS)
        mask = _first(obj, MASK_KEYS)
        net = None
        if cidr:
            net = _net(cidr)
        elif isinstance(ip, str) and IPV4.match(ip) and mask not in (None, ""):
            m = str(mask).strip()
            if m.isdigit() or IPV4.match(m):
                net = _net(f"{ip}/{m}")
        if net is not None and 0 < net.prefixlen < 32:
            gw = _first(obj, GW_KEYS)
            name = _first(obj, NAME_KEYS)
            vlan = _first(obj, VLAN_KEYS)
            try:
                vlan = int(vlan) if vlan not in (None, "", 0, "0") else None
            except (TypeError, ValueError):
                vlan = None
            router_ip = ip if isinstance(ip, str) and IPV4.match(ip) and ipaddress.IPv4Address(ip) != net.network_address else None
            out.append({"network": str(net), "via": gw if isinstance(gw, str) and IPV4.match(gw) and gw != "0.0.0.0" else None,
                        "iface": str(name) if name is not None else None, "router_ip": router_ip, "vlan_hint": vlan,
                        "proto": "static" if re.search(r"route", api, re.I) else None, "api": api})
        for v in obj.values():
            if isinstance(v, (dict, list)):
                extract_networks(v, api, depth + 1, out)
    elif isinstance(obj, list):
        for v in obj:
            extract_networks(v, api, depth + 1, out)
    return out


def networks_from_srm(responses: dict[str, object]) -> list[dict]:
    rows: list[dict] = []
    for api, data in responses.items():
        if data is None or (isinstance(data, dict) and "error" in data and len(data) == 1):
            continue
        rows += extract_networks(data, api)
    # Skip the WAN side (public addresses) only when it's clearly WAN.
    rows = [r for r in rows if not re.search(r"\bwan\b|pppoe|internet", f"{r.get('iface') or ''} {r['api']}", re.I)]
    nets = build_networks([{"network": r["network"], "via": r["via"], "iface": r["iface"], "proto": r["proto"]} for r in rows],
                          [{"iface": r["iface"] or "", "ip": r["router_ip"], "network": r["network"]} for r in rows
                           if r["router_ip"] and not r["via"]], source="router")
    hints = {r["network"]: r for r in rows}
    for n in nets:
        h = hints.get(n["network"], {})
        if h.get("vlan_hint") and not n.get("vlan"):
            n["vlan"] = h["vlan_hint"]
            n["label"] = network_label(n)
        if n["type"] == "static" and not n.get("via"):
            n["type"] = "connected"
    return nets


def ssids_from_srm(responses: dict[str, object]) -> list[dict]:
    rows: list[dict] = []

    def walk(obj, api, ctx, depth=0):
        if depth > 8:
            return
        if isinstance(obj, dict):
            ctx = dict(ctx)
            for k in ("band", "radio", "frequency", "wifi_band", "channel"):
                if k in obj and not isinstance(obj[k], (dict, list)):
                    ctx[k] = obj[k]
            ssid = _first(obj, ("ssid", "wifi_ssid", "ssid_name", "essid"))
            if isinstance(ssid, str) and ssid.strip():
                band = _band_from(_first(obj, ("band", "radio", "wifi_band", "frequency")) or ctx.get("band") or ctx.get("radio")
                                  or ctx.get("frequency")) or _band_from_channel(_first(obj, ("channel",)) or ctx.get("channel"))
                sec = _first(obj, ("security", "security_type", "auth_type", "encryption", "encrypt", "auth_mode", "sec_mode", "wpa_mode"))
                enabled = _first(obj, ("enable", "enabled", "is_enabled", "wifi_enable", "status"))
                hidden = _first(obj, ("hide_ssid", "hidden", "ssid_hidden", "is_hidden", "broadcast_ssid", "ssid_broadcast"))
                if "broadcast_ssid" in obj or "ssid_broadcast" in obj:
                    hidden = not bool(hidden)
                iso = _first(obj, ("isolation", "client_isolation", "ap_isolation", "isolate", "guest_isolation", "lan_access"))
                if "lan_access" in obj:
                    iso = not bool(iso)
                rows.append({
                    "ssid": ssid.strip(), "band": band, "channel": _first(obj, ("channel",)) or ctx.get("channel"),
                    "security": security_label(sec) if sec not in (None, "") else None,
                    "hidden": bool(hidden) if hidden not in (None, "") else False,
                    "enabled": (str(enabled).lower() not in ("false", "0", "off", "disabled", "disable")) if enabled not in (None, "") else True,
                    "guest": bool(re.search(r"guest", api + " " + ssid, re.I) or obj.get("is_guest") or obj.get("guest")),
                    "isolated": bool(iso) if iso not in (None, "") else None,
                    "network": _first(obj, ("network", "vlan_name", "lan_name")) if isinstance(_first(obj, ("network", "vlan_name", "lan_name")), str) else None,
                    "vlan": _first(obj, VLAN_KEYS),
                    "interface": _first(obj, ("ifname", "interface")), "wps": bool(obj.get("wps_enable") or obj.get("wps")) if ("wps_enable" in obj or "wps" in obj) else None,
                    "pmf": None, "source": "SRM API"})
            for v in obj.values():
                if isinstance(v, (dict, list)):
                    walk(v, api, ctx, depth + 1)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, api, ctx, depth + 1)

    for api, data in responses.items():
        if re.search(r"client|station|device|nsm|survey|scan|neighbor", api, re.I):
            continue                     # client lists and site surveys name *other* networks
        walk(data, api, {})
    return merge_ssids(rows)

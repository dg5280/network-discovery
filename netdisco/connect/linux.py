"""Health collection for Linux-family devices over SSH: servers, Raspberry Pi,
Synology DSM/SRM, OpenWrt and other BusyBox-based routers.

Everything runs as ONE read-only POSIX sh script (works on BusyBox ash) whose output is
split into sections. Nothing here changes the device. Some logs need root; when they
aren't readable we say so rather than guess.
"""
from __future__ import annotations

import re
import time

from .findings import finding, human_bytes, human_duration, overall, signal_status, sort_findings

SECTIONS = [
    ("uname", "uname -a"),
    ("arch", "uname -m"),
    ("hostname", "hostname 2>/dev/null || cat /proc/sys/kernel/hostname"),
    ("whoami", "id -un 2>/dev/null || whoami"),
    ("os_release", "cat /etc/os-release 2>/dev/null"),
    ("openwrt", "cat /etc/openwrt_release 2>/dev/null"),
    ("synology", "cat /etc.defaults/VERSION 2>/dev/null; grep -E '^(upnpmodelname|unique|company_title)=' "
                 "/etc/synoinfo.conf /etc.defaults/synoinfo.conf 2>/dev/null | head -n 4"),
    ("model", "cat /proc/device-tree/model 2>/dev/null; echo; cat /sys/class/dmi/id/product_name 2>/dev/null"),
    ("uptime", "cat /proc/uptime"),
    ("loadavg", "cat /proc/loadavg"),
    ("cpus", "grep -c ^processor /proc/cpuinfo"),
    ("meminfo", "cat /proc/meminfo"),
    ("df", "df -P -k 2>/dev/null || df -k"),
    ("dfi", "df -P -i 2>/dev/null"),
    ("netdev", "cat /proc/uptime; cat /proc/net/dev"),
    ("links", "for i in /sys/class/net/*; do n=${i##*/}; "
              "p=0; [ -e $i/device ] && p=1; w=0; { [ -d $i/wireless ] || [ -e $i/phy80211 ]; } && w=1; "
              "b=0; [ -d $i/bridge ] && b=1; bd=0; [ -d $i/bonding ] && bd=1; "
              "d=$(readlink $i/device/driver 2>/dev/null); m=$(readlink $i/master 2>/dev/null); "
              "echo \"if=$n phys=$p wireless=$w bridge=$b bond=$bd state=$(cat $i/operstate 2>/dev/null) "
              "carrier=$(cat $i/carrier 2>/dev/null) speed=$(cat $i/speed 2>/dev/null) duplex=$(cat $i/duplex 2>/dev/null) "
              "mtu=$(cat $i/mtu 2>/dev/null) mac=$(cat $i/address 2>/dev/null) cc=$(cat $i/carrier_changes 2>/dev/null) "
              "type=$(cat $i/type 2>/dev/null) master=${m##*/} driver=${d##*/}\"; done"),
    ("ethtool", "command -v ethtool >/dev/null && for i in /sys/class/net/*; do n=${i##*/}; [ -e $i/device ] || continue; "
                "echo \"## $n\"; ethtool $n 2>/dev/null | grep -E 'Speed:|Duplex:|Auto-negotiation:|Link detected:|Port:'; "
                "ethtool -i $n 2>/dev/null | grep -E '^(driver|firmware-version):'; "
                "ethtool -S $n 2>/dev/null | grep -iE 'err|crc|drop|miss|fifo|align|collision|over|jabber|fragment|"
                "undersize|oversize|discard|timeout|symbol|pause' | head -n 60; done"),
    ("bonding", "for f in /proc/net/bonding/*; do [ -r $f ] && { echo \"## ${f##*/}\"; cat $f; }; done 2>/dev/null"),
    ("addrs", "ip -o -4 addr show 2>/dev/null"),
    ("dmesg", "dmesg 2>&1 | tail -n 400"),
    ("journal", "command -v journalctl >/dev/null && t journalctl -p 3 -b --no-pager -n 80 -o short-iso 2>&1"),
    ("logread", "command -v logread >/dev/null && logread 2>/dev/null | tail -n 400"),
    ("syslog", "for f in /var/log/messages /var/log/syslog; do [ -r $f ] && { echo \"## $f\"; tail -n 400 $f; break; }; done"),
    ("failed_units", "command -v systemctl >/dev/null && t systemctl --failed --no-legend --plain 2>/dev/null"),
    ("apt", "command -v apt-get >/dev/null && t apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst'"),
    ("reboot_required", "[ -f /var/run/reboot-required ] && cat /var/run/reboot-required.pkgs 2>/dev/null; "
                        "[ -f /var/run/reboot-required ] && echo REBOOT_REQUIRED"),
    ("opkg", "command -v opkg >/dev/null && t opkg list-upgradable 2>/dev/null | head -n 60"),
    ("mdstat", "cat /proc/mdstat 2>/dev/null"),
    ("thermal", "for z in /sys/class/thermal/thermal_zone*; do [ -r $z/temp ] && echo \"$(cat $z/type 2>/dev/null) "
                "$(cat $z/temp)\"; done; for h in /sys/class/hwmon/hwmon*; do for f in $h/temp*_input; do "
                "[ -r $f ] && echo \"$(cat $h/name 2>/dev/null) $(cat $f)\"; done; done 2>/dev/null"),
    ("top", "ps -eo pid,comm,%cpu,%mem --sort=-%cpu 2>/dev/null | head -n 8"),
    ("iw", "command -v iw >/dev/null && for d in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do "
           "echo \"## $d\"; iw dev $d info 2>/dev/null | grep -E 'type|ssid|channel'; "
           "iw dev $d station dump 2>/dev/null; done"),
    ("iwinfo", "command -v iwinfo >/dev/null && for d in $(iwinfo 2>/dev/null | awk '/ESSID/{print $1}'); do "
               "echo \"## $d\"; iwinfo $d info 2>/dev/null | grep -E 'ESSID|Channel|Mode'; iwinfo $d assoclist 2>/dev/null; done"),
    ("wlanconfig", "command -v wlanconfig >/dev/null && for d in $(ls /sys/class/net 2>/dev/null | grep -E '^ath'); do "
                   "echo \"## $d\"; wlanconfig $d list sta 2>/dev/null; done"),
    ("leases", "for f in /tmp/dhcp.leases /var/lib/misc/dnsmasq.leases /etc/dhcpd/dhcpd.leases "
               "/tmp/dhcpd.leases /var/lib/dhcp/dhcpd.leases; do [ -r $f ] && { echo \"## $f\"; tail -n 300 $f; }; done"),
    ("arp", "cat /proc/net/arp 2>/dev/null"),
    ("routes", "ip -4 route show table all 2>/dev/null || ip -4 route show 2>/dev/null || route -n 2>/dev/null "
               "|| cat /proc/net/route"),
    # Wi-Fi networks this device broadcasts. Only whitelisted keys are read — never passwords/keys.
    ("wifi_conf", "command -v uci >/dev/null && uci -q show wireless 2>/dev/null | grep -E "
                  "'^wireless\\.[^.=]+=|\\.(ssid|encryption|hidden|disabled|network|device|mode|band|hwmode|channel|htmode|"
                  "isolate|wps_pushbutton|ieee80211w|ifname)='; echo '@@HOSTAPD@@'; "
                  "for f in /var/run/hostapd*.conf /var/run/hostapd/*.conf /tmp/run/hostapd*.conf /tmp/hostapd*.conf "
                  "/tmp/*/hostapd*.conf /etc/hostapd/*.conf /etc/hostapd.conf /var/packages/*/target/etc/hostapd*.conf; do "
                  "[ -r \"$f\" ] && { echo \"## $f\"; grep -E '^(interface|bss|ssid|ssid2|hw_mode|channel|op_class|"
                  "ignore_broadcast_ssid|wpa|wpa_key_mgmt|ieee80211w|wps_state|bridge|ap_isolate|disabled|ieee80211ac|ieee80211ax)=' "
                  "\"$f\"; }; done 2>/dev/null"),
    ("netdev2", "sleep 2; cat /proc/uptime; cat /proc/net/dev"),
]

MARK = "@@@ND@@@"


def build_script() -> str:
    lines = ["t() { if command -v timeout >/dev/null 2>&1; then timeout 15 \"$@\"; else \"$@\"; fi; }",
             "export LC_ALL=C PATH=\"$PATH:/usr/sbin:/sbin:/usr/syno/bin:/usr/syno/sbin\""]
    for name, cmd in SECTIONS:
        lines.append(f"echo '{MARK} {name}'")
        lines.append(f"{{ {cmd} ; }} 2>&1")
    lines.append(f"echo '{MARK} end'")
    return "\n".join(lines) + "\n"


def split_sections(output: str) -> dict[str, str]:
    out, cur, buf = {}, None, []
    for line in output.splitlines():
        if line.startswith(MARK):
            if cur:
                out[cur] = "\n".join(buf).strip("\n")
            cur, buf = line[len(MARK):].strip(), []
        else:
            buf.append(line)
    if cur and cur != "end":
        out[cur] = "\n".join(buf).strip("\n")
    return out


# ------------------------------------------------------------------ parsers

def _kv(text: str) -> dict[str, str]:
    d = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z0-9_]+)\s*=\s*\"?(.*?)\"?\s*$", line)
        if m:
            d[m.group(1)] = m.group(2).strip("'")
    return d


def parse_identity(s: dict) -> dict:
    osr = _kv(s.get("os_release", ""))
    owrt = _kv(s.get("openwrt", ""))
    syno = _kv(re.sub(r"^[^:\n=]+:", "", s.get("synology", ""), flags=re.M))
    uname = s.get("uname", "")
    model = next((l.strip("\x00 ").strip() for l in s.get("model", "").splitlines()
                  if l.strip("\x00 ").strip() and "Default string" not in l), None)
    platform, os_name = "linux", osr.get("PRETTY_NAME") or osr.get("NAME")
    if owrt.get("DISTRIB_ID") or "OpenWrt" in (os_name or ""):
        platform = "openwrt"
        os_name = owrt.get("DISTRIB_DESCRIPTION") or os_name or "OpenWrt"
    if syno.get("productversion") or syno.get("majorversion"):
        is_srm = "srm" in s.get("synology", "").lower() or syno.get("os_name", "").upper() == "SRM"
        platform = "synology-srm" if is_srm else "synology-dsm"
        ver = syno.get("productversion") or f"{syno.get('majorversion')}.{syno.get('minorversion')}"
        os_name = f"{'SRM' if is_srm else 'DSM'} {ver}-{syno.get('buildnumber', '?')}"
        if syno.get("smallfixnumber") and syno["smallfixnumber"] != "0":
            os_name += f" Update {syno['smallfixnumber']}"
        model = syno.get("upnpmodelname") or model
    if model and "raspberry pi" in model.lower():
        platform = "raspberrypi" if platform == "linux" else platform
    kernel = uname.split()[2] if len(uname.split()) > 2 else None
    return {"hostname": s.get("hostname", "").strip() or None, "os": os_name or (uname.split()[0] if uname else None),
            "kernel": kernel, "arch": s.get("arch", "").strip() or None,
            "model": model, "platform": platform, "user": s.get("whoami", "").strip() or None}


def parse_meminfo(text: str) -> dict:
    kb = {}
    for line in text.splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m:
            kb[m.group(1)] = int(m.group(2)) * 1024
    total = kb.get("MemTotal")
    avail = kb.get("MemAvailable")
    if avail is None and total:
        avail = kb.get("MemFree", 0) + kb.get("Buffers", 0) + kb.get("Cached", 0)
    swap_t, swap_f = kb.get("SwapTotal", 0), kb.get("SwapFree", 0)
    return {"total": total, "available": avail,
            "used_pct": round(100 * (1 - avail / total), 1) if total and avail is not None else None,
            "swap_total": swap_t, "swap_used": swap_t - swap_f,
            "swap_pct": round(100 * (swap_t - swap_f) / swap_t, 1) if swap_t else 0.0}


SKIP_FS = re.compile(r"^(tmpfs|devtmpfs|overlay|none|udev|shm|run|cgroup.*|proc|sysfs|squashfs|/dev/loop\d+|efivarfs)$")
SKIP_MNT = re.compile(r"^/(dev|proc|sys|run)(/|$)|^/snap/|/docker/|^/rom$|^/tmp$|^/var/run")


def parse_df(text: str, inodes: bool = False) -> list[dict]:
    rows = []
    lines = text.splitlines()
    # df can wrap long device names onto their own line; join them back.
    joined, carry = [], ""
    for line in lines[1:]:
        if carry:
            line, carry = carry + " " + line.strip(), ""
        if len(line.split()) == 1:
            carry = line.strip()
            continue
        joined.append(line)
    for line in joined:
        p = line.split()
        if len(p) < 6:
            continue
        fs, total, used, avail, pct, mnt = p[0], p[1], p[2], p[3], p[4], " ".join(p[5:])
        if SKIP_FS.match(fs) or SKIP_MNT.search(mnt) or not total.isdigit() or int(total) == 0:
            continue
        pct_v = int(pct.rstrip("%")) if pct.rstrip("%").isdigit() else None
        mult = 1 if inodes else 1024
        rows.append({"filesystem": fs, "mount": mnt, "total": int(total) * mult, "used": int(used) * mult,
                     "avail": int(avail) * mult, "used_pct": pct_v})
    # de-duplicate bind mounts of the same filesystem
    seen, uniq = set(), []
    for r in rows:
        key = (r["filesystem"], r["total"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


def _read_netdev(text: str) -> tuple[float | None, dict[str, list[int]]]:
    """Returns (uptime_at_sample, {iface: [16 counters]}) — tolerant of a leading /proc/uptime line."""
    t, rows = None, {}
    for line in text.splitlines():
        if t is None and re.match(r"^\s*\d+\.\d+\s+\d+\.\d+\s*$", line):
            t = float(line.split()[0])
            continue
        if ":" not in line or "|" in line:
            continue
        name, data = line.split(":", 1)
        v = data.split()
        if len(v) >= 16 and all(x.isdigit() for x in v[:16]):
            rows[name.strip()] = [int(x) for x in v[:16]]
    return t, rows


def _parse_links(text: str) -> dict[str, dict]:
    links = {}
    for line in text.splitlines():
        if line.startswith("if="):
            kv = dict(re.findall(r"(\w+)=(\S*)", line))
            links[kv["if"]] = kv
        else:  # older one-line format: name state speed carrier_changes mac
            p = line.split()
            if len(p) >= 5:
                links[p[0]] = {"if": p[0], "state": p[1], "speed": p[2], "cc": p[3], "mac": p[4]}
    return links


def _parse_ethtool(text: str) -> dict[str, dict]:
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            cur = out.setdefault(line[3:].strip(), {"counters": {}})
            continue
        if cur is None or ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        if k in ("Speed", "Duplex", "Auto-negotiation", "Link detected", "Port", "driver", "firmware-version"):
            cur[k.lower().replace("-", "_").replace(" ", "_")] = v
        elif re.fullmatch(r"\d+", v):
            if int(v):
                cur["counters"][k] = int(v)
    return out


def _parse_bonding(text: str) -> dict[str, dict]:
    bonds, cur, slave = {}, None, None
    for line in text.splitlines():
        if line.startswith("## "):
            cur = bonds.setdefault(line[3:].strip(), {"mode": None, "members": []})
            continue
        if cur is None:
            continue
        m = re.match(r"Bonding Mode:\s*(.+)", line)
        if m:
            cur["mode"] = m.group(1).strip()
        m = re.match(r"Slave Interface:\s*(\S+)", line)
        if m:
            slave = {"name": m.group(1), "status": None, "failures": None}
            cur["members"].append(slave)
        elif slave:
            m = re.match(r"MII Status:\s*(\S+)", line)
            if m and slave["status"] is None:
                slave["status"] = m.group(1)
            m = re.match(r"Link Failure Count:\s*(\d+)", line)
            if m:
                slave["failures"] = int(m.group(1))
    return bonds


VIRTUAL_NAME = re.compile(r"^(lo|docker\d*|br-|veth|virbr|vnet|tun|tap|wg|zt|tailscale|ip6?tnl|sit|gre|gretap|erspan|"
                          r"dummy|ifb|bond_slave|ovs|lxc|cni|flannel|cali|kube|vxlan|nlmon|teql|ip_vti|ip6_vti|sixxs|ppp)")
PHYS_NAME = re.compile(r"^(eth|en[ospx]|lan|wan|wl|wlan|ath|ra|rai|mlan|ovs_eth|sw)\w*$")
ARPHRD = {"1": "ethernet", "772": "loopback", "65534": "tunnel", "768": "tunnel", "776": "tunnel", "778": "tunnel",
          "512": "ppp", "801": "wifi", "803": "wifi"}


def parse_netdev(text: str, links_text: str = "", text2: str = "", ethtool_text: str = "", bonding_text: str = "") -> list[dict]:
    """Every interface with full kernel counters, link details, live rates (from two samples) and,
    for physical ports, driver/NIC counters from ethtool."""
    t1, a = _read_netdev(text)
    t2, b = _read_netdev(text2) if text2 else (None, {})
    dt = (t2 - t1) if t1 is not None and t2 is not None and t2 > t1 else None
    links = _parse_links(links_text)
    eth = _parse_ethtool(ethtool_text)
    bonds = _parse_bonding(bonding_text)
    rows = []
    for name, v in a.items():
        lk = links.get(name, {})
        (rx_b, rx_p, rx_e, rx_d, rx_fifo, rx_frame, _rx_comp, rx_mc,
         tx_b, tx_p, tx_e, tx_d, tx_fifo, tx_coll, tx_carrier, _tx_comp) = v
        if name in bonds or lk.get("bond") == "1":
            kind = "bond"
        elif lk.get("bridge") == "1":
            kind = "bridge"
        elif lk.get("wireless") == "1":
            kind = "wifi"
        elif name == "lo" or lk.get("type") == "772":
            kind = "loopback"
        elif "." in name or "@" in name:
            kind = "vlan"
        elif lk.get("phys") == "1":
            kind = "ethernet"
        elif lk.get("phys") == "0" or VIRTUAL_NAME.match(name):
            kind = ARPHRD.get(lk.get("type", ""), "virtual") if lk.get("type") not in (None, "1") else "virtual"
        else:
            kind = "ethernet" if PHYS_NAME.match(name) else "virtual"
        physical = kind in ("ethernet", "wifi") and (lk.get("phys") in ("1", None)) or kind == "bond"
        speed = lk.get("speed", "")
        speed_mbps = int(speed) if speed.lstrip("-").isdigit() and 0 < int(speed) < 10_000_000 else None
        et = eth.get(name, {})
        if speed_mbps is None and et.get("speed"):
            m = re.match(r"(\d+)", et["speed"])
            speed_mbps = int(m.group(1)) if m else None
        cc = lk.get("cc", "")
        pk = rx_p + tx_p
        rx_err_total = rx_e + rx_frame + rx_fifo
        tx_err_total = tx_e + tx_carrier + tx_fifo
        errs = rx_e + tx_e + rx_frame + tx_carrier
        row = {
            "name": name, "kind": kind, "physical": bool(physical),
            "state": lk.get("state") or None, "carrier": lk.get("carrier") == "1" if lk.get("carrier") else None,
            "speed_mbps": speed_mbps, "duplex": next((d for d in ((lk.get("duplex") or "").lower(), (et.get("duplex") or "").lower())
                           if d in ("full", "half")), None),
            "autoneg": et.get("auto_negotiation"), "port": et.get("port"),
            "mtu": int(lk["mtu"]) if lk.get("mtu", "").isdigit() else None, "mac": lk.get("mac") or None,
            "driver": lk.get("driver") or et.get("driver") or None, "firmware": et.get("firmware_version"),
            "master": lk.get("master") or None,
            "carrier_changes": int(cc) if cc.isdigit() else None,
            "rx_bytes": rx_b, "tx_bytes": tx_b, "rx_packets": rx_p, "tx_packets": tx_p, "rx_multicast": rx_mc,
            "rx_errors": rx_err_total, "tx_errors": tx_err_total,
            "rx_errs": rx_e, "rx_fifo": rx_fifo, "rx_frame": rx_frame,
            "tx_errs": tx_e, "tx_fifo": tx_fifo, "tx_carrier": tx_carrier, "collisions": tx_coll,
            "rx_dropped": rx_d, "tx_dropped": tx_d,
            "error_pct": round(100 * errs / pk, 3) if pk else 0.0,
            "drop_pct": round(100 * (rx_d + tx_d) / pk, 3) if pk else 0.0,
            "hw_counters": et.get("counters", {}),
            "rx_bps": None, "tx_bps": None, "util_pct": None,
            "members": bonds.get(name, {}).get("members"), "bond_mode": bonds.get(name, {}).get("mode"),
        }
        if dt and name in b:
            row["rx_bps"] = max(0, (b[name][0] - rx_b) * 8 / dt)
            row["tx_bps"] = max(0, (b[name][8] - tx_b) * 8 / dt)
            if speed_mbps:
                row["util_pct"] = round(100 * max(row["rx_bps"], row["tx_bps"]) / (speed_mbps * 1e6), 1)
        rows.append(row)
    order = {"ethernet": 0, "bond": 1, "wifi": 2, "vlan": 3, "bridge": 4}
    rows.sort(key=lambda r: (not r["physical"], order.get(r["kind"], 5), r["name"]))
    return [r for r in rows if r["kind"] != "loopback"]


LOG_PATTERNS = [
    ("critical", "storage", r"I/O error|blk_update_request|Buffer I/O error|ata\d+.*(failed|error)|"
                            r"EXT4-fs error|XFS.*(corruption|error)|btrfs.*(error|corrupt)|md/raid.*(fail|degraded)|"
                            r"SMART.*(fail|error)|Medium Error|sense key", "Disk or filesystem errors in the kernel log",
     "Back up now, then check drive health (SMART) and the RAID/volume status; replace the failing disk."),
    ("warning", "memory", r"Out of memory|oom-killer|oom_reaper|Killed process",
     "The system ran out of memory and killed processes",
     "Find what is using memory (top processes below), reduce services, or add RAM/swap."),
    ("warning", "system", r"soft lockup|hard LOCKUP|hung_task|blocked for more than \d+ seconds|rcu_sched self-detected",
     "Kernel reports hung or locked-up tasks", "Often storage or driver related — check disks and update firmware/kernel."),
    ("warning", "system", r"Call Trace:|kernel BUG|general protection fault|Oops:",
     "Kernel crash traces found", "Update the OS/firmware; if it repeats, note the module named in the trace."),
    ("warning", "hardware", r"thermal.*(critical|shutdown|throttl|overheat|trip)|overheat|temperature above threshold|clock throttled",
     "Overheating or thermal throttling reported", "Improve airflow, clean fans/vents, check ambient temperature."),
    ("warning", "power", r"under-?voltage|Undervoltage detected|voltage normalised",
     "Under-voltage detected (power supply too weak)", "Use the proper power supply/cable (common on Raspberry Pi)."),
    ("info", "network", r"Link is Down|link down|NIC Link is Down|carrier lost",
     "Network link went down at least once", "If it repeats, re-seat or replace the cable and check the switch port."),
    ("info", "apps", r"segfault|core dumped", "Programs crashed (segfaults)", "Update the affected package; check which program in the lines below."),
    ("info", "security", r"Failed password|authentication failure|Invalid user|BREAK-IN",
     "Failed login attempts", "Expected occasionally; many from unknown IPs means SSH is exposed — restrict or use keys."),
]


def scan_logs(sections: dict) -> dict:
    sources = []
    text = ""
    for key, label in (("dmesg", "kernel (dmesg)"), ("journal", "systemd journal (errors)"),
                       ("logread", "system log (logread)"), ("syslog", "system log")):
        t = sections.get(key, "")
        if t and not re.search(r"Operation not permitted|Permission denied|read kernel buffer failed|No journal files",
                               t[:400], re.I):
            sources.append(label)
            text += "\n" + t
    restricted = [k for k in ("dmesg", "journal", "syslog")
                  if re.search(r"Operation not permitted|Permission denied|read kernel buffer failed", sections.get(k, "")[:400], re.I)]
    hits = []
    for sev, area, pat, title, remedy in LOG_PATTERNS:
        lines = [l.strip() for l in text.splitlines() if re.search(pat, l, re.I)]
        if lines:
            hits.append({"severity": sev, "area": area, "title": title, "remedy": remedy,
                         "count": len(lines), "examples": lines[-5:]})
    error_lines = [l.strip() for l in text.splitlines()
                   if re.search(r"\b(error|fail(ed|ure)?|critical|crit|emerg|alert|panic)\b", l, re.I)
                   and not re.search(r"no error|0 errors|error=0", l, re.I)]
    return {"sources": sources, "restricted": restricted, "hits": hits,
            "recent_errors": error_lines[-25:], "error_count": len(error_lines)}


def parse_updates(s: dict) -> dict:
    if s.get("apt"):
        pkgs = [l.split()[1] for l in s["apt"].splitlines() if l.startswith("Inst ")]
        sec = [l.split()[1] for l in s["apt"].splitlines() if l.startswith("Inst ") and re.search(r"securi", l, re.I)]
        return {"manager": "apt", "count": len(pkgs), "security": len(sec), "packages": pkgs[:40],
                "reboot_required": "REBOOT_REQUIRED" in s.get("reboot_required", "")}
    if s.get("opkg") is not None and "command not found" not in s.get("opkg", "") and s.get("opkg", "").strip():
        pkgs = [l.split(" - ")[0] for l in s["opkg"].splitlines() if " - " in l]
        return {"manager": "opkg", "count": len(pkgs), "security": None, "packages": pkgs[:40], "reboot_required": False}
    return {"manager": None, "count": None, "security": None, "packages": [],
            "reboot_required": "REBOOT_REQUIRED" in s.get("reboot_required", "")}


def parse_mdstat(text: str) -> list[dict]:
    arrays = []
    cur = None
    for line in text.splitlines():
        m = re.match(r"^(md\d+)\s*:\s*(\w+)\s+(\S+)?\s*(.*)", line)
        if m:
            cur = {"name": m.group(1), "state": m.group(2), "level": m.group(3), "members": m.group(4).split(),
                   "status": None, "degraded": False, "rebuilding": None}
            arrays.append(cur)
            continue
        if cur:
            st = re.search(r"\[(\d+)/(\d+)\]\s*\[([U_]+)\]", line)
            if st:
                cur["status"] = st.group(3)
                cur["degraded"] = "_" in st.group(3)
            rb = re.search(r"(recovery|resync|reshape|check)\s*=\s*([\d.]+)%", line)
            if rb:
                cur["rebuilding"] = f"{rb.group(1)} {rb.group(2)}%"
    return arrays


def parse_thermal(text: str) -> list[dict]:
    temps = []
    for line in text.splitlines():
        p = line.rsplit(None, 1)
        if len(p) == 2 and p[1].lstrip("-").isdigit():
            v = int(p[1])
            c = v / 1000 if abs(v) > 200 else v
            if -20 < c < 150:
                temps.append({"sensor": p[0], "celsius": round(c, 1)})
    return temps


def parse_top(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        p = line.split()
        if len(p) >= 4:
            try:
                rows.append({"pid": p[0], "command": p[1], "cpu_pct": float(p[2]), "mem_pct": float(p[3])})
            except ValueError:
                pass
    return rows


# ------------------------------------------------------------------ wireless clients

def _leases(text: str) -> dict[str, dict]:
    """MAC -> {ip, name} from dnsmasq or ISC dhcpd lease files."""
    m: dict[str, dict] = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 4 and re.fullmatch(r"\d+", p[0]) and re.fullmatch(r"[0-9a-fA-F:]{17}", p[1]):
            m[p[1].lower()] = {"ip": p[2], "name": None if p[3] == "*" else p[3]}
    for block in re.findall(r"lease ([\d.]+) \{(.*?)\}", text, re.S):
        mac = re.search(r"hardware ethernet ([0-9a-fA-F:]{17})", block[1])
        name = re.search(r'client-hostname "([^"]+)"', block[1])
        if mac:
            m[mac.group(1).lower()] = {"ip": block[0], "name": name.group(1) if name else None}
    return m


def parse_wireless(s: dict) -> dict:
    clients: list[dict] = []
    source = None
    # iw station dump (hostapd / most Linux APs)
    iface, radio = None, {}
    for line in s.get("iw", "").splitlines():
        if line.startswith("## "):
            iface = line[3:].strip()
            continue
        m = re.match(r"\s*(ssid|channel|type)\s+(.*)", line)
        if m and iface:
            radio.setdefault(iface, {})[m.group(1)] = m.group(2).strip()
            continue
        m = re.match(r"Station ([0-9a-fA-F:]{17})", line)
        if m:
            clients.append({"mac": m.group(1).lower(), "interface": iface, "signal_dbm": None})
            source = "iw"
            continue
        if clients and source == "iw":
            c = clients[-1]
            for key, rx in (("signal_dbm", r"^\s*signal:\s*(-?\d+)"), ("signal_avg_dbm", r"^\s*signal avg:\s*(-?\d+)"),
                            ("tx_rate_mbps", r"^\s*tx bitrate:\s*([\d.]+)"), ("rx_rate_mbps", r"^\s*rx bitrate:\s*([\d.]+)"),
                            ("connected_s", r"^\s*connected time:\s*(\d+)"), ("inactive_ms", r"^\s*inactive time:\s*(\d+)"),
                            ("tx_retries", r"^\s*tx retries:\s*(\d+)"), ("tx_failed", r"^\s*tx failed:\s*(\d+)")):
                mm = re.search(rx, line)
                if mm:
                    c[key] = float(mm.group(1)) if "." in mm.group(1) else int(mm.group(1))
    # iwinfo assoclist (OpenWrt)
    if not clients:
        iface = None
        for line in s.get("iwinfo", "").splitlines():
            if line.startswith("## "):
                iface = line[3:].strip()
                continue
            m = re.match(r"\s*([0-9A-Fa-f:]{17})\s+(-?\d+) dBm / (-?\d+) dBm \(SNR (\d+)\)\s+(\d+) ms ago", line)
            if m:
                clients.append({"mac": m.group(1).lower(), "interface": iface, "signal_dbm": int(m.group(2)),
                                "noise_dbm": int(m.group(3)), "snr_db": int(m.group(4)), "inactive_ms": int(m.group(5))})
                source = "iwinfo"
                continue
            m = re.match(r"\s*(RX|TX):\s*([\d.]+) MBit/s", line)
            if m and clients:
                clients[-1][f"{m.group(1).lower()}_rate_mbps"] = float(m.group(2))
    # wlanconfig list sta (Qualcomm/Atheros — RSSI is relative to a ~-95 dBm noise floor)
    if not clients:
        iface = None
        header = []
        for line in s.get("wlanconfig", "").splitlines():
            if line.startswith("## "):
                iface = line[3:].strip()
                continue
            if line.startswith("ADDR"):
                header = line.split()
                continue
            p = line.split()
            if header and p and re.fullmatch(r"[0-9a-fA-F:]{17}", p[0]):
                row = dict(zip(header, p))
                rssi = int(row["RSSI"]) if row.get("RSSI", "").isdigit() else None
                clients.append({"mac": p[0].lower(), "interface": iface,
                                "signal_dbm": rssi - 95 if rssi is not None else None, "signal_estimated": True,
                                "channel": row.get("CHAN"),
                                "tx_rate_mbps": float(re.sub(r"[^\d.]", "", row.get("TXRATE", "")) or 0) or None,
                                "rx_rate_mbps": float(re.sub(r"[^\d.]", "", row.get("RXRATE", "")) or 0) or None})
                source = "wlanconfig"
    leases = _leases(s.get("leases", ""))
    arp = {}
    for line in s.get("arp", "").splitlines()[1:]:
        p = line.split()
        if len(p) >= 4:
            arp[p[3].lower()] = p[0]
    for c in clients:
        info = leases.get(c["mac"], {})
        c["ip"] = info.get("ip") or arp.get(c["mac"])
        c["name"] = info.get("name")
        c["status"] = signal_status(c.get("signal_dbm"), "dBm")
        r = radio.get(c.get("interface") or "", {})
        c["ssid"] = r.get("ssid")
        if not c.get("channel") and r.get("channel"):
            c["channel"] = r["channel"].split(" (")[0]
    clients.sort(key=lambda c: (c.get("signal_dbm") is None, c.get("signal_dbm") or 0))
    aps = [{"interface": k, **v} for k, v in radio.items() if v.get("type") == "AP"]
    return {"source": source, "unit": "dBm", "clients": clients, "radios": aps}


# ------------------------------------------------------------------ analysis

def analyze(sections: dict) -> dict:
    ident = parse_identity(sections)
    findings: list[dict] = []

    # uptime & load
    uptime = None
    try:
        uptime = float(sections.get("uptime", "").split()[0])
    except (IndexError, ValueError):
        pass
    load = None
    try:
        load = [float(x) for x in sections.get("loadavg", "").split()[:3]]
    except ValueError:
        pass
    cpus = int(sections.get("cpus", "1").strip() or 1) if sections.get("cpus", "").strip().isdigit() else 1
    mem = parse_meminfo(sections.get("meminfo", ""))
    disks = parse_df(sections.get("df", ""))
    inodes = {r["mount"]: r for r in parse_df(sections.get("dfi", ""), inodes=True)}
    ifaces = parse_netdev(sections.get("netdev", ""), sections.get("links", ""), sections.get("netdev2", ""),
                          sections.get("ethtool", ""), sections.get("bonding", ""))
    logs = scan_logs(sections)
    updates = parse_updates(sections)
    raid = parse_mdstat(sections.get("mdstat", ""))
    temps = parse_thermal(sections.get("thermal", ""))
    top = parse_top(sections.get("top", ""))
    wireless = parse_wireless(sections)
    failed_units = [l.split()[0] for l in sections.get("failed_units", "").splitlines() if l.strip() and "●" not in l[:2]]
    failed_units += [l.split()[1] for l in sections.get("failed_units", "").splitlines() if l.startswith("●")]

    if uptime is not None:
        if uptime < 3600:
            findings.append(finding("info", "system", "Rebooted within the last hour",
                                    f"Up {human_duration(uptime)}.", "If nobody restarted it, check power and the logs below for a crash."))
        elif uptime > 180 * 86400:
            findings.append(finding("info", "system", f"Running for {human_duration(uptime)} without a reboot",
                                    "Long uptimes usually mean kernel and firmware updates haven't been applied.",
                                    "Plan a maintenance reboot after installing updates."))
    if load:
        per_core = load[1] / max(cpus, 1)
        if per_core >= 2:
            findings.append(finding("critical", "cpu", "Very high CPU load",
                                    f"5-minute load {load[1]:.2f} on {cpus} core(s).", "See top processes; stop or move heavy jobs."))
        elif per_core >= 1:
            findings.append(finding("warning", "cpu", "High CPU load",
                                    f"5-minute load {load[1]:.2f} on {cpus} core(s).", "See top processes below."))
    if mem.get("used_pct") is not None:
        if mem["used_pct"] >= 95:
            findings.append(finding("critical", "memory", "Memory almost full",
                                    f"{mem['used_pct']}% used ({human_bytes(mem['available'])} available).",
                                    "Restart or remove memory-hungry services, or add RAM."))
        elif mem["used_pct"] >= 90:
            findings.append(finding("warning", "memory", "Memory is running low",
                                    f"{mem['used_pct']}% used.", "Check top processes; consider more RAM."))
    if mem.get("swap_pct", 0) >= 50:
        findings.append(finding("warning", "memory", "Heavy swap use",
                                f"{mem['swap_pct']}% of swap in use — the system is short of RAM and will feel slow.",
                                "Reduce running services or add RAM."))
    for d in disks:
        pct = d["used_pct"] or 0
        ino = inodes.get(d["mount"], {}).get("used_pct") or 0
        if pct >= 95 or ino >= 95:
            findings.append(finding("critical", "storage", f"{d['mount']} is full",
                                    f"{pct}% space used" + (f", {ino}% of inodes" if ino >= 95 else "") +
                                    f" ({human_bytes(d['avail'])} free).",
                                    "Delete or move data now — services fail when a disk fills."))
        elif pct >= 85 or ino >= 85:
            findings.append(finding("warning", "storage", f"{d['mount']} is getting full",
                                    f"{pct}% used ({human_bytes(d['avail'])} free).", "Clean up old files, logs or snapshots."))
    for r in raid:
        if r["degraded"]:
            findings.append(finding("critical", "storage", f"RAID array {r['name']} is degraded",
                                    f"Member status [{r['status']}] — a disk has failed or dropped out.",
                                    "Replace the failed disk and let the array rebuild. Back up first."))
        if r["rebuilding"]:
            findings.append(finding("warning", "storage", f"RAID array {r['name']} is rebuilding",
                                    r["rebuilding"], "Avoid heavy use and don't power off until it finishes."))
    for i in ifaces:
        if not i["physical"]:
            continue
        hw = i.get("hw_counters") or {}
        crc = sum(v for k, v in hw.items() if re.search(r"crc|align|symbol|fcs|jabber|fragment", k, re.I))
        if crc:
            findings.append(finding("critical" if crc >= 1000 else "warning", "network",
                                    f"CRC / alignment errors on {i['name']}",
                                    f"{crc:,} frames arrived corrupted ({', '.join(f'{k} {v:,}' for k, v in hw.items() if re.search(r'crc|align|symbol|fcs|jabber|fragment', k, re.I))}).",
                                    "Almost always the physical path: replace the patch cable, then try another switch port / patch-panel jack."))
        if i.get("duplex") == "half" and i.get("state") == "up":
            findings.append(finding("warning", "network", f"{i['name']} is running half duplex",
                                    f"{i.get('speed_mbps') or '?'} Mb/s half duplex — often a duplex mismatch with the switch.",
                                    "Set both ends to auto-negotiate (or both to the same fixed speed/duplex)."))
        if i.get("util_pct") is not None and i["util_pct"] >= 80:
            findings.append(finding("warning", "network", f"{i['name']} is busy ({i['util_pct']:.0f}% of link speed)",
                                    "Measured over 2 seconds during the check.", "If this persists, consider a faster link or link aggregation."))
        for mbr in i.get("members") or []:
            if mbr.get("status") and mbr["status"].lower() != "up":
                findings.append(finding("warning", "network", f"Bond {i['name']}: member {mbr['name']} is {mbr['status']}",
                                        "The bond is running without one of its links.", "Check that port's cable and switch configuration."))
        if i["state"] == "down" and i["kind"] == "ethernet" and i.get("carrier") is False and (i["rx_packets"] + i["tx_packets"]) > 0:
            findings.append(finding("info", "network", f"{i['name']} has no link", "The port was used since boot but is disconnected now.",
                                    "Expected if you unplugged it; otherwise check the cable and switch port."))
        pk = i["rx_packets"] + i["tx_packets"]
        errs = i["rx_errors"] + i["tx_errors"]
        if pk > 1000 and i["error_pct"] >= 1:
            findings.append(finding("critical", "network", f"Many errors on {i['name']}",
                                    f"{errs:,} errors ({i['error_pct']}% of packets).",
                                    "Replace the cable, try another switch port, and check speed/duplex settings."))
        elif pk > 1000 and (i["error_pct"] >= 0.01 or errs >= 100):
            findings.append(finding("warning", "network", f"Errors on {i['name']}",
                                    f"{errs:,} errors ({i['error_pct']}% of packets).", "Check the cable and switch port."))
        if pk > 1000 and i["drop_pct"] >= 1:
            findings.append(finding("warning", "network", f"Dropped packets on {i['name']}",
                                    f"{i['rx_dropped'] + i['tx_dropped']:,} dropped ({i['drop_pct']}%).",
                                    "Usually congestion or unwanted traffic types; persistent drops can mean an overloaded device."))
        if i.get("carrier_changes") and i["carrier_changes"] > 20 and uptime and uptime < 30 * 86400:
            findings.append(finding("warning", "network", f"{i['name']} link keeps flapping",
                                    f"The link went up/down {i['carrier_changes']} times since boot.",
                                    "Replace the cable or check the switch port / power saving settings."))
        if i.get("speed_mbps") and i["speed_mbps"] in (10, 100) and i["kind"] == "ethernet" and i.get("state") == "up":
            findings.append(finding("info", "network", f"{i['name']} negotiated only {i['speed_mbps']} Mb/s",
                                    "Gigabit hardware running at 10/100 usually points to a bad cable.",
                                    "Try a Cat5e/Cat6 cable and a different port."))
    for t in temps:
        if t["celsius"] >= 90:
            findings.append(finding("critical", "hardware", f"{t['sensor']} is very hot ({t['celsius']}°C)", "",
                                    "Check fans and airflow immediately."))
        elif t["celsius"] >= 80:
            findings.append(finding("warning", "hardware", f"{t['sensor']} is hot ({t['celsius']}°C)", "",
                                    "Improve airflow; clean dust from vents and fans."))
    for h in logs["hits"]:
        findings.append(finding(h["severity"], h["area"], h["title"],
                                f"{h['count']} matching log line(s). Latest: {h['examples'][-1][:220]}", h["remedy"]))
    if logs["restricted"]:
        findings.append(finding("info", "access", "Some logs need admin rights to read",
                                f"Couldn't read: {', '.join(logs['restricted'])}.",
                                "Connect as root/admin (or add the user to the adm/systemd-journal group) for a full check."))
    if failed_units:
        findings.append(finding("warning", "services", f"{len(failed_units)} service(s) failed",
                                ", ".join(failed_units[:8]), "Run `systemctl status <name>` on the device to see why."))
    if updates["count"]:
        sev = "warning" if (updates.get("security") or updates["count"] >= 20) else "info"
        sec = f", {updates['security']} security" if updates.get("security") else ""
        findings.append(finding(sev, "updates", f"{updates['count']} update(s) available{sec}",
                                ", ".join(updates["packages"][:8]),
                                "Install updates (e.g. `sudo apt update && sudo apt upgrade`)."
                                if updates["manager"] == "apt" else "Install updates with the package manager."))
    if updates.get("reboot_required"):
        findings.append(finding("warning", "updates", "Reboot required to finish updates", "",
                                "Reboot at a convenient time."))
    if ident["platform"] in ("synology-dsm", "synology-srm"):
        findings.append(finding("info", "updates", f"Firmware: {ident['os']}", "",
                                "Check for updates in Control Panel › Update & Restore (DSM) or SRM › Update & Restore."))
    weak = [c for c in wireless["clients"] if c["status"] == "red"]
    fair = [c for c in wireless["clients"] if c["status"] == "yellow"]
    if weak:
        findings.append(finding("warning", "wireless", f"{len(weak)} Wi-Fi client(s) with weak signal",
                                ", ".join((c.get("name") or c["mac"]) + f" ({c['signal_dbm']} dBm)" for c in weak[:6]),
                                "Move the device or access point closer, add an access point/mesh node, or use 5 GHz with line of sight."))
    elif fair:
        findings.append(finding("info", "wireless", f"{len(fair)} Wi-Fi client(s) with fair signal",
                                ", ".join((c.get("name") or c["mac"]) for c in fair[:6]), "Fine for browsing; may struggle with video calls."))

    from .. import netinfo
    networks = netinfo.networks_from_ssh(sections)
    ssids = netinfo.ssids_from_ssh(sections, wireless.get("radios"))
    findings += netinfo.ssid_findings(ssids)

    if not any(f["severity"] in ("critical", "warning") for f in findings):
        findings.append(finding("ok", "summary", "No problems found", "Everything checked is within normal ranges."))
    findings = sort_findings(findings)
    return {
        "networks": networks, "ssids": ssids, "neighbors": netinfo.neighbors_from_ssh(sections),
        "kind": "ssh", "collected_at": time.time(), "device": ident, "status": overall(findings),
        "findings": findings,
        "system": {"uptime_s": uptime, "uptime": human_duration(uptime), "load": load, "cpus": cpus, "memory": mem,
                   "temperatures": temps, "top": top},
        "disks": disks, "raid": raid, "interfaces": ifaces, "logs": logs, "updates": updates,
        "services_failed": failed_units, "wireless": wireless,
        "raw": {k: v[-20000:] for k, v in sections.items()},
    }

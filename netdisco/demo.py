"""Sample data for trying the dashboard without scanning (python3 -m netdisco --demo)."""
from __future__ import annotations

import math
import random
import threading
import time

from . import classify
from .health import THRESHOLDS

RAW = [
    dict(ip="192.168.1.1", mac="90:09:d0:11:22:33", vendor="Synology", is_gateway=True, ports=[53, 80, 443, 8000, 8001],
         ssdp={"server": "Linux UPnP/1.0", "types": ["device:InternetGatewayDevice"],
               "description": {"friendlyName": "SynologyRouter", "manufacturer": "Synology", "modelName": "RT6600ax"}}),
    dict(ip="192.168.1.12", mac="3c:22:fb:1a:2b:3c", vendor="Apple", is_self=True, hostname="alexs-mbp.lan",
         mdns={"services": ["_companion-link._tcp"], "instances": ["Alex's MacBook Pro"], "model": "MacBookPro18,3"}),
    dict(ip="192.168.1.20", mac="da:a1:19:4c:5d:6e", randomized=True, ports=[62078],
         mdns={"services": ["_companion-link._tcp"], "instances": ["Alex's iPhone"], "model": "iPhone15,2"}),
    dict(ip="192.168.1.21", mac="6a:12:9c:aa:01:02", randomized=True, ports=[],
         mdns={"services": [], "instances": [], "model": None}),
    dict(ip="192.168.1.25", mac="00:1b:a9:30:40:50", vendor="Brother Industries", ports=[80, 443, 515, 631, 9100],
         mdns={"services": ["_ipp._tcp", "_pdl-datastream._tcp", "_uscan._tcp"], "instances": ["Brother MFC-L2750DW"],
               "model": "Brother MFC-L2750DW series"}),
    dict(ip="192.168.1.31", mac="c0:56:e3:10:20:30", vendor="Hikvision", ports=[80, 554, 8000], hostname="driveway-cam.lan"),
    dict(ip="192.168.1.32", mac="34:3e:a4:aa:bb:01", vendor="Ring", ports=[], hostname="front-door.lan"),
    dict(ip="192.168.1.40", mac="00:11:32:ab:cd:ef", vendor="Synology", ports=[22, 80, 139, 445, 5000, 5001, 32400],
         mdns={"services": ["_smb._tcp", "_adisk._tcp", "_http._tcp"], "instances": ["HomeNAS"], "model": None},
         netbios={"name": "HOMENAS", "workgroup": "WORKGROUP"}),
    dict(ip="192.168.1.45", mac="f4:8e:38:12:34:56", vendor="Dell", ports=[135, 139, 445, 3389, 5357],
         netbios={"name": "DESKTOP-7QK2M", "workgroup": "WORKGROUP"}),
    dict(ip="192.168.1.50", mac="b0:a7:37:99:88:77", vendor="Roku", ports=[8060],
         ssdp={"server": "Roku/12.5.0 UPnP/1.0", "types": ["device:MediaRenderer"],
               "description": {"friendlyName": "Living Room Roku", "manufacturer": "Roku", "modelName": "Roku Ultra"}}),
    dict(ip="192.168.1.51", mac="48:a6:b8:01:02:03", vendor="Sonos", ports=[1400],
         ssdp={"types": ["device:ZonePlayer"], "description": {"friendlyName": "Kitchen", "manufacturer": "Sonos, Inc.",
                                                                 "modelName": "Sonos One"}}),
    dict(ip="192.168.1.60", mac="24:0a:c4:55:66:77", vendor="Espressif", ports=[80]),
    dict(ip="192.168.1.61", mac="64:16:66:aa:bb:cc", vendor="Nest Labs", ports=[],
         mdns={"services": ["_googlecast._tcp"], "instances": ["Hallway display"], "model": "Google Nest Hub"}),
    dict(ip="192.168.1.70", mac="98:b6:e9:12:ab:cd", vendor="Nintendo", ports=[]),
    dict(ip="192.168.1.88", mac="dc:a6:32:01:02:03", vendor="Raspberry Pi Trading", ports=[22, 53, 80],
         hostname="pihole.lan"),
    dict(ip="192.168.1.99", mac="00:00:00:00:00:00", ports=[]),
]


class DemoHealth:
    interval = 5.0

    def __init__(self):
        self.start_t = time.time()

    def start(self):
        pass

    def snapshot(self):
        now = time.time()
        hist_i, hist_g = [], []
        for k in range(60, 0, -1):
            t = now - k * 5
            hist_i.append({"t": t, "ms": round(18 + 6 * math.sin(k / 4) + random.random() * 4, 1)
                           if k not in (22,) else None, "loss": 0 if k != 22 else 100})
            hist_g.append({"t": t, "ms": round(3 + random.random() * 2 + (35 if k in (8, 9) else 0), 1), "loss": 0})
        return {
            "timestamp": now,
            "local": {"ip": "192.168.1.12", "network": "192.168.1.0/24", "interface": "en0",
                      "mac": "3c:22:fb:1a:2b:3c", "hostname": "Alexs-MacBook-Pro"},
            "internet": {"target": "1.1.1.1", "method": "icmp", "latency_ms": hist_i[-1]["ms"], "loss_pct": 0.0,
                         "status": "green", "summary": "Internet reachable"},
            "gateway": {"target": "192.168.1.1", "method": "icmp", "latency_ms": hist_g[-1]["ms"], "loss_pct": 0.0,
                        "status": "green", "summary": "Router responding"},
            "dns": {"status": "green", "summary": "Lookups working", "worst_ms": 24.0, "servers": ["192.168.1.88"],
                    "lookups": [{"name": n, "ok": True, "ms": 12.0, "address": "0.0.0.0"}
                                for n in ("apple.com", "google.com", "cloudflare.com")]},
            "wifi": {"interface": "en0", "is_wifi": True, "ssid": "HomeNet-5G", "rssi_dbm": -69, "noise_dbm": -94,
                     "channel": "149 (5GHz, 80MHz)", "tx_rate_mbps": 576, "ssid_hidden_by_os": False,
                     "status": "yellow", "summary": "Fair signal"},
            "thresholds": THRESHOLDS,
            "history": {"internet": hist_i, "gateway": hist_g},
        }


class DemoScanner:
    def __init__(self):
        self.state = {"running": False, "phase": "idle", "progress": 0, "started": None, "finished": None,
                      "error": None, "network": "192.168.1.0/24", "targets": 253}
        self.devices = []

    def start(self):
        if self.state["running"]:
            return False
        self.state.update(running=True, phase="Sweeping the network", progress=10, started=time.time())

        def run():
            for pct, ph in [(30, "Reading neighbour table"), (45, "Listening for Bonjour & UPnP"),
                            (65, "Checking common ports"), (85, "Looking up names")]:
                time.sleep(0.6)
                self.state.update(phase=ph, progress=pct)
            now = time.time()
            devs = []
            for r in RAW:
                d = dict(randomized=False, vendor=None, hostname=None, is_gateway=False, is_self=False,
                         mdns=None, ssdp=None, netbios=None)
                d.update(r)
                if d["mac"] == "00:00:00:00:00:00":
                    d["mac"] = None
                d.update(classify.classify(d))
                from .discovery import _display_name
                d["name"] = _display_name(d)
                d.update(first_seen=now - 86400, last_seen=now, online=d["ip"] != "192.168.1.70")
                devs.append(d)
            self.devices = devs
            self.state.update(running=False, phase="done", progress=100, finished=time.time())

        threading.Thread(target=run, daemon=True).start()
        return True

    def snapshot(self):
        return {"state": dict(self.state), "devices": list(self.devices)}


# ---------------------------------------------------------------------------- v0.2 demo pieces

class DemoPinger:
    interval = 5.0

    def __init__(self, scanner):
        self.scanner = scanner

    def start(self):
        pass

    def clear(self):
        pass

    def snapshot(self):
        from .pinger import GREEN_MS, YELLOW_MS, status_for
        base = {"192.168.1.1": 2, "192.168.1.20": 48, "192.168.1.21": None, "192.168.1.25": 4, "192.168.1.31": 7,
                "192.168.1.32": 140, "192.168.1.40": 1, "192.168.1.45": 3, "192.168.1.50": 12, "192.168.1.51": 9,
                "192.168.1.60": 35, "192.168.1.61": 22, "192.168.1.88": 1, "192.168.1.99": 5}
        res = {}
        for ip, ms in base.items():
            v = None if ms is None else round(ms * (0.8 + random.random() * 0.4), 1)
            res[ip] = {"ms": v, "status": status_for(v), "method": "icmp", "t": time.time()}
        return {"thresholds": {"green_ms": GREEN_MS, "yellow_ms": YELLOW_MS}, "interval": 5.0, "results": res}


class DemoWifi:
    """Simulates walking away from an access point, roaming to a second one, then coming back."""

    def __init__(self):
        from .wifi_live import WifiLive
        self.live = WifiLive()
        self.live.mode = "demo"
        self.t0 = time.time()
        now = time.time()
        for i in range(180, 0, -1):
            self.live._add(self._sample(now - i))

    def _sample(self, t):
        k = (t - self.t0) % 240
        if k < 120:
            rssi, bssid, ch, band = -48 - k * 0.28, "a0:40:a0:11:22:34", 149, "5 GHz"
        else:
            rssi, bssid, ch, band = -79 + (k - 120) * 0.22, "a0:40:a0:55:66:78", 36, "5 GHz"
        rssi += random.uniform(-2.5, 2.5)
        return {"t": t, "ok": True, "interface": "en0", "associated": True, "rssi_dbm": int(rssi),
                "noise_dbm": -94 + random.randint(-2, 2), "tx_rate_mbps": max(24.0, round(1200 + (rssi + 45) * 30, 0)),
                "ssid": "HomeNet-5G", "bssid": bssid, "channel": ch, "band": band, "width_mhz": 80}

    def start(self):
        def run():
            while True:
                self.live._add(self._sample(time.time()))
                time.sleep(1)
        threading.Thread(target=run, daemon=True).start()
        self.live.marks = [
            {"label": "Front desk", "t": time.time() - 600, "rssi_dbm": -52, "noise_dbm": -94, "snr_db": 42, "tx_rate_mbps": 1080,
             "min_rssi": -55, "bssid": "a0:40:a0:11:22:34", "ssid": "HomeNet-5G", "channel": 149, "band": "5 GHz",
             "width_mhz": 80, "status": "green", "quality": "Excellent"},
            {"label": "Conference room", "t": time.time() - 420, "rssi_dbm": -71, "noise_dbm": -93, "snr_db": 22,
             "tx_rate_mbps": 390, "min_rssi": -74, "bssid": "a0:40:a0:11:22:34", "ssid": "HomeNet-5G", "channel": 149,
             "band": "5 GHz", "width_mhz": 80, "status": "yellow", "quality": "Fair"},
            {"label": "Back office (by the printer)", "t": time.time() - 240, "rssi_dbm": -80, "noise_dbm": -92,
             "snr_db": 12, "tx_rate_mbps": 58, "min_rssi": -83, "bssid": "a0:40:a0:55:66:78", "ssid": "HomeNet-5G",
             "channel": 36, "band": "5 GHz", "width_mhz": 80, "status": "red", "quality": "Poor"},
        ]

    def stop(self):
        pass

    def latest(self, max_age=5.0):
        return self.live.latest(max_age)

    def snapshot(self, since=0.0):
        return self.live.snapshot(since)

    def mark(self, label):
        return self.live.mark(label)

    def clear_marks(self):
        self.live.clear_marks()


NAS_SECTIONS = {
    "uname": "Linux HomeNAS 4.4.302+ #69057 SMP Fri Jan 12 17:02:28 CST 2024 x86_64 GNU/Linux synology_geminilake_920+",
    "arch": "x86_64", "hostname": "HomeNAS", "whoami": "admin",
    "synology": 'majorversion="7"\nminorversion="2"\nproductversion="7.2.1"\nbuildnumber="69057"\nsmallfixnumber="3"\n'
                '/etc/synoinfo.conf:upnpmodelname="DS920+"',
    "uptime": "11923456.12 40211234.55", "loadavg": "3.10 2.85 2.40 3/712 22013", "cpus": "4",
    "meminfo": "MemTotal:        3868220 kB\nMemFree:          112340 kB\nMemAvailable:     301220 kB\n"
               "Buffers:           20400 kB\nCached:           640000 kB\nSwapTotal:       4194300 kB\nSwapFree:        1500000 kB",
    "df": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/md0 2385528 1601932 664812 71% /\n"
          "/dev/mapper/cachedev_0 11238298624 10571173376 667125248 95% /volume1\ntmpfs 1934108 244 1933864 1% /dev/shm",
    "dfi": "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/md0 155648 37012 118636 24% /",
    "netdev": "11923456.12 40211234.55\nInter-|   Receive                                                |  Transmit\n"
              " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
              "    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n"
              "  eth0: 912345678901 812345678 0 1203 0 0 0 5000 812345678901 712345678 0 0 0 0 0 0\n"
              "  eth1: 45678901 356789 4210 12 0 1880 0 0 12345678 98765 0 0 0 0 310 0\n"
              "docker0: 1200000 9000 0 0 0 0 0 0 800000 7000 0 0 0 0 0 0",
    "netdev2": "11923458.12 40211240.55\nInter-|   Receive\n face |bytes\n"
               "  eth0: 912371678901 812365678 0 1203 0 0 0 5000 812347678901 712355678 0 0 0 0 0 0\n"
               "  eth1: 45679901 356799 4210 12 0 1880 0 0 12345978 98769 0 0 0 0 310 0\n"
               "docker0: 1200000 9000 0 0 0 0 0 0 800000 7000 0 0 0 0 0 0",
    "links": "if=eth0 phys=1 wireless=0 bridge=0 bond=0 state=up carrier=1 speed=1000 duplex=full mtu=1500 mac=00:11:32:ab:cd:ef cc=2 type=1 master= driver=igc\n"
             "if=eth1 phys=1 wireless=0 bridge=0 bond=0 state=up carrier=1 speed=100 duplex=full mtu=1500 mac=00:11:32:ab:cd:f0 cc=57 type=1 master= driver=igc\n"
             "if=docker0 phys=0 wireless=0 bridge=1 bond=0 state=up carrier=1 speed= duplex= mtu=1500 mac=02:42:ac:11:00:01 cc=4 type=1 master= driver=\n"
             "if=lo phys=0 wireless=0 bridge=0 bond=0 state=unknown carrier=1 speed= duplex= mtu=65536 mac=00:00:00:00:00:00 cc=0 type=772 master= driver=",
    "ethtool": "## eth0\n\tSpeed: 1000Mb/s\n\tDuplex: Full\n\tAuto-negotiation: on\n\tPort: Twisted Pair\n\tLink detected: yes\n"
               "driver: igc\nfirmware-version: 1057:8754\n     rx_crc_errors: 0\n     rx_missed_errors: 0\n"
               "## eth1\n\tSpeed: 100Mb/s\n\tDuplex: Full\n\tAuto-negotiation: on\n\tPort: Twisted Pair\n\tLink detected: yes\n"
               "driver: igc\n     rx_crc_errors: 1874\n     rx_align_errors: 6\n     rx_missed_errors: 12",
    "dmesg": "[11800000.1] ata2.00: exception Emask 0x0 SAct 0x0 SErr 0x0 action 0x0\n"
             "[11800000.2] ata2.00: failed command: READ FPDMA QUEUED\n"
             "[11800000.3] blk_update_request: I/O error, dev sdb, sector 1953520000\n"
             "[11800100.0] md/raid1:md2: Disk failure on sdb5, disabling device.\n"
             "[11800200.0] r8169 0000:02:00.0 eth1: Link is Down\n[11800210.0] r8169 0000:02:00.0 eth1: Link is Up - 100Mbps/Full",
    "syslog": "## /var/log/messages\n2026-09-20T02:11:03 HomeNAS synostoraged: disk_health_check.c:210 Disk [2] bad sector count increased",
    "mdstat": "Personalities : [raid1] [raid5]\nmd2 : active raid5 sda5[0] sdc5[2] sdd5[3]\n"
              "      11701135232 blocks super 1.2 level 5, 64k chunk, algorithm 2 [4/3] [U_UU]\n\n"
              "md0 : active raid1 sda1[0] sdc1[2] sdd1[3]\n      2490176 blocks [4/3] [U_UU]",
    "thermal": "x86_pkg_temp 67000\ncoretemp 71000",
    "top": "  PID COMMAND %CPU %MEM\n 1201 synoindexd 62.0 4.1\n 2210 synofoto-face 35.2 18.3\n  911 smbd 8.1 1.2",
}

ROUTER_API = {
    "query.cgi": {"success": True, "data": {
        "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 3},
        "SYNO.Core.System": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.Core.System.Utilization": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.Core.Upgrade.Server": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.Core.Network.NSM.Device": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.Mesh.Node.List": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.Core.Network.Ethernet": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1}}},
    "SYNO.Core.Network.Ethernet": [{"ifname": "wan", "status": "connected", "speed": 2500, "duplex": True, "ip": "203.0.113.24"},
                                   {"ifname": "lan1", "status": "connected", "speed": 1000, "duplex": True},
                                   {"ifname": "lan2", "status": "connected", "speed": 100, "duplex": True},
                                   {"ifname": "lan3", "status": "disconnected", "speed": 0}],
    "SYNO.Core.System": {"model": "RT6600ax", "firmware_ver": "SRM 1.3.1-9346 Update 8", "up_time": "1234:05:10"},
    "SYNO.Core.System.Utilization": {"cpu": {"user_load": 12, "system_load": 6, "other_load": 1},
                                     "memory": {"real_usage": 58},
                                     "network": [{"device": "wan", "rx": 11250000, "tx": 1400000},
                                                 {"device": "lan1", "rx": 1300000, "tx": 10900000}]},
    "SYNO.Core.Upgrade.Server": {"update": {"available": True, "version": "SRM 1.3.1-9346 Update 9"}},
    "SYNO.Mesh.Node.List": {"nodes": [{"node_id": 0, "name": "RT6600ax (Primary)", "status": "online", "ip": "192.168.1.1"},
                                      {"node_id": 1, "name": "WRX560 Back office", "status": "online", "ip": "192.168.1.2"}]},
    "SYNO.Core.Network.NSM.Device": {"devices": [
        {"mac": "da:a1:19:4c:5d:6e", "hostname": "Alexs-iPhone", "ip_addr": "192.168.1.20", "is_online": True,
         "is_wireless": True, "band": "5G", "signalstrength": 82, "current_rate": 1201, "max_rate": 1201,
         "mesh_node_name": "RT6600ax (Primary)"},
        {"mac": "3c:22:fb:1a:2b:3c", "hostname": "Alexs-MBP", "ip_addr": "192.168.1.12", "is_online": True,
         "is_wireless": True, "band": "5G", "signalstrength": 64, "current_rate": 866, "max_rate": 1201,
         "mesh_node_name": "RT6600ax (Primary)"},
        {"mac": "24:0a:c4:55:66:77", "hostname": "esp-thermostat", "ip_addr": "192.168.1.60", "is_online": True,
         "is_wireless": True, "band": "2.4G", "signalstrength": 31, "current_rate": 11, "max_rate": 72,
         "mesh_node_name": "WRX560 Back office"},
        {"mac": "34:3e:a4:aa:bb:01", "hostname": "Ring-Doorbell", "ip_addr": "192.168.1.32", "is_online": True,
         "is_wireless": True, "band": "2.4G", "signalstrength": 44, "current_rate": 39, "max_rate": 144,
         "mesh_node_name": "RT6600ax (Primary)"},
        {"mac": "b0:a7:37:99:88:77", "hostname": "Roku-Ultra", "ip_addr": "192.168.1.50", "is_online": True,
         "is_wireless": True, "band": "5G", "signalstrength": 71, "current_rate": 433, "max_rate": 867,
         "mesh_node_name": "WRX560 Back office"},
        {"mac": "00:11:32:ab:cd:ef", "hostname": "HomeNAS", "ip_addr": "192.168.1.40", "is_online": True,
         "is_wireless": False},
        {"mac": "f4:8e:38:12:34:56", "hostname": "DESKTOP-7QK2M", "ip_addr": "192.168.1.45", "is_online": True,
         "is_wireless": False}]},
}


def demo_router_report():
    return _fake_synology(ROUTER_API, "192.168.1.1")


def demo_nas_report():
    from .connect import linux
    r = linux.analyze(dict(NAS_SECTIONS))
    r["connection"] = {"method": "SSH", "host": "192.168.1.40", "port": 22, "user": "admin",
                       "host_key": "SHA256:3kq1H0q0…demo", "new_host_key": False}
    return r


class DemoSessions:
    def __init__(self):
        self.sessions = {}

    def connect(self, req):
        from .connect.errors import ConnectError
        if not req.get("otp") and req.get("host") == "192.168.1.1":
            raise ConnectError("otp_required", "Enter the 6-digit code from your authenticator app.")
        time.sleep(1.2)
        if req.get("method") in ("srm", "synology"):
            rep = demo_router_report() if req.get("host") == "192.168.1.1" else demo_dsm_report()
        else:
            rep = demo_nas_report()
        sid = f"demo{len(self.sessions) + 1}"
        self.sessions[sid] = {"id": sid, "method": req.get("method"), "host": req.get("host"),
                              "user": req.get("username"), "device_ip": req.get("device_ip"), "report": rep,
                              "created": time.time(), "last_used": time.time()}
        return {"session_id": sid, "report": rep}

    def refresh(self, sid):
        s = self.sessions[sid]
        return {"session_id": sid, "report": s["report"]}

    def get(self, sid):
        return self.sessions.get(sid)

    def list(self):
        return [{k: v for k, v in s.items() if k != "report"} for s in self.sessions.values()]

    def disconnect(self, sid):
        self.sessions.pop(sid, None)


DSM_API = {
    "query.cgi": {"success": True, "data": {
        "SYNO.API.Auth": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 7},
        "SYNO.Core.System": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 3},
        "SYNO.Core.System.Utilization": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.Core.Upgrade.Server": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 4},
        "SYNO.Storage.CGI.Storage": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.Core.Network.Ethernet": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 2},
        "SYNO.Core.SyslogClient.Log": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1}}},
    "SYNO.Core.System": {"model": "DS920+", "firmware_ver": "DSM 7.2.1-69057 Update 5", "up_time": "2210:14:03",
                         "sys_temp": 48, "temperature_warning": False, "ram_size": 4096, "serial": "21A0XXXXXX",
                         "hostname": "OFFICE-NAS"},
    "SYNO.Core.System.Utilization": {"cpu": {"user_load": 21, "system_load": 7, "other_load": 2},
                                     "memory": {"real_usage": 71},
                                     "network": [{"device": "total", "rx": 5320000, "tx": 910000},
                                                 {"device": "eth0", "rx": 5320000, "tx": 910000},
                                                 {"device": "eth1", "rx": 0, "tx": 0}]},
    "SYNO.Core.Upgrade.Server": {"update": {"available": True, "version": "DSM 7.2.2-72806"}},
    "SYNO.Storage.CGI.Storage": {
        "disks": [
            {"id": "sata1", "longName": "Drive 1", "vendor": "WDC", "model": "WD40EFZX", "status": "normal", "smart_status": "normal", "temp": 36, "size_total": "4000787030016"},
            {"id": "sata2", "longName": "Drive 2", "vendor": "WDC", "model": "WD40EFZX", "status": "crashed", "smart_status": "failing", "temp": 39, "size_total": "4000787030016"},
            {"id": "sata3", "longName": "Drive 3", "vendor": "Seagate", "model": "ST4000VN008", "status": "normal", "smart_status": "normal", "temp": 37, "size_total": "4000787030016"},
            {"id": "sata4", "longName": "Drive 4", "vendor": "Seagate", "model": "ST4000VN008", "status": "normal", "smart_status": "normal", "temp": 38, "size_total": "4000787030016"}],
        "storagePools": [{"id": "reuse_1", "display_name": "Storage Pool 1", "status": "degraded", "raidType": "SHR-1"}],
        "volumes": [{"id": "volume_1", "vol_path": "/volume1", "fs_type": "btrfs", "status": "attention",
                     "size": {"total": "11511874854912", "used": "10130449872896"}}]},
    "SYNO.Core.Network.Ethernet": [{"ifname": "eth0", "status": "connected", "speed": 1000, "duplex": True, "ip": "192.168.1.3", "mtu": 1500},
                                   {"ifname": "eth1", "status": "disconnected", "speed": 0, "ip": "", "mtu": 1500}],
    "SYNO.Core.SyslogClient.Log": {"items": [
        {"time": "2026/09/22 13:35:02", "level": "warn", "who": "SYSTEM", "descr": "User [alex] failed to log in from [192.168.1.8]."},
        {"time": "2026/09/22 04:10:44", "level": "err", "who": "SYSTEM", "descr": "Storage Pool [1] was degraded [3/4]. Please repair it."},
        {"time": "2026/09/22 04:10:40", "level": "err", "who": "SYSTEM", "descr": "Drive 2 crashed."},
        {"time": "2026/09/21 22:01:12", "level": "info", "who": "SYSTEM", "descr": "System successfully backed up to Hyper Backup task [Offsite]."}],
        "total": 4},
}


def _fake_synology(api_data, host):
    from .connect.srm import SRMSession

    class Fake(SRMSession):
        def _get(self, path, params, timeout=20.0):
            if path == "query.cgi":
                return api_data["query.cgi"]
            if params.get("api") == "SYNO.API.Auth":
                return {"success": True, "data": {"sid": "demo"}}
            data = api_data.get(params.get("api"))
            return {"success": data is not None, "data": data, "error": {"code": 103}}
        _post = _get

    s = Fake(host, 5001)
    s.connect("alex", "x", "123456")
    return s.collect()


def demo_dsm_report():
    return _fake_synology(DSM_API, "192.168.1.40")

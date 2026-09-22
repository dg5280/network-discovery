"""Tests for v0.2: network-change reset, pinger, Wi-Fi survey, health collectors, SRM client."""
import json
import socket
import struct
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock
from urllib.parse import parse_qs, urlparse

from netdisco import demo, discovery, health, pinger, wifi_live
from netdisco.connect import linux, srm
from netdisco.connect.errors import ConnectError


class NetworkChange(unittest.TestCase):
    def test_identity_compare(self):
        a = {"ssid": "Office", "network": "10.0.0.0/24", "gateway_mac": "aa"}
        self.assertFalse(health._network_changed(None, a))
        self.assertFalse(health._network_changed(a, dict(a)))
        self.assertTrue(health._network_changed(a, dict(a, ssid="Guest")))
        # SSID hidden by macOS on one read → not a change
        self.assertFalse(health._network_changed(a, dict(a, ssid=None)))
        self.assertTrue(health._network_changed(dict(a, ssid=None), dict(a, ssid=None, network="192.168.1.0/24")))

    def test_scanner_reset_clears_and_discards_stale_scan(self):
        s = discovery.Scanner()
        s.devices = {"aa": {"ip": "10.0.0.5"}}
        with mock.patch.object(s, "start") as start:
            s.reset("Wi-Fi “Guest”")
            start.assert_called_once()
        self.assertEqual(s.devices, {})
        self.assertEqual(s.state["network_label"], "Wi-Fi “Guest”")
        # a reset while a scan runs schedules a restart instead
        s.state["running"] = True
        s.reset("x")
        self.assertTrue(s._restart_pending)


class Pinger(unittest.TestCase):
    def test_status(self):
        self.assertEqual(pinger.status_for(4), "green")
        self.assertEqual(pinger.status_for(45), "yellow")
        self.assertEqual(pinger.status_for(150), "red")
        self.assertEqual(pinger.status_for(None), "red")

    def test_macos_reply_with_ip_header(self):
        """macOS delivers the IP header on ICMP datagram sockets; make sure we strip it."""
        sent_seq = {}

        class FakeSock:
            def __init__(self, *a):
                self.q = []

            def setblocking(self, b):
                pass

            def sendto(self, pkt, addr):
                seq = struct.unpack("!H", pkt[6:8])[0]
                sent_seq[addr[0]] = seq
                ip_hdr = bytes([0x45]) + b"\x00" * 19
                reply = struct.pack("!BBHHH", 0, 0, 0, 0x1234, seq) + pkt[8:]
                self.q.append((ip_hdr + reply, (addr[0], 0)))

            def recvfrom(self, n):
                return self.q.pop(0)

            def close(self):
                pass

        fake = FakeSock()
        with mock.patch("socket.socket", return_value=fake), \
                mock.patch("select.select", side_effect=lambda r, w, x, t: (r if fake.q else [], [], [])):
            res = pinger.icmp_sweep(["10.0.0.2", "10.0.0.3"], timeout=0.2)
        self.assertEqual(set(res), {"10.0.0.2", "10.0.0.3"})


class Survey(unittest.TestCase):
    def test_marks_and_roaming(self):
        w = wifi_live.WifiLive()
        t = time.time()
        for i, (r, b) in enumerate([(-50, "aa"), (-52, "aa"), (-70, "aa"), (-74, "bb"), (-76, "bb")]):
            w._add({"t": t + i, "ok": True, "associated": True, "rssi_dbm": r, "noise_dbm": -92, "bssid": b})
        snap = w.snapshot()
        self.assertEqual([e["type"] for e in snap["events"]], ["roam"])
        self.assertEqual(snap["current"]["status"], "red")
        m = w.mark("Kitchen")
        self.assertEqual(m["rssi_dbm"], -64)          # average of last five
        self.assertEqual(m["min_rssi"], -76)
        self.assertEqual(m["label"], "Kitchen")
        self.assertEqual(wifi_live.rssi_status(-66), ("green", "Good"))
        self.assertEqual(wifi_live.rssi_status(-70), ("yellow", "Fair"))


IW = """## wlan0
	ssid Office
	type AP
	channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz
Station 3c:22:fb:1a:2b:3c (on wlan0)
	inactive time:	120 ms
	signal:  	-58 [-60, -61] dBm
	signal avg:	-57 dBm
	tx bitrate:	866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
	rx bitrate:	780.0 MBit/s
	connected time:	3600 seconds
Station 24:0a:c4:55:66:77 (on wlan0)
	signal:  	-81 dBm
	tx bitrate:	6.5 MBit/s
	connected time:	120 seconds"""
IWINFO = """## wlan1
wlan1     ESSID: "Office-2G"
AA:BB:CC:DD:EE:01  -71 dBm / -95 dBm (SNR 24)  30 ms ago
	RX: 72.2 MBit/s, MCS 7, 20MHz                  1200 Pkts.
	TX: 65.0 MBit/s, MCS 6, 20MHz                  900 Pkts."""
WLANCONFIG = """## ath1
ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE  TXSEQ  RXSEQ  CAPS XCAPS ACAPS     ERP    STATE MAXRATE(DOT11) HTCAPS ASSOCTIME    IEs   MODE
da:a1:19:4c:5d:6e    1  149  866M   780M   40      32      48    0      0   65535  EPSs         0          b              0           AWPSM 00:12:33 RSN WME IEEE80211_MODE_11AC_VHT80"""
LEASES = "## /tmp/dhcp.leases\n1790000000 3c:22:fb:1a:2b:3c 192.168.1.12 Alexs-MBP *\n1790000000 24:0a:c4:55:66:77 192.168.1.60 * *"


class Collectors(unittest.TestCase):
    def test_script_sections_roundtrip(self):
        script = linux.build_script()
        self.assertIn("@@@ND@@@ uptime", script)
        out = "@@@ND@@@ uptime\n123.4 55\n@@@ND@@@ loadavg\n0.1 0.2 0.3 1/2 3\n@@@ND@@@ end\n"
        self.assertEqual(linux.split_sections(out), {"uptime": "123.4 55", "loadavg": "0.1 0.2 0.3 1/2 3"})

    def test_wireless_iw(self):
        w = linux.parse_wireless({"iw": IW, "leases": LEASES})
        self.assertEqual(w["source"], "iw")
        c = {x["mac"]: x for x in w["clients"]}
        self.assertEqual(c["3c:22:fb:1a:2b:3c"]["signal_dbm"], -58)
        self.assertEqual(c["3c:22:fb:1a:2b:3c"]["name"], "Alexs-MBP")
        self.assertEqual(c["3c:22:fb:1a:2b:3c"]["ssid"], "Office")
        self.assertEqual(c["24:0a:c4:55:66:77"]["status"], "red")
        self.assertEqual(w["clients"][0]["mac"], "24:0a:c4:55:66:77")   # weakest first

    def test_wireless_iwinfo_and_wlanconfig(self):
        w = linux.parse_wireless({"iwinfo": IWINFO})
        self.assertEqual((w["source"], w["clients"][0]["signal_dbm"], w["clients"][0]["snr_db"]), ("iwinfo", -71, 24))
        self.assertEqual(w["clients"][0]["tx_rate_mbps"], 65.0)
        w = linux.parse_wireless({"wlanconfig": WLANCONFIG})
        self.assertEqual((w["source"], w["clients"][0]["signal_dbm"]), ("wlanconfig", -55))

    def test_nas_report_findings(self):
        r = demo.demo_nas_report()
        titles = " | ".join(f["title"] for f in r["findings"])
        self.assertEqual(r["status"], "red")
        self.assertEqual(r["device"]["platform"], "synology-dsm")
        for expect in ("RAID array md2 is degraded", "/volume1 is full", "Many errors on eth1",
                       "Disk or filesystem errors", "Heavy swap use"):
            self.assertIn(expect, titles)

    def test_physical_interfaces(self):
        r = demo.demo_nas_report()
        ifs = {i["name"]: i for i in r["interfaces"]}
        self.assertEqual([i["name"] for i in r["interfaces"] if i["physical"]], ["eth0", "eth1"])
        self.assertEqual(ifs["docker0"]["kind"], "bridge")
        self.assertFalse(ifs["docker0"]["physical"])
        e0 = ifs["eth0"]
        self.assertEqual((e0["speed_mbps"], e0["duplex"], e0["driver"], e0["autoneg"]), (1000, "full", "igc", "on"))
        self.assertEqual(e0["rx_bps"], 104_000_000)          # 26 MB over 2 s
        self.assertEqual(e0["util_pct"], 10.4)
        self.assertEqual(ifs["eth1"]["hw_counters"]["rx_crc_errors"], 1874)
        titles = [f["title"] for f in r["findings"]]
        self.assertIn("CRC / alignment errors on eth1", titles)

    def test_bonding_and_old_link_format(self):
        nd = "Inter-|\n face |\n  eth0: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0\n bond0: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0"
        bond = "## bond0\nBonding Mode: IEEE 802.3ad Dynamic link aggregation\nSlave Interface: eth0\nMII Status: up\n" \
               "Link Failure Count: 3\nSlave Interface: eth1\nMII Status: down\nLink Failure Count: 9"
        rows = {i["name"]: i for i in linux.parse_netdev(nd, "eth0 up 1000 2 aa:bb:cc:dd:ee:ff", bonding_text=bond)}
        self.assertEqual(rows["bond0"]["kind"], "bond")
        self.assertEqual([m["status"] for m in rows["bond0"]["members"]], ["up", "down"])
        self.assertEqual((rows["eth0"]["kind"], rows["eth0"]["speed_mbps"], rows["eth0"]["rx_bps"]), ("ethernet", 1000, None))

    def test_quiet_system_is_green(self):
        s = {"uptime": "864000 1", "loadavg": "0.1 0.1 0.1 1/1 1", "cpus": "4",
             "meminfo": "MemTotal: 4000000 kB\nMemAvailable: 3000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB",
             "df": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000000 100000 900000 10% /"}
        r = linux.analyze(s)
        self.assertEqual(r["status"], "green")
        self.assertEqual(r["findings"][0]["severity"], "ok")


class FakeSRM(BaseHTTPRequestHandler):
    seen = []
    dataset = demo.ROUTER_API

    def log_message(self, *a):
        pass

    auth_max = 3

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self._handle(urlparse(self.path), {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()})

    def do_GET(self):
        u = urlparse(self.path)
        self._handle(u, {k: v[0] for k, v in parse_qs(u.query).items()})

    def _handle(self, u, q):
        FakeSRM.seen.append(dict(q, _method=self.command))
        if u.path.endswith("query.cgi"):
            body = json.loads(json.dumps(FakeSRM.dataset["query.cgi"]))
            body["data"]["SYNO.API.Auth"]["maxVersion"] = FakeSRM.auth_max
        elif q.get("api") == "SYNO.API.Auth":
            if int(q["version"]) > FakeSRM.auth_max:
                body = {"success": False, "error": {"code": 104}}
            elif q.get("passwd") != "pw":
                body = {"success": False, "error": {"code": 400}}
            elif not q.get("otp_code"):
                body = {"success": False, "error": {"code": 403}}
            elif q["otp_code"] != "654321":
                body = {"success": False, "error": {"code": 404}}
            else:
                body = {"success": True, "data": {"sid": "abc"}}
        else:
            assert q.get("_sid") == "abc" and q.get("method") in srm.READ_ONLY_METHODS
            data = FakeSRM.dataset.get(q.get("api"))
            body = {"success": data is not None, "data": data, "error": {"code": 102}}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class SRM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), FakeSRM)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def s(self):
        return srm.SRMSession("127.0.0.1", self.port, https=False)

    def test_login_flow(self):
        for pw, otp, code in (("bad", None, "auth_failed"), ("pw", None, "otp_required"), ("pw", "000000", "otp_failed")):
            with self.assertRaises(ConnectError) as cm:
                self.s().connect("admin", pw, otp)
            self.assertEqual(cm.exception.code, code)
        FakeSRM.seen.clear()
        s = self.s()
        s.connect("admin", "pw", "654 321")          # spaces in the code are ignored
        self.assertEqual(s.sid, "abc")
        logins = [x for x in FakeSRM.seen if x.get("api") == "SYNO.API.Auth"]
        self.assertEqual(len(logins), 1)             # one attempt → the one-time code is used once
        self.assertEqual((logins[0]["_method"], logins[0]["version"], logins[0]["otp_code"]), ("POST", "3", "654321"))
        self.assertNotIn("pw", json.dumps(s.trace))  # trace never contains secrets
        r = s.collect()
        self.assertEqual(r["device"]["model"], "RT6600ax")
        self.assertEqual(len(r["wireless"]["clients"]), 5)
        self.assertEqual(r["wireless"]["clients"][0]["name"], "esp-thermostat")
        self.assertEqual(r["wireless"]["wired_devices"], 2)
        self.assertTrue(r["updates"]["available"])

    def test_only_supported_versions(self):
        FakeSRM.auth_max = 2
        try:
            FakeSRM.seen.clear()
            with self.assertRaises(ConnectError) as cm:
                self.s().connect("admin", "pw", None)
            self.assertEqual(cm.exception.code, "otp_required")
            self.assertEqual({x["version"] for x in FakeSRM.seen if x.get("api") == "SYNO.API.Auth"}, {"2"})
            self.assertIn("trace", cm.exception.extra)
        finally:
            FakeSRM.auth_max = 3

    def test_http_port_autodetect(self):
        """A plain-HTTP port (like DSM's 5000) that we first try as HTTPS must still work."""
        s = srm.SRMSession("127.0.0.1", self.port)      # random port → HTTPS guessed first
        self.assertTrue(s.https)
        s.connect("admin", "pw", "654321")
        self.assertFalse(s.https)
        self.assertTrue(any(t.get("step") == "scheme" for t in s.trace))
        self.assertFalse(srm.SRMSession("10.0.0.1", 5000).https)
        self.assertTrue(srm.SRMSession("10.0.0.1", 5001).https)

    def test_dsm_report(self):
        FakeSRM.dataset = demo.DSM_API
        try:
            s = self.s()
            s.connect("alex", "pw", "654321")
            r = s.collect()
        finally:
            FakeSRM.dataset = demo.ROUTER_API
        self.assertEqual((r["kind"], r["device"]["model"], r["status"]), ("dsm", "DS920+", "red"))
        titles = " | ".join(f["title"] for f in r["findings"])
        for expect in ("Storage Pool 1 is degraded", "Drive 2 is failing", "/volume1 is getting full",
                       "A DSM update is available", "failed sign-in"):
            self.assertIn(expect, titles)
        self.assertEqual(r["disks"][0]["used_pct"], 88)
        eth0 = next(i for i in r["interfaces"] if i["name"] == "eth0")
        self.assertEqual((eth0["state"], eth0["speed_mbps"], eth0["duplex"], eth0["rx_bps"]), ("up", 1000, "full", 42_560_000))

    def test_normalize_variants(self):
        n = srm.SRMSession.normalize_client({"macaddr": "AA:BB:CC:00:11:22", "name": "x", "rssi": "-72",
                                             "connection": "wifi_5g", "rate": "300 Mbps"})
        self.assertEqual((n["mac"], n["signal"], n["unit"], n["status"], n["wireless"], n["tx_rate_mbps"]),
                         ("aa:bb:cc:00:11:22", -72, "dBm", "yellow", True, 300.0))


if __name__ == "__main__":
    unittest.main()

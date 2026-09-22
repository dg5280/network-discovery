"""Offline tests: macOS command-output parsing, protocol packet parsing, classification.
Run:  python3 -m unittest discover -s tests
"""
import socket
import struct
import unittest
from unittest import mock

from netdisco import classify, discovery, oui, sysinfo
from netdisco.protocols import dnswire, netbios

ROUTE_GET = """   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""
IFCONFIG = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether 3c:22:fb:1a:2b:3c
	inet6 fe80::1c8a:9f1d:a1b2:c3d4%en0 prefixlen 64 secured scopeid 0xb
	inet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
	status: active
"""
ARP = """? (192.168.1.1) at 0:1e:c9:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.40) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.52) at 3c:2a:f4:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""
HWPORTS = """
Hardware Port: Ethernet
Device: en5
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 3c:22:fb:1a:2b:3c
"""
SP_AIRPORT = """Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0 (1657)
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          Status: Connected
          Current Network Information:
            HomeNet-5G:
              PHY Mode: 802.11ax
              Channel: 149 (5GHz, 80MHz)
              Country Code: US
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -58 dBm / -94 dBm
              Transmit Rate: 864
              MCS Index: 9
          Other Local Wi-Fi Networks:
            Neighbor:
              PHY Mode: 802.11ac
"""
PING_MAC = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=14.123 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 13.901/14.456/15.002/0.450 ms
"""


def fake_run(outputs):
    def _run(cmd, timeout=5.0):
        return outputs.get(" ".join(cmd), "")
    return _run


class MacParsing(unittest.TestCase):
    def test_route_ifconfig(self):
        with mock.patch.object(sysinfo, "IS_MAC", True), \
             mock.patch.object(sysinfo, "run", fake_run({"route -n get default": ROUTE_GET,
                                                         "ifconfig en0": IFCONFIG})):
            self.assertEqual(sysinfo.default_route(), ("192.168.1.1", "en0"))
            ip, net = sysinfo.interface_network("en0")
            self.assertEqual((ip, str(net)), ("192.168.1.23", "192.168.1.0/24"))
            self.assertEqual(sysinfo.interface_mac("en0"), "3c:22:fb:1a:2b:3c")

    def test_arp(self):
        with mock.patch.object(sysinfo, "run", fake_run({"arp -an": ARP})):
            t = discovery.read_arp()
        self.assertEqual(t, {"192.168.1.1": "00:1e:c9:aa:bb:cc", "192.168.1.52": "3c:2a:f4:01:02:03"})

    def test_wifi_redacted_ssid_falls_back_to_system_profiler(self):
        outs = {"networksetup -listallhardwareports": HWPORTS,
                "ipconfig getsummary en0": "  SSID : <redacted>\n",
                "system_profiler SPAirPortDataType": SP_AIRPORT}
        with mock.patch.object(sysinfo, "run", fake_run(outs)):
            w = sysinfo._mac_wifi("en0")
        self.assertEqual(w["ssid"], "HomeNet-5G")
        self.assertEqual((w["rssi_dbm"], w["noise_dbm"]), (-58, -94))
        self.assertEqual(w["channel"], "149 (5GHz, 80MHz)")

    def test_ping_parse(self):
        from netdisco import health
        with mock.patch.object(sysinfo, "IS_MAC", True), \
             mock.patch("subprocess.run", return_value=mock.Mock(stdout=PING_MAC)), \
             mock.patch.object(sysinfo.shutil, "which", return_value="/sbin/ping"):
            r = health.icmp_ping("1.1.1.1")
        self.assertEqual((r["latency_ms"], r["loss_pct"]), (14.5, 0.0))
        self.assertEqual(health.latency_status(r), "green")
        self.assertEqual(health.latency_status({"latency_ms": 80, "loss_pct": 0}), "yellow")
        self.assertEqual(health.latency_status({"latency_ms": 20, "loss_pct": 33}), "yellow")
        self.assertEqual(health.latency_status({"latency_ms": 200, "loss_pct": 0}), "red")
        self.assertEqual(health.latency_status({"latency_ms": None, "loss_pct": 100}), "red")


def rr(name, rtype, rdata):
    return dnswire.encode_name(name) + struct.pack("!HHIH", rtype, 0x8001, 120, len(rdata)) + rdata


class Protocols(unittest.TestCase):
    def test_mdns_response(self):
        txt = b"".join(bytes([len(s)]) + s for s in [b"model=MacBookPro18,3", b"osxvers=23"])
        srv = struct.pack("!HHH", 0, 0, 49152) + dnswire.encode_name("Alexs-MBP.local")
        records = [
            rr("_companion-link._tcp.local", dnswire.PTR, dnswire.encode_name("Alex's MacBook Pro._companion-link._tcp.local")),
            rr("Alex's MacBook Pro._device-info._tcp.local", dnswire.TXT, txt),
            rr("Alex's MacBook Pro._companion-link._tcp.local", dnswire.SRV, srv),
            rr("Alexs-MBP.local", dnswire.A, socket.inet_aton("192.168.1.30")),
        ]
        msg = struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)
        parsed = dnswire.parse_message(msg)
        self.assertEqual([r["type"] for r in parsed], [12, 16, 33, 1])
        self.assertEqual(parsed[1]["value"]["model"], "MacBookPro18,3")
        self.assertEqual(parsed[2]["value"], {"port": 49152, "target": "Alexs-MBP.local"})
        self.assertEqual(parsed[3]["value"], "192.168.1.30")

    def test_netbios_node_status(self):
        def entry(n, suffix, flags):
            return n.ljust(15).encode() + bytes([suffix]) + struct.pack("!H", flags)
        names = entry("DESKTOP-ABC123", 0x00, 0x0400) + entry("WORKGROUP", 0x00, 0x8400) + entry("DESKTOP-ABC123", 0x20, 0x0400)
        rdata = bytes([3]) + names + bytes.fromhex("aabbccddeeff") + b"\x00" * 40
        pkt = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0) + netbios._encode_name(b"*") + \
            struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata
        r = netbios._parse(pkt)
        self.assertEqual(r, {"name": "DESKTOP-ABC123", "workgroup": "WORKGROUP", "file_server": True,
                             "mac": "aa:bb:cc:dd:ee:ff"})


class Classification(unittest.TestCase):
    def test_oui(self):
        self.assertEqual(oui.lookup("00:03:93:00:00:01")["vendor"], "Apple")
        self.assertTrue(oui.lookup("da:a1:19:00:00:01")["randomized"])

    def c(self, **kw):
        base = {"ip": "192.168.1.9", "mac": None, "vendor": None, "randomized": False, "ports": []}
        base.update(kw)
        return classify.classify(base)

    def test_cases(self):
        self.assertEqual(self.c(is_gateway=True)["category"], "router")
        self.assertEqual(self.c(mdns={"services": ["_companion-link._tcp"], "model": "MacBookPro18,3"})["category"], "mac")
        self.assertEqual(self.c(mdns={"services": ["_companion-link._tcp"], "model": "iPhone15,2"})["category"], "phone")
        self.assertEqual(self.c(vendor="Brother Industries", ports=[80, 631, 9100])["category"], "printer")
        self.assertEqual(self.c(vendor="Hangzhou Hikvision Digital", ports=[80, 554, 8000])["category"], "camera")
        self.assertEqual(self.c(vendor="Synology", ports=[22, 445, 5000, 5001])["category"], "storage")
        self.assertEqual(self.c(netbios={"name": "DESKTOP-ABC"}, ports=[135, 445])["category"], "windows")
        self.assertEqual(self.c(randomized=True, ports=[62078])["category"], "phone")
        self.assertEqual(self.c(vendor="Roku", ports=[8060])["category"], "tv")
        self.assertEqual(self.c(vendor="Sonos", ports=[1400])["category"], "speaker")
        self.assertEqual(self.c(vendor="Espressif")["category"], "smarthome")
        self.assertEqual(self.c()["category"], "unknown")


if __name__ == "__main__":
    unittest.main()

"""Tests for v0.3: subnet tabs, routed scans, router route tables, router SSIDs, history log."""
import ipaddress
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from netdisco import discovery, events, netinfo, sysinfo
from netdisco.connect import linux


def _load(path):
    with open(path) as fh:
        return json.load(fh)


class SubnetSpecs(unittest.TestCase):
    def test_forms(self):
        p = discovery.parse_spec("10.0.20.0/24")
        self.assertEqual((p["spec"], p["count"], str(p["first"]), str(p["last"])), ("10.0.20.0/24", 254, "10.0.20.1", "10.0.20.254"))
        self.assertEqual(discovery.parse_spec("10.0.20.9 255.255.255.0")["spec"], "10.0.20.0/24")
        self.assertEqual(discovery.parse_spec(" 172.16.4.0 / 22 ")["count"], 1022)
        r = discovery.parse_spec("10.0.20.10-50")
        self.assertEqual((r["spec"], r["count"], r["network"]), ("10.0.20.10-10.0.20.50", 41, None))
        self.assertEqual(discovery.parse_spec("10.0.20.50-10.0.20.10")["count"], 41)
        self.assertEqual(discovery.parse_spec("10.0.20.0-10.0.20.255")["spec"], "10.0.20.0/24")   # range that is a CIDR
        single = discovery.parse_spec("192.168.7.33")
        self.assertEqual(single["spec"], "192.168.7.0/24")
        self.assertIn("No mask", single["note"])
        self.assertEqual(discovery.spec_id("10.0.20.0/24"), "10.0.20.0_24")

    def test_rejections(self):
        for bad, why in [("8.8.8.0/24", "private"), ("10.0.0.0/16", "limit"), ("10.0.0.300/24", "invalid"),
                         ("hello", "isn't a subnet"), ("", "Enter"), ("10.0.0.0/33", "mask")]:
            with self.assertRaises(ValueError, msg=bad) as cm:
                discovery.parse_spec(bad)
            self.assertIn(why, str(cm.exception), bad)

    def test_targets(self):
        p = discovery.parse_spec("10.1.1.250-10.1.2.3")
        t = discovery.spec_targets(p)
        self.assertEqual(t[0], "10.1.1.250")
        self.assertEqual(t[-1], "10.1.2.3")
        self.assertTrue(discovery.spec_contains(p, "10.1.2.0"))
        self.assertFalse(discovery.spec_contains(p, "10.1.2.4"))


class ScanTabs(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = os.path.join(self.dir, "subnets.json")

    def test_add_remove_persist(self):
        m = discovery.ScanManager(store=self.store)
        r = m.add("10.0.20.0/24", "IoT", source="router", scan=False)
        self.assertTrue(r["created"])
        self.assertFalse(m.add("10.0.20.5/24", scan=False)["created"])      # same subnet → same tab
        m.add("10.0.30.10-20", scan=False)
        self.assertEqual([t["id"] for t in m.list()], ["local", "10.0.20.0_24", "10.0.30.10-10.0.30.20"])
        self.assertEqual(m.covers("10.0.20.0/24"), "10.0.20.0_24")
        saved = _load(self.store)
        self.assertEqual(saved[0], {"spec": "10.0.20.0/24", "label": "IoT", "source": "router"})
        m2 = discovery.ScanManager(store=self.store)                         # remembered after restart
        self.assertEqual(len(m2.list()), 3)
        self.assertEqual(m2.get("10.0.20.0_24").label, "IoT")
        self.assertTrue(m2.remove("10.0.20.0_24"))
        self.assertFalse(m2.remove("local"))
        self.assertEqual(len(_load(self.store)), 1)

    def test_tab_limit(self):
        m = discovery.ScanManager(store=self.store)
        for i in range(m.MAX_TABS - 1):
            m.add(f"10.9.{i}.0/24", scan=False, save=False)
        with self.assertRaises(ValueError):
            m.add("10.10.0.0/24", scan=False)

    def test_routed_scan_uses_router_macs(self):
        s = discovery.Scanner("10.0.20.0/29", tab_id="t", mac_hints=lambda: {"10.0.20.3": "00:17:88:aa:bb:cc"})
        with mock.patch.object(sysinfo, "default_route", return_value=("192.168.1.1", "en0")), \
             mock.patch.object(sysinfo, "all_interfaces", return_value=[
                 {"iface": "en0", "ip": "192.168.1.12", "network": ipaddress.IPv4Network("192.168.1.0/24")}]), \
             mock.patch.object(discovery, "icmp_alive", return_value={"10.0.20.1", "10.0.20.3"}), \
             mock.patch.object(discovery, "tcp_alive", return_value={"10.0.20.5"}) as tcp, \
             mock.patch.object(discovery.netbios, "query", return_value={}), \
             mock.patch.object(discovery, "probe_ports", return_value={"10.0.20.3": [80, 443]}), \
             mock.patch.object(discovery, "reverse_dns", return_value={"10.0.20.3": "hue-bridge.lan"}):
            s._scan()
        tcp.assert_called_once()
        self.assertEqual(sorted(tcp.call_args[0][0]), ["10.0.20.2", "10.0.20.4", "10.0.20.5", "10.0.20.6"])
        snap = s.snapshot()
        self.assertEqual(snap["state"]["mode"], "routed")
        ips = {d["ip"]: d for d in snap["devices"]}
        self.assertEqual(sorted(ips), ["10.0.20.1", "10.0.20.3", "10.0.20.5"])
        self.assertEqual(ips["10.0.20.3"]["mac"], "00:17:88:aa:bb:cc")
        self.assertEqual(ips["10.0.20.3"]["name"], "hue-bridge")
        self.assertIsNone(ips["10.0.20.1"]["mac"])

    def test_firewall_answering_for_everything_is_ignored(self):
        s = discovery.Scanner("10.0.21.0/28", tab_id="t")
        everyone = set(discovery.spec_targets(s.spec))
        with mock.patch.object(sysinfo, "default_route", return_value=("192.168.1.1", "en0")), \
             mock.patch.object(sysinfo, "all_interfaces", return_value=[]), \
             mock.patch.object(discovery, "icmp_alive", return_value={"10.0.21.1"}), \
             mock.patch.object(discovery, "tcp_alive", return_value=everyone - {"10.0.21.1"}), \
             mock.patch.object(discovery.netbios, "query", return_value={}), \
             mock.patch.object(discovery, "probe_ports", return_value={}), \
             mock.patch.object(discovery, "reverse_dns", return_value={}):
            s._scan()
        self.assertEqual([d["ip"] for d in s.snapshot()["devices"]], ["10.0.21.1"])
        self.assertIn("firewall", s.state["note"])

    def test_directly_connected_subnet_uses_arp_pipeline(self):
        s = discovery.Scanner("192.168.5.0/24", tab_id="t")
        with mock.patch.object(sysinfo, "default_route", return_value=("192.168.1.1", "en0")), \
             mock.patch.object(sysinfo, "all_interfaces", return_value=[
                 {"iface": "en7", "ip": "192.168.5.20", "network": ipaddress.IPv4Network("192.168.5.0/24")}]), \
             mock.patch.object(s, "_scan_local", return_value=[]) as loc, \
             mock.patch.object(s, "_scan_routed") as routed:
            s._scan()
        routed.assert_not_called()
        self.assertEqual(loc.call_args[0][0], "192.168.5.20")
        self.assertNotIn("192.168.5.20", loc.call_args[0][2])
        self.assertIn("en7", s.state["note"])


class Routes(unittest.TestCase):
    IP_ROUTE = """default via 203.0.113.1 dev wan proto static
10.0.20.0/24 dev lan.20 proto kernel scope link src 10.0.20.1
10.0.30.0/24 dev br-guest proto kernel scope link src 10.0.30.1
192.168.1.0/24 dev br-lan proto kernel scope link src 192.168.1.1
192.168.50.0/24 via 192.168.1.254 dev br-lan proto static metric 10
10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.1
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1
203.0.113.0/24 dev wan proto kernel scope link src 203.0.113.24
10.99.0.0/16 via 192.168.1.254 dev br-lan proto ospf metric 20
local 192.168.1.1 dev br-lan table local proto kernel scope host src 192.168.1.1
broadcast 192.168.1.255 dev br-lan table local proto kernel scope link src 192.168.1.1
10.0.40.7 via 192.168.1.2 dev br-lan"""

    def test_ip_route(self):
        nets = {n["network"]: n for n in netinfo.build_networks(netinfo.parse_ip_route(self.IP_ROUTE))}
        self.assertNotIn("192.168.1.1/32", nets)             # local table / host routes dropped
        self.assertNotIn("10.0.40.7/32", nets)
        self.assertEqual(nets["10.0.20.0/24"]["vlan"], 20)
        self.assertEqual(nets["10.0.20.0/24"]["type"], "connected")
        self.assertEqual(nets["10.0.20.0/24"]["router_ip"], "10.0.20.1")
        self.assertEqual(nets["192.168.50.0/24"]["type"], "static")
        self.assertEqual(nets["192.168.50.0/24"]["via"], "192.168.1.254")
        self.assertEqual(nets["10.8.0.0/24"]["type"], "vpn")
        self.assertEqual(nets["172.17.0.0/16"]["type"], "virtual")
        self.assertFalse(nets["172.17.0.0/16"]["scannable"])
        self.assertFalse(nets["203.0.113.0/24"]["scannable"])
        self.assertIn("public", nets["203.0.113.0/24"]["why_not"])
        self.assertEqual(nets["10.99.0.0/16"]["type"], "dynamic")
        self.assertFalse(nets["10.99.0.0/16"]["scannable"])
        self.assertIn("too large", nets["10.99.0.0/16"]["why_not"])
        self.assertEqual(nets["10.0.30.0/24"]["label"], "guest")

    def test_route_n_and_proc(self):
        rn = """Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         203.0.113.1     0.0.0.0         UG    0      0        0 eth1
10.0.20.0       0.0.0.0         255.255.255.0   U     0      0        0 eth0.20
192.168.50.0    192.168.1.254   255.255.255.0   UG    0      0        0 br0"""
        nets = {n["network"]: n for n in netinfo.build_networks(netinfo.parse_route_n(rn))}
        self.assertEqual(set(nets), {"10.0.20.0/24", "192.168.50.0/24"})
        self.assertEqual(nets["10.0.20.0/24"]["vlan"], 20)
        proc = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
                "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
        self.assertEqual([r["network"] for r in netinfo.parse_proc_route(proc)], ["192.168.1.0/24"])

    def test_vlan_names(self):
        for name, v in [("eth0.20", 20), ("vlan30", 30), ("br-lan.40", 40), ("lan.50@eth0", 50), ("eth0", None),
                        ("wlan0", None), ("eth0.5000", None)]:
            self.assertEqual(netinfo.vlan_of(name), v, name)

    def test_mac_netstat(self):
        out = """Routing tables

Internet:
Destination        Gateway            Flags           Netif Expire
default            192.168.1.1        UGScg             en0
10.8/16            10.8.0.1           UGSc            utun4
127                127.0.0.1          UCS               lo0
169.254            link#11            UCS               en0      !
192.168.1          link#11            UCS               en0      !
192.168.1.1/32     link#11            UCS               en0      !
192.168.1.12       3c:22:fb:1a:2b:3c  UHLWIi            en0   1180
"""
        with mock.patch.object(sysinfo, "IS_MAC", True), mock.patch.object(sysinfo, "run", return_value=out):
            r = {x["network"]: x for x in sysinfo.local_routes()}
        self.assertEqual(set(r), {"10.8.0.0/16", "169.254.0.0/16", "192.168.1.0/24"})
        self.assertEqual(r["10.8.0.0/16"]["via"], "10.8.0.1")
        self.assertEqual(r["192.168.1.0/24"]["type"], "connected")


class SSIDs(unittest.TestCase):
    UCI = """wireless.radio0=wifi-device
wireless.radio0.band='2g'
wireless.radio0.channel='6'
wireless.radio1=wifi-device
wireless.radio1.band='5g'
wireless.radio1.channel='36'
wireless.default_radio0=wifi-iface
wireless.default_radio0.device='radio0'
wireless.default_radio0.network='lan'
wireless.default_radio0.mode='ap'
wireless.default_radio0.ssid='Home'
wireless.default_radio0.encryption='sae-mixed'
wireless.default_radio1=wifi-iface
wireless.default_radio1.device='radio1'
wireless.default_radio1.mode='ap'
wireless.default_radio1.ssid='Home'
wireless.default_radio1.encryption='sae-mixed'
wireless.guest=wifi-iface
wireless.guest.device='radio1'
wireless.guest.mode='ap'
wireless.guest.ssid='Home Guest'
wireless.guest.network='guest'
wireless.guest.encryption='none'
wireless.guest.isolate='1'
wireless.old=wifi-iface
wireless.old.device='radio0'
wireless.old.ssid='Legacy'
wireless.old.encryption='psk-mixed+tkip'
wireless.old.hidden='1'
wireless.old.disabled='1'
wireless.mesh=wifi-iface
wireless.mesh.device='radio1'
wireless.mesh.mode='mesh'
wireless.mesh.ssid='backhaul'"""

    HOSTAPD = """## /var/run/hostapd-phy0.conf
interface=wlan0
hw_mode=g
channel=11
ssid=Office
wpa=2
wpa_key_mgmt=WPA-PSK
ieee80211w=1
wps_state=2
bss=wlan0-1
ssid=Office-IoT
wpa=3
wpa_key_mgmt=WPA-PSK
ignore_broadcast_ssid=1
## /var/run/hostapd-phy1.conf
interface=wlan1
hw_mode=a
channel=149
ssid=Office
wpa=2
wpa_key_mgmt=WPA-PSK SAE"""

    def test_uci(self):
        rows = {(r["ssid"]): r for r in netinfo.merge_ssids(netinfo.parse_uci_wireless(self.UCI))}
        self.assertNotIn("backhaul", rows)                    # mesh links aren't SSIDs people join
        self.assertEqual(rows["Home"]["bands"], ["2.4 GHz", "5 GHz"])
        self.assertEqual(rows["Home"]["security"], "WPA2/WPA3")
        self.assertTrue(rows["Home Guest"]["guest"])
        self.assertTrue(rows["Home Guest"]["isolated"])
        self.assertEqual(rows["Home Guest"]["security_status"], "red")
        self.assertFalse(rows["Legacy"]["enabled"])
        self.assertTrue(rows["Legacy"]["hidden"])
        self.assertEqual(rows["Legacy"]["security"], "WPA/WPA2")

    def test_hostapd(self):
        rows = netinfo.merge_ssids(netinfo.parse_hostapd(self.HOSTAPD))
        by = {(r["ssid"], r["security"]): r for r in rows}
        self.assertEqual(set(by), {("Office", "WPA2"), ("Office", "WPA2/WPA3"), ("Office-IoT", "WPA/WPA2")})
        self.assertTrue(by[("Office", "WPA2")]["wps"])
        self.assertEqual(by[("Office", "WPA2")]["bands"], ["2.4 GHz"])
        self.assertEqual(by[("Office", "WPA2/WPA3")]["bands"], ["5 GHz"])
        self.assertTrue(by[("Office-IoT", "WPA/WPA2")]["hidden"])

    def test_findings(self):
        rows = netinfo.merge_ssids(netinfo.parse_uci_wireless(self.UCI) + netinfo.parse_hostapd(self.HOSTAPD))
        titles = " | ".join(f["title"] for f in netinfo.ssid_findings(rows))
        self.assertIn("“Home Guest” has no password", titles)
        self.assertIn("WPS is on for “Office”", titles)
        self.assertIn("“Office-IoT” allows old WPA", titles)
        self.assertNotIn("Legacy", titles)                   # disabled networks don't count
        self.assertIn("Hidden network: Office-IoT", titles)

    def test_security_labels(self):
        for raw, want in [("wpa2_psk", "WPA2"), ("psk2", "WPA2"), ("sae", "WPA3"), ("wpa3", "WPA3"), ("none", "Open (no password)"),
                          ("open", "Open (no password)"), ("wep-open", "WEP"), ("wpa_wpa2_psk", "WPA/WPA2"), ("psk", "WPA"),
                          ("wpa2-eap", "WPA2-Enterprise"), ("owe", "Enhanced Open (OWE)"), ("wpa2_wpa3_psk", "WPA2/WPA3")]:
            self.assertEqual(netinfo.security_label(raw), want, raw)

    def test_script_never_reads_secrets(self):
        cmd = dict(linux.SECTIONS)["wifi_conf"]
        whitelist = cmd.split("grep -E", 1)[1]
        for secret in ("key", "psk", "password", "passphrase", "secret"):
            self.assertNotIn(secret, whitelist.replace("wpa_key_mgmt", "").lower(), secret)

    def test_redact(self):
        r = netinfo.redact({"ssid": "Home", "password": "hunter2", "wpa_key": "x", "list": [{"psk": "y", "key_mgmt": "sae"}],
                            "has_password": True, "radius_key": "z"})
        self.assertEqual(r["password"], "•••")
        self.assertEqual(r["wpa_key"], "•••")
        self.assertEqual(r["list"][0]["psk"], "•••")
        self.assertEqual(r["ssid"], "Home")
        self.assertIs(r["has_password"], True)
        self.assertNotIn("hunter2", json.dumps(r))

    def test_srm_extraction(self):
        from netdisco import demo
        rep = demo.demo_router_report()
        nets = {n["network"]: n for n in rep["networks"]}
        self.assertEqual(nets["10.0.20.0/24"]["label"], "IoT · VLAN 20")
        self.assertEqual(nets["192.168.50.0/24"]["via"], "192.168.1.254")
        self.assertNotIn("203.0.113.0/24", nets)
        self.assertEqual({s["ssid"] for s in rep["ssids"]}, {"HomeNet", "HomeNet-IoT", "HomeNet-Guest"})
        self.assertNotIn("correct-horse-battery", json.dumps(rep))    # passwords never reach the report
        self.assertNotIn("iot-secret", json.dumps(rep))
        self.assertEqual(rep["neighbors"]["192.168.1.60"], "24:0a:c4:55:66:77")


class SSHRouter(unittest.TestCase):
    def test_analyze_router(self):
        sections = {
            "uname": "Linux OpenWrt 5.15.137 #0 SMP mips GNU/Linux", "hostname": "OpenWrt",
            "openwrt": "DISTRIB_ID='OpenWrt'\nDISTRIB_DESCRIPTION='OpenWrt 23.05.2'",
            "uptime": "1000.0 900.0", "loadavg": "0.1 0.1 0.1 1/80 100", "cpus": "2",
            "routes": Routes.IP_ROUTE,
            "addrs": "5: br-lan    inet 192.168.1.1/24 brd 192.168.1.255 scope global br-lan\n"
                     "9: br-iot    inet 10.0.60.1/24 brd 10.0.60.255 scope global br-iot",
            "wifi_conf": SSIDs.UCI + "\n@@HOSTAPD@@\n",
            "arp": "IP address       HW type     Flags       HW address            Mask     Device\n"
                   "10.0.20.11       0x1         0x2         24:0a:c4:11:22:33     *        lan.20",
            "leases": "## /tmp/dhcp.leases\n1790000000 d8:f1:5b:44:55:66 10.0.20.12 smartplug *",
        }
        r = linux.analyze(sections)
        nets = {n["network"] for n in r["networks"]}
        self.assertIn("10.0.60.0/24", nets)                   # from `ip addr` even without a route line
        self.assertIn("10.0.20.0/24", nets)
        self.assertIn("Home", {s["ssid"] for s in r["ssids"]})
        self.assertEqual(r["neighbors"], {"10.0.20.11": "24:0a:c4:11:22:33", "10.0.20.12": "d8:f1:5b:44:55:66"})
        self.assertTrue(any("Home Guest" in f["title"] for f in r["findings"]))


class HistoryLog(unittest.TestCase):
    def snap(self, t, inet="green", gw="green", dns="green", ip="192.168.1.12", rssi=-60, wifi_status="green"):
        return {"timestamp": t, "local": {"interface": "en0", "ip": ip}, "identity": {"label": "Wi-Fi “Home”"},
                "internet": {"status": inet, "latency_ms": 300 if inet == "yellow" else None if inet == "red" else 20,
                             "loss_pct": 100.0 if inet == "red" else 0.0},
                "gateway": {"target": "192.168.1.1", "status": gw, "latency_ms": 3, "loss_pct": 0.0},
                "dns": {"status": dns, "servers": ["192.168.1.1"], "worst_ms": 20},
                "wifi": {"is_wifi": True, "rssi_dbm": rssi, "status": wifi_status, "ssid": "Home"},
                "thresholds": {"latency_green_ms": 50, "rssi_yellow_dbm": -75}}

    def test_debounce_open_close(self):
        log = events.EventLog(persist=False)
        t = 1000.0
        log.observe(self.snap(t, inet="red"))                  # one bad check: nothing yet
        self.assertEqual(log.query()["events"], [])
        log.observe(self.snap(t + 5, inet="red"))
        q = log.query()
        self.assertEqual(len(q["ongoing"]), 1)
        e = q["ongoing"][0]
        self.assertEqual((e["kind"], e["severity"], e["title"]), ("internet", "critical", "Internet outage"))
        self.assertIn("upstream", e["detail"])                 # router was fine → ISP side
        log.observe(self.snap(t + 10, inet="red"))
        log.observe(self.snap(t + 15))                         # one good check: still open
        self.assertEqual(len(log.query()["ongoing"]), 1)
        log.observe(self.snap(t + 20))
        q = log.query()
        self.assertEqual(q["ongoing"], [])
        self.assertEqual(q["events"][0]["start"], t + 5)
        self.assertEqual(q["events"][0]["end"], t + 10)
        self.assertEqual(q["events"][0]["max_loss"], 100.0)

    def test_slow_needs_three_checks_and_escalates(self):
        log = events.EventLog(persist=False)
        for i in range(2):
            log.observe(self.snap(1000 + i * 5, inet="yellow"))
        self.assertEqual(log.query()["events"], [])
        log.observe(self.snap(1010, inet="yellow"))
        self.assertEqual(log.query()["ongoing"][0]["severity"], "warning")
        log.observe(self.snap(1015, inet="red"))
        self.assertEqual(log.query()["ongoing"][0]["title"], "Internet outage")

    def test_router_down_blames_local_network(self):
        log = events.EventLog(persist=False)
        for i in range(2):
            log.observe(self.snap(1000 + i * 5, inet="red", gw="red"))
        titles = {e["title"]: e for e in log.query()["ongoing"]}
        self.assertIn("Router not responding", titles)
        self.assertIn("local network", titles["Internet outage"]["detail"])

    def test_offline_suppresses_other_incidents(self):
        log = events.EventLog(persist=False)
        for i in range(3):
            log.observe(self.snap(1000 + i * 5, inet="red", gw="red", dns="red", ip=None))
        self.assertEqual([e["title"] for e in log.query()["ongoing"]], ["Not connected to any network"])

    def test_weak_signal(self):
        log = events.EventLog(persist=False)
        for i in range(2):
            log.observe(self.snap(1000 + i * 5, rssi=-80 - i, wifi_status="red"))
        e = log.query()["ongoing"][0]
        self.assertEqual((e["title"], e["min_rssi"]), ("Weak Wi-Fi signal", -81))

    def test_gap_closes_incidents(self):
        log = events.EventLog(persist=False)
        log.observe(self.snap(1000, inet="red"))
        log.observe(self.snap(1005, inet="red"))
        log.observe(self.snap(5000, inet="red"))               # laptop slept for an hour
        evs = log.query()["events"]
        self.assertFalse(evs[0]["open"])
        self.assertEqual(evs[0]["end"], 1005)
        self.assertIn("paused", evs[0]["detail"])

    def test_wifi_drop_events(self):
        class W:
            events = [{"t": 1000.0, "type": "disconnect"}, {"t": 1030.0, "type": "connect", "ssid": "Home"},
                      {"t": 1100.0, "type": "roam", "from": "aa", "to": "bb", "channel": 36}]
        log = events.EventLog(persist=False)
        log.observe_wifi(W)
        log.observe_wifi(W)                                    # seen events aren't logged twice
        evs = log.query()["events"]
        self.assertEqual(len(evs), 2)
        drop = next(e for e in evs if e["title"] == "Wi-Fi disconnected")
        self.assertEqual(drop["duration_s"], 30.0)
        self.assertIn("Reconnected to “Home”", drop["detail"])

    def test_persistence_and_query_window(self):
        path = os.path.join(tempfile.mkdtemp(), "events.jsonl")
        log = events.EventLog(path=path)
        log.add("app", "info", "Monitoring started", t=time.time() - 3 * 86400)
        now = time.time()
        log.observe(self.snap(now - 10, dns="red"))
        log.observe(self.snap(now - 5, dns="red"))             # open when the app "stops"
        log2 = events.EventLog(path=path)
        evs = log2.query()["events"]
        self.assertEqual(len(evs), 2)
        dns = next(e for e in evs if e["kind"] == "dns")
        self.assertFalse(dns["open"])
        self.assertIn("monitoring stopped", dns["detail"])
        recent = log2.query(since=now - 86400)["events"]
        self.assertEqual([e["kind"] for e in recent], ["dns"])     # old point event outside the window
        log2.clear()
        self.assertEqual(events.EventLog(path=path).query()["events"], [])

    def test_csv(self):
        log = events.EventLog(persist=False)
        log.add("network", "info", "Joined Wi-Fi “Home”", "Previously on “Office”, with a comma", t=1000)
        text = events.to_csv(log.query()["events"])
        self.assertIn('"Previously on “Office”, with a comma"', text)
        self.assertTrue(text.startswith("start,end,duration_s,type"))


class AppNetworks(unittest.TestCase):
    def test_demo_suggestions(self):
        from netdisco.server import App
        app = App(demo=True)
        app.sessions.connect({"method": "synology", "host": "192.168.1.1", "username": "a", "password": "b",
                              "otp": "123456", "device_ip": "192.168.1.1"})
        n = app.networks()
        sug = {s["network"] for s in n["suggestions"]}
        self.assertIn("10.0.30.0/24", sug)
        self.assertNotIn("10.0.20.0/24", sug)                   # already has a tab
        self.assertNotIn("192.168.1.0/24", sug)                 # it's the network we're on
        self.assertEqual(app.router_neighbors()["192.168.1.60"], "24:0a:c4:55:66:77")


if __name__ == "__main__":
    unittest.main()

"""Synology Router Manager (SRM) — web API client, read-only.

Logs in the way the SRM web UI does (account + password + optional one-time code),
discovers which APIs this router offers, and calls only read-only methods.
SRM field names vary between versions, so results are normalized defensively and the
raw responses are kept for the "raw data" view.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .errors import ConnectError
from .findings import finding, human_bytes, human_duration, overall, signal_status, sort_findings

READ_ONLY_METHODS = ("get", "list", "info", "check", "load", "load_info", "status")
AUTH_ERRORS = {
    400: ("auth_failed", "Username or password was rejected."),
    401: ("auth_failed", "This account is disabled."),
    402: ("auth_failed", "This account isn't allowed to sign in (it needs administrator rights)."),
    403: ("otp_required", "This account uses 2-step verification. Enter the 6-digit code from your authenticator app and press Connect again."),
    404: ("otp_failed", "The one-time code was rejected. Codes expire quickly — try the next one."),
    406: ("auth_failed", "The device requires 2-step verification to be set up for this account first."),
    407: ("auth_failed", "Too many failed attempts — the device has temporarily blocked this computer's IP (check Auto Block)."),
    408: ("auth_failed", "This account's password has expired — sign in on the router's web page to change it."),
    409: ("auth_failed", "This account's password has expired — sign in on the router's web page to change it."),
    410: ("auth_failed", "The router requires a password change — sign in on its web page first."),
}
MAC_KEYS = ("mac", "mac_addr", "macaddr", "mac_address", "hwaddr")


def _first(d: dict, *keys):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        m = re.search(r"-?\d+(\.\d+)?", str(v or ""))
        return float(m.group()) if m else None


class SRMSession:
    kind = "srm"

    def __init__(self, host: str, port: int = 8001, https: bool | None = None):
        self.host, self.port = host, int(port or 8001)
        # Synology defaults: DSM 5000 = HTTP, 5001 = HTTPS; SRM 8000 = HTTP, 8001 = HTTPS.
        self._set_scheme(self.port not in (80, 5000, 8000) if https is None else https)
        self.sid = None
        self.apis: dict = {}
        self.username = None
        # Routers use self-signed certificates; we talk only to the address you chose on your LAN.
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _set_scheme(self, https: bool):
        self.https = https
        self.base = f"{'https' if https else 'http'}://{self.host}:{self.port}/webapi/"

    # ------------------------------------------------------------------ http
    def _get(self, path: str, params: dict, timeout: float = 20.0) -> dict:
        url = self.base + path + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"User-Agent": "netdisco/0.2.3"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx if self.https else None) as r:
                return json.loads(r.read(5_000_000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            raise ConnectError("error", f"The device returned HTTP {e.code} for {path}.", {"http_status": e.code})
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise ConnectError("unreachable", f"Couldn't reach the Synology web interface at {self.base} ({reason}). "
                                              "Defaults: DSM 5000 (HTTP) / 5001 (HTTPS); SRM 8000 (HTTP) / 8001 (HTTPS).")
        except ValueError:
            raise ConnectError("error", "The reply wasn't JSON — is this a Synology DSM or SRM web port?")

    def call(self, api: str, method: str, version: int | None = None, **params) -> dict:
        if method not in READ_ONLY_METHODS:
            raise ValueError("refusing non read-only method")
        info = self.apis.get(api, {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1})
        v = version or info.get("minVersion", 1)
        v = max(info.get("minVersion", 1), min(v, info.get("maxVersion", v)))
        p = {"api": api, "method": method, "version": v, "_sid": self.sid}
        p.update({k: (json.dumps(val) if isinstance(val, (list, dict, bool)) else val) for k, val in params.items()})
        return self._get(info.get("path", "entry.cgi"), p)

    # ------------------------------------------------------------------ connect
    def _post(self, path: str, params: dict, timeout: float = 20.0) -> dict:
        """Form POST (how the SRM web page signs in) — keeps the password out of the URL."""
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(self.base + path, data=data, headers={
            "User-Agent": "netdisco/0.2.3", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx if self.https else None) as r:
                return json.loads(r.read(1_000_000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return {"success": False, "error": {"code": f"HTTP {e.code}"}}
        except (urllib.error.URLError, OSError) as e:
            raise ConnectError("unreachable", f"Couldn't reach the router at {self.base} ({getattr(e, 'reason', e)}).")
        except ValueError:
            return {"success": False, "error": {"code": "not-json"}}

    def connect(self, username: str, password: str, otp: str | None = None, **_):
        """Sign in. Every attempt is recorded in self.trace (never the password or code)."""
        self.username = username
        self.trace = []
        otp = re.sub(r"\D", "", otp or "") or None       # "123 456" → "123456"
        info_q = {"api": "SYNO.API.Info", "version": 1, "method": "query", "query": "all"}
        try:
            q = self._get("query.cgi", info_q)
        except ConnectError as first:
            # Wrong guess about HTTP vs HTTPS for this port (e.g. an SSL "wrong version number" error
            # when the port speaks plain HTTP) — try the other one before giving up.
            self._set_scheme(not self.https)
            try:
                q = self._get("query.cgi", info_q)
            except ConnectError:
                self._set_scheme(not self.https)
                raise first
            self.trace.append({"step": "scheme", "note": f"port {self.port} speaks {'HTTPS' if self.https else 'HTTP'}"})
        if not q.get("success"):
            raise ConnectError("error", "This doesn't look like a Synology DSM or SRM web interface.")
        self.apis = q.get("data", {})
        auth = self.apis.get("SYNO.API.Auth", {"path": "auth.cgi", "minVersion": 1, "maxVersion": 3})
        lo, hi = int(auth.get("minVersion", 1)), int(auth.get("maxVersion", 3))
        self.trace.append({"step": "api-info", "auth_path": auth.get("path"), "auth_versions": f"{lo}-{hi}"})
        # Newest supported version first (2-step codes need v3+); only versions the router says it has.
        versions = [v for v in dict.fromkeys((min(hi, 6), 3, 2)) if lo <= v <= hi] or [hi]
        path = auth.get("path", "auth.cgi")
        for ver in versions:
            for transport in ("post", "get"):
                params = {"api": "SYNO.API.Auth", "version": ver, "method": "login", "account": username,
                          "passwd": password, "session": "webui", "format": "sid"}
                if otp:
                    params["otp_code"] = otp
                r = self._post(path, params) if transport == "post" else self._get(path, params)
                code = None if r.get("success") else (r.get("error") or {}).get("code")
                self.trace.append({"step": "login", "version": ver, "via": transport.upper(),
                                   "otp_sent": bool(otp), "result": "ok" if r.get("success") else f"error {code}"})
                if r.get("success"):
                    self.sid = (r.get("data") or {}).get("sid")
                    if self.sid:
                        return
                    code = "no-sid"
                if code in AUTH_ERRORS:
                    c, msg = AUTH_ERRORS[code]
                    if code == 400 and not otp:
                        msg += " If this account uses 2-step verification, also enter the current code."
                    raise ConnectError(c, f"{msg} (router error {code})", {"trace": self.trace})
                # These are rejected before the password or code is checked, so trying another
                # variant can't use up the one-time code.
                if code in ("HTTP 404", "HTTP 405", "HTTP 501", "not-json"):
                    continue            # try the same version via GET
                if code in (101, 102, 103, 104, 105, 119):
                    break               # try the next API version
                raise ConnectError("error", f"The device refused the sign-in (error {code}). See details below.",
                                   {"trace": self.trace})
        raise ConnectError("error", f"The device refused the sign-in (error {code}). See details below.",
                           {"trace": self.trace})

    # ------------------------------------------------------------------ collect
    def _try(self, raw: dict, api: str, methods=("get", "list"), **params):
        if api not in self.apis:
            return None
        for m in methods:
            try:
                r = self.call(api, m, **params)
            except (ConnectError, ValueError):
                continue
            if r.get("success"):
                raw[f"{api}.{m}"] = r.get("data")
                return r.get("data")
            raw[f"{api}.{m}"] = {"error": r.get("error")}
        return None

    @staticmethod
    def _find_rows(obj, want=MAC_KEYS, depth=0) -> list[dict]:
        """Find lists of dicts that carry a MAC address, anywhere in a response."""
        if depth > 5:
            return []
        if isinstance(obj, list) and obj and all(isinstance(x, dict) for x in obj) \
                and any(any(k in x for k in want) for x in obj):
            return obj
        rows = []
        if isinstance(obj, dict):
            for v in obj.values():
                rows += SRMSession._find_rows(v, want, depth + 1)
        elif isinstance(obj, list):
            for v in obj:
                rows += SRMSession._find_rows(v, want, depth + 1)
        return rows

    @staticmethod
    def normalize_client(d: dict) -> dict:
        conn = str(_first(d, "connection", "conn_type", "conntype", "interface", "link_type") or "").lower()
        wireless = _first(d, "is_wireless", "wireless")
        if wireless is None:
            wireless = any(w in conn for w in ("wifi", "wireless", "wlan", "2.4", "5g"))
        sig = _num(_first(d, "signalstrength", "signal_strength", "rssi", "signal", "signal_level"))
        unit = "dBm" if sig is not None and sig < 0 else "%"
        band = _first(d, "band", "wifi_band", "radio", "frequency")
        return {
            "mac": str(_first(d, *MAC_KEYS) or "").lower() or None,
            "name": _first(d, "hostname", "name", "dev_name", "device_name", "alias"),
            "ip": _first(d, "ip_addr", "ip", "ipaddr", "ip_address"),
            "online": bool(_first(d, "is_online", "online", "is_connected", "connected") if
                           _first(d, "is_online", "online", "is_connected", "connected") is not None else True),
            "wireless": bool(wireless),
            "signal": int(sig) if sig is not None else None, "unit": unit,
            "status": signal_status(sig, unit) if wireless else "unknown",
            "band": str(band) if band is not None else None,
            "tx_rate_mbps": _num(_first(d, "current_rate", "tx_rate", "link_rate", "rate", "phy_rate")),
            "max_rate_mbps": _num(_first(d, "max_rate", "max_phy_rate")),
            "node": _first(d, "mesh_node_name", "node_name", "ap_name", "connected_node", "mesh_node_id"),
            "connection": conn or None,
        }

    @property
    def is_dsm(self) -> bool:
        return "SYNO.Storage.CGI.Storage" in self.apis or (
            "SYNO.Core.Network.NSM.Device" not in self.apis and not any(a.startswith("SYNO.Mesh") for a in self.apis))

    def collect(self) -> dict:
        return self._collect_dsm() if self.is_dsm else self._collect_srm()

    # shared pieces --------------------------------------------------------
    def _system(self, raw: dict) -> dict:
        sysinfo = self._try(raw, "SYNO.Core.System", ("info",)) or {}
        util = self._try(raw, "SYNO.Core.System.Utilization", ("get",)) or {}
        upgrade = self._try(raw, "SYNO.Core.Upgrade.Server", ("check", "get")) or {}
        up = _first(sysinfo, "up_time", "uptime")
        uptime_s = None
        if isinstance(up, (int, float)):
            uptime_s = float(up)
        elif isinstance(up, str) and re.fullmatch(r"\d+:\d+:\d+", up):
            h, m, sec = (int(x) for x in up.split(":"))
            uptime_s = h * 3600 + m * 60 + sec
        cpu = util.get("cpu", {}) if isinstance(util, dict) else {}
        cpu_pct = None
        if cpu:
            cpu_pct = sum(_num(cpu.get(k)) or 0 for k in ("user_load", "system_load", "other_load")) or _num(cpu.get("load"))
        mem = util.get("memory", {}) if isinstance(util, dict) else {}
        mem_pct = _num(_first(mem, "real_usage", "usage", "memory_usage")) if mem else None
        avail, new_ver = None, None
        if isinstance(upgrade, dict):
            u = upgrade.get("update", upgrade)
            if isinstance(u, dict):
                avail = _first(u, "available", "has_update", "update_available")
                new_ver = _first(u, "version", "latest_version")
        return {"info": sysinfo, "util": util, "uptime_s": uptime_s, "cpu_pct": cpu_pct, "mem_pct": mem_pct,
                "update_available": bool(avail), "update_version": new_ver,
                "model": _first(sysinfo, "model", "model_name", "product"),
                "firmware": _first(sysinfo, "firmware_ver", "version_string", "firmware_version", "version")}

    def _logs(self, raw: dict) -> list[dict]:
        lines = []
        for api in [a for a in self.apis if re.search(r"(Syslog|Log)(\.|$)", a) and "Setting" not in a][:4]:
            data = self._try(raw, api, ("list", "get"), offset=0, limit=200, start=0)
            for row in self._find_rows(data, want=("descr", "msg", "message", "event", "content", "desc")) if data else []:
                msg = _first(row, "descr", "msg", "message", "event", "content", "desc")
                lvl = str(_first(row, "level", "severity", "type") or "").lower()
                when = _first(row, "time", "date", "timestamp")
                lines.append({"time": when, "level": lvl, "message": str(msg)})
            if lines:
                break
        return lines

    @staticmethod
    def _log_findings(findings: list, log_lines: list):
        failed = [l for l in log_lines if re.search(r"failed to (log|sign) ?in|login fail|authentication fail", l["message"], re.I)]
        if failed:
            who = sorted({m.group(1) for l in failed for m in [re.search(r"from \[?([\d.:a-fA-F]+)\]?", l["message"])] if m})
            sev = "warning" if len(failed) >= 10 else "info"
            findings.append(finding(sev, "security", f"{len(failed)} failed sign-in attempt(s) in the log",
                                    (f"From: {', '.join(who[:6])}. " if who else "") + f"Latest: {failed[0]['message'][:160]}",
                                    "If you don't recognise these, turn on Auto Block and 2-step verification, and don't "
                                    "expose the admin port to the internet."))
        errs = [l for l in log_lines if re.search(r"err|crit|fail|attack|block|degrad|crash", l["level"] + " " + l["message"], re.I)
                and l not in failed]
        if errs:
            findings.append(finding("info", "logs", f"{len(errs)} warning/error log entries", errs[0]["message"][:200],
                                    "Review the log entries below."))

    def _interfaces(self, raw: dict, util: dict, findings: list) -> list[dict]:
        """Physical ports (and bonds) from the web API: link state, speed, duplex, MTU, MAC, IP, and
        live throughput from the utilization API. Kernel error counters aren't exposed over the web API."""
        apis = [a for a in self.apis if re.search(r"Network\.(Router\.)?(Ethernet|Bond|Interface|Port(Status)?|LAN|WAN)$", a)]
        rows: dict[str, dict] = {}
        for api in sorted(apis):
            data = self._try(raw, api, ("list", "get"))
            for e in self._find_rows(data, want=("ifname", "port", "port_name", "id", "name")) if data else []:
                name = str(_first(e, "ifname", "port_name", "port", "id", "name") or "")
                if not name or re.match(r"^(lo|docker|veth|tun|br-)", name):
                    continue
                status = str(_first(e, "status", "link_status", "link", "state") or "").lower()
                speed = _num(_first(e, "speed", "link_speed", "current_speed"))
                duplex = _first(e, "duplex", "link_duplex")
                if isinstance(duplex, bool):
                    duplex = "full" if duplex else "half"
                row = rows.setdefault(name, {"name": name})
                kind = "bond" if "Bond" in api or name.startswith("bond") or e.get("slaves") or e.get("members") else \
                       "wifi" if re.match(r"^(wl|ath|ra)", name) else "ethernet"
                up = status in ("connected", "up", "link_up", "1", "true") or (status == "" and speed and speed > 0)
                row.update({
                    "kind": kind, "physical": True,
                    "state": "up" if up else ("down" if status else row.get("state")),
                    "speed_mbps": int(speed) if speed and speed > 0 else row.get("speed_mbps"),
                    "duplex": str(duplex).lower() if duplex not in (None, "") else row.get("duplex"),
                    "mtu": _num(_first(e, "mtu")) or row.get("mtu"),
                    "mac": _first(e, "mac", "hwaddr", "mac_addr") or row.get("mac"),
                    "ip": _first(e, "ip", "ipv4", "ip_addr") or row.get("ip"),
                    "members": [{"name": str(x), "status": None} for x in (e.get("slaves") or e.get("members") or [])] or row.get("members"),
                    "bond_mode": _first(e, "mode", "bond_mode") or row.get("bond_mode"),
                })
        # Live throughput (bytes/s) per device from SYNO.Core.System.Utilization
        for n in (util.get("network") or []) if isinstance(util, dict) else []:
            dev = str(n.get("device") or n.get("name") or "")
            if not dev or dev == "total":
                continue
            row = rows.setdefault(dev, {"name": dev, "kind": "ethernet", "physical": True, "state": None})
            rx, tx = _num(n.get("rx")), _num(n.get("tx"))
            row["rx_bps"] = rx * 8 if rx is not None else None
            row["tx_bps"] = tx * 8 if tx is not None else None
        out = []
        for r in rows.values():
            if r.get("speed_mbps") and r.get("rx_bps") is not None:
                r["util_pct"] = round(100 * max(r["rx_bps"], r.get("tx_bps") or 0) / (r["speed_mbps"] * 1e6), 1)
            out.append(r)
            if r.get("state") == "up" and r.get("speed_mbps") in (10, 100) and r.get("kind") == "ethernet":
                findings.append(finding("info", "network", f"{r['name']} negotiated only {r['speed_mbps']} Mb/s",
                                        "Gigabit ports at 10/100 usually mean a bad cable or switch port.",
                                        "Try a Cat5e/Cat6 cable and another port."))
            if r.get("state") == "up" and r.get("duplex") == "half":
                findings.append(finding("warning", "network", f"{r['name']} is running half duplex",
                                        "Often a duplex mismatch with the switch.", "Set both ends to auto-negotiate."))
            if r.get("util_pct") is not None and r["util_pct"] >= 80:
                findings.append(finding("warning", "network", f"{r['name']} is busy ({r['util_pct']:.0f}% of link speed)",
                                        "", "If this persists, consider a faster link or link aggregation."))
        out.sort(key=lambda r: ({"ethernet": 0, "bond": 1, "wifi": 2}.get(r.get("kind"), 3), r["name"]))
        return out

    # DSM (NAS) ------------------------------------------------------------
    def _collect_dsm(self) -> dict:
        raw: dict = {}
        findings: list[dict] = []
        sysd = self._system(raw)
        storage = self._try(raw, "SYNO.Storage.CGI.Storage", ("load_info",)) or {}
        log_lines = self._logs(raw)
        info = sysd["info"]

        def size(v):
            return _num(v) if v is not None else None

        volumes, pools, drives = [], [], []
        for v in storage.get("volumes", []) if isinstance(storage, dict) else []:
            sz = v.get("size", {}) if isinstance(v.get("size"), dict) else {}
            total, used = size(sz.get("total")), size(sz.get("used"))
            pct = round(100 * used / total) if total and used is not None else None
            volumes.append({"mount": v.get("vol_path") or v.get("display_name") or v.get("id"),
                            "filesystem": v.get("fs_type") or "", "status": str(v.get("status", "")).lower(),
                            "total": total, "used": used, "avail": (total - used) if total and used is not None else None,
                            "used_pct": pct})
        for p in (storage.get("storagePools") or storage.get("storage_pools") or []) if isinstance(storage, dict) else []:
            st = str(p.get("status", "")).lower()
            prog = p.get("progress") if isinstance(p.get("progress"), dict) else {}
            pools.append({"name": p.get("display_name") or p.get("id"), "level": p.get("raidType") or p.get("device_type"),
                          "status": st, "degraded": st in ("degraded", "crashed", "abnormal"),
                          "rebuilding": f"{prog.get('step') or st} {prog.get('percent', '')}%".strip()
                          if st in ("repairing", "expanding", "migrating", "rebuilding") or prog.get("percent") not in (None, "-1", -1)
                          else None})
        for d in storage.get("disks", []) if isinstance(storage, dict) else []:
            drives.append({"name": d.get("longName") or d.get("name") or d.get("id"), "model": " ".join(
                x for x in (d.get("vendor", "").strip(), d.get("model", "").strip()) if x),
                "status": str(d.get("status") or d.get("overview_status") or "").lower(),
                "smart": str(d.get("smart_status") or "").lower(), "temp_c": _num(d.get("temp")),
                "size": size(d.get("size_total")), "life_pct": _num(d.get("remain_life")) if d.get("remain_life") not in (None, -1, "-1") else None})

        # ---- findings
        for p in pools:
            if p["status"] == "crashed":
                findings.append(finding("critical", "storage", f"Storage pool {p['name']} has crashed", f"Status: {p['status']}.",
                                        "Stop writing to it, back up what's readable, and open Storage Manager for recovery steps."))
            elif p["degraded"]:
                findings.append(finding("critical", "storage", f"Storage pool {p['name']} is degraded",
                                        f"RAID {p['level'] or ''} — a drive has failed or been removed.",
                                        "Replace the failed drive (Storage Manager › HDD/SSD) and repair the pool. Back up first."))
            elif p["rebuilding"]:
                findings.append(finding("warning", "storage", f"Storage pool {p['name']} is {p['status']}", p["rebuilding"],
                                        "Avoid heavy use and don't power off until it finishes."))
        for d in drives:
            bad = d["status"] not in ("", "normal", "initialized", "not_use") or d["smart"] not in ("", "normal", "safe")
            if d["smart"] in ("failing", "abnormal", "damage", "crashed") or d["status"] in ("crashed", "failing", "damage"):
                findings.append(finding("critical", "storage", f"{d['name']} is failing", f"{d['model']} — status {d['status']}, SMART {d['smart']}.",
                                        "Back up now and replace this drive."))
            elif bad:
                findings.append(finding("warning", "storage", f"{d['name']} needs attention", f"{d['model']} — status {d['status'] or '?'}, SMART {d['smart'] or '?'}.",
                                        "Run a SMART test in Storage Manager and check the drive's health info."))
            if d["temp_c"] and d["temp_c"] >= 60:
                findings.append(finding("warning", "hardware", f"{d['name']} is hot ({d['temp_c']:.0f}°C)", "",
                                        "Check fans and airflow around the NAS."))
            if d["life_pct"] is not None and d["life_pct"] <= 10:
                findings.append(finding("warning", "storage", f"{d['name']} (SSD) is near end of life", f"{d['life_pct']:.0f}% life left.",
                                        "Plan to replace it."))
        for v in volumes:
            pct = v["used_pct"] or 0
            if v["status"] in ("crashed", "read_only", "readonly"):
                findings.append(finding("critical", "storage", f"{v['mount']} is {v['status']}", "", "Open Storage Manager for details."))
            elif v["status"] not in ("", "normal", "background"):
                findings.append(finding("warning", "storage", f"{v['mount']} status: {v['status']}", "", "Open Storage Manager for details."))
            if pct >= 95:
                findings.append(finding("critical", "storage", f"{v['mount']} is full", f"{pct}% used ({human_bytes(v['avail'])} free).",
                                        "Free space now — Btrfs volumes misbehave when full. Check snapshots and the recycle bin."))
            elif pct >= 85:
                findings.append(finding("warning", "storage", f"{v['mount']} is getting full", f"{pct}% used ({human_bytes(v['avail'])} free).",
                                        "Clean up old files, snapshots and recycle bins."))
        sys_temp = _num(_first(info, "sys_temp", "temperature"))
        if info.get("temperature_warning") or (sys_temp and sys_temp >= 70):
            findings.append(finding("warning", "hardware", f"System temperature is high ({sys_temp:.0f}°C)" if sys_temp else "System temperature warning",
                                    "", "Check fans (Control Panel › Hardware & Power) and airflow."))
        if sysd["cpu_pct"] is not None and sysd["cpu_pct"] >= 85:
            findings.append(finding("warning", "cpu", "CPU is busy", f"{sysd['cpu_pct']:.0f}% in use.",
                                    "Open Resource Monitor to see which package or task is responsible (indexing, Photos face recognition, backups)."))
        if sysd["mem_pct"] is not None and sysd["mem_pct"] >= 90:
            findings.append(finding("warning", "memory", "Memory almost full", f"{sysd['mem_pct']:.0f}% used.",
                                    "Stop unused packages or add RAM."))
        if sysd["update_available"]:
            findings.append(finding("warning", "updates", "A DSM update is available",
                                    f"New version: {sysd['update_version']}" if sysd["update_version"] else "",
                                    "Install it in Control Panel › Update & Restore (outside business hours, after a backup)."))
        if sysd["uptime_s"] and sysd["uptime_s"] > 180 * 86400:
            findings.append(finding("info", "system", f"Up for {human_duration(sysd['uptime_s'])}",
                                    "Long uptime often means updates haven't been installed.", "Check for DSM updates."))
        interfaces = self._interfaces(raw, sysd["util"], findings)
        self._log_findings(findings, log_lines)
        if not any(f["severity"] in ("critical", "warning") for f in findings):
            findings.append(finding("ok", "summary", "No problems found", "Everything checked is within normal ranges."))
        findings = sort_findings(findings)
        fw = sysd["firmware"]
        return {
            "kind": "dsm", "collected_at": time.time(), "status": overall(findings), "findings": findings,
            "device": {"hostname": _first(info, "hostname", "server_name"), "model": sysd["model"],
                       "os": (fw if str(fw).upper().startswith("DSM") else f"DSM {fw}") if fw else "DSM",
                       "platform": "synology-dsm", "user": self.username, "serial": _first(info, "serial")},
            "system": {"uptime_s": sysd["uptime_s"], "uptime": human_duration(sysd["uptime_s"]) if sysd["uptime_s"] else None,
                       "cpu_pct": sysd["cpu_pct"], "memory_pct": sysd["mem_pct"], "temp_c": sys_temp,
                       "ram_mb": _num(_first(info, "ram_size", "ram"))},
            "disks": volumes, "raid": pools, "drives": drives, "interfaces": interfaces,
            "interfaces_note": "Error and drop counters aren't available through the Synology web API — connect with SSH for full counters.",
            "logs": {"sources": ["DSM log"] if log_lines else [], "entries": log_lines[:100]},
            "updates": {"manager": "DSM", "available": sysd["update_available"]},
            "raw": {k: json.dumps(v, indent=1)[:20000] for k, v in raw.items()},
            "connection": {"method": "Synology DSM web API", "host": self.host, "port": self.port, "user": self.username,
                           "https": self.https},
        }

    # SRM (router) ---------------------------------------------------------
    def _collect_srm(self) -> dict:
        raw: dict = {}
        findings: list[dict] = []
        sysd = self._system(raw)
        sysinfo = sysd["info"]
        mesh_nodes = self._try(raw, "SYNO.Mesh.Node.List", ("get", "list")) or {}

        # Client lists: NSM.Device is the known one; also try anything client/station-like.
        client_apis = [a for a in self.apis if re.search(
            r"NSM\.Device$|Mesh.*(Client|Station|WifiDevice)|Wifi.*(Client|Station)|Network\.Client", a)]
        rows: list[dict] = []
        for api in sorted(client_apis, key=lambda a: a != "SYNO.Core.Network.NSM.Device"):
            data = self._try(raw, api, ("get", "list"), conntype="all")
            if data is not None:
                rows += self._find_rows(data)
            if rows:
                break
        clients, seen = [], set()
        for r in rows:
            c = self.normalize_client(r)
            if c["mac"] and c["mac"] not in seen:
                seen.add(c["mac"])
                clients.append(c)
        wireless = [c for c in clients if c["wireless"] and c["online"]]
        wireless.sort(key=lambda c: (c["signal"] is None, c["signal"] if c["unit"] == "dBm" else (c["signal"] or 0)))

        log_lines = self._logs(raw)
        interfaces = self._interfaces(raw, sysd["util"], findings)
        model, firmware, uptime_s = sysd["model"], sysd["firmware"], sysd["uptime_s"]
        cpu_pct, mem_pct = sysd["cpu_pct"], sysd["mem_pct"]
        if cpu_pct is not None and cpu_pct >= 85:
            findings.append(finding("warning", "cpu", "Router CPU is busy", f"{cpu_pct:.0f}% CPU in use.",
                                    "Check Traffic Control / Threat Prevention load; heavy features slow routing."))
        if mem_pct is not None and mem_pct >= 90:
            findings.append(finding("warning", "memory", "Router memory is almost full", f"{mem_pct:.0f}% used.",
                                    "Disable unused packages (e.g. Threat Prevention, VPN Plus) or reboot."))
        avail = sysd["update_available"]
        if avail:
            ver = sysd["update_version"]
            findings.append(finding("warning", "updates", "A router firmware update is available",
                                    f"New version: {ver}" if ver else "",
                                    "Install it in SRM › Control Panel › System › Update & Restore (outside business hours)."))
        if uptime_s is not None and uptime_s > 120 * 86400:
            findings.append(finding("info", "system", f"Router up for {human_duration(uptime_s)}",
                                    "Long uptime often means firmware updates are pending.", "Check for updates."))
        weak = [c for c in wireless if c["status"] == "red"]
        fair = [c for c in wireless if c["status"] == "yellow"]
        if weak:
            findings.append(finding("warning", "wireless", f"{len(weak)} Wi-Fi client(s) with weak signal",
                                    ", ".join(f"{c['name'] or c['mac']} ({c['signal']}{' dBm' if c['unit'] == 'dBm' else '%'})"
                                              for c in weak[:6]),
                                    "Move closer, add a Synology mesh point (MR2200ac/WRX560) where these devices sit, "
                                    "or steer them to 5 GHz."))
        elif fair:
            findings.append(finding("info", "wireless", f"{len(fair)} Wi-Fi client(s) with fair signal",
                                    ", ".join(c["name"] or c["mac"] for c in fair[:6]), "Usually fine; watch for complaints."))
        slow = [c for c in wireless if c["tx_rate_mbps"] and c["tx_rate_mbps"] < 30]
        if slow:
            findings.append(finding("info", "wireless", f"{len(slow)} client(s) connected at a very low rate",
                                    ", ".join(f"{c['name'] or c['mac']} ({c['tx_rate_mbps']:.0f} Mb/s)" for c in slow[:6]),
                                    "Low link rates slow the whole radio for everyone — often old 2.4 GHz devices at range."))
        self._log_findings(findings, log_lines)
        if not clients:
            findings.append(finding("info", "wireless", "Client list not available from this SRM version",
                                    "Open “Raw data” below and send it to support so the parser can be extended.", ""))
        if not any(f["severity"] in ("critical", "warning") for f in findings):
            findings.append(finding("ok", "summary", "No problems found", "Everything checked is within normal ranges."))
        findings = sort_findings(findings)

        bands = {}
        for c in wireless:
            bands[c["band"] or "unknown"] = bands.get(c["band"] or "unknown", 0) + 1
        nodes = self._find_rows(mesh_nodes, want=("node_id", "name", "node_name", "mac"))
        return {
            "kind": "srm", "collected_at": time.time(), "status": overall(findings), "findings": findings,
            "device": {"hostname": _first(sysinfo, "hostname", "server_name"), "model": model, "os": (firmware if str(firmware).upper().startswith("SRM") else f"SRM {firmware}") if firmware else "SRM",
                       "platform": "synology-srm", "user": self.username},
            "system": {"uptime_s": uptime_s, "uptime": human_duration(uptime_s) if uptime_s else None,
                       "cpu_pct": cpu_pct, "memory_pct": mem_pct},
            "wireless": {"source": "SRM API", "unit": wireless[0]["unit"] if wireless else "%", "clients": wireless,
                         "by_band": bands, "total_devices": len(clients),
                         "wired_devices": len([c for c in clients if not c["wireless"] and c["online"]]),
                         "nodes": [{"name": _first(n, "name", "node_name"), "status": _first(n, "status", "state"),
                                    "ip": _first(n, "ip", "ip_addr"), "model": _first(n, "model")} for n in nodes]},
            "logs": {"sources": ["SRM log"] if log_lines else [], "entries": log_lines[:100]},
            "interfaces": interfaces,
            "interfaces_note": "Error and drop counters aren't available through the Synology web API — connect with SSH (as root) for full counters.",
            "updates": {"manager": "SRM", "available": bool(avail)},
            "apis": sorted(a for a in self.apis if a.startswith(("SYNO.Core.Network", "SYNO.Mesh", "SYNO.Core.System"))),
            "raw": {k: json.dumps(v, indent=1)[:20000] for k, v in raw.items()},
            "connection": {"method": "SRM web API", "host": self.host, "port": self.port, "user": self.username,
                           "https": self.https},
        }

    def close(self):
        if self.sid:
            try:
                auth = self.apis.get("SYNO.API.Auth", {"path": "auth.cgi"})
                self._get(auth.get("path", "auth.cgi"), {"api": "SYNO.API.Auth", "version": 1, "method": "logout",
                                                          "session": "webui", "_sid": self.sid}, timeout=5)
            except ConnectError:
                pass
            self.sid = None


SynologySession = SRMSession  # handles both DSM (NAS) and SRM (router)

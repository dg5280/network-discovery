"""Local web server: serves the dashboard and a small JSON API on 127.0.0.1 only."""
from __future__ import annotations

import json
import mimetypes
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .classify import CATEGORIES
from .connect.errors import ConnectError

STATIC = os.path.join(os.path.dirname(__file__), "static")
MAX_BODY = 64 * 1024


class App:
    def __init__(self, health_interval: float = 5.0, rescan_interval: float = 300.0, demo: bool = False):
        self.demo = demo
        if demo:
            from .demo import DemoHealth, DemoPinger, DemoScanner, DemoSessions, DemoWifi
            self.health, self.scanner = DemoHealth(), DemoScanner()
            self.pinger, self.wifi, self.sessions = DemoPinger(self.scanner), DemoWifi(), DemoSessions()
        else:
            from .connect.manager import SessionManager
            from .discovery import Scanner
            from .health import HealthMonitor
            from .pinger import DevicePinger
            from .wifi_live import WifiLive
            self.health = HealthMonitor(interval=health_interval)
            self.scanner = Scanner()
            self.pinger = DevicePinger(self.scanner)
            self.wifi = WifiLive()
            self.sessions = SessionManager()
            self.health.wifi_live = self.wifi
            self.health.on_network_change = self._network_changed
        self.rescan_interval = rescan_interval

    def _network_changed(self, old, new):
        print(f"[network] changed to {new.get('label')} — clearing device list and rescanning")
        self.pinger.clear()
        self.scanner.reset(new.get("label"))

    def start(self):
        self.wifi.start()
        self.health.start()
        self.scanner.start()
        self.pinger.start()
        if self.rescan_interval > 0:
            threading.Thread(target=self._rescan_loop, daemon=True, name="rescan").start()

    def _rescan_loop(self):
        while True:
            time.sleep(self.rescan_interval)
            self.scanner.start()

    def capabilities(self) -> dict:
        try:
            import paramiko  # noqa: F401
            ssh = True
        except ImportError:
            ssh = self.demo
        return {"version": __version__, "ssh": ssh, "srm": True, "demo": self.demo,
                "rescan_interval": self.rescan_interval, "health_interval": getattr(self.health, "interval", 5)}


def make_handler(app: App, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = f"netdisco/{__version__}"

        def log_message(self, fmt, *args):  # keep the terminal quiet (and never log request bodies)
            pass

        def _host_ok(self) -> bool:
            # Blocks DNS-rebinding: only answer requests addressed to localhost.
            return self.headers.get("Host", "") in allowed_hosts

        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                             "frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200):
            self._send(code, json.dumps(obj, default=list).encode(), "application/json")

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ValueError("body too large")
            data = self.rfile.read(n) if n else b"{}"
            obj = json.loads(data or b"{}")
            if not isinstance(obj, dict):
                raise ValueError("expected an object")
            return obj

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, b"Forbidden", "text/plain")
            u = urlparse(self.path)
            path, q = u.path, parse_qs(u.query)
            if path == "/api/health":
                return self._json(app.health.snapshot())
            if path == "/api/devices":
                return self._json(app.scanner.snapshot())
            if path == "/api/pings":
                return self._json(app.pinger.snapshot())
            if path == "/api/wifi/live":
                since = float((q.get("since") or ["0"])[0] or 0)
                return self._json(app.wifi.snapshot(since))
            if path == "/api/sessions":
                return self._json(app.sessions.list())
            m = re.fullmatch(r"/api/sessions/([\w-]+)", path)
            if m:
                s = app.sessions.get(m.group(1))
                return self._json(s) if s else self._json({"error": "not found"}, 404)
            if path == "/api/categories":
                return self._json(CATEGORIES)
            if path == "/api/info":
                return self._json(app.capabilities())
            if path in ("/", "/index.html"):
                path = "/index.html"
            full = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
            if not full.startswith(STATIC) or not os.path.isfile(full):
                return self._send(404, b"Not found", "text/plain")
            with open(full, "rb") as fh:
                ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
                return self._send(200, fh.read(), ctype)

        def do_POST(self):
            if not self._host_ok():
                return self._send(403, b"Forbidden", "text/plain")
            origin = self.headers.get("Origin")
            if origin and origin.split("//", 1)[-1] not in allowed_hosts:
                return self._send(403, b"Forbidden", "text/plain")
            # JSON-only POSTs can't be forged by a plain HTML form on another site.
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return self._send(415, b"JSON required", "text/plain")
            try:
                body = self._body()
            except ValueError as e:
                return self._json({"ok": False, "error": "bad_request", "message": str(e)}, 400)
            path = urlparse(self.path).path
            try:
                if path == "/api/scan":
                    return self._json({"started": app.scanner.start()})
                if path == "/api/wifi/mark":
                    m = app.wifi.mark(body.get("label", ""))
                    return self._json({"ok": bool(m), "mark": m,
                                       "message": None if m else "No Wi-Fi signal reading yet."})
                if path == "/api/wifi/marks/clear":
                    app.wifi.clear_marks()
                    return self._json({"ok": True})
                if path == "/api/connect":
                    r = app.sessions.connect(body)
                    return self._json({"ok": True, **r})
                m = re.fullmatch(r"/api/sessions/([\w-]+)/(refresh|disconnect)", path)
                if m:
                    if m.group(2) == "refresh":
                        return self._json({"ok": True, **app.sessions.refresh(m.group(1))})
                    app.sessions.disconnect(m.group(1))
                    return self._json({"ok": True})
            except ConnectError as e:
                return self._json({"ok": False, "error": e.code, "message": e.message, **e.extra})
            except Exception as e:
                return self._json({"ok": False, "error": "error", "message": f"Unexpected error: {e}"}, 500)
            finally:
                body.pop("password", None)
                body.pop("otp", None)
            return self._send(404, b"Not found", "text/plain")

    return Handler


def serve(port: int = 8765, open_browser: bool = True, health_interval: float = 5.0,
          rescan_interval: float = 300.0, demo: bool = False):
    app = App(health_interval, rescan_interval, demo)
    app.start()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, port))
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{port}/"
    print(f"Network Discovery is running at {url}  (press Ctrl+C to stop)")
    if open_browser:
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        try:
            app.wifi.stop()
        except Exception:
            pass
        httpd.server_close()

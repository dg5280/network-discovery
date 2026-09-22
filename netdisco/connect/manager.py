"""Keeps device sessions open so checks can be re-run without logging in again.
Secrets are never stored: SSH keeps its open transport, SRM keeps its session id."""
from __future__ import annotations

import secrets
import threading
import time

from .errors import ConnectError

IDLE_TIMEOUT = 15 * 60


class SessionManager:
    def __init__(self):
        self.sessions: dict[str, dict] = {}
        self._lock = threading.Lock()
        threading.Thread(target=self._reaper, daemon=True, name="session-reaper").start()

    def _make(self, method: str, host: str, port):
        if method == "ssh":
            from .ssh import SSHSession
            return SSHSession(host, port or 22)
        if method in ("srm", "synology"):
            from .srm import SynologySession
            return SynologySession(host, port or 5001)
        raise ConnectError("error", f"Unknown connection method {method!r}.")

    def connect(self, req: dict) -> dict:
        host = str(req.get("host") or "").strip()
        method = req.get("method") or "ssh"
        username = str(req.get("username") or "").strip()
        if not host or not username:
            raise ConnectError("error", "Host and username are required.")
        sess = self._make(method, host, req.get("port"))
        if method == "ssh":
            sess.username = username
            sess.connect(password=req.get("password") or "", otp=(req.get("otp") or "").strip() or None,
                         trust_new_key=bool(req.get("trust_new_key")))
        else:
            sess.connect(username, req.get("password") or "", otp=(req.get("otp") or "").strip() or None)
        try:
            report = sess.collect()
        except ConnectError:
            sess.close()
            raise
        except Exception as e:
            sess.close()
            raise ConnectError("error", f"Connected, but collecting health data failed: {e}")
        sid = secrets.token_urlsafe(12)
        with self._lock:
            self.sessions[sid] = {"id": sid, "method": method, "host": host, "user": username,
                                  "device_ip": req.get("device_ip") or host, "obj": sess,
                                  "created": time.time(), "last_used": time.time(), "report": report}
        return {"session_id": sid, "report": report}

    def refresh(self, sid: str) -> dict:
        with self._lock:
            s = self.sessions.get(sid)
        if not s:
            raise ConnectError("disconnected", "That session has ended. Connect again.")
        try:
            report = s["obj"].collect()
        except ConnectError as e:
            if e.code in ("disconnected", "unreachable"):
                self.disconnect(sid)
            raise
        s.update(report=report, last_used=time.time())
        return {"session_id": sid, "report": report}

    def get(self, sid: str) -> dict | None:
        with self._lock:
            s = self.sessions.get(sid)
            return {k: v for k, v in s.items() if k != "obj"} if s else None

    def list(self) -> list[dict]:
        with self._lock:
            return [{k: v for k, v in s.items() if k not in ("obj", "report")} |
                    {"status": s["report"].get("status")} for s in self.sessions.values()]

    def disconnect(self, sid: str):
        with self._lock:
            s = self.sessions.pop(sid, None)
        if s:
            try:
                s["obj"].close()
            except Exception:
                pass

    def _reaper(self):
        while True:
            time.sleep(60)
            now = time.time()
            with self._lock:
                stale = [k for k, s in self.sessions.items() if now - s["last_used"] > IDLE_TIMEOUT]
            for k in stale:
                self.disconnect(k)

"""SSH connection with password + one-time-code support (via paramiko).

Host keys are trust-on-first-use: the first key seen for a host is saved to
~/.netdisco/known_hosts; a different key later is refused (possible impersonation).
Passwords and codes are used only during login and never stored.
"""
from __future__ import annotations

import os
import re
import socket
import threading

from . import linux
from .errors import ConnectError

KNOWN_HOSTS = os.path.join(os.path.expanduser("~"), ".netdisco", "known_hosts")
OTP_PROMPT = re.compile(r"code|token|otp|one[- ]?time|verification|passcode|authenticator|2fa|two[- ]factor", re.I)
_kh_lock = threading.Lock()


def _paramiko():
    try:
        import paramiko  # noqa: F401
        return paramiko
    except ImportError:
        raise ConnectError("missing_dependency",
                           "SSH support needs the 'paramiko' package. Start the app with "
                           "“Start Network Discovery.command”, which installs it automatically.")


def fingerprint(key) -> str:
    import base64
    import hashlib
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class SSHSession:
    kind = "ssh"

    def __init__(self, host: str, port: int = 22, username: str = ""):
        self.host, self.port, self.username = host, int(port or 22), username
        self.transport = None
        self.host_key_fp = None
        self.new_host_key = False

    # ------------------------------------------------------------------ connect
    def connect(self, password: str = "", otp: str | None = None, trust_new_key: bool = False,
                timeout: float = 12.0):
        paramiko = _paramiko()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=timeout)
        except OSError as e:
            raise ConnectError("unreachable", f"Couldn't reach {self.host}:{self.port} ({e.strerror or e}).")
        t = paramiko.Transport(sock)
        t.banner_timeout = timeout
        t.auth_timeout = 30
        try:
            t.start_client(timeout=timeout)
        except Exception as e:
            t.close()
            raise ConnectError("error", f"SSH handshake failed: {e}")
        self._check_host_key(t, trust_new_key)

        try:
            self._authenticate(t, paramiko, password, otp)
        except ConnectError:
            t.close()
            raise
        except Exception as e:
            t.close()
            raise ConnectError("error", f"Login failed: {e}")
        t.set_keepalive(30)
        self.transport = t

    def _check_host_key(self, t, trust_new_key: bool):
        import paramiko
        key = t.get_remote_server_key()
        self.host_key_fp = fingerprint(key)
        name = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
        with _kh_lock:
            os.makedirs(os.path.dirname(KNOWN_HOSTS), exist_ok=True)
            hk = paramiko.HostKeys()
            if os.path.exists(KNOWN_HOSTS):
                hk.load(KNOWN_HOSTS)
            known = hk.lookup(name)
            if known and key.get_name() in known:
                if known[key.get_name()].asbytes() != key.asbytes() and not trust_new_key:
                    t.close()
                    raise ConnectError("hostkey_mismatch",
                                       f"The SSH key for {self.host} changed (now {self.host_key_fp}). This happens after "
                                       "a reinstall or firmware reset — or if something is impersonating the device.",
                                       {"fingerprint": self.host_key_fp})
                if known[key.get_name()].asbytes() == key.asbytes():
                    return
            self.new_host_key = True
            hk.add(name, key.get_name(), key)
            hk.save(KNOWN_HOSTS)

    def _authenticate(self, t, paramiko, password: str, otp: str | None):
        user = self.username
        try:
            t.auth_none(user)
            return
        except paramiko.BadAuthenticationType as e:
            allowed = list(e.allowed_types)
        except paramiko.AuthenticationException:
            allowed = ["password", "keyboard-interactive", "publickey"]

        # 1) SSH agent keys when no password was given
        if not password and "publickey" in allowed:
            try:
                for key in paramiko.Agent().get_keys():
                    try:
                        rest = t.auth_publickey(user, key)
                        if t.is_authenticated():
                            return
                        if rest:
                            allowed = list(rest)
                            break
                    except paramiko.AuthenticationException:
                        continue
            except Exception:
                pass

        # 2) password
        if password and "password" in allowed and not t.is_authenticated():
            try:
                rest = t.auth_password(user, password)
                if t.is_authenticated():
                    return
                allowed = list(rest) or allowed   # partial success → usually keyboard-interactive for the code
            except paramiko.BadAuthenticationType as e:
                allowed = list(e.allowed_types)
            except paramiko.AuthenticationException:
                if "keyboard-interactive" not in allowed:
                    raise ConnectError("auth_failed", "Username or password was rejected.")

        # 3) keyboard-interactive (password prompts and one-time-code prompts)
        if "keyboard-interactive" in allowed and not t.is_authenticated():
            state = {"otp_needed": False, "otp_prompt": None, "otp_sent": False}

            def handler(title, instructions, prompts):
                answers = []
                for prompt, _echo in prompts:
                    if OTP_PROMPT.search(prompt) or OTP_PROMPT.search(instructions or ""):
                        if not otp:
                            state.update(otp_needed=True, otp_prompt=prompt.strip())
                            answers.append("")
                        else:
                            state["otp_sent"] = True
                            answers.append(otp)
                    else:
                        answers.append(password)
                return answers

            try:
                t.auth_interactive(user, handler)
            except paramiko.AuthenticationException:
                pass
            if t.is_authenticated():
                return
            if state["otp_needed"]:
                raise ConnectError("otp_required", f"The device asked for a one-time code (“{state['otp_prompt']}”). "
                                                  "Enter the current code and press Connect again."
                                  if state["otp_prompt"] else "The device asked for a one-time code.")
            if state["otp_sent"]:
                raise ConnectError("otp_failed", "The one-time code was rejected. Codes expire quickly — try the next one.")
            raise ConnectError("auth_failed", "Username, password or code was rejected.")
        if not t.is_authenticated():
            if not password:
                raise ConnectError("auth_failed", "Enter a password (no usable SSH agent key was accepted).")
            raise ConnectError("auth_failed", "Username or password was rejected.")

    # ------------------------------------------------------------------ use
    def run(self, command: str, timeout: float = 90.0) -> str:
        if not self.transport or not self.transport.is_active():
            raise ConnectError("disconnected", "The SSH session has closed. Connect again.")
        chan = self.transport.open_session(timeout=15)
        chan.settimeout(timeout)
        chan.exec_command("/bin/sh -s")
        chan.sendall(command.encode())
        chan.shutdown_write()
        out = []
        try:
            while True:
                data = chan.recv(65536)
                if not data:
                    break
                out.append(data)
        except socket.timeout:
            pass
        chan.close()
        return b"".join(out).decode("utf-8", "replace")

    def collect(self) -> dict:
        text = self.run(linux.build_script())
        sections = linux.split_sections(text)
        if not sections:
            raise ConnectError("error", "The device accepted the login but didn't run the health commands "
                                        "(it may not provide a Unix shell — e.g. a restricted CLI).",
                               {"output": text[:2000]})
        report = linux.analyze(sections)
        report["connection"] = {"method": "SSH", "host": self.host, "port": self.port, "user": self.username,
                                "host_key": self.host_key_fp, "new_host_key": self.new_host_key}
        return report

    def close(self):
        if self.transport:
            self.transport.close()
            self.transport = None

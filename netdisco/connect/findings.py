"""Shared helpers for health findings."""
from __future__ import annotations

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def finding(severity: str, area: str, title: str, detail: str = "", remedy: str = "") -> dict:
    return {"severity": severity, "area": area, "title": title, "detail": detail, "remedy": remedy}


def sort_findings(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["area"]))


def overall(items: list[dict]) -> str:
    """Traffic-light summary for a device: red if anything critical, yellow if warnings."""
    sev = {f["severity"] for f in items}
    return "red" if "critical" in sev else "yellow" if "warning" in sev else "green"


def signal_status(value, unit: str) -> str:
    """Client signal → traffic light. dBm (negative) or percent (0-100)."""
    if value is None:
        return "unknown"
    if unit == "dBm":
        return "green" if value >= -67 else "yellow" if value >= -75 else "red"
    return "green" if value >= 60 else "yellow" if value >= 40 else "red"


def human_bytes(n: float | None) -> str:
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"

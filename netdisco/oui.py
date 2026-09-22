"""MAC address vendor lookup using a bundled copy of the IEEE OUI registry."""
from __future__ import annotations

import gzip
import os
import re
import threading

_DB: dict[str, str] | None = None
_LOCK = threading.Lock()
_PATH = os.path.join(os.path.dirname(__file__), "oui.tsv.gz")

_SUFFIXES = re.compile(r"[,.]?\s+(inc|incorporated|co|corp|corporation|ltd|limited|llc|gmbh|ag|sa|s\.a|"
                       r"b\.v|bv|plc|pte|pty|oy|ab|as|kk|srl|spa|technologies|technology|electronics|"
                       r"international|holdings|group|company)\.?$", re.I)


def _load() -> dict[str, str]:
    global _DB
    with _LOCK:
        if _DB is None:
            db = {}
            try:
                with gzip.open(_PATH, "rt", encoding="utf-8") as fh:
                    for line in fh:
                        k, _, v = line.rstrip("\n").partition("\t")
                        db[k] = v
            except OSError:
                pass
            _DB = db
    return _DB


def short_name(vendor: str) -> str:
    v = vendor.strip()
    for _ in range(3):
        v2 = _SUFFIXES.sub("", v).strip(" ,.")
        if v2 == v:
            break
        v = v2
    return v


def is_randomized(mac: str) -> bool:
    """Locally administered bit set -> private/randomized MAC (phones, tablets, some laptops)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def lookup(mac: str | None) -> dict:
    if not mac:
        return {"vendor": None, "randomized": False}
    if is_randomized(mac):
        return {"vendor": None, "randomized": True}
    key = mac.replace(":", "").upper()[:6]
    v = _load().get(key)
    return {"vendor": short_name(v) if v else None, "vendor_full": v, "randomized": False}

"""Fast Wi-Fi sampler for macOS using CoreWLAN via ctypes (no extra packages).

Run as a separate process (python -m netdisco.wifi_helper [interval]) so that if the
Objective-C bridge ever misbehaves it can't take the dashboard down with it.
Prints one JSON object per line.
"""
from __future__ import annotations

import ctypes
import json
import sys
import time

BANDS = {1: "2.4 GHz", 2: "5 GHz", 3: "6 GHz"}
WIDTHS = {1: 20, 2: 40, 3: 80, 4: 160, 5: 320}


def main(interval: float = 1.0):
    objc = ctypes.cdll.LoadLibrary("/usr/lib/libobjc.A.dylib")
    ctypes.cdll.LoadLibrary("/System/Library/Frameworks/Foundation.framework/Foundation")
    ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreWLAN.framework/CoreWLAN")
    objc.objc_getClass.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = [ctypes.c_char_p]
    objc.sel_registerName.restype = ctypes.c_void_p
    objc.sel_registerName.argtypes = [ctypes.c_char_p]
    send_addr = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
    protos: dict = {}

    def msg(restype, obj, name: str):
        if not obj:
            return None
        f = protos.get(restype)
        if f is None:
            f = protos[restype] = ctypes.CFUNCTYPE(restype, ctypes.c_void_p, ctypes.c_void_p)(send_addr)
        return f(obj, objc.sel_registerName(name.encode()))

    def nsstr(obj):
        if not obj:
            return None
        raw = msg(ctypes.c_char_p, obj, "UTF8String")
        return raw.decode("utf-8", "replace") if raw else None

    cls = objc.objc_getClass
    client = msg(ctypes.c_void_p, cls(b"CWWiFiClient"), "sharedWiFiClient")
    pool_cls = cls(b"NSAutoreleasePool")

    while True:
        pool = msg(ctypes.c_void_p, msg(ctypes.c_void_p, pool_cls, "alloc"), "init")
        sample = {"t": time.time(), "ok": False}
        try:
            iface = msg(ctypes.c_void_p, client, "interface")
            if iface:
                rssi = msg(ctypes.c_long, iface, "rssiValue")
                noise = msg(ctypes.c_long, iface, "noiseMeasurement")
                sample.update(
                    ok=True,
                    interface=nsstr(msg(ctypes.c_void_p, iface, "interfaceName")),
                    associated=bool(rssi),
                    rssi_dbm=int(rssi) if rssi else None,
                    noise_dbm=int(noise) if noise else None,
                    tx_rate_mbps=round(msg(ctypes.c_double, iface, "transmitRate") or 0, 1) or None,
                    ssid=nsstr(msg(ctypes.c_void_p, iface, "ssid")),
                    bssid=nsstr(msg(ctypes.c_void_p, iface, "bssid")),
                )
                ch = msg(ctypes.c_void_p, iface, "wlanChannel")
                if ch:
                    sample["channel"] = int(msg(ctypes.c_long, ch, "channelNumber"))
                    sample["band"] = BANDS.get(int(msg(ctypes.c_long, ch, "channelBand")))
                    sample["width_mhz"] = WIDTHS.get(int(msg(ctypes.c_long, ch, "channelWidth")))
        finally:
            msg(None, pool, "drain")
        print(json.dumps(sample), flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    main(float(sys.argv[1]) if len(sys.argv) > 1 else 1.0)

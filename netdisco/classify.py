"""Guess what kind of device something is from everything discovery learned.

Each clue casts a weighted vote for a category and records human-readable evidence,
so the dashboard can show *why* a device was labelled the way it was.
"""
from __future__ import annotations

import collections
import re

CATEGORIES = {
    "router": "Router / Gateway",
    "network": "Network gear",
    "mac": "Mac",
    "windows": "Windows PC",
    "linux": "Linux / Unix",
    "computer": "Computer",
    "phone": "Phone / Tablet",
    "printer": "Printer / Scanner",
    "camera": "Camera",
    "security": "Security / Doorbell",
    "storage": "Storage / NAS",
    "tv": "TV / Streaming",
    "speaker": "Speaker",
    "smarthome": "Smart home",
    "console": "Game console",
    "unknown": "Unknown",
}

# Vendor keyword -> (category, weight). Matched case-insensitively against the OUI vendor.
VENDOR_HINTS = [
    (r"hikvision|dahua|amcrest|reolink|wyze|arlo|axis communications|foscam|uniview|lorex|"
     r"hanwha|vivotek|mobotix|swann|annke|tp-link.*tapo", "camera", 3),
    (r"^ring\b|simplisafe|\badt\b|abode|alarm\.com|qolsys|vivint|skybell|august home|yale", "security", 3),
    (r"hewlett|hp inc|brother|canon|seiko epson|epson|xerox|lexmark|kyocera|ricoh|konica|sharp|oki data|zebra",
     "printer", 2),
    (r"synology|qnap|western digital|buffalo|drobo|asustor|terramaster|seagate|promise tech", "storage", 3),
    (r"ubiquiti|cisco|netgear|tp-link|arris|eero|linksys|aruba|juniper|mikrotik|ruckus|meraki|"
     r"fortinet|sonicwall|commscope|sagemcom|technicolor|actiontec|calix|zyxel|d-link|plume|"
     r"nokia solutions|google fiber|starlink|space exploration", "network", 2),
    (r"espressif|tuya|ecobee|signify|philips lighting|lifx|belkin|shelly|allterco|sonoff|itead|"
     r"silicon labs|texas instruments|chamberlain|rachio|myq|wemo|leviton|lutron|ikea|aqara|lumi united|"
     r"tado|netatmo|meross|govee|kasa|nanoleaf|wiz ", "smarthome", 2),
    (r"roku|vizio|tcl|hisense|nvidia|tivo|lg electronics|sling|funai|universal electronics", "tv", 2),
    (r"sonos|bose|denon|marantz|harman|yamaha|bang & olufsen|bluesound|d&m holdings", "speaker", 3),
    (r"nintendo|sony interactive|valve", "console", 3),
    (r"raspberry pi", "linux", 3),
    (r"dell|lenovo|micro-star|gigabyte|asustek|acer|intel corporate|intel|liteon|azurewave|"
     r"hon hai|foxconn|realtek|framework|clevo|quanta|compal|wistron", "computer", 1),
    (r"murata|samsung|oneplus|xiaomi|motorola|huawei|oppo|vivo mobile|zte|htc|nothing tech|fairphone",
     "phone", 1),
    (r"amazon", "smarthome", 1),
    (r"google|nest labs", "smarthome", 1),
]

PORT_HINTS = {
    9100: ("printer", 3, "Raw print port 9100 open"),
    631: ("printer", 2, "IPP print port 631 open"),
    515: ("printer", 2, "LPD print port 515 open"),
    554: ("camera", 2, "RTSP video port 554 open"),
    37777: ("camera", 3, "Dahua camera port 37777 open"),
    8000: ("camera", 1, "Port 8000 open (common on cameras/NVRs)"),
    62078: ("phone", 3, "Apple device sync port 62078 open"),
    8008: ("tv", 2, "Google Cast port 8008 open"),
    8009: ("tv", 2, "Google Cast port 8009 open"),
    1400: ("speaker", 3, "Sonos port 1400 open"),
    8060: ("tv", 3, "Roku control port 8060 open"),
    5000: ("storage", 1, "Port 5000 open (Synology/NAS web)"),
    5001: ("storage", 1, "Port 5001 open (Synology/NAS web)"),
    3389: ("windows", 3, "Remote Desktop port 3389 open"),
    135: ("windows", 2, "Windows RPC port 135 open"),
    5357: ("windows", 2, "Windows device discovery port 5357 open"),
    445: ("computer", 1, "File sharing (SMB) port 445 open"),
    548: ("mac", 1, "AFP file sharing port 548 open"),
    22: ("linux", 1, "SSH port 22 open"),
    53: ("router", 1, "DNS port 53 open"),
    32400: ("storage", 1, "Plex media server port 32400 open"),
    1883: ("smarthome", 1, "MQTT port 1883 open"),
}

MDNS_HINTS = [
    (r"_ipps?\b|_printer\b|_pdl-datastream|_uscan|_scanner", "printer", 4, "Advertises printing/scanning (Bonjour)"),
    (r"_googlecast", "tv", 3, "Google Cast device (Bonjour)"),
    (r"_amzn-wplay", "tv", 3, "Amazon Fire TV (Bonjour)"),
    (r"_roku", "tv", 3, "Roku (Bonjour)"),
    (r"_androidtvremote", "tv", 3, "Android TV (Bonjour)"),
    (r"_nvstream", "tv", 3, "NVIDIA Shield (Bonjour)"),
    (r"_sonos|_spotify-connect", "speaker", 2, "Speaker service (Bonjour)"),
    (r"_hap\b|_homekit|_matter|_hue\b|_miio|_esphomelib|_meshcop", "smarthome", 3, "Smart-home accessory (HomeKit/Matter)"),
    (r"_axis-video|_onvif|_rtsp", "camera", 3, "Video streaming service (Bonjour)"),
    (r"_adisk", "storage", 2, "Time Machine / network disk (Bonjour)"),
    (r"_companion-link", "phone", 1, "Apple device (companion link)"),
    (r"_workstation", "linux", 1, "Linux workstation service (Bonjour)"),
    (r"_rfb\b", "computer", 1, "Screen sharing enabled (Bonjour)"),
    (r"_smb\b|_afpovertcp", "computer", 1, "File sharing (Bonjour)"),
    (r"_raop|_airplay", "speaker", 1, "AirPlay receiver (Bonjour)"),
]

APPLE_MODELS = [
    (r"^(MacBook|iMac|Macmini|MacPro|Mac\d|MacStudio)", "mac", "Mac"),
    (r"^iPhone", "phone", "iPhone"),
    (r"^iPad", "phone", "iPad"),
    (r"^AppleTV", "tv", "Apple TV"),
    (r"^AudioAccessory", "speaker", "HomePod"),
    (r"^Watch", "phone", "Apple Watch"),
]


def classify(d: dict) -> dict:
    votes: dict[str, float] = collections.defaultdict(float)
    evidence: list[str] = []
    model = None
    os_guess = None

    def vote(cat, w, why):
        votes[cat] += w
        if why and why not in evidence:
            evidence.append(why)

    if d.get("is_self"):
        vote("computer", 2, "This computer (running the scanner)")
    if d.get("is_gateway"):
        vote("router", 10, "Default gateway for this network")

    vendor = d.get("vendor") or ""
    if vendor:
        for pat, cat, w in VENDOR_HINTS:
            if re.search(pat, vendor, re.I):
                vote(cat, w, f"Hardware maker: {vendor}")
                break
        if re.search(r"^apple", vendor, re.I):
            vote("phone", 0.5, f"Hardware maker: {vendor}")
            vote("mac", 0.5, None)
    if d.get("randomized") and not d.get("is_gateway"):
        vote("phone", 2, "Uses a private (randomized) MAC address — typical of phones, tablets and watches")

    # Bonjour / mDNS
    mdns = d.get("mdns") or {}
    services = " ".join(mdns.get("services", []))
    for pat, cat, w, why in MDNS_HINTS:
        if re.search(pat, services):
            vote(cat, w, why)
    mm = mdns.get("model")
    if mm:
        for pat, cat, label in APPLE_MODELS:
            if re.search(pat, mm):
                vote(cat, 6, f"Reports Apple model {mm}")
                model = f"{label} ({mm})"
                os_guess = {"mac": "macOS", "phone": "iOS / iPadOS", "tv": "tvOS", "speaker": "HomePod software"}.get(cat)
                break
        else:
            model = mm
    txt = mdns.get("txt", {})
    for k in ("ty", "usb_mdl", "product"):
        if txt.get(k) and not model:
            model = txt[k]

    # SSDP / UPnP
    ssdp = d.get("ssdp") or {}
    desc = ssdp.get("description") or {}
    dtype = (desc.get("deviceType") or "") + " " + " ".join(ssdp.get("types", []))
    server = ssdp.get("server") or ""
    if "InternetGatewayDevice" in dtype or "WANDevice" in dtype:
        vote("router", 4, "UPnP internet gateway")
    if "MediaRenderer" in dtype:
        vote("tv", 2, "UPnP media player")
    if "MediaServer" in dtype:
        vote("storage", 1, "UPnP media server")
    if re.search(r"Printer", dtype):
        vote("printer", 3, "UPnP printer")
    if re.search(r"DigitalSecurityCamera|Camera", dtype):
        vote("camera", 3, "UPnP camera")
    if re.search(r"ZonePlayer", dtype):
        vote("speaker", 4, "Sonos player (UPnP)")
    if re.search(r"dial-multiscreen|dial:1", dtype, re.I):
        vote("tv", 2, "Supports DIAL casting (smart TV / streamer)")
    if re.search(r"windows", server, re.I):
        vote("windows", 2, f"UPnP server header: {server}")
        os_guess = os_guess or "Windows"
    if desc.get("manufacturer"):
        for pat, cat, w in VENDOR_HINTS:
            if re.search(pat, desc["manufacturer"], re.I):
                vote(cat, w + 1, f"UPnP manufacturer: {desc['manufacturer']}")
                break
        if not model and desc.get("modelName"):
            maker = re.split(r"[ ,]", desc["manufacturer"].strip())[0]
            mn = desc["modelName"].strip()
            model = mn if mn.lower().startswith(maker.lower()) else f"{maker} {mn}"
    md = (desc.get("modelDescription") or "") + " " + (desc.get("modelName") or "")
    for pat, cat in [(r"camera|nvr|dvr", "camera"), (r"printer", "printer"), (r"nas|diskstation|storage", "storage"),
                     (r"\btv\b|television|roku|fire ?tv|bravia", "tv"), (r"speaker|soundbar", "speaker"),
                     (r"router|gateway|access point|mesh|extender", "network"), (r"xbox|playstation", "console")]:
        if re.search(pat, md, re.I):
            vote(cat, 3, f"UPnP model: {md.strip()}")

    # NetBIOS
    nb = d.get("netbios") or {}
    if nb.get("name"):
        vote("windows", 2, f"Answers Windows (NetBIOS) name queries as {nb['name']}")

    # Open ports
    for p in d.get("ports", []):
        if p in PORT_HINTS:
            cat, w, why = PORT_HINTS[p]
            vote(cat, w, why)

    # Hostname keywords
    host = " ".join(filter(None, [d.get("hostname"), " ".join(mdns.get("instances", [])),
                                  " ".join(mdns.get("hostnames", [])), nb.get("name")]))
    for pat, cat in [(r"iphone|ipad|android|galaxy|pixel|-phone", "phone"), (r"macbook|imac|mac-?mini|mac-?pro|mbp", "mac"),
                     (r"desktop-|laptop-|\bpc\b|win-?\w+", "windows"), (r"printer|officejet|laserjet|deskjet|envy|epson|brother", "printer"),
                     (r"cam(era)?\b|doorbell|nvr", "camera"), (r"nas|diskstation|synology|qnap", "storage"),
                     (r"roku|firetv|fire-tv|chromecast|appletv|apple-tv|\btv\b|bravia|shield", "tv"),
                     (r"echo|homepod|sonos|speaker", "speaker"), (r"xbox|playstation|ps[45]|switch", "console"),
                     (r"raspberrypi|ubuntu|debian|pi-?hole", "linux"), (r"router|gateway|\bap\b|eero|orbi|unifi", "network")]:
        if re.search(pat, host, re.I):
            vote(cat, 2, f"Device name suggests {CATEGORIES[cat].lower()}")

    # Resolve generic buckets into OS-specific ones when possible
    if votes:
        category = max(votes, key=votes.get)
        top = votes[category]
    else:
        category, top = "unknown", 0
    if category == "computer":
        for specific in ("mac", "windows", "linux"):
            if votes.get(specific, 0) >= 1:
                category = specific
                break
    if category == "mac":
        os_guess = os_guess or "macOS"
    elif category == "windows":
        os_guess = os_guess or "Windows"

    confidence = "high" if top >= 5 else "medium" if top >= 2.5 else "low" if top > 0 else "none"
    return {"category": category, "category_label": CATEGORIES[category], "confidence": confidence,
            "model": model, "os": os_guess, "evidence": evidence}

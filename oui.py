"""
oui.py — MAC vendor (OUI) lookup.

Compact built-in table of common manufacturer prefixes + MAC type detection
(universally administered vs randomized/private). No internet required.
"""

import re

OUI_DB = {
    # Single-board computers / hobbyist
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "D8:3A:DD": "Raspberry Pi Trading",
    "2C:CF:67": "Raspberry Pi Trading",

    # Apple
    "F0:18:98": "Apple", "AC:BC:32": "Apple", "A4:83:E7": "Apple",
    "D0:03:4B": "Apple", "3C:22:FB": "Apple", "14:99:E2": "Apple",
    "00:03:93": "Apple",

    # Phones / common consumer
    "38:B8:EB": "Samsung", "84:25:DB": "Samsung", "50:01:BB": "Samsung",
    "34:CE:00": "Samsung", "F4:09:D8": "Samsung",
    "20:82:C0": "Xiaomi", "64:09:80": "Xiaomi", "8C:BE:BE": "Xiaomi",
    "94:FE:22": "Google", "30:FD:38": "Google", "F4:F5:D8": "Google",
    "74:23:44": "Huawei", "18:DE:D7": "Huawei", "34:6B:D3": "Huawei",
    "00:1A:11": "Google", "BC:9C:31": "OnePlus",
    "40:B8:37": "Oppo", "24:0A:45": "Vivo",
    "F4:F5:E8": "Google Nest",

    # PCs / NICs
    "00:1A:2B": "Ayecom", "3C:D9:2B": "HP", "B4:B5:2F": "HP",
    "00:26:B9": "Dell", "F8:BC:12": "Dell", "5C:B9:01": "Dell",
    "00:22:68": "Lenovo", "8C:16:45": "Lenovo", "54:E1:AD": "Lenovo",
    "30:D1:6B": "Intel", "9C:B6:D0": "Intel", "A0:A8:CD": "Intel",
    "00:14:22": "Dell", "00:50:56": "VMware", "00:0C:29": "VMware",
    "00:1C:14": "VMware", "08:00:27": "VirtualBox (Oracle)",
    "52:54:00": "QEMU/KVM", "00:16:3E": "Xen",
    "00:1B:63": "Apple", "40:6C:8F": "Microsoft", "7C:1E:52": "Microsoft Surface",
    "00:15:5D": "Microsoft (Hyper-V)", "00:1C:42": "Parallels",
    "00:1D:D8": "Supermicro", "28:CD:C1": "Raspberry Pi Trading",

    # Networking gear
    "00:1A:2A": "TP-Link", "50:C7:BF": "TP-Link", "AC:84:C6": "TP-Link",
    "B0:4E:26": "TP-Link", "C0:25:E9": "TP-Link",
    "00:1F:33": "Netgear", "A0:40:A0": "Netgear", "9C:3D:CF": "Netgear",
    "20:E5:2A": "Netgear", "B0:39:56": "Netgear",
    "00:1D:7E": "Cisco", "00:25:45": "Cisco", "F8:66:F2": "Cisco",
    "18:E8:29": "Asus", "AC:9E:17": "Asus", "04:D9:F5": "Asus",
    "00:24:A5": "Buffalo", "00:18:4D": "Netgear",
    "A8:9C:ED": "TOTO Link", "44:FB:42": "Tenda", "50:2B:73": "D-Link",
    "00:05:CA": "Beckhoff", "28:80:23": "AVM (Fritz!Box)", "38:10:D5": "AVM (Fritz!Box)",
    "DC:39:6F": "AVM (Fritz!Box)", "C8:0E:14": "AVM (Fritz!Box)",

    # Enterprise WiFi / network gear (2nd gen)
    "24:5A:4C": "Ubiquiti", "78:8A:20": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti",
    "74:AC:B9": "MikroTik", "2C:C8:1D": "MikroTik", "48:8F:5A": "MikroTik",
    "00:0B:86": "Aruba Networks", "AC:A3:1E": "Aruba (HPE)",
    "00:19:CB": "Zyxel", "00:09:0F": "Fortinet (FortiGate)",
    "00:12:17": "Cisco-Linksys", "00:16:B6": "Cisco-Linksys", "00:18:39": "Cisco-Linksys",

    # Printers
    "00:1E:A1": "HP Printer", "00:25:19": "HP Printer", "98:4F:EE": "HP Printer",
    "00:80:77": "Brother", "30:05:5C": "Brother", "AC:18:26": "Brother",
    "00:00:48": "Seiko Epson", "A0:4B:C0": "Epson", "DC:85:DE": "Epson",
    "00:1B:A9": "Brother", "08:00:06": "Siemens",

    # NAS / IoT / misc
    "00:11:32": "Synology", "90:09:D0": "Synology", "00:1C:C0": "Intel",
    "5C:CF:7F": "Espressif (ESP8266/ESP32)", "24:0A:C4": "Espressif",
    "30:AE:A4": "Espressif", "84:0D:8E": "Espressif", "BC:DD:C2": "Espressif",
    "00:1A:22": "Axcomm", "D0:73:D5": "Amazon (Echo/Alexa)",
    "44:65:0D": "Amazon", "F0:F0:A4": "Amazon", "AC:63:BE": "Amazon",
    "6C:56:97": "Amazon Echo", "B4:7C:9C": "Aqara", "54:EF:44": "Espressif",
    "00:17:88": "Philips Hue", "EC:1B:BD": "Philips Hue", "00:17:18": "Standard Solar",
    "48:A4:72": "Sonoff", "D8:F1:5B": "Sonoff", "68:57:2D": "Samsung SmartThings",

    # Cameras / consoles / misc (2nd gen)
    "C0:56:E3": "Hikvision (IP camera)", "E0:50:8B": "Dahua (IP camera)",
    "00:04:4B": "Sony", "40:B0:FA": "Sony PlayStation",
    "00:00:85": "Canon",
}

RANDOMIZED_PREFIXES = {
    "DA:A1:19", "F6:F5:A4", "3E:2C:67", "B2:FB:98", "96:AB:63",
}


def normalize_mac(mac: str) -> str:
    """Normalize MAC to AA:BB:CC:DD:EE:FF (uppercase, colons)."""
    if not mac or mac == "—":
        return ""
    hexpart = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexpart) != 12:
        return mac.upper()
    return ":".join(hexpart[i:i + 2] for i in range(0, 12, 2)).upper()


def lookup_vendor(mac: str) -> str:
    """Return vendor name for a MAC, or a useful fallback description."""
    norm = normalize_mac(mac)
    if not norm or norm == "—":
        return ""
    oui = norm[:8]
    if oui in RANDOMIZED_PREFIXES:
        return "Randomized MAC (privacy feature)"
    if norm[1] in "26AE":  # locally administered bit set in 2nd nibble patterns
        return "Randomized/local MAC"
    return OUI_DB.get(oui, "")


def mac_type(mac: str) -> str:
    """universally administered vs locally/randomized."""
    norm = normalize_mac(mac)
    if not norm or norm == "—":
        return "unknown"
    second_nibble = norm[1]
    if second_nibble in "26AE":
        return "randomized (locally administered)"
    return "permanent (universally administered)"

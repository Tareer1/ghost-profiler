"""Tests for oui.py — vendor lookup + MAC normalization/randomization."""

import pytest

from oui import OUI_DB, lookup_vendor, mac_type, normalize_mac


# ---- normalize_mac -----------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("28-80-23-aa-bb-cc", "28:80:23:AA:BB:CC"),
    ("2880.23AA.BBCC", "28:80:23:AA:BB:CC"),
    ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"),
    ("", ""),
    ("not-a-mac", "NOT-A-MAC"),      # unparseable → uppercased passthrough
    (None, ""),
    ("—", ""),
])
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


# ---- vendor lookup --------------------------------------------------------------

def test_known_vendors():
    assert lookup_vendor("28:80:23:00:00:01") == "AVM (Fritz!Box)"
    assert lookup_vendor("B8:27:EB:00:00:01") == "Raspberry Pi Foundation"
    assert lookup_vendor("00:17:88:00:00:01") == "Philips Hue"


def test_unknown_vendor_returns_empty():
    assert lookup_vendor("00:11:22:33:44:55") == ""


def test_oui_db_entries_are_wellformed():
    for prefix, name in OUI_DB.items():
        assert len(prefix) == 8 and prefix.count(":") == 2
        assert prefix == prefix.upper()
        assert name and isinstance(name, str)


# ---- randomized / locally administered ---------------------------------------------

def test_listed_randomized_prefix():
    assert lookup_vendor("DA:A1:19:11:22:33") == "Randomized MAC (privacy feature)"


def test_locally_administered_bit_detection():
    # 2nd nibble in {2,6,A,E} ⇒ locally administered, even if OUI is unknown
    assert lookup_vendor("X2:11:22:33:44:55".replace("X", "0")) == "Randomized/local MAC"


def test_mac_type():
    assert mac_type("DA:A1:19:11:22:33").startswith("randomized")
    assert mac_type("28:80:23:AA:BB:CC").startswith("permanent")
    assert mac_type(None) == "unknown"
    assert mac_type("—") == "unknown"

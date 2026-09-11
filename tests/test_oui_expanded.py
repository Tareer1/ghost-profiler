"""Tests for expanded OUI coverage — new vendor prefixes (2nd gen)."""

from oui import OUI_DB, lookup_vendor, mac_type


def test_enterprise_wifi_vendors():
    assert lookup_vendor("24:5A:4C:00:00:01") == "Ubiquiti"
    assert lookup_vendor("74:AC:B9:00:00:01") == "MikroTik"
    assert lookup_vendor("00:0B:86:00:00:01") == "Aruba Networks"
    assert lookup_vendor("00:09:0F:00:00:01") == "Fortinet (FortiGate)"
    assert lookup_vendor("00:19:CB:00:00:01") == "Zyxel"


def test_vm_and_hypervisor_vendors():
    assert lookup_vendor("00:15:5D:00:00:01") == "Microsoft (Hyper-V)"
    assert lookup_vendor("00:1C:42:00:00:01") == "Parallels"
    assert lookup_vendor("00:1D:D8:00:00:01") == "Supermicro"


def test_camera_and_console_vendors():
    assert lookup_vendor("C0:56:E3:00:00:01") == "Hikvision (IP camera)"
    assert lookup_vendor("E0:50:8B:00:00:01") == "Dahua (IP camera)"
    assert lookup_vendor("40:B0:FA:00:00:01") == "Sony PlayStation"
    assert lookup_vendor("00:04:4B:00:00:01") == "Sony"


def test_new_entries_are_wellformed():
    """All new OUIs must follow the same format contract as the originals."""
    for prefix, name in OUI_DB.items():
        assert len(prefix) == 8 and prefix.count(":") == 2
        assert prefix == prefix.upper()
        assert name and isinstance(name, str)
        assert name.strip() == name


def test_new_entries_keep_mac_type_semantics():
    assert mac_type("24:5A:4C:11:22:33").startswith("permanent")
    assert mac_type("C0:56:E3:11:22:33").startswith("permanent")


def test_no_duplicate_prefixes():
    prefixes = [p for p in OUI_DB.keys()]
    assert len(prefixes) == len(set(prefixes))

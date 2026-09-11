"""Tests for profiler.py — profiling, risk scoring, codenames, grading."""

import pytest

from profiler import (codename, enrich_vendor, guess_os,
                      guess_device_type, posture_grade, risk_assessment)


# ---- build_profile ---------------------------------------------------------

def test_gateway_profile_fields(gateway_profile):
    p = gateway_profile
    assert p["codename"] == "GATEKEEPER-1"
    assert p["ip"] == "192.168.100.1"
    assert p["device_type"] == "Router/Gateway"
    assert "Linux" in p["os"]            # nginx banner fingerprint
    assert 23 in p["open_ports"] and 80 in p["open_ports"]
    assert p["vendor"] == "AVM (Fritz!Box)"
    assert p["mac_type"].startswith("permanent")


def test_hardened_host_is_low(hardened_profile):
    assert hardened_profile["risk_score"] == 0
    assert hardened_profile["risk_level"] == "LOW"
    assert hardened_profile["services"] == ["none detected"]


# ---- risk scoring ----------------------------------------------------------

def test_telnet_is_medium_or_worse():
    score, level, notes = risk_assessment([23])
    assert score >= 25 and level in ("MEDIUM", "HIGH")
    assert any("Telnet" in n for n in notes)


def test_risk_scores_ordered():
    low = risk_assessment([])[0]
    telnet = risk_assessment([23])[0]
    telnet_smb = risk_assessment([23, 445])[0]
    assert low < telnet < telnet_smb


def test_risk_capped_at_100():
    awful = [21, 23, 25, 80, 110, 139, 161, 445, 3306, 3389, 5900, 6379, 9100]
    score, level, _ = risk_assessment(awful)
    assert score == 100 and level == "CRITICAL"


def test_risk_level_thresholds():
    assert risk_assessment([])[1] == "LOW"
    assert risk_assessment([23])[1] == "MEDIUM"          # 25
    assert risk_assessment([23, 5900])[1] == "HIGH"      # 45


# ---- OS / device-type guessing ----------------------------------------------

def test_guess_os_from_ttl():
    assert guess_os(128, [], "")[0] == "Windows"
    assert guess_os(64, [], "")[0] == "Linux/Unix-like"
    assert guess_os(255, [], "")[0] == "Network appliance"
    assert guess_os(None, [], "")[0] == "Unknown"


def test_guess_os_from_banner():
    assert guess_os(None, [], "OpenSSH_9.6p1 Debian")[0] == "Linux"
    assert guess_os(None, [], "Microsoft-IIS/10.0")[0] == "Windows"


def test_guess_device_type_by_hostname():
    assert guess_device_type([], "hp-laserjet-office") == "Printer"
    assert guess_device_type([], "openwrt-gw") == "Router/Gateway"
    assert guess_device_type([], "truenas-box") == "NAS / Storage"


def test_guess_device_type_by_ports():
    assert guess_device_type([9100], "") == "Printer"
    assert guess_device_type([3389, 445], "") == "Windows workstation/server"
    assert guess_device_type([6379], "") == "Database server"
    assert guess_device_type([], "") == "Unknown device"


# ---- codenames ---------------------------------------------------------------

@pytest.mark.parametrize("ip,dtype,expected", [
    ("10.0.0.77", "Printer", "PAPERJAM-77"),
    ("10.0.0.5", "Router/Gateway", "GATEKEEPER-5"),
    ("10.0.0.9", "Something new", "UNKNOWN-9"),
])
def test_codename(ip, dtype, expected):
    assert codename(ip, dtype, 0) == expected


# ---- posture grade -------------------------------------------------------------

def test_posture_grade_empty():
    assert posture_grade([]) == ("N/A", "No devices profiled")


def test_posture_grade_hardened_network(hardened_profile):
    grade, _ = posture_grade([hardened_profile])
    assert grade == "A"


def test_posture_grade_critical_network():
    bad = [{"risk_score": 100, "risk_level": "CRITICAL"}]
    grade, note = posture_grade(bad)
    assert grade == "F" and "CRITICAL" in note


# ---- MEDIUM weighting & grade floor (one router must not earn an 'A') --------

def _dev(score, level):
    return {"risk_score": score, "risk_level": level}


def test_single_medium_stops_a_grade():
    """1 MEDIUM router + 9 clean hosts: old logic gave A, floor gives B."""
    net = [_dev(33, "MEDIUM")] + [_dev(0, "LOW")] * 9
    grade, note = posture_grade(net)
    assert grade == "B"
    assert "attention" in note


def test_medium_devices_add_weight():
    """avg 8.3 + 1 medium*2 = 10.3 → B; without the +2 it would be A."""
    net = [_dev(25, "MEDIUM")] + [_dev(0, "LOW")] * 4
    assert posture_grade(net)[0] == "B"


def test_many_mediums_reach_c():
    """5 MEDIUM devices: avg 25 + 10 = 35 → C (was B before weighting)."""
    net = [_dev(25, "MEDIUM")] * 5
    assert posture_grade(net)[0] == "C"


def test_all_clean_keeps_a():
    net = [_dev(0, "LOW")] * 5
    assert posture_grade(net)[0] == "A"


def test_critical_still_f_overrides_floor():
    """avg 50 + 2 critical*15 = 80 → F (floor only ever limits A, never F)."""
    net = [_dev(100, "CRITICAL")] * 2 + [_dev(0, "LOW")] * 2
    assert posture_grade(net)[0] == "F"


# ---- expanded coverage: new risky ports, device types, codenames ----------

def test_docker_api_is_critical():
    """Exposed Docker API (2375) is remote-root: must score above Telnet."""
    docker = risk_assessment([2375])
    telnet = risk_assessment([23])
    assert docker[0] >= 30 and docker[0] > telnet[0]
    assert docker[1] in ("HIGH", "CRITICAL")
    assert any("Docker" in n for n in docker[2])


def test_kubelet_and_etcd_flagged():
    score, level, notes = risk_assessment([10250, 2379])
    assert score >= 40 and level in ("HIGH", "CRITICAL")
    assert any("kubelet" in n for n in notes)
    assert any("etcd" in n for n in notes)


def test_iot_broker_ports_flagged():
    for port in (1883, 9200, 11211, 5555, 2049, 2181, 5984):
        score, _, notes = risk_assessment([port])
        assert score > 0, f"port {port} should be flagged"
        assert notes, f"port {port} should carry a note"


def test_infra_ports_not_flagged():
    """DHCP-ish/infra services must not create noise."""
    assert risk_assessment([67, 68, 123])[0] == 0


def test_container_host_detection():
    assert guess_device_type([22, 2375, 2379], "") == "Container host"
    assert guess_device_type([10250], "") == "Container host"
    assert guess_device_type([22, 80], "") != "Container host"


def test_container_host_codename():
    assert codename("10.0.0.4", "Container host", 0) == "DOCKERFIEND-4"


def test_expanded_services_have_names():
    """Scannable ports need names; every risky port needs a name too."""
    from scanner import DEFAULT_PORT_LIST
    from profiler import SERVICE_NAMES, RISKY_PORTS
    for port in DEFAULT_PORT_LIST:
        assert port in SERVICE_NAMES, f"{port} missing from SERVICE_NAMES"
    for port in RISKY_PORTS:
        assert port in SERVICE_NAMES, f"risky port {port} missing from SERVICE_NAMES"


def test_expanded_coverage_growth():
    """Detection DB must cover the new container/IoT/infra services."""
    from profiler import RISKY_PORTS
    for port in (2375, 10250, 9200, 11211, 1883, 2049, 2181, 5984, 5555, 873, 389):
        assert port in RISKY_PORTS, f"{port} missing from RISKY_PORTS"


def test_port_scan_still_speed_bounded():
    """Expanded list must stay >= 50 ports so full-scan cost is predictable."""
    from scanner import DEFAULT_PORT_LIST
    assert 50 <= len(DEFAULT_PORT_LIST) <= 60


# ---- vendor enrichment -----------------------------------------------------------

def test_enrich_vendor_randomized():
    host = enrich_vendor({"ip": "1.2.3.4", "mac": "DA:A1:19:11:22:33"})
    assert host["vendor"].startswith("Randomized")
    assert "randomized" in host["mac_type"]


def test_enrich_vendor_missing_mac():
    host = enrich_vendor({"ip": "1.2.3.4", "mac": None})
    assert host["vendor"] is None and host["mac_type"] is None

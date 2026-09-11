"""Tests for scanner.py probe_host — safe: loopback + TEST-NET only."""

from scanner import probe_host


def test_probe_host_loopback_up():
    """127.0.0.1 must be alive with TTL + localhost reverse DNS."""
    host = probe_host("127.0.0.1")
    assert host is not None
    assert host["ip"] == "127.0.0.1"
    assert isinstance(host["ttl"], int) and host["ttl"] > 0
    assert host["hostname"] == "localhost"
    # loopback never appears in ARP — must be None, not an exception
    assert host["mac"] is None


def test_probe_host_returns_all_keys():
    host = probe_host("127.0.0.1")
    assert set(host.keys()) == {"ip", "ttl", "hostname", "mac"}


def test_probe_host_unreachable_returns_none():
    """TEST-NET-1 (RFC 5737) never answers; no ARP entry possible on any real LAN."""
    assert probe_host("192.0.2.123") is None

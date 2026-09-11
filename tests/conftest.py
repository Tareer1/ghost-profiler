"""Shared fixtures for the Ghost Profiler test suite."""

import sys
from pathlib import Path

# Make project-root imports work no matter where pytest is invoked from.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from profiler import build_profile, enrich_vendor


@pytest.fixture
def gateway_host():
    """A fake router/gateway host with a real AVM OUI."""
    return enrich_vendor({
        "ip": "192.168.100.1",
        "ttl": 64,
        "hostname": "fritz.box",
        "mac": "28:80:23:AA:BB:CC",
    })


@pytest.fixture
def gateway_profile(gateway_host):
    """Router profile with Telnet + HTTP + DNS open → MEDIUM risk."""
    return build_profile(gateway_host, [
        {"port": 53, "banner": ""},
        {"port": 80, "banner": "Server: nginx | Title: Router Admin"},
        {"port": 23, "banner": "BusyBox telnetd"},
    ], index=0)


@pytest.fixture
def hardened_profile():
    """Linux box with zero open ports → LOW 0."""
    return build_profile({
        "ip": "192.168.100.7",
        "ttl": 64,
        "hostname": "pi.local",
        "mac": "B8:27:EB:AA:BB:CC",
    }, [], index=1)


@pytest.fixture
def mixed_profiles(gateway_profile, hardened_profile):
    """A small network: one medium-risk router + one hardened host."""
    return [gateway_profile, hardened_profile]

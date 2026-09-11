"""Tests for report.py — single-file HTML dashboard generation."""

from report import generate_html


def _html(mixed_profiles, summary="PRIORITY: fix the router."):
    return generate_html(mixed_profiles, "192.168.100.0/24", "test-model",
                         "C", "Fair — several risks need attention", summary)


def test_html_contains_grade_and_devices(mixed_profiles):
    html = _html(mixed_profiles)
    assert "<h1>👻 GHOST PROFILER</h1>" in html
    assert ">C<" in html                       # grade badge
    assert "GATEKEEPER-1" in html and "UNKNOWN-7" in html


def test_html_escapes_malicious_scan_data(mixed_profiles):
    """Banner text must never break out of the HTML (XSS via scan data)."""
    p = dict(mixed_profiles[0])
    p["codename"] = "<script>alert(1)</script>"
    p["services"] = ["<img src=x onerror=alert(2)>"]
    html = generate_html([p], "t", "m", "B", "n", None)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_stat_counters(mixed_profiles):
    html = _html(mixed_profiles)
    # 3 open ports total (53 + 80 + 23 + 0 on the hardened host)
    assert "<b>2</b>devices" in html
    assert "<b>3</b>open ports" in html
    assert "<b>0</b>high/critical" in html


def test_html_without_summary():
    html = generate_html([], "10.0.0.0/24", "offline", "A", "Hardened network", None)
    assert "EXECUTIVE SUMMARY" not in html
    assert ">A<" in html


def test_html_ai_block_present(mixed_profiles):
    p = dict(mixed_profiles[0])
    p["ai_analysis"] = "RISK: telnet. FIX: use SSH."
    p["ai_source"] = "test (in-process)"
    html = generate_html([p], "t", "m", "B", "n", None)
    assert "GHOST-1:" in html and "use SSH" in html

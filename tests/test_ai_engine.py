"""Tests for ai_engine.py offline analyst + llama_engine.py postprocessing."""

import llama_engine
from ai_engine import executive_summary, offline_analyst, profile_to_context
from llama_engine import (clean_response, detect_gpu_offload, parse_gpu_layers,
                          postprocess, strip_to_verdict)


# ---- offline analyst (the fallback that must never break) ------------------------

def test_offline_analyst_clean_host(hardened_profile):
    out = offline_analyst(hardened_profile)
    assert "minimal exposure" in out and "FIX:" in out


def test_offline_analyst_risky_host(gateway_profile):
    out = offline_analyst(gateway_profile)
    assert "RISK:" in out and "FIX:" in out
    assert "Telnet" in out                      # top risk surfaced


def test_offline_analyst_container_risks(hardened_profile):
    """Docker/k8s exposure must get a concrete container-aware FIX line."""
    p = dict(hardened_profile)
    p["codename"] = "DOCKERFIEND-4"
    p["risk_level"] = "CRITICAL"
    p["risk_score"] = 55
    p["risk_notes"] = ["Docker API (2375): remote root-equivalent REST, NO TLS by default",
                       "kubelet (10250): container exec API; anonymous access known CVEs"]
    out = offline_analyst(p)
    assert "Docker API" in out and "TLS" in out
    assert "kubelet" in out and "anonymous" in out


def test_offline_analyst_iot_broker_fix(hardened_profile):
    p = dict(hardened_profile)
    p["risk_level"] = "MEDIUM"
    p["risk_score"] = 20
    p["risk_notes"] = ["MQTT (1883): plaintext IoT messaging, weak auth"]
    out = offline_analyst(p)
    assert "MQTT" in out and "TLS" in out


def test_profile_to_context_has_core_fields(gateway_profile):
    ctx = profile_to_context(gateway_profile)
    for token in ("GATEKEEPER-1", "192.168.100.1", "Router/Gateway", "Open ports:"):
        assert token in ctx


# ---- executive summary fallback ----------------------------------------------------

def test_offline_summary_names_priority(mixed_profiles):
    out = executive_summary(None, mixed_profiles)
    assert out["source"] == "offline analyst"
    assert "PRIORITY:" in out["text"]
    assert "GATEKEEPER-1" in out["text"]        # worst device must be named


def test_offline_summary_empty_network():
    out = executive_summary(None, [])
    assert "0 device(s)" in out["text"]


# ---- LLM output postprocessing --------------------------------------------------

def test_clean_response_strips_preamble():
    assert clean_response("Sure! Here is the assessment:\nVERDICT: ok") == "VERDICT: ok"


def test_clean_response_strips_role_prefix():
    assert clean_response("GHOST-1: RISK: nothing") == "RISK: nothing"


def test_strip_to_verdict_keeps_meaningful_tail():
    txt = "Blah blah intro\nRISK: telnet exposed\nFIX: disable it"
    assert strip_to_verdict(txt).startswith("RISK:")


def test_postprocess_summary_mode():
    assert postprocess("Certainly. PRIORITY: router", "summary") == "PRIORITY: router"


def test_postprocess_never_returns_empty():
    assert postprocess("", "device") != ""


# ---- GHOST_N_GPU_LAYERS parsing & GPU detection ---------------------------------

def test_parse_gpu_layers_default_off():
    assert parse_gpu_layers("") == (0, "off")
    assert parse_gpu_layers("0") == (0, "off")
    assert parse_gpu_layers(None) == (0, "off")


def test_parse_gpu_layers_fixed():
    assert parse_gpu_layers("16") == (16, "fixed")
    assert parse_gpu_layers(" 8 ") == (8, "fixed")


def test_parse_gpu_layers_auto():
    assert parse_gpu_layers("auto") == ("auto", "auto")
    assert parse_gpu_layers("ON") == ("auto", "auto")


def test_parse_gpu_layers_invalid_falls_back_to_off():
    assert parse_gpu_layers("sixteen") == (0, "off")
    assert parse_gpu_layers("-3") == (0, "off")


def test_detect_gpu_offload_off_by_default(monkeypatch):
    monkeypatch.setattr(llama_engine, "N_GPU_LAYERS_RAW", "")
    assert "off" in detect_gpu_offload()


def test_detect_gpu_offload_warns_when_no_cuda(monkeypatch):
    """Requesting layers on a machine without CUDA must not claim success."""
    monkeypatch.setattr(llama_engine, "N_GPU_LAYERS_RAW", "16")
    monkeypatch.setattr(llama_engine, "_has_cuda_device", lambda: False)
    out = detect_gpu_offload()
    assert "requested 16" in out and "CPU" in out


def test_detect_gpu_offload_enabled(monkeypatch):
    monkeypatch.setattr(llama_engine, "N_GPU_LAYERS_RAW", "auto")
    monkeypatch.setattr(llama_engine, "_has_cuda_device", lambda: True)
    assert "enabled" in detect_gpu_offload()


def test_engine_load_cpu_fallback_on_gpu_failure(monkeypatch, tmp_path):
    """If Llama() rejects n_gpu_layers, load() must retry with 0, not crash."""
    import pytest
    from llama_engine import GhostEngine

    eng = GhostEngine.__new__(GhostEngine)          # skip __init__ discovery
    eng.available = True
    eng._llm = None
    eng._loaded_path = None
    eng._lock = __import__("threading").Lock()
    eng._resolved = "fake.gguf"
    eng.auto_note = None

    calls = []

    class FakeLlama:
        def __init__(self, **kw):
            calls.append(kw.get("n_gpu_layers"))
            if kw.get("n_gpu_layers", 0) > 0:
                raise RuntimeError("no CUDA")

    fake_mod = type("M", (), {"Llama": FakeLlama})
    monkeypatch.setitem(__import__("sys").modules, "llama_cpp", fake_mod)
    monkeypatch.setattr(llama_engine, "parse_gpu_layers", lambda raw=None: (16, "fixed"))

    assert eng.load() is True
    assert calls == [16, 0]                          # tried GPU, then fell back
    assert eng.is_loaded and "CPU" in eng.auto_note

"""
ai_engine.py — GHOST-1 analysis layer for the Ghost Profiler.

Sends TECHNICAL scan findings (ports, banners, OS guesses) to the GhostCore
in-process engine (llama_engine.py — Dolphin GGUF loaded directly into this
process; no Ollama, no server, nothing leaves the machine).

If GhostCore can't load (missing llama-cpp-python or GGUF), a built-in
rule-based analyst produces the same structure so the profiler never breaks.
"""

from llama_engine import SYSTEM_PROMPT, EXEC_SUMMARY_PROMPT, postprocess


def profile_to_context(profile: dict) -> str:
    """Serialize a device profile into compact text for the LLM."""
    lines = [
        f"DEVICE {profile['codename']}",
        f"IP: {profile['ip']}",
        f"Hostname: {profile['hostname']}",
        f"MAC: {profile['mac']}",
        f"OS guess: {profile['os']}",
        f"Type: {profile['device_type']}",
        f"Open ports: {', '.join(map(str, profile['open_ports'])) or 'none'}",
        f"Services: {'; '.join(profile['services'])}",
        f"Rule-based risk: {profile['risk_level']} ({profile['risk_score']}/100)",
    ]
    if profile["risk_notes"]:
        lines.append("Rule findings: " + " | ".join(profile["risk_notes"]))
    return "\n".join(lines)


def offline_analyst(profile: dict) -> str:
    """Rule-based fallback analysis when no LLM is available."""
    name = profile["codename"]
    level = profile["risk_level"]
    risks = profile["risk_notes"]
    if not risks:
        return (f"DEVICE {name}: minimal exposure. No legacy or high-risk "
                f"services detected. RISK: none significant. "
                f"FIX: keep firmware/patches current.")
    risk_lines = [f"RISK: {r}" for r in risks[:3]]
    fix = {
        "Telnet": "FIX: disable Telnet, use SSH.",
        "VNC": "FIX: tunnel VNC over SSH or replace with RDP+VPN.",
        "Redis": "FIX: bind Redis to 127.0.0.1 and set requirepass.",
        "SMB": "FIX: patch SMB, disable SMBv1, restrict shares.",
        "RDP": "FIX: put RDP behind VPN, enable NLA.",
        "FTP": "FIX: replace FTP with SFTP.",
        "TFTP": "FIX: disable TFTP unless needed; restrict source IPs.",
        "JetDirect": "FIX: restrict printer access by IP allowlist.",
        "Docker API": "FIX: bind Docker API to unix socket or require TLS NOW (remote root).",
        "kubelet": "FIX: disable anonymous kubelet auth, enable webhook authorization.",
        "ADB": "FIX: disable ADB over network immediately.",
        "etcd": "FIX: require client certs + firewall etcd to control plane nodes.",
        "Memcached": "FIX: bind to localhost, disable UDP, use SASL.",
        "Elasticsearch": "FIX: enable x-pack security, bind away from 0.0.0.0.",
        "NFS": "FIX: restrict exports by IP, enable root_squash.",
        "CouchDB": "FIX: set admin credentials (end admin party), bind to localhost.",
        "ZooKeeper": "FIX: enable SASL auth, firewall to cluster members.",
        "MQTT": "FIX: require username/password + TLS (8883), ACL topics.",
        "Rsync": "FIX: restrict modules by hosts allow, use ssh transport.",
        "LDAP": "FIX: disable anonymous binds, require TLS (LDAPS).",
        "Kibana": "FIX: put Kibana behind auth proxy, enable space isolation.",
        "InfluxDB": "FIX: enable auth, bind HTTP to localhost/VPN.",
        "Squid proxy": "FIX: require auth, restrict http_access ACLs.",
    }
    first_risky = next((r for r in risks if r.split(" ")[0] in fix), None)
    fix_line = fix[first_risky.split(" ")[0]] if first_risky else "FIX: firewall unused services to trusted hosts."
    return (f"DEVICE {name}: {level} exposure ({profile['risk_score']}/100). "
            + " ".join(risk_lines) + " " + fix_line)


def analyze_device(engine, profile: dict) -> dict:
    """Returns {text, source} where source is the model name or 'offline analyst'."""
    if engine is not None and getattr(engine, "available", False):
        try:
            text = engine.generate(
                f"Assess this scanned device:\n\n{profile_to_context(profile)}\n\n"
                f"Your assessment:",
                system=SYSTEM_PROMPT,
            )
            if text:
                return {"text": postprocess(text, "device"),
                        "source": f"{engine.model} (in-process)"}
        except Exception:
            pass
    return {"text": offline_analyst(profile), "source": "offline analyst"}


def _offline_summary(profiles: list) -> str:
    """Rule-based network-wide brief when no LLM is available."""
    n = len(profiles)
    crit = [p for p in profiles if p["risk_level"] == "CRITICAL"]
    high = [p for p in profiles if p["risk_level"] == "HIGH"]
    med = [p for p in profiles if p["risk_level"] == "MEDIUM"]
    worst = max(profiles, key=lambda p: p["risk_score"], default=None)
    lines = [f"NETWORK BRIEF: {n} device(s) profiled — "
             f"{len(crit)} critical, {len(high)} high, {len(med)} medium risk."]
    if worst and worst["risk_score"] > 0:
        lines.append(f"PRIORITY: {worst['codename']} ({worst['ip']}) — "
                     f"{worst['risk_score']}/100. {worst['risk_notes'][0] if worst['risk_notes'] else 'Review exposed services.'}")
    else:
        lines.append("No high-risk services detected across the network.")
    lines.append("STRATEGY: firewall unused services, patch exposed hosts, re-scan after changes.")
    return " ".join(lines)


def executive_summary(engine, profiles: list) -> dict:
    """One LLM call summarizing the whole network. Falls back to rules."""
    if engine is not None and getattr(engine, "available", False) and profiles:
        try:
            lines = []
            for p in profiles:
                lines.append(f"- {p['codename']} ({p['ip']}): {p['device_type']}, "
                             f"risk {p['risk_level']} {p['risk_score']}/100, "
                             f"ports: {','.join(map(str, p['open_ports'])) or 'none'}")
            text = engine.generate(
                "You scanned an authorized network. Write a network-wide executive "
                "security brief (max 120 words): overall posture in one line, "
                "top 2-3 priorities as 'PRIORITY: ...', one strategic "
                "recommendation as 'STRATEGY: ...'. Devices:\n" + "\n".join(lines),
                system=EXEC_SUMMARY_PROMPT,
            )
            if text:
                return {"text": postprocess(text, "summary"),
                        "source": f"{engine.model} (in-process)"}
        except Exception:
            pass
    return {"text": _offline_summary(profiles), "source": "offline analyst"}

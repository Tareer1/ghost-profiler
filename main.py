#!/usr/bin/env python3
"""
GHOST PROFILER — god-tier network device profiler for Kali Linux.

Scans YOUR OWN / authorized networks, profiles devices (not people), and
runs a local LLM IN-PROCESS (GhostCore: Dolphin GGUF loaded directly into
this script — no Ollama, no server, nothing leaves the machine).

Usage:
  python3 main.py                          # auto-detect network
  python3 main.py --cidr 192.168.1.0/24    # specific network
  python3 main.py --model models/x.gguf    # pick a GGUF (default: auto-find)
  python3 main.py --quick                  # fast port set
  python3 main.py --ip 192.168.1.42        # single host deep dive
  python3 main.py --yes --json r.json --html r.html   # reports + exit codes
  python3 main.py --monitor                # baseline mode + alerts
  python3 main.py --list-models            # show local GGUF models

Exit codes: 0 = scan ok, low risk | 1 = findings need attention | 2 = error/aborted

ONLY scan networks you own or are authorized to test.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import sys
import datetime
from pathlib import Path

# ---- GhostCore venv auto-bootstrap -----------------------------------------
# The LLM core (llama-cpp-python) lives in .venv. If we're not running inside
# it and it isn't importable, create/install once, then re-exec transparently.
_VENV = Path(__file__).resolve().parent / ".venv"
_VENV_PY = _VENV / "bin" / "python3"


def _has_llamacpp() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("llama_cpp") is not None
    except Exception:
        return False


def _deps_ok() -> bool:
    try:
        import importlib.util
        return all(importlib.util.find_spec(m) is not None for m in ("rich", "requests"))
    except Exception:
        return False


def _pip(venv_pip: str, *pkgs: str) -> bool:
    """Quiet pip install; prints output only on failure."""
    import subprocess
    r = subprocess.run([venv_pip, "install", "-q", *pkgs],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
    return r.returncode == 0


def _bootstrap_venv() -> None:
    """One-time setup: .venv + deps + llama-cpp-python, then re-exec."""
    import subprocess

    if not _VENV_PY.exists():
        print("[ghost-profiler] first run: creating .venv (one-time setup) ...")
        subprocess.run([sys.executable, "-m", "venv", str(_VENV)], check=True)
        _pip(str(_VENV / "bin" / "pip"), "--upgrade", "pip")
    # deps must live in .venv (system python may lack them under PEP 668)
    print("[ghost-profiler] installing dependencies into .venv (one-time) ...")
    if not _pip(str(_VENV / "bin" / "pip"), "rich>=13.0.0", "requests>=2.31.0"):
        print("[ghost-profiler] ERROR: dependency install failed.")
        sys.exit(2)
    if "--no-ai" in sys.argv:
        os.execv(str(_VENV_PY), [str(_VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]])
    print("[ghost-profiler] installing llama-cpp-python (GhostCore core, one-time, can take a few minutes) ...")
    _pip(str(_VENV / "bin" / "pip"), "--upgrade", "cmake")
    if not _pip(str(_VENV / "bin" / "pip"), "llama-cpp-python"):
        print("[ghost-profiler] WARNING: GhostCore build failed — rule-based analyst will be used.")
        print("[ghost-profiler] Continuing without the LLM (offline analyst). Re-run later to retry.")
        os.execv(str(_VENV_PY), [str(_VENV_PY), str(Path(__file__).resolve()), "--no-ai", *sys.argv[1:]])
    os.execv(str(_VENV_PY), [str(_VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]])


if (getattr(sys, "prefix", "") != str(_VENV) and os.name != "nt"
        and (not _deps_ok() or ("--no-ai" not in sys.argv and not _has_llamacpp()))):
    _bootstrap_venv()
# -----------------------------------------------------------------------------

from rich.console import Console

from scanner import (detect_local_cidr, discover_hosts, scan_ports, DEFAULT_PORT_LIST,
                     _fast_ports, _arp_table, probe_host)
from profiler import build_profile, enrich_vendor, posture_grade
from llama_engine import GhostEngine, detect_gpu_offload
from ai_engine import analyze_device, executive_summary
from report import generate_html
import ui

console = Console()
BASELINE_FILE = Path.home() / ".ghost_profiler_baseline.json"


def parse_args():
    ap = argparse.ArgumentParser(
        prog="ghost-profiler",
        description="God-tier device profiler: authorized network recon + local LLM analysis",
    )
    ap.add_argument("--cidr", help="Network to scan, e.g. 192.168.1.0/24 (default: auto-detect)")
    ap.add_argument("--ip", help="Deep-scan a single host instead of sweeping")
    ap.add_argument("--model", default=None,
                    help="GGUF model file/dir (default: auto-find in ./models/, bundled dir, $GHOST_MODEL)")
    ap.add_argument("--ollama-host", default=None, help=argparse.SUPPRESS)  # deprecated, ignored
    ap.add_argument("--quick", action="store_true", help="Scan only 8 common ports per host (faster)")
    ap.add_argument("--no-ai", action="store_true", help="Skip LLM analysis")
    ap.add_argument("--yes", "-y", action="store_true", help="Skip authorization prompt (for scripts)")
    ap.add_argument("--list-models", action="store_true", help="List local GGUF models and exit")
    ap.add_argument("--json", metavar="FILE", help="Save full report to JSON")
    ap.add_argument("--html", metavar="FILE", help="Save HTML dashboard report")
    ap.add_argument("--monitor", action="store_true",
                    help="Baseline mode: save state, alert on new devices/ports")
    return ap.parse_args()


def scan_and_profile(args, cidr, hosts=None):
    """Discover hosts (live progress), enrich via ARP, port-scan, profile."""
    if hosts is None:
        try:
            total = len(list(ipaddress.ip_network(cidr, strict=False).hosts()))
        except ValueError:
            total = 254
        progress, task_id = ui.scan_progress(cidr, total)
        with progress:
            def cb(done, total_, found):
                progress.update(task_id, completed=done)
            hosts = discover_hosts(cidr, progress_cb=cb)
    if not hosts:
        console.print("[bold red]No live hosts found.[/]")
        return []

    # First pass: ARP now (discovery pings just populated it)
    arp = _arp_table()
    for host in hosts:
        if not host.get("mac"):
            host["mac"] = arp.get(host["ip"])
        enrich_vendor(host)

    ports = _fast_ports if args.quick else DEFAULT_PORT_LIST
    ui.feed(f"{len(hosts)} live host(s) found. Port scanning ({len(ports)} ports, parallel) ...",
            "bright_green")

    def _profile_work(pair):
        i, host = pair
        return i, host, scan_ports(host["ip"], ports=ports)

    # Per-host parallel profiling: each host's port scan runs concurrently;
    # results are yielded in index order so the feed stays deterministic.
    profiles = [None] * len(hosts)
    max_workers = min(16, max(4, len(hosts)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for i, host, open_ports in ex.map(_profile_work, enumerate(hosts)):
            profile = build_profile(host, open_ports, index=i)
            profiles[i] = profile
            vendor = profile["vendor"] if profile["vendor"] != "—" else ""
            ui.feed(f"profiled {profile['codename']}  {profile['ip']}  {vendor}  "
                    f"[{profile['risk_level']} {profile['risk_score']}]", "bright_white")

    # Second pass: port scans just populated ARP again — refresh MACs
    arp2 = _arp_table()
    changed = False
    for host in hosts:
        if not host.get("mac") and arp2.get(host["ip"]):
            host["mac"] = arp2[host["ip"]]
            enrich_vendor(host)
            changed = True
    if changed:
        for p, host in zip(profiles, hosts):
            p["mac"] = host.get("mac") or "—"
            p["vendor"] = host.get("vendor") or "—"
            p["mac_type"] = host.get("mac_type") or "unknown"
    return profiles


def ai_pass(args, engine, profiles):
    """Per-device LLM analysis, attached to profiles."""
    if args.no_ai or not profiles:
        return
    console.print()
    console.rule("[bold bright_magenta]GHOST-1 AI ANALYSIS", style="bright_magenta")
    if engine is not None and getattr(engine, "available", False) and not engine.is_loaded:
        ui.feed("Loading model into RAM (first inference) ...", "bright_cyan")
    for p in profiles:
        analysis = analyze_device(engine, p)
        p["ai_analysis"] = analysis["text"]
        p["ai_source"] = analysis["source"]
        ui.print_ai_analysis(analysis)


def load_baseline():
    if BASELINE_FILE.exists():
        try:
            return json.loads(BASELINE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"devices": {}}


def save_baseline(profiles):
    devices = {}
    for p in profiles:
        devices[p["ip"]] = {"codename": p["codename"], "mac": p["mac"], "ports": p["open_ports"]}
    BASELINE_FILE.write_text(json.dumps(
        {"saved": datetime.datetime.now().isoformat(), "devices": devices}, indent=2))


def monitor_diff(profiles):
    """Compare current scan vs saved baseline."""
    base = load_baseline()
    known = base.get("devices", {})
    new_devices, changes = [], []
    current_ips = {p["ip"] for p in profiles}

    for p in profiles:
        prev = known.get(p["ip"])
        if prev is None:
            new_devices.append(p)
            continue
        old_ports = set(prev.get("ports", []))
        new_ports = sorted(set(p["open_ports"]) - old_ports)
        closed = sorted(old_ports - set(p["open_ports"]))
        if new_ports:
            changes.append((p, "PORTS OPENED", new_ports))
        if closed:
            changes.append((p, "PORTS CLOSED", closed))
        if prev.get("mac") != p["mac"] and p["mac"] != "—":
            changes.append((p, "MAC CHANGED", f"{prev.get('mac')} → {p['mac']}"))
    for ip, prev in known.items():
        if ip not in current_ips:
            changes.append(({"ip": ip, "codename": prev.get("codename", "?")}, "DEVICE OFFLINE", None))
    return new_devices, changes, base


def write_reports(args, engine, cidr, profiles):
    """JSON + HTML report output. Returns True if anything was written."""
    wrote = False
    if args.json:
        report = {
            "tool": "ghost-profiler",
            "generated": datetime.datetime.now().isoformat(),
            "target": cidr,
            "model": engine.model if engine else "offline",
            "profiles": profiles,
        }
        Path(args.json).write_text(json.dumps(report, indent=2))
        ui.feed(f"Report saved → {args.json}", "bright_green")
        wrote = True
    if args.html:
        grade, note = posture_grade(profiles)
        html = generate_html(profiles, cidr, engine.model if engine else "offline",
                             grade, note, next((p.get("ai_analysis") for p in profiles
                                                if p.get("ai_analysis")), None))
        Path(args.html).write_text(html)
        ui.feed(f"HTML dashboard → {args.html}", "bright_green")
        wrote = True
    return wrote


def main():
    args = parse_args()
    exit_code = 0

    # ---- AI engine (GhostCore — in-process GGUF) -----------------------
    engine = None
    if not args.no_ai:
        engine = GhostEngine(model=args.model)
        if args.list_models:
            models = engine.list_models()
            if models:
                console.print("[bright_cyan]GhostCore — local GGUF models:[/]")
                for m in models:
                    console.print(f"  • {m}")
                console.print("[dim]Pick with --model /path/to/model.gguf (or $GHOST_MODEL).[/]")
            else:
                console.print("[yellow]No .gguf models found.[/]")
                console.print("[dim]Put a GGUF in ./models/ or pass --model /path/to/model.gguf[/]")
            return 0
        if engine.available:
            ui.feed(f"GhostCore armed — {engine.auto_note}", "bright_green")
            gpu_note = detect_gpu_offload()
            ui.feed(gpu_note,
                    "bright_green" if "enabled" in gpu_note else
                    ("yellow" if "requested" in gpu_note else "dim"))
            ui.feed("Model loads into RAM on first analysis; everything stays in-process.", "dim")
        else:
            ui.feed(f"GhostCore unavailable — {engine.auto_note}", "yellow")
    elif args.list_models:
        console.print("[yellow]--no-ai given; nothing to list.[/]")
        return 2

    # ---- Target + consent ---------------------------------------------
    try:
        cidr = args.cidr or detect_local_cidr()
    except Exception as e:
        console.print(f"[bold red]Cannot detect network: {e}[/]")
        return 2

    ui.banner(model=(args.model or (engine.model if engine else "none")),
              engine_available=bool(engine and engine.available), cidr=cidr)

    if not args.yes and not ui.consent_gate(cidr):
        console.print("[bold red]Scan aborted — no authorization confirmation provided.[/]")
        return 2

    # ---- Scan / monitor -------------------------------------------------
    profiles = []
    try:
        if args.monitor:
            ui.feed("MONITOR MODE — baseline & diff", "bright_cyan")
            profiles = scan_and_profile(args, cidr)
            if not profiles:
                return 2
            new_devices, changes, base = monitor_diff(profiles)
            console.print()
            if base.get("devices"):
                console.rule("[bold bright_yellow]MONITOR DIFF", style="bright_yellow")
                for p in new_devices:
                    ui.feed(f"NEW DEVICE: {p['codename']} {p['ip']} "
                            f"(ports: {', '.join(map(str, p['open_ports'])) or 'none'})", "bold bright_red")
                for p, kind, detail in changes:
                    ui.feed(f"{kind}: {p['codename']} {p['ip']} {detail or ''}", "bright_yellow")
                if not new_devices and not changes:
                    ui.feed("No changes since last baseline — network stable.", "bright_green")
            else:
                ui.feed("Baseline created. Run --monitor again later to see diffs.", "bright_green")
            save_baseline(profiles)
        elif args.ip:
            ui.feed(f"Single-host mode: {args.ip} — probing ...", "bright_cyan")
            host = probe_host(args.ip)
            if host is None:
                console.print(f"[bold red]{args.ip} unreachable — no ping/TCP response (and no ARP entry).[/]")
                return 2
            host.setdefault("mac", None)
            resolved = []
            if host.get("hostname"):
                resolved.append(f"host: {host['hostname']}")
            if host.get("ttl") is not None:
                resolved.append(f"ttl: {host['ttl']}")
            if host.get("mac"):
                resolved.append(f"mac: {host['mac']}")
            ui.feed("target is UP" + (" (" + ", ".join(resolved) + ")" if resolved else ""),
                    "bright_green")
            profiles = scan_and_profile(args, cidr, hosts=[host])
        else:
            profiles = scan_and_profile(args, cidr)

        if not profiles:
            return 2

        # ---- AI + results -------------------------------------------
        ai_pass(args, engine, profiles)
        console.print()
        grade, grade_note = posture_grade(profiles)
        ui.grade_panel(grade, grade_note)

        summary = executive_summary(engine, profiles)
        ui.executive_panel(summary)

        ui.print_profiles(profiles)
        ui.summary_table(profiles)
        write_reports(args, engine, cidr, profiles)

        if grade in ("D", "F"):
            exit_code = 1
        ui.feed("ctOS profiler session complete.", "bright_magenta")
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user.[/]")
        return 2
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/]")
        return 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

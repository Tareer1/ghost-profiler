# 👻 Ghost Profiler v1.0.0 — First Stable Release

**ctOS-style network device profiler with a built-in local LLM.** Scan your own / authorized network, profile every device into Watch Dogs-style cards, and get AI-powered security analysis — fully offline.

🔗 Repo: https://github.com/Tareer1/ghost-profiler

---

## ✨ Highlights

- 🔍 **Host discovery** — ICMP + TCP fallback + ARP enrichment, live progress bar
- 🎛️ **Parallel port & banner scan** — 50 ports/host, HTTP title + TLS detection
- 🧠 **GhostCore LLM** — Dolphin3.0-Llama3.1-8B GGUF loaded **in-process** (llama-cpp-python): no Ollama, no server, nothing leaves the machine; rule-based offline analyst fallback
- 🏷️ **Device profiling** — OS guess (TTL/banners), MAC vendor + randomized-MAC detection, risk score 0–100, ctOS codenames (`GATEKEEPER-1`, `WEBWRAITH-26`…)
- 📊 **Network posture grade** — A–F, CI/cron-friendly exit codes (0 ok / 1 findings / 2 error)
- 📡 **Monitor mode** — baseline diff alerts: NEW DEVICE, PORTS OPENED/CLOSED, MAC CHANGED, DEVICE OFFLINE
- 🌙 **Nightly cron wrapper** — dated reports, alert extraction, Slack/Discord webhook, retention pruning
- 🖥️ **ctOS terminal UI** + single-file dark HTML dashboard
- ⚙️ **GPU offload config** — `GHOST_N_GPU_LAYERS` (fixed or `auto`) with honest CUDA detection and automatic CPU fallback
- 🧪 **79 offline pytest tests** — no internet, no LLM load needed

## 📦 Install (Kali Linux)

```bash
git clone https://github.com/Tareer1/ghost-profiler.git
cd ghost-profiler
python3 main.py          # first run auto-creates .venv and installs deps
```

Put any `.gguf` in `models/` (e.g. Dolphin 8B Q4_K_S) or pass `--model`. Full guide in the [README](https://github.com/Tareer1/ghost-profiler#readme).

## 🚀 Usage

```bash
python3 main.py                          # full scan + AI analysis
python3 main.py --quick                  # fast scan (8 ports)
python3 main.py --ip 192.168.1.42        # single-host deep dive
python3 main.py --monitor                # baseline + change alerts
python3 main.py --json r.json --html r.html -y   # reports
```

## ⚠️ Legal

For **authorized security testing and education** on networks you own. Unauthorized scanning is illegal in most jurisdictions (PECA, CFAA). This tool profiles devices, not people.

---

**Full Changelog:** https://github.com/Tareer1/ghost-profiler/commits/v1.0.0

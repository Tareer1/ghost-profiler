# 👻 GHOST PROFILER

**God-tier Watch Dogs-style network device profiler** — Kali Linux · Python 3 · built-in local LLM (GhostCore: Dolphin GGUF loaded in-process) · 100% offline

Scans **your own / authorized network**, profiles every device into ctOS-style cards (OS guess, MAC vendor, open ports, banners, risk score), grades your whole network A–F, and runs a **local LLM** over everything for executive-level security analysis.

> ⚠️ **Authorization required.** Only scan networks you own or are explicitly authorized to test. This tool profiles **devices, not people** — no OSINT on humans, no exploits.

---

## 📁 Project Structure

Sab kuch **ek folder** mein — software + LLM + reports + tests:

```
ghost-profiler/
├── main.py                     # CLI pipeline (entry point)
├── scanner.py                  # Host discovery + port/banner scan
├── profiler.py                 # Fingerprinting, risk scoring, grades
├── oui.py                      # MAC vendor DB + randomized-MAC detection
├── llama_engine.py             # GhostCore: in-process GGUF LLM engine
├── ai_engine.py                # GHOST-1 prompt layer + offline analyst
├── report.py                   # HTML dashboard generator
├── ui.py                       # ctOS terminal UI
├── models/                     # 🧠 LLM models (GGUF) — bundled
│   └── Dolphin3.0-Llama3.1-8B-Q4_K_S.gguf   (~4.4 GB)
├── scripts/
│   └── nightly.sh              # Cron wrapper: nightly scan + alerts
├── tests/                      # 79 pytest tests (offline, fast)
├── reports/                    # Scan output (auto-created)
│   ├── scan_latest.json / .html
│   └── nightly/                # dated JSON + alerts + logs
├── requirements.txt            # runtime deps
├── requirements-dev.txt        # dev deps (pytest)
└── README.md                   # ← ye file
```

> `.venv/` first run par khud banti hai — usay delete karne par agle run par dobara auto-build ho jayegi.

## 📋 Requirements

| Requirement | Detail |
|---|---|
| OS | Kali / Debian / Ubuntu Linux (Windows par chal sakta hai magar Linux recommended) |
| Python | 3.10+ (3.14 tested) |
| RAM | 8 GB minimum, **16 GB+ recommended** (model ~5 GB RAM leta hai) |
| Disk | 6 GB free (model + venv) |
| Network | Scan karne ke liye LAN access; **AI ke liye internet zaroori NAHI** |
| Extras | nmap/ollama/llama.cpp server ki **zaroorat nahi** — sab built-in |

---

# 🚀 Installation Guide

## Step 1 — Folder copy karo

```bash
# Git se:
git clone <this-repo> && cd ghost-profiler

# Ya pura folder USB/scp se copy karo (models/ included — 4.4 GB):
scp -r ghost-profiler/ user@kali-box:~/
cd ~/ghost-profiler
```

## Step 2 — Pehla run (auto-setup)

```bash
python3 main.py --list-models
```

First run par ye khud hota hai:
1. `.venv/` virtual environment ban jati hai
2. `rich` + `requests` install hote hain
3. `llama-cpp-python` compile hota hai (**5–10 min** — one-time)
4. Phir `models/` se Dolphin GGUF mil jayega aur list ho jayega

> `--no-ai` ke sath chalao to LLM compile skip hota hai (sirf scanning chahiye to).

## Step 3 — Verify

```bash
python3 main.py --list-models
# GhostCore — local GGUF models:
#   • /path/to/ghost-profiler/models/Dolphin3.0-Llama3.1-8B-Q4_K_S.gguf
```

Model list mein aa gaya? **Install complete.** ✅

## Step 4 — (Optional) Test suite chala kar confirm

```bash
.venv/bin/python3 -m pytest -q     # 79 tests — ~30s, no LLM load
```

## Model placement (agar custom model chahiye)

GhostCore GGUF is order mein dhoondta hai:
1. `--model /path/to/model.gguf` (ya directory)
2. `$GHOST_MODEL` env var
3. `./models/*.gguf` ← **bundled model yahan hai**
4. `Dolphin3.0-Llama3.1-8B-GGUF/` (legacy layout, agar ho)
5. `~/.ghost_profiler/models/`

Koi bhi Llama-architecture GGUF chalega (Q4_K_S recommended balance hai; RAM 16 GB+ ho to Q6_K/13B bhi fit hota hai).

---

# 📖 User Guide

## Consent gate

Har scan se pehle tool authorization poochta hai (apna IP/CIDR dikha kar). `yes` likho. Scripts/cron ke liye `-y` flag use karo.

## Commands — sab modes

```bash
python3 main.py                                    # Full scan: auto-detect network + AI analysis
python3 main.py --cidr 192.168.1.0/24              # Specific network scan
python3 main.py --ip 192.168.1.42                  # Single-host deep dive (ping TTL, rDNS, ARP MAC)
python3 main.py --quick                            # 8 common ports only — fast scan
python3 main.py --no-ai                            # LLM skip — sirf scanning (seconds mein)
python3 main.py --model models/other.gguf          # Koi aur GGUF
python3 main.py --list-models                      # Local models list
python3 main.py --monitor                          # Baseline + diff alerts (NEW DEVICE, PORTS OPENED/CLOSED, MAC CHANGED, DEVICE OFFLINE)
python3 main.py --yes --json r.json --html r.html  # Reports save, no prompt
```

## Scan kya karta hai (pipeline)

```
consent → host discovery (ICMP+TCP+ARP, progress bar)
        → parallel port scan (30–50 ports/host, 16 threads)
        → banner grab (HTTP titles, TLS detect)
        → profiling (OS guess, device type, vendor, risk 0–100, codename)
        → AI pass (per-device + executive summary — LLM ya rule-based)
        → posture grade (A–F) → terminal cards → reports
```

## Output samajhna

- **Device cards** — codename (`GATEKEEPER-1`, `WEBWRAITH-26`…), IP, MAC + vendor, OS guess, open ports + services, risk meter
- **Risk score** — 0–100: risky/legacy ports (Telnet, SMB, Redis, Docker API…) + flags
- **Posture grade** — A–F network-wide; **D/F par exit code 1** (cron/CI alerting ke liye)
- **AI analysis** — `RISK:` / `FIX:` lines per device; `PRIORITY:` / `STRATEGY:` network summary
- **Reports** — JSON (automation) + single-file HTML dashboard (browser mein kholo)

## Exit codes

| Code | Matlab |
|---|---|
| `0` | Scan ok, low risk |
| `1` | Findings need attention (D/F grade) |
| `2` | Error / abort / no hosts |

## Monitor mode (change detection)

```bash
python3 main.py --monitor -y        # pehli baar: baseline banta hai
python3 main.py --monitor -y        # baad mein: diff dikhata hai
```

Alerts: `NEW DEVICE` · `PORTS OPENED` · `PORTS CLOSED` · `MAC CHANGED` · `DEVICE OFFLINE`. Baseline `~/.ghost_profiler_baseline.json` mein save hota hai.

---

# ⚙️ Configuration (env vars)

| Variable | Default | Kaam |
|---|---|---|
| `GHOST_MODEL` | — | Model path force karo |
| `GHOST_N_GPU_LAYERS` | `0` | GPU offload: `16` = fixed layers, `auto` = CPU-core count. Sirf tab asar karta hai jab NVIDIA driver + CUDA llama build dono hon; warna startup par CPU fallback batata hai |
| `GHOST_MAX_TOKENS` | `350` | AI output length — slow CPU par `180` karo |
| `GHOST_NIGHTLY_AI` | `0` | `1` = nightly cron mein bhi LLM chale (slow) |
| `GHOST_WEBHOOK_URL` | — | Slack/Discord webhook — nightly alerts wahan POST hongi |
| `GHOST_RETENTION_DAYS` | `30` | Nightly reports is se purani delete |
| `GHOST_RUN_DIR` | `reports/nightly` | Nightly output directory |

GPU offload ki ground reality: offload tabhi kaam karta hai jab **dono** cheezein hon — `/dev/nvidia*` (proprietary driver) **aur** CUDA-enabled llama-cpp build (`CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python --force-reinstall`). Nouveau/open driver ya CPU-only build par tool saaf batata hai ke CPU par chal raha hai — kabhi crash nahi hota.

---

# 🌙 Nightly Monitoring (cron)

```bash
# One-time install (dedupe-safe):
( crontab -l 2>/dev/null; echo "0 3 * * * $PWD/scripts/nightly.sh >> $PWD/reports/nightly/cron.log 2>&1" ) | crontab -
```

Har raat 3 AM: `--monitor` scan → `reports/nightly/` mein `scan_<date>.json`, `alerts_<date>.txt`, `nightly_<date>.log`. Webhook set ho to alerts Slack/Discord par bhi. Retention auto-prune. Exit code scan ka mirror hai.

---

# 🧠 How the AI part works

`ai_engine.py` sirf **technical scan facts** (ports, banners, OS guess, risk) GhostCore ko bhejta hai — `llama_engine.py` Dolphin GGUF ko **in-process** load karta hai (llama-cpp-python). No Ollama, no server, no daemon — inference ek function call. **Kuch bhi internet par nahi jata.**

- Model pehli inference par RAM load hota hai (~2.5s warm cache se; phir ~6 tok/s CPU par)
- Har scan ke end mein unload — RAM release
- Model load na ho sake to **rule-based offline analyst** same format deta hai — tool kabhi nahi tootta

---

# 🧪 Testing

```bash
.venv/bin/python3 -m pytest        # 79 tests — no internet, no LLM load
```

Suite: profiling & risk scoring, scanner primitives (safe loopback/TEST-NET only), OUI detection, AI postprocessing + offline analyst + GPU config, HTML report (XSS escaping included).

---

# 🔧 Troubleshooting

| Problem | Hal |
|---|---|
| `no .gguf model found` | `python3 main.py --list-models` — model `models/` mein hai? ya `--model` do |
| `llama-cpp-python` build fail | `sudo apt install build-essential cmake` phir `python3 main.py` dobara — ya `--no-ai` use karo |
| AI bahut slow | `--no-ai`, ya `GHOST_MAX_TOKENS=180`, ya GPU route (config section dekho) |
| `Cannot detect network` | `--cidr 192.168.x.0/24` explicitly do |
| Koi host nahi mila | Target network hi sahi hai? ICMP block ho to bhi TCP fallback chalta hai; `-y` ke sath `--cidr` verify karo |
| `Permission denied` (cron/ssh) | `scripts/nightly.sh` ko `chmod +x` karo |
| Nightly alerts nahi aa rahin | `crontab -l` check karo; `reports/nightly/cron.log` padho; `GHOST_WEBHOOK_URL` set hai? |
| RAM kam hai | 13B/Q8 mat lo; Q4_K_S rakhho; ya `--no-ai` |

---

# 📄 Legal

**License:** MIT — see [LICENSE](LICENSE). Copyright (c) 2026 REBEL.

**Use:** For **authorized security testing and education** on networks you own. Scanning networks without permission is illegal in most jurisdictions (including Pakistan's PECA and the US CFAA). The authors accept no liability for misuse.

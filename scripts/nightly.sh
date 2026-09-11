#!/usr/bin/env bash
#
# GHOST PROFILER — nightly monitor scan for cron
#
# Install (see README):
#   0 3 * * * /path/to/ghost-profiler/scripts/nightly.sh >> /var/log/ghost-profiler/cron.log 2>&1
#
# Every night it:
#   1. Runs main.py --monitor (diff alerts: NEW DEVICE, PORTS OPENED/CLOSED,
#      MAC CHANGED, DEVICE OFFLINE) with a DATED JSON report.
#      LLM analysis is OFF by default on cron (fast, no 4GB model load);
#      opt in with GHOST_NIGHTLY_AI=1.
#   2. Extracts alert lines into alerts_<date>.txt.
#   3. Optionally POSTs alerts to a webhook (Slack/Discord-compatible) —
#      set GHOST_WEBHOOK_URL in /etc/default/ghost-profiler or the environment.
#   4. Prunes reports older than GHOST_RETENTION_DAYS (default 30).
#
# Exit code = main.py's exit code (0 ok, 1 findings need attention, 2 error).

set -u

# ---- configuration ----------------------------------------------------------
PROFILER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUN_DIR="${GHOST_RUN_DIR:-$PROFILER_DIR/reports/nightly}"
LOG_DIR="${GHOST_LOG_DIR:-$RUN_DIR}"
RETENTION_DAYS="${GHOST_RETENTION_DAYS:-30}"
# Optional: /etc/default/ghost-profiler may set GHOST_WEBHOOK_URL / overrides
[ -f /etc/default/ghost-profiler ] && . /etc/default/ghost-profiler

PY="$PROFILER_DIR/.venv/bin/python3"
[ -x "$PY" ] || PY="python3"
TODAY="$(date +%F)"
OUT_JSON="$RUN_DIR/scan_$TODAY.json"
LOG_FILE="$LOG_DIR/nightly_$TODAY.log"
ALERT_FILE="$LOG_DIR/alerts_$TODAY.txt"

mkdir -p "$RUN_DIR"

# ---- run the monitor scan ----------------------------------------------------
cd "$PROFILER_DIR"
ARGS=(--monitor --yes --json "$OUT_JSON")
[ "${GHOST_NIGHTLY_AI:-0}" != "1" ] && ARGS+=(--no-ai)
"$PY" main.py "${ARGS[@]}" > "$LOG_FILE" 2>&1
RC=$?

# ---- extract alerts ----------------------------------------------------------
# feed lines look like:   > NEW DEVICE: GATEKEEPER-1 192.168.100.9 (ports: ...)
grep -E "^\s+>\s+(NEW DEVICE|PORTS OPENED|PORTS CLOSED|MAC CHANGED|DEVICE OFFLINE)" \
    "$LOG_FILE" > "$ALERT_FILE" 2>/dev/null || true

N_ALERTS=$(grep -c . "$ALERT_FILE" 2>/dev/null || echo 0)

# ---- optional webhook ----------------------------------------------------------
if [ -n "${GHOST_WEBHOOK_URL:-}" ] && [ "$N_ALERTS" -gt 0 ]; then
    # Slack/Discord-compatible payload; never fatal on failure.
    "$PY" - "$GHOST_WEBHOOK_URL" "$ALERT_FILE" <<'PYEOF' >/dev/null 2>&1 || true
import json, sys, urllib.request
url, alert_file = sys.argv[1], sys.argv[2]
with open(alert_file, encoding="utf-8") as f:
    alerts = [ln.strip() for ln in f if ln.strip()]
if alerts:
    text = "👻 *Ghost Profiler* — nightly diff (%s), %d alert(s):\n```%s```" % (
        sys.argv[2].split("alerts_")[-1], len(alerts), "\n".join(alerts[:25]))
    req = urllib.request.Request(url, data=json.dumps(
        {"content": text[:3900], "text": text[:3900]}).encode(),
        headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=15)
PYEOF
fi

# ---- retention -----------------------------------------------------------------
find "$RUN_DIR" -type f \( -name 'scan_*.json' -o -name 'nightly_*.log' \
    -o -name 'alerts_*.txt' \) -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true

echo "$(date '+%F %T') nightly done rc=$RC alerts=$N_ALERTS -> $OUT_JSON"
exit $RC

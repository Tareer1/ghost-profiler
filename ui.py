"""
ui.py — Watch Dogs-style Profiler rendering (rich).

ctOS-style panels: device cards, glitch codenames, risk meters, feed log.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box

console = Console()

RISK_STYLE = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "bright_red", "CRITICAL": "bold red"}


def banner(model: str, engine_available: bool, cidr: str):
    engine_line = f"[bright_green]ONLINE[/] · {model}" if engine_available else "[yellow]OFFLINE MODE[/] · rule-based analyst"
    art = Text()
    art.append(" ██████  ██   ██  ██████  ███████ ████████ ", style="bold bright_white")
    art.append("██ ▓▓██ ", style="bright_magenta")
    art.append("\n", style="")
    art.append("██   ██ ██   ██ ██    ██ ██         ██      G H O S T   P R O F I L E R\n", style="bold bright_white")
    art.append(" ██████  ███████ ██    ██ ███████    ██   ", style="bold bright_white")
    art.append(" ctOS v2.0 // unauthorized access is a crime", style="dim")
    panel = Panel(
        Text.assemble(art, "\n\n", Text.from_markup(
            f"  [bright_cyan]LLM:[/] {engine_line}   [bright_cyan]TARGET:[/] {cidr}   [bright_cyan]SCOPE:[/] own network only"
        )),
        border_style="bright_magenta",
        box=box.DOUBLE,
    )
    console.print(panel)


def consent_gate(cidr: str) -> bool:
    """Authorization check before any packet leaves the machine."""
    console.print(Panel(
        "[bold]AUTHORIZATION GATE[/]\n\n"
        f"You are about to scan: [bright_cyan]{cidr}[/]\n\n"
        "[yellow]Rules of engagement:[/]\n"
        "  1. Scan ONLY networks you own or are authorized to test\n"
        "  2. Devices are profiled — people are NOT\n"
        "  3. Findings are for hardening your own systems\n",
        border_style="yellow", box=box.HEAVY,
    ))
    console.print()
    try:
        answer = input("  [y] I own/authorize this network — proceed: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    return answer in ("y", "yes")


def device_card(p: dict, ai_text: str = None, ai_source: str = None) -> Panel:
    """A single ctOS-style device card."""
    style = RISK_STYLE.get(p["risk_level"], "white")
    head = Text()
    head.append(f" {p['codename']} ", style=f"bold black on {style}")
    head.append(f"  {p['risk_level']} {p['risk_score']}/100 ", style=style)

    rows = Table.grid(padding=(0, 2))
    rows.add_column(style="bright_cyan", justify="right")
    rows.add_column(style="white")
    rows.add_row("IP", p["ip"])
    rows.add_row("HOST", p["hostname"])
    rows.add_row("MAC", f"{p['mac']}  {p.get('vendor', '') or ''}")
    if p.get("mac_type") and p["mac_type"] != "unknown":
        rows.add_row("MACTYPE", p["mac_type"])
    rows.add_row("OS", p["os"])
    rows.add_row("TYPE", p["device_type"])
    rows.add_row("PORTS", ", ".join(map(str, p["open_ports"])) or "—")
    rows.add_row("SVC", "\n      ".join(p["services"]))

    if ai_text:
        rows.add_row()
        rows.add_row("AI", Text(ai_text, style="bright_magenta"))
        if ai_source:
            rows.add_row("", Text(f"— {ai_source}", style="dim italic"))

    # Risk meter bar
    filled = p["risk_score"] // 10
    meter = Text("RISK  [" + "█" * filled + "░" * (10 - filled) + f"] {p['risk_score']}/100", style=style)
    body = Table.grid()
    body.add_column()
    body.add_row(head)
    body.add_row(rows)
    body.add_row(meter)
    return Panel(body, border_style=style, box=box.HEAVY_EDGE, expand=True)


def feed(msg: str, style: str = "bright_white"):
    """ctOS event feed line."""
    console.print(f"  [dim]>[/] [{style}]{msg}[/]")


def scan_progress(cidr: str, total: int):
    """Live progress bar for host discovery."""
    progress = Progress(
        SpinnerColumn("dots", style="bright_magenta"),
        TextColumn("[bright_cyan]SCANNING {task.fields[cidr]}"),
        BarColumn(bar_width=30, style="bright_magenta", complete_style="bright_green"),
        TextColumn("[bright_white]{task.completed}/{task.total}"),
        console=console, transient=True,
    )
    task_id = progress.add_task("", total=total, cidr=cidr)
    return progress, task_id


def grade_panel(grade: str, note: str):
    """Big posture grade banner."""
    style = {"A": "bold bright_green", "B": "green", "C": "yellow",
             "D": "bright_red", "F": "bold red"}.get(grade, "white")
    console.print(Panel(
        Text.assemble(
            Text(f"  {grade}  ", style="bold black on " + style.split()[-1]),
            Text(f"  NETWORK POSTURE GRADE\n  {note}", style="bright_white"),
        ),
        border_style=style, box=box.DOUBLE, expand=False,
    ))


def executive_panel(summary: dict):
    """Network-wide AI summary panel."""
    console.print(Panel(
        Text(summary["text"], style="bright_white"),
        title=f"[bold bright_magenta]EXECUTIVE SUMMARY[/] [dim]({summary['source']})[/]",
        border_style="bright_magenta", box=box.ROUNDED,
    ))


def print_profiles(profiles: list):
    console.print()
    console.rule("[bold bright_magenta]ctOS PROFILER RESULTS", style="bright_magenta")
    console.print()
    for p in profiles:
        console.print(device_card(p))
        console.print()


def print_ai_analysis(analysis: dict):
    console.print(Panel(
        Text(analysis["text"], style="bright_white"),
        title=f"[bold bright_magenta]GHOST-1 ANALYSIS[/] [dim]({analysis['source']})[/]",
        border_style="bright_magenta", box=box.ROUNDED,
    ))


def summary_table(profiles: list):
    t = Table(title="NETWORK SUMMARY", box=box.SIMPLE_HEAVY, title_style="bold bright_magenta")
    t.add_column("CODENAME", style="bright_cyan")
    t.add_column("IP")
    t.add_column("TYPE")
    t.add_column("RISK", justify="right")
    for p in sorted(profiles, key=lambda x: -x["risk_score"]):
        t.add_row(p["codename"], p["ip"], p["device_type"],
                  Text(f"{p['risk_level']} {p['risk_score']}", style=RISK_STYLE[p["risk_level"]]))
    console.print(t)

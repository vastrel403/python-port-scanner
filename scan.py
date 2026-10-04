#!/usr/bin/env python3
"""Vastrel Port Scanner - Made by Vastrel

A fully menu-driven port scanner. Requirements:
    pip install python-nmap rich
nmap must be installed on the system for the nmap-based profiles (the Python TCP profile does not require nmap).
"""
import csv
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn, TaskProgressColumn,
                           TextColumn, TimeElapsedColumn, TimeRemainingColumn)
from rich.prompt import Prompt
from rich.table import Table

from menu import ACCENT, BORDER, MUTED, PANEL_BOX, TABLE_BOX, Menu, tag

try:
    import nmap
except ImportError:  # if python-nmap isn't installed, the Python TCP scanner still works
    nmap = None

console = Console()


class Ask(Prompt):
    illegal_choice_message = "[prompt.invalid.choice]  Invalid choice, pick one from the list"


class MainAsk(Ask):
    prompt_suffix = " "


def ask(text, **kw):
    cls = MainAsk if text == PROMPT else Ask
    return cls.ask(text, console=console, **kw)


PROMPT = f"\n  [bold {ACCENT}]vastrel[/] [{MUTED}]>[/]"


# ====================================================================== message helpers
def ok(msg):
    console.print(f"  [green]OK[/]      {msg}")


def err(msg):
    console.print(f"  [red]ERROR[/]   {msg}")


def warn(msg):
    console.print(f"  [yellow]WARNING[/] {msg}")


def note(msg):
    console.print(f"  [{MUTED}]{msg}[/]")


# ====================================================================== constants
TIMING_NAMES = ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"]

PROFILES = {
    "1": dict(name="Fast", desc="Top 100 most common ports", engine="nmap", args=["-F"], ports=None, root=False),
    "2": dict(name="Standard", desc="Ports 1-1024", engine="nmap", args=[], ports="1-1024", root=False),
    "3": dict(name="Full", desc="All ports (1-65535)", engine="nmap", args=[], ports="1-65535", root=False),
    "4": dict(name="Custom", desc="Enter your own port list (e.g. 22,80,8000-8100)", engine="nmap", args=[], ports="custom", root=False),
    "5": dict(name="Stealth SYN", desc="Half-open (-sS) scan, ports 1-1024", engine="nmap", args=["-sS"], ports="1-1024", root=True),
    "6": dict(name="UDP", desc="Top 50 most common UDP ports", engine="nmap", args=["-sU", "--top-ports", "50"], ports=None, root=True),
    "7": dict(name="Python TCP", desc="No nmap required, multi-threaded, grabs banners", engine="python", args=[], ports="custom", root=False),
}

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
STATE_STYLE = {"open": "bold green", "open|filtered": "bold yellow", "filtered": "yellow", "closed": "red"}

HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
RANGE_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$")

NMAP_HELP = ("nmap not found. Install it with: Linux 'sudo apt install nmap'  |  macOS 'brew install nmap'  |  "
             "Windows nmap.org/download. You can also use the Python TCP profile (7), which doesn't need nmap.")


# ====================================================================== data models
@dataclass
class Settings:
    targets: list = field(default_factory=list)
    ports: str = "1-1024"
    timing: int = 4
    version: bool = True
    scripts: bool = False
    os_detect: bool = False
    skip_ping: bool = True
    threads: int = 200
    timeout: float = 1.0
    out_dir: str = "vastrel_reports"
    auto_report: bool = True


@dataclass
class Row:
    host: str
    proto: str
    port: int
    state: str
    service: str
    version: str
    script: str


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    state: str = "up"
    os: str = ""
    mac: str = ""
    rows: list = field(default_factory=list)


@dataclass
class Record:
    profile: str
    target: str
    command: str
    started: str
    duration: float
    kind: str = "ports"  # "ports" or "hosts"
    hosts: list = field(default_factory=list)

    def open_keys(self):
        return {(h.ip, r.proto, r.port) for h in self.hosts for r in h.rows if r.state == "open"}

    def count(self, state):
        return sum(1 for h in self.hosts for r in h.rows if r.state == state)


# ====================================================================== helpers
def is_admin():
    try:
        return os.geteuid() == 0
    except AttributeError:  # Windows
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


def nmap_available():
    return nmap is not None and shutil.which("nmap") is not None


def pause():
    ask(f"\n  [{MUTED}]Press Enter to return to the menu[/]", default="", show_default=False)


def clip(text, n=110):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def screen(menu, cfg, history):
    """For sub-screens: clear the screen and print a compact header and context line."""
    menu.clear()
    menu.header(compact=True)
    menu.context(cfg, len(history))


def valid_target(t):
    """IP, CIDR, an a.b.c.d-e range, or a domain name. Cannot start with '-' (prevents argument injection)."""
    for parser in (ipaddress.ip_address, lambda x: ipaddress.ip_network(x, strict=False)):
        try:
            parser(t)
            return True
        except ValueError:
            pass
    if RANGE_RE.match(t):
        base, end = t.rsplit("-", 1)
        try:
            ipaddress.ip_address(base)
        except ValueError:
            return False
        return int(base.split(".")[-1]) <= int(end) <= 255
    return bool(HOST_RE.match(t))


def parse_ports(text):
    """'22,80,8000-8100' -> sorted port list; None if invalid."""
    ports = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            return None
        a, sep, b = part.partition("-")
        if not a.isdigit() or (sep and not b.isdigit()):
            return None
        lo, hi = int(a), int(b) if sep else int(a)
        if not 1 <= lo <= hi <= 65535:
            return None
        ports.update(range(lo, hi + 1))
    return sorted(ports)


def service_name(port, proto="tcp"):
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def ask_number(label, cast, lo, hi, default):
    raw = ask(f"  {label} ({lo}-{hi})", default=str(default))
    try:
        v = cast(raw)
    except ValueError:
        err("Invalid number.")
        return default
    if not lo <= v <= hi:
        err(f"Value must be between {lo}-{hi}.")
        return default
    return v


def fix_owner(*paths):
    """When running under sudo, restore ownership of created files to the real user."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid and hasattr(os, "chown")):
        return
    for p in paths:
        try:
            os.chown(p, int(uid), int(gid))
        except OSError:
            pass


# ====================================================================== target selection
def set_target(cfg, state):
    console.print(Panel(
        "  192.168.1.10          single IP\n"
        "  scanme.nmap.org       domain name\n"
        "  192.168.1.0/24        CIDR\n"
        "  192.168.1.1-50        range\n"
        "  10.0.0.1, 10.0.0.5    multiple (comma or space separated)\n"
        "  @targets.txt          from a file (one target per line, # for comments)",
        title=f"[{MUTED}]TARGET FORMATS[/]", title_align="left", border_style=BORDER,
        box=PANEL_BOX, padding=(1, 2)))
    raw = ask("\n  Target(s)").strip()
    if raw.startswith("@"):
        try:
            lines = Path(raw[1:].strip()).read_text(encoding="utf-8").splitlines()
        except OSError as e:
            err(f"Could not read file: {escape(str(e))}")
            return
        raw = " ".join(line.split("#")[0] for line in lines)
    items = list(dict.fromkeys(t for t in re.split(r"[,\s]+", raw) if t))
    if not items:
        err("No target entered.")
        return
    bad = [t for t in items if not valid_target(t)]
    if bad:
        err(f"Invalid target(s): {escape(', '.join(bad))}")
        return
    cfg.targets = items
    state["authorized"] = False
    ok(f"{len(items)} target(s) set.")


# ====================================================================== nmap engine
def build_args(cfg, prof, admin):
    args = []
    if cfg.skip_ping:
        args.append("-Pn")
    args.append("-n")
    args.append(f"-T{cfg.timing}")
    args += prof["args"]
    if cfg.version:
        args.append("-sV")
    if cfg.scripts:
        args.append("-sC")
    if cfg.os_detect:
        if admin:
            args.append("-O")
        else:
            warn("OS detection (-O) requires root, skipped for this scan.")
    return list(dict.fromkeys(args))


def nmap_scan(cfg, targets, ports, args, profile_name, kind="ports"):
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        err(NMAP_HELP)
        return None
    start = time.time()
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with console.status(f"  [bold white]{profile_name} scan running[/] [{MUTED}](cancel: Ctrl+C)[/]",
                            spinner="dots2", spinner_style=ACCENT):
            nm.scan(hosts=" ".join(targets), ports=ports, arguments=" ".join(args))
    except KeyboardInterrupt:
        warn("Scan cancelled by user.")
        return None
    except nmap.PortScannerError as e:
        err(f"nmap error: {escape(str(e).strip())}")
        return None
    except Exception as e:
        err(f"Unexpected error: {escape(str(e))}")
        return None

    try:
        info = nm.scaninfo()
        for key in ("error", "warning"):
            val = info.get(key)
            for item in ([val] if isinstance(val, str) else (val or [])):
                warn(f"nmap: {escape(str(item).strip())}")
    except Exception:
        pass

    hosts = []
    for ip in nm.all_hosts():
        hd = nm[ip]
        h = HostInfo(ip=ip, hostname=hd.hostname(), state=hd.state())
        matches = hd.get("osmatch") or []
        if matches:
            h.os = f"{matches[0].get('name', '?')} ({matches[0].get('accuracy', '?')}%)"
        h.mac = hd.get("addresses", {}).get("mac", "")
        for proto in hd.all_protocols():
            for p in sorted(hd[proto]):
                d = hd[proto][p]
                st = d.get("state", "")
                if st in ("closed", "filtered"):
                    continue
                bits = [d.get("product", ""), d.get("version", "")]
                ver = " ".join(b for b in bits if b)
                if d.get("extrainfo"):
                    ver = f"{ver} ({d['extrainfo']})".strip()
                script = "; ".join(f"{k}: {' '.join(str(v).split())}" for k, v in (d.get("script") or {}).items())
                h.rows.append(Row(ip, proto, p, st, d.get("name") or "unknown", ver or "-", script or "-"))
        hosts.append(h)

    if not hosts:
        warn("No host responded (it may be down, filtered, or the target invalid).")
        return None
    return Record(profile=profile_name, target=", ".join(targets), command=nm.command_line(),
                  started=started, duration=time.time() - start, kind=kind, hosts=hosts)


def ping_sweep(cfg):
    if not nmap_available():
        err(NMAP_HELP)
        return None
    args = ["-sn", "-n", f"-T{cfg.timing}"]
    return nmap_scan(cfg, cfg.targets, None, args, "Network discovery", kind="hosts")


# ====================================================================== Python TCP engine
def probe(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            return "open", grab_banner(s, ip, port, timeout)
    except ConnectionRefusedError:
        return "closed", ""
    except OSError:
        return "filtered", ""


def grab_banner(sock, ip, port, timeout):
    try:
        sock.settimeout(max(timeout, 1.5))
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        data = sock.recv(512).decode(errors="ignore")
    except OSError:
        return ""
    lines = [ln.strip() for ln in data.splitlines() if ln.strip()]
    for ln in lines:
        if ln.lower().startswith("server:"):
            return clip("".join(c for c in ln[7:] if c.isprintable()).strip(), 60)
    text = "".join(c for c in (lines[0] if lines else "") if c.isprintable())
    return clip(text, 60)


def expand_targets(targets):
    """Expand targets into an {ip: hostname} dict (for the Python scanner)."""
    out = {}
    for t in targets:
        try:
            ipaddress.ip_address(t)
            out[t] = ""
            continue
        except ValueError:
            pass
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses > 1024:
                warn(f"{escape(t)} is too large (max /22), skipped.")
                continue
            for ip in (net.hosts() if net.num_addresses > 2 else net):
                out[str(ip)] = ""
            continue
        except ValueError:
            pass
        if RANGE_RE.match(t):
            base, end = t.rsplit("-", 1)
            a, b, c, d = base.split(".")
            for i in range(int(d), int(end) + 1):
                out[f"{a}.{b}.{c}.{i}"] = ""
            continue
        try:
            out[socket.gethostbyname(t)] = t
        except OSError:
            warn(f"{escape(t)} could not be resolved, skipped.")
    return out


def python_scan(cfg):
    ports = parse_ports(cfg.ports)
    ips = expand_targets(cfg.targets)
    if not ports or not ips:
        err("No valid ports or targets.")
        return None
    total = len(ips) * len(ports)
    if total > 500_000:
        if ask(f"  [yellow]{total:,} connections will be attempted. Continue?[/]", choices=["y", "n"], default="n") == "n":
            return None

    start = time.time()
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hosts = {ip: HostInfo(ip=ip, hostname=name) for ip, name in ips.items()}
    responded = set()
    ex = ThreadPoolExecutor(max_workers=max(1, min(cfg.threads, 1000)))
    try:
        futures = {ex.submit(probe, ip, p, cfg.timeout): (ip, p) for ip in ips for p in ports}
        with Progress(SpinnerColumn("dots2", style=ACCENT), TextColumn("[bold white]{task.description}"),
                      BarColumn(bar_width=None, complete_style=ACCENT, finished_style=ACCENT),
                      TaskProgressColumn(), TimeElapsedColumn(), TimeRemainingColumn(),
                      console=console, transient=True) as prog:
            task = prog.add_task(f"  TCP scan ({len(ips)} hosts x {len(ports)} ports)", total=total)
            for fut in as_completed(futures):
                ip, p = futures[fut]
                st, banner = fut.result()
                prog.advance(task)
                if st in ("open", "closed"):
                    responded.add(ip)
                if st == "open":
                    hosts[ip].rows.append(Row(ip, "tcp", p, st, service_name(p), banner or "-", "-"))
    except KeyboardInterrupt:
        warn("Scan cancelled, showing partial results.")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    result = []
    for ip, h in hosts.items():
        h.rows.sort(key=lambda r: r.port)
        h.state = "up" if ip in responded else "no response"
        if ip in responded or len(hosts) <= 5:
            result.append(h)
    if not result:
        warn("No host responded.")
        return None
    return Record(profile="Python TCP", target=", ".join(cfg.targets),
                  command=f"python-tcp ports={cfg.ports} threads={cfg.threads} timeout={cfg.timeout}s",
                  started=started, duration=time.time() - start, hosts=result)


# ====================================================================== display
def show_record(rec):
    console.print()
    if rec.kind == "hosts":
        t = Table(title=f"LIVE HOSTS ({len(rec.hosts)})", title_justify="left", title_style=f"bold {ACCENT}",
                  box=TABLE_BOX, border_style=BORDER, header_style=MUTED, pad_edge=False)
        for c in ("IP", "HOSTNAME", "MAC", "STATE"):
            t.add_column(c)
        for h in rec.hosts:
            t.add_row(escape(h.ip), escape(h.hostname or "-"), escape(h.mac or "-"), "[green]up[/]")
        console.print(t)
    else:
        for h in rec.hosts:
            title = escape(h.ip) + (f"  ({escape(h.hostname)})" if h.hostname else "")
            cap = f"state: {escape(h.state)}"
            if h.os:
                cap += f"   os: {escape(h.os)}"
            if h.mac:
                cap += f"   mac: {escape(h.mac)}"
            if not h.rows:
                console.print(f"  [bold {ACCENT}]{title}[/]  [{MUTED}]{cap}[/]")
                note("No open ports found.\n")
                continue
            has_script = any(r.script != "-" for r in h.rows)
            # Open ports are printed as a classic framed ┌─┬─┐ table
            t = Table(title=title, title_justify="left", title_style=f"bold {ACCENT}",
                      caption=cap, caption_justify="left", caption_style=MUTED,
                      box=box.SQUARE, border_style=BORDER, header_style=f"bold {ACCENT}",
                      padding=(0, 2), pad_edge=True)
            t.add_column("PORT", justify="right", style="bold white")
            t.add_column("STATE")
            t.add_column("SERVICE", style=ACCENT)
            t.add_column("VERSION / BANNER", max_width=48)
            if has_script:
                t.add_column("SCRIPT", max_width=60)
            for r in h.rows:
                cells = [f"{r.port}/{r.proto}", f"[{STATE_STYLE.get(r.state, 'white')}]{escape(r.state)}[/]",
                         escape(r.service), escape(r.version)]
                if has_script:
                    cells.append(escape(clip(r.script)))
                t.add_row(*cells)
            console.print(t)
            console.print()

    filtered = rec.count("filtered") + rec.count("open|filtered")
    console.print(Panel(
        f"HOST [bold white]{len(rec.hosts)}[/]     OPEN [bold green]{rec.count('open')}[/]     "
        f"FILTERED [yellow]{filtered}[/]     DURATION [bold white]{rec.duration:.1f}s[/]\n"
        f"[{MUTED}]{escape(rec.command)}[/]",
        title=f"[{MUTED}]SUMMARY[/]", title_align="left", border_style=BORDER, box=PANEL_BOX, padding=(0, 2)))


def history_table(history):
    t = Table(title="SCAN HISTORY", title_justify="left", title_style=f"bold {ACCENT}",
              box=TABLE_BOX, border_style=BORDER, header_style=MUTED, pad_edge=False)
    t.add_column("", justify="right", style=f"bold {ACCENT}")
    for c in ("TIME", "PROFILE", "TARGET", "HOSTS", "OPEN", "DURATION"):
        t.add_column(c)
    for i, r in enumerate(history, 1):
        t.add_row(tag(i), r.started, r.profile, escape(clip(r.target, 30)),
                  str(len(r.hosts)), str(r.count("open")), f"{r.duration:.1f}s")
    console.print(t)
    console.print()


def pick_record(history, label="Scan number", default=None):
    history_table(history)
    choices = [str(i) for i in range(1, len(history) + 1)]
    return history[int(ask(f"  {label}", choices=choices, default=default or str(len(history)))) - 1]


# ====================================================================== HTML report
REPORT_CSS = """
:root{--bg:#000;--line:#1a1a1a;--line2:#2c2c2c;--t:#f5f5f5;--m:#777;--mx:-500px;--my:-500px}
*{box-sizing:border-box}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;background:#000;color:var(--t);overflow-x:hidden;
font:14px/1.6 "Manrope",-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.mono,code{font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
::selection{background:#fff;color:#000}
::-webkit-scrollbar{height:6px;width:6px}::-webkit-scrollbar-thumb{background:#2c2c2c;border-radius:9px}

/* background: mouse-following grid + light + particles */
#fx{position:fixed;inset:0;z-index:0;pointer-events:none}
body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;
background-image:linear-gradient(rgba(255,255,255,.07) 1px,transparent 1px),
linear-gradient(90deg,rgba(255,255,255,.07) 1px,transparent 1px);background-size:56px 56px;
-webkit-mask-image:radial-gradient(380px circle at var(--mx) var(--my),#000,transparent);
mask-image:radial-gradient(380px circle at var(--mx) var(--my),#000,transparent)}
body::after{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;
background:radial-gradient(520px circle at var(--mx) var(--my),rgba(255,255,255,.06),transparent 65%)}
.bar{position:fixed;top:0;left:0;right:0;height:1px;z-index:50;overflow:hidden;background:#111}
.bar::after{content:"";position:absolute;top:0;height:1px;width:30%;
background:linear-gradient(90deg,transparent,#fff,transparent);animation:sweep 3.4s cubic-bezier(.6,0,.4,1) infinite}
@keyframes sweep{from{transform:translateX(-100%)}to{transform:translateX(340%)}}

/* custom cursor */
.cur,.dot{position:fixed;left:0;top:0;pointer-events:none;z-index:99;border-radius:50%;opacity:0}
.cur{width:38px;height:38px;margin:-19px 0 0 -19px;border:1px solid rgba(255,255,255,.55);
transition:width .25s,height .25s,margin .25s,background .25s,opacity .3s}
.dot{width:5px;height:5px;margin:-2.5px 0 0 -2.5px;background:#fff}
.cur.on{width:76px;height:76px;margin:-38px 0 0 -38px;background:rgba(255,255,255,.07);border-color:#fff}
.cur.down{width:26px;height:26px;margin:-13px 0 0 -13px;background:rgba(255,255,255,.2)}
.fx-on .cur,.fx-on .dot{opacity:1}
@media (hover:hover) and (pointer:fine){.fx-on,.fx-on *{cursor:none!important}}
@media (hover:none){.cur,.dot{display:none}}

.wrap{position:relative;z-index:1;max-width:1180px;margin:0 auto;padding:56px 32px 72px}

/* header */
header{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;flex-wrap:wrap;
padding-bottom:26px;margin-bottom:34px;border-bottom:1px solid var(--line);position:relative}
header::after{content:"";position:absolute;left:0;bottom:-1px;height:1px;width:0;background:#fff;
animation:draw 1.6s .3s cubic-bezier(.2,.7,.2,1) forwards}
@keyframes draw{to{width:100%}}
.brand{font-size:30px;font-weight:800;letter-spacing:.5em;line-height:1.1;
background:linear-gradient(110deg,#4a4a4a 25%,#fff 45%,#fff 55%,#4a4a4a 75%);background-size:260% 100%;
-webkit-background-clip:text;background-clip:text;color:transparent;animation:shine 5s linear infinite}
@keyframes shine{from{background-position:130% 0}to{background-position:-130% 0}}
.sub{color:var(--m);margin-top:10px;letter-spacing:.08em}
.stamp{color:var(--m);font-size:12.5px;text-align:right}
.stamp b{color:var(--t);font-weight:600;display:block;font-size:14px}

/* cards: light tracking + 3D tilt */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px}
.card,.spot{position:relative;background:linear-gradient(180deg,#0b0b0b,#030303);
border:1px solid var(--line);border-radius:16px;overflow:hidden}
.card{padding:22px 24px;transition:transform .2s ease-out,border-color .35s,box-shadow .35s;will-change:transform}
.card:hover{border-color:#333;box-shadow:0 20px 60px -20px rgba(255,255,255,.14)}
.spot::before,.spot::after{content:"";position:absolute;inset:0;border-radius:inherit;pointer-events:none;
opacity:0;transition:opacity .35s}
.spot::before{background:radial-gradient(300px circle at var(--x,50%) var(--y,50%),rgba(255,255,255,.1),transparent 60%)}
.spot::after{padding:1px;background:radial-gradient(200px circle at var(--x,50%) var(--y,50%),#fff,transparent 65%);
-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;
mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0)}
.spot:hover::before,.spot:hover::after{opacity:1}
.spot>*{position:relative;z-index:1}
.k{color:var(--m);font-size:12.5px}
.v{font-size:34px;font-weight:700;margin-top:6px;line-height:1.15;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.v.sm{font-size:22px;padding-top:9px}

dl{display:grid;grid-template-columns:110px 1fr;gap:10px 22px;margin:0 0 40px;padding:22px 26px}
dt{color:var(--m);padding-top:2px}
dd{margin:0;word-break:break-word}

/* search + tables */
.tools{display:flex;justify-content:space-between;align-items:center;gap:16px;margin:0 0 18px}
h2{font-size:16px;margin:0;font-weight:700;letter-spacing:-.01em}
input{background:#050505;border:1px solid var(--line2);color:var(--t);border-radius:99px;padding:10px 18px;
min-width:300px;font:inherit;transition:border-color .3s,box-shadow .3s,min-width .4s}
input::placeholder{color:#555}
input:focus{outline:none;border-color:#fff;box-shadow:0 0 0 4px rgba(255,255,255,.08),0 0 40px rgba(255,255,255,.1);min-width:380px}
section{margin-bottom:34px}
.host{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;margin:0 0 12px}
.host .ip{font-size:20px;font-weight:700}
.host .info{color:var(--m)}
.tablebox{border-radius:16px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--m);font-weight:500;font-size:12.5px;padding:14px 20px;
border-bottom:1px solid var(--line2);white-space:nowrap;background:rgba(255,255,255,.02)}
td{padding:14px 20px;border-bottom:1px solid var(--line);vertical-align:top;transition:background .3s,padding .3s}
tbody tr:last-child td{border-bottom:none}
tbody tr{transition:background .3s}
tbody tr:hover{background:linear-gradient(90deg,rgba(255,255,255,.09),rgba(255,255,255,0) 80%)}
tbody tr:hover td:first-child{box-shadow:inset 2px 0 0 #fff}
tbody tr:hover td:nth-child(3){letter-spacing:.04em}
tr[hidden]{display:none}
td.port{font-weight:700;white-space:nowrap}
td.wrap-cell{color:#b5b5b5;word-break:break-word;max-width:460px}
.badge{display:inline-flex;align-items:center;gap:9px;padding:3px 14px 3px 11px;border-radius:99px;
border:1px solid #fff;font-size:12px;font-weight:700;box-shadow:0 0 22px rgba(255,255,255,.16)}
.badge i{width:6px;height:6px;border-radius:50%;background:#fff;animation:pulse 1.9s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(255,255,255,.75)}100%{box-shadow:0 0 0 11px rgba(255,255,255,0)}}
.empty{color:var(--m);padding:22px 24px}
footer{margin-top:54px;padding-top:20px;border-top:1px solid var(--line);color:var(--m);font-size:12.5px;
display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}

/* entrance animations (only if JS runs) */
.fx .rv{opacity:0;transform:translateY(30px) scale(.97);filter:blur(10px);
transition:opacity .9s cubic-bezier(.2,.7,.2,1),transform .9s cubic-bezier(.2,.7,.2,1),filter .9s cubic-bezier(.2,.7,.2,1)}
.fx .rv.in{opacity:1;transform:none;filter:none}
@keyframes rowin{from{opacity:0;transform:translateX(-18px)}to{opacity:1;transform:none}}
.fx tbody tr{animation:rowin .7s cubic-bezier(.2,.7,.2,1) both;animation-delay:calc(var(--i)*70ms + .5s)}

@media(max-width:820px){.cards{grid-template-columns:repeat(2,1fr)}.wrap{padding:36px 16px 48px}
dl{grid-template-columns:1fr}.stamp{text-align:left}input,input:focus{min-width:0;width:100%}.tools{flex-wrap:wrap}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}
.fx .rv{opacity:1!important;transform:none!important;filter:none!important}}
@media print{#fx,.cur,.dot,.bar,input{display:none!important}body::before,body::after{display:none}
body{background:#fff;color:#111}.card,.spot{background:#fff;border-color:#ccc}.k,dt,th,.sub,.stamp,.info{color:#555}
.brand{background:none;color:#111}.fx .rv,.fx tbody tr{opacity:1!important;transform:none!important;filter:none!important}
.badge{border-color:#111;box-shadow:none}.badge i{background:#111;animation:none}.stamp b{color:#111}}
"""

REPORT_JS = """
(function(){
var R=document.documentElement,cur=document.getElementById('cur'),dot=document.getElementById('dot');
var fine=matchMedia('(hover:hover) and (pointer:fine)').matches;
var tx=innerWidth/2,ty=innerHeight/2,cx=tx,cy=ty,M={x:-999,y:-999};

/* cursor + grid light */
addEventListener('pointermove',function(e){
  tx=e.clientX;ty=e.clientY;M.x=tx;M.y=ty;
  R.style.setProperty('--mx',tx+'px');R.style.setProperty('--my',ty+'px');
  if(fine){R.classList.add('fx-on');dot.style.transform='translate('+tx+'px,'+ty+'px)';}
});
(function loop(){cx+=(tx-cx)*.17;cy+=(ty-cy)*.17;cur.style.transform='translate('+cx+'px,'+cy+'px)';requestAnimationFrame(loop);})();
document.addEventListener('pointerover',function(e){cur.classList.toggle('on',!!e.target.closest('input,.card,tbody tr'));});
addEventListener('pointerdown',function(){cur.classList.add('down');});
addEventListener('pointerup',function(){cur.classList.remove('down');});

/* card light + 3D tilt */
document.querySelectorAll('.spot').forEach(function(el){
  el.addEventListener('pointermove',function(e){
    var r=el.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;
    el.style.setProperty('--x',x+'px');el.style.setProperty('--y',y+'px');
    if(el.classList.contains('card')){
      el.style.transform='perspective(800px) rotateX('+(-(y/r.height-.5)*12)+'deg) rotateY('+((x/r.width-.5)*12)+'deg) translateY(-3px)';
    }
  });
  el.addEventListener('pointerleave',function(){if(el.classList.contains('card'))el.style.transform='';});
});

/* entrance animation */
var io=new IntersectionObserver(function(es){es.forEach(function(e){
  if(!e.isIntersecting)return;var t=e.target;t.classList.add('in');io.unobserve(t);
  setTimeout(function(){t.classList.remove('rv','in');t.style.transitionDelay='';},1500+(parseInt(t.style.transitionDelay)||0));
});},{threshold:.06});
document.querySelectorAll('.rv').forEach(function(el,i){el.style.transitionDelay=(i%7)*90+'ms';io.observe(el);});

/* counter animation */
document.querySelectorAll('[data-n]').forEach(function(el){
  var n=+el.dataset.n,d=+el.dataset.d||0,s=el.dataset.s||'',t0=null;
  function f(t){if(!t0)t0=t;var p=Math.min((t-t0)/1500,1),e=1-Math.pow(1-p,4);
    el.textContent=(n*e).toFixed(d)+s;if(p<1)requestAnimationFrame(f);}
  requestAnimationFrame(f);
});

/* search */
var q=document.getElementById('q');
if(q)q.addEventListener('input',function(){var v=q.value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(function(r){r.hidden=v!==''&&r.textContent.toLowerCase().indexOf(v)<0;});});

/* particle network */
var c=document.getElementById('fx'),x=c.getContext('2d'),W,H,P=[];
function rs(){W=c.width=innerWidth;H=c.height=innerHeight;P=[];
  for(var i=0,n=Math.min(90,Math.floor(W*H/17000));i<n;i++)
    P.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.35,vy:(Math.random()-.5)*.35});}
function draw(){
  x.clearRect(0,0,W,H);
  for(var i=0;i<P.length;i++){
    var a=P[i];a.x+=a.vx;a.y+=a.vy;
    if(a.x<0||a.x>W)a.vx*=-1;if(a.y<0||a.y>H)a.vy*=-1;
    var dx=a.x-M.x,dy=a.y-M.y,d=Math.sqrt(dx*dx+dy*dy);
    if(d>1&&d<130){a.x+=dx/d*1.4;a.y+=dy/d*1.4;}
    x.fillStyle='rgba(255,255,255,.55)';x.fillRect(a.x,a.y,1.6,1.6);
    for(var j=i+1;j<P.length;j++){
      var b=P[j],ex=a.x-b.x,ey=a.y-b.y,e=ex*ex+ey*ey;
      if(e<14400){x.strokeStyle='rgba(255,255,255,'+(.14*(1-e/14400))+')';x.beginPath();x.moveTo(a.x,a.y);x.lineTo(b.x,b.y);x.stroke();}
    }
    if(d<190){x.strokeStyle='rgba(255,255,255,'+(.35*(1-d/190))+')';x.beginPath();x.moveTo(a.x,a.y);x.lineTo(M.x,M.y);x.stroke();}
  }
  requestAnimationFrame(draw);
}
rs();addEventListener('resize',rs);
if(!matchMedia('(prefers-reduced-motion:reduce)').matches)draw();
})();
"""

REPORT_CSS += """
.badge.f{border-color:#666;color:#c4c4c4;box-shadow:none}.badge.f i{background:#c4c4c4;animation:none}
.badge.o{border-color:#333;color:#777;box-shadow:none}.badge.o i{background:#777;animation:none}
"""

BADGE = {"open": ("", "OPEN"), "open|filtered": ("f", "OPEN|FILTERED"),
         "filtered": ("f", "FILTERED"), "closed": ("o", "CLOSED")}


def badge(state):
    cls, label = BADGE.get(state, ("o", state.upper()))
    return f"<span class='badge {cls}'><i></i>{html.escape(label)}</span>"


def render_html(rec):
    e = html.escape
    opened, filtered = rec.count("open"), rec.count("filtered") + rec.count("open|filtered")
    cards = [("Hosts", str(len(rec.hosts)), len(rec.hosts), 0, ""), ("Open ports", str(opened), opened, 0, ""),
             ("Filtered", str(filtered), filtered, 0, ""),
             ("Duration", f"{rec.duration:.1f}s", round(rec.duration, 1), 1, "s")]
    cards_html = "".join(
        f"<div class='card spot rv'><div class='k'>{e(k)}</div>"
        f"<div class='v' data-n='{n}' data-d='{d}' data-s='{s}'>{e(t)}</div></div>" for k, t, n, d, s in cards)
    details = "".join(f"<dt>{e(k)}</dt><dd{' class=mono' if m else ''}>{e(v)}</dd>" for k, v, m in (
        ("Profile", rec.profile, False), ("Target", rec.target, False),
        ("Started", rec.started, False), ("Command", rec.command, True)))

    body = []
    if rec.kind == "hosts":
        rows = "".join(
            f"<tr style='--i:{i}'><td class='mono port'>{e(h.ip)}</td><td>{e(h.hostname or '-')}</td>"
            f"<td class='mono'>{e(h.mac or '-')}</td><td><span class='badge'><i></i>UP</span></td></tr>"
            for i, h in enumerate(rec.hosts))
        body.append("<div class='tools rv'><h2>Live hosts</h2>"
                    "<input id='q' type='search' placeholder='Filter'></div>"
                    "<section class='rv'><div class='tablebox spot'><div class='scroll'><table>"
                    "<thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>State</th></tr></thead>"
                    f"<tbody>{rows}</tbody></table></div></div></section>")
    else:
        body.append("<div class='tools rv'><h2>Scan results</h2>"
                    "<input id='q' type='search' placeholder='Search port, service, or version'></div>")
        for h in rec.hosts:
            info = [f"state: {h.state}"] + ([f"os: {h.os}"] if h.os else []) + ([f"mac: {h.mac}"] if h.mac else [])
            name = f"<span class='info'>{e(h.hostname)}</span>" if h.hostname else ""
            head = (f"<div class='host'><span class='ip mono'>{e(h.ip)}</span>{name}"
                    f"<span class='info'>{e('   '.join(info))}</span></div>")
            if not h.rows:
                body.append(f"<section class='rv'>{head}<div class='tablebox spot'>"
                            "<div class='empty'>No open ports found.</div></div></section>")
                continue
            has_script = any(r.script != "-" for r in h.rows)
            rows = "".join(
                f"<tr style='--i:{i}'><td class='mono port'>{r.port}/{e(r.proto)}</td><td>{badge(r.state)}</td>"
                f"<td>{e(r.service)}</td><td class='wrap-cell'>{e(r.version)}</td>"
                + (f"<td class='wrap-cell mono'>{e(clip(r.script, 400))}</td>" if has_script else "") + "</tr>"
                for i, r in enumerate(h.rows))
            th_script = "<th>Script</th>" if has_script else ""
            body.append(f"<section class='rv'>{head}<div class='tablebox spot'><div class='scroll'><table>"
                        "<thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version / Banner</th>"
                        f"{th_script}</tr></thead><tbody>{rows}</tbody></table></div></div></section>")

    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<script>document.documentElement.classList.add('fx')</script>"
            "<link rel='preconnect' href='https://fonts.googleapis.com'>"
            "<link href='https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700"
            "&family=Manrope:wght@400;500;700;800&display=swap' rel='stylesheet'>"
            f"<title>Vastrel Report - {e(clip(rec.target, 60))}</title><style>{REPORT_CSS}</style></head><body>"
            "<canvas id='fx'></canvas><div class='bar'></div><div class='cur' id='cur'></div><div class='dot' id='dot'></div>"
            "<div class='wrap'><header class='rv'><div><div class='brand'>VASTREL</div>"
            "<div class='sub'>Port Scanner - Scan Report</div></div>"
            f"<div class='stamp'>Generated<b>{datetime.now().strftime('%d.%m.%Y %H:%M')}</b></div></header>"
            f"<div class='cards'>{cards_html}</div><dl class='spot rv'>{details}</dl>{''.join(body)}"
            "<footer class='rv'><span>Made by Vastrel</span>"
            "<span>Think you can do better?</span></footer>"
            f"</div><script>{REPORT_JS}</script></body></html>")


# ====================================================================== export
def csv_safe(v):
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


def rows_of(rec):
    return [(h, r) for h in rec.hosts for r in h.rows]


def export_record(rec, cfg, fmt):
    out = Path(cfg.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"vastrel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"

    if fmt == "json":
        path.write_text(json.dumps(asdict(rec), ensure_ascii=False, indent=2), encoding="utf-8")
    elif fmt == "csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if rec.kind == "hosts":
                # Host-discovery records have no port rows, so export host info instead.
                w.writerow(["ip", "hostname", "mac", "state"])
                for h in rec.hosts:
                    w.writerow([csv_safe(x) for x in (h.ip, h.hostname, h.mac, h.state)])
            else:
                w.writerow(["host", "hostname", "proto", "port", "state", "service", "version", "script"])
                for h, r in rows_of(rec):
                    w.writerow([csv_safe(x) for x in (h.ip, h.hostname, r.proto, r.port, r.state,
                                                      r.service, r.version, r.script)])
    elif fmt == "html":
        path.write_text(render_html(rec), encoding="utf-8")
    fix_owner(out, path)
    return path


def firefox_command():
    exe = shutil.which("firefox") or shutil.which("firefox-esr")
    if exe:
        return [exe]
    if sys.platform == "darwin" and Path("/Applications/Firefox.app").exists():
        return ["open", "-a", "Firefox"]
    if sys.platform.startswith("win"):
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if base and (Path(base) / "Mozilla Firefox" / "firefox.exe").exists():
                return [str(Path(base) / "Mozilla Firefox" / "firefox.exe")]
    return None


def open_report(path):
    """Open the report in Firefox. Returns: 'firefox', 'default', or None."""
    uri = Path(path).resolve().as_uri()
    cmd = firefox_command()
    if cmd:
        # When running under sudo, don't launch Firefox as root; switch to the real user.
        if sys.platform.startswith("linux") and is_admin() and os.environ.get("SUDO_USER"):
            cmd = ["sudo", "-E", "-u", os.environ["SUDO_USER"]] + cmd
        try:
            subprocess.Popen(cmd + [uri], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            return "firefox"
        except OSError:
            pass
    try:
        if webbrowser.open(uri):
            return "default"
    except webbrowser.Error:
        pass
    return None


def auto_report(rec, cfg):
    if not cfg.auto_report:
        return
    try:
        path = export_record(rec, cfg, "html")
    except OSError as e:
        err(f"Could not write HTML report: {escape(str(e))}")
        return
    how = open_report(path)
    if how == "firefox":
        ok("HTML report opened in Firefox.")
    elif how:
        warn("Firefox not found, report opened in the default browser.")
    else:
        warn("Report created but the browser could not be opened.")
    note(f"File: {escape(str(path))}")


# ====================================================================== menu flows
def confirm_authorized(state):
    if state["authorized"]:
        return True
    state["authorized"] = ask("  [yellow]Are you sure you want to scan these targets?[/]",
                              choices=["y", "n"], default="n") == "y"
    if not state["authorized"]:
        err("Operation cancelled")
    return state["authorized"]


def start_scan(cfg, menu, history, state):
    if not cfg.targets:
        err("Set a target first (menu 1).")
        return
    menu.profiles_menu(PROFILES, is_admin(), nmap_available())
    choice = ask("  Profile", choices=list(PROFILES) + ["0"], default="1")
    if choice == "0":
        return
    prof = PROFILES[choice]

    if prof["engine"] == "nmap" and not nmap_available():
        err(NMAP_HELP)
        return
    if prof["root"] and not is_admin():
        warn(f"The '{prof['name']}' profile requires root/admin privileges. Run the program with 'sudo python3 scan.py'.")
        return
    if prof["ports"] == "custom":
        p = ask("  Port list", default=cfg.ports).replace(" ", "")
        if parse_ports(p) is None:
            err("Invalid port list. Example: 22,80,443,8000-8100")
            return
        cfg.ports = p
    if not confirm_authorized(state):
        return

    console.print()
    if prof["engine"] == "python":
        rec = python_scan(cfg)
    else:
        ports = cfg.ports if prof["ports"] == "custom" else prof["ports"]
        rec = nmap_scan(cfg, cfg.targets, ports, build_args(cfg, prof, is_admin()), prof["name"])
    if rec:
        history.append(rec)
        show_record(rec)
        console.print()
        auto_report(rec, cfg)


def sweep_flow(cfg, history, state):
    if not cfg.targets:
        err("Set a target first (e.g. 192.168.1.0/24).")
        return
    if not confirm_authorized(state):
        return
    console.print()
    rec = ping_sweep(cfg)
    if rec:
        history.append(rec)
        show_record(rec)
        console.print()
        auto_report(rec, cfg)


def settings_loop(cfg, menu, history):
    toggles = {"3": "version", "4": "scripts", "5": "os_detect", "6": "skip_ping", "10": "auto_report"}
    while True:
        screen(menu, cfg, history)
        menu.settings_menu(cfg, TIMING_NAMES)
        c = ask(PROMPT, choices=[str(i) for i in range(11)], default="0", show_choices=False)
        if c == "0":
            return
        if c in toggles:
            setattr(cfg, toggles[c], not getattr(cfg, toggles[c]))
        elif c == "1":
            p = ask("  Port list", default=cfg.ports).replace(" ", "")
            if parse_ports(p) is None:
                err("Invalid port list. Example: 22,80,443,8000-8100")
                pause()
            else:
                cfg.ports = p
        elif c == "2":
            for i, n in enumerate(TIMING_NAMES):
                console.print(f"    [bold {ACCENT}]{tag(i)}[/]  {n}")
            cfg.timing = int(ask("  Timing", choices=[str(i) for i in range(6)], default=str(cfg.timing)))
        elif c == "7":
            cfg.threads = ask_number("Thread count", int, 1, 1000, cfg.threads)
        elif c == "8":
            cfg.timeout = ask_number("Timeout (s)", float, 0.1, 30, cfg.timeout)
        elif c == "9":
            cfg.out_dir = ask("  Report folder", default=cfg.out_dir).strip() or cfg.out_dir


def export_flow(cfg, history):
    if not history:
        warn("No scan to export yet.")
        return
    rec = pick_record(history)
    fmt = ask("  Format", choices=["html", "json", "csv"], default="html")
    try:
        path = export_record(rec, cfg, fmt)
    except OSError as e:
        err(f"Could not write: {escape(str(e))}")
        return
    ok(f"Saved: {escape(str(path))}")
    if fmt == "html" and ask("  Open in Firefox?", choices=["y", "n"], default="y") == "y":
        if not open_report(path):
            warn("Could not open browser.")


def main():
    cfg, history, state = Settings(), [], {"authorized": False}
    menu = Menu(console)
    while True:
        menu.clear()
        menu.header()
        menu.status(cfg, nmap_available(), is_admin(), len(history))
        menu.main_menu()
        choice = ask(PROMPT, choices=[str(i) for i in range(7)], show_choices=False)

        if choice == "0":
            menu.clear()
            console.print(f"\n  [bold {ACCENT}]VASTREL[/]  [{MUTED}]Made by Vastrel[/]\n")
            return
        if choice == "4":
            settings_loop(cfg, menu, history)
            continue

        screen(menu, cfg, history)
        if choice == "1":
            set_target(cfg, state)
        elif choice == "2":
            start_scan(cfg, menu, history, state)
        elif choice == "3":
            sweep_flow(cfg, history, state)
        elif choice == "5":
            if not history:
                warn("History is empty.")
            else:
                show_record(pick_record(history, "Scan to view"))
        elif choice == "6":
            export_flow(cfg, history)
        pause()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print(f"\n  [red]Exiting...[/]  [{MUTED}]Made by Vastrel[/]")

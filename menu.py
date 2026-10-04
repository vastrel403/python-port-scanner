"""Vastrel Port Scanner - UI (menu) layer | Made by Vastrel"""
from rich import box
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

VERSION = "2.2"

BANNER = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⢰⡆⢘⣆⠀⠀⡆⠀⢸⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⣆⣧⡤⠾⢷⡚⠛⢻⣏⢹⡏⠉⣹⠟⡟⣾⠳⣼⢦⣀⣰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠰⣄⡬⢷⣝⢯⣷⢤⣘⣿⣦⣼⣿⣾⣷⣼⣽⣽⣿⣯⡾⢃⣠⣞⠟⠓⢦⣀⠆⠀⠀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠲⣄⣤⣞⡉⠛⢶⣾⡷⠟⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⡿⢿⡛⠻⠿⣥⣤⣶⠞⠉⢓⣤⡴⢁⠄⠀⠀⠀⠀⠀
⠀⠀⠀⣄⣠⠞⠉⢛⣻⡿⠛⠁⠀⣸⠯⠈⠀⠁⣴⣿⣿⣿⡶⠤⠽⣇⠈⣿⠀⠀⠈⠙⠻⢶⣾⣻⣭⠿⢫⣀⣴⡶⠃⠀⠀
⠀⢤⣀⣜⣉⣩⣽⠿⠋⠀⠀⠀⠀⣿⠈⠀⠀⢸⣿⣿⣿⣿⣀⠀⠀⠸⠇⢸⡇⠀⠀⠀⠀⠀⠘⠛⢶⣶⣾⣻⡯⠄⠀⣠⠄
⠀⠤⠬⢭⣿⣿⠋⠀⠀⠀⠀⠀⠀⢻⡀⠀⠀⠀⢿⣿⣿⣿⡿⠋⠁⠀⠀⣼⠁⠀⠀⠀⠀⠀⢀⣴⣫⣏⣙⠛⠒⠚⠋⠁⠀
⡔⢀⡵⠋⢧⢹⡀⠀⠀⠀⠀⠀⠀⠈⢷⡀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⣰⠏⠀⠀⠀⠀⠀⣠⣾⣿⡛⠛⠛⠓⠦⠀⠀⠀⠀
⣇⠘⠳⠦⠼⠧⠷⣄⣀⠀⠀⠀⠀⠀⠀⠳⢤⣀⠀⠀⠀⠀⠀⢀⣠⠾⠃⠀⠀⠀⣀⣴⣻⣟⡋⠉⠉⢻⠶⠀⠀⠀⠀⠀⠀
⠈⠑⠒⠒⠀⠀⢄⣀⡴⣯⣵⣖⣦⠤⣀⣀⣀⠉⠙⠒⠒⠒⠚⠉⢁⣀⣠⢤⣖⣿⣷⢯⡉⠉⠙⣲⠞⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠣⢤⡞⠉⢉⡿⠒⢻⢿⡿⠭⣭⡭⠿⣿⡿⠒⠻⣯⡷⡄⠉⠳⣬⠷⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠺⠤⣄⣠⡏⠀⠀⡿⠀⠀⠘⡾⠀⢀⣈⡧⠴⠒⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠒⠓⠒⠒⠚⠛⠉⠉⠁⠀⠀
"""

# A single accent color + neutral grays. Green/red/yellow report state only.
ACCENT = "#5fa8d3"
MUTED = "grey50"
BORDER = "grey30"
TABLE_BOX = box.SIMPLE_HEAD
PANEL_BOX = box.SQUARE


def tag(n):
    """Render a menu number as [1] (escaped so it doesn't clash with Rich markup)."""
    return escape(f"[{n}]")


class Menu:
    def __init__(self, console):
        self.console = console

    # ------------------------------------------------------------ screen
    def clear(self):
        self.console.clear()
        if self.console.is_terminal and not self.console.legacy_windows:
            self.console.file.write("\033[3J")  # also clear scrollback
            self.console.file.flush()

    def header(self, compact=False):
        c = self.console
        if compact:
            line = Text("  ")
            line.append("VASTREL", style=f"bold {ACCENT}")
            line.append("  PORT SCANNER", style="bold white")
            line.append(f"    Made by Vastrel  ·  v{VERSION}", style=MUTED)
            c.print(line)
            c.print(Rule(style=BORDER))
            return
        art = Text()
        for row in BANNER.splitlines():
            art.append(row + "\n", style=f"bold {ACCENT}")
        art.rstrip()
        c.print()
        c.print(Padding(art, (0, 2)))
        c.print()
        c.print(Text("  H O L Y  P O R T  S C A N N E R", style="bold white"))
        meta = Text("  ")
        meta.append("Made by Vastrel", style=ACCENT)
        meta.append(f"  ·  v{VERSION}", style=MUTED)
        c.print(meta)
        c.print(Rule(style=BORDER))

    def context(self, cfg, scans):
        """A one-line context bar for sub-screens."""
        targets = ", ".join(cfg.targets[:2]) + (f" +{len(cfg.targets) - 2}" if len(cfg.targets) > 2 else "")
        line = Text("  ")
        for label, val, style in (("TARGET", targets or "not set", "white" if targets else "red"),
                                  ("PORT", cfg.ports, "white"),
                                  ("TIMING", f"T{cfg.timing}", "white"),
                                  ("HISTORY", f"{scans} scan(s)", "white")):
            line.append(label + " ", style=MUTED)
            line.append(val, style=style)
            line.append("     ")
        self.console.print(line)
        self.console.print()

    # ------------------------------------------------------------ status panel
    def status(self, cfg, nmap_ok, admin, scans):
        targets = ", ".join(cfg.targets[:3]) + (f" +{len(cfg.targets) - 3}" if len(cfg.targets) > 3 else "")
        flags = [n for n, on in (("-sV", cfg.version), ("-sC", cfg.scripts),
                                 ("-O", cfg.os_detect), ("-Pn", cfg.skip_ping)) if on]
        g = Table.grid(padding=(0, 3), expand=True)
        g.add_column(style=MUTED, no_wrap=True)
        g.add_column(ratio=1)
        g.add_column(style=MUTED, no_wrap=True)
        g.add_column(ratio=1)
        g.add_row("TARGET", escape(targets) if targets else "[red]not set[/]",
                  "PORT", escape(cfg.ports))
        g.add_row("TIMING", f"T{cfg.timing}",
                  "FLAGS", " ".join(flags) or "-")
        g.add_row("NMAP", "[green]ready[/]" if nmap_ok else "[red]not installed[/]",
                  "PRIVILEGE", "[green]root / admin[/]" if admin else "[dim]standard user[/]")
        g.add_row("HISTORY", f"{scans} scan(s)",
                  "AUTO REPORT", "[green]on[/] [dim](Firefox)[/]" if cfg.auto_report else "[dim]off[/]")
        self.console.print(Panel(g, title=f"[{MUTED}]STATUS[/]", title_align="left",
                                 border_style=BORDER, box=PANEL_BOX, padding=(0, 2)))

    # ------------------------------------------------------------ main menu
    def main_menu(self):
        items = [
            ("1", "Set target", "IP, domain, CIDR, range, or file (@targets.txt)"),
            ("2", "Start scan", "7 built-in scan profiles"),
            ("3", "Network discovery", "List live hosts on the network"),
            ("4", "Settings", "Ports, timing, detection options, reports"),
            ("5", "History", "View previous scans"),
            ("6", "Export report", "HTML / JSON / CSV"),
            ("0", "Exit", ""),
        ]
        g = Table.grid(padding=(0, 3), expand=True)
        g.add_column(justify="right", style=f"bold {ACCENT}", width=4)
        g.add_column(style="bold white", no_wrap=True)
        g.add_column(style=MUTED)
        for n, name, desc in items:
            g.add_row(tag(n), name, desc)
        self.console.print(Panel(g, title=f"[{MUTED}]MENU[/]", title_align="left",
                                 border_style=BORDER, box=PANEL_BOX, padding=(1, 2)))

    # ------------------------------------------------------------ profiles
    def profiles_menu(self, profiles, admin, nmap_ok):
        t = Table(title="SCAN PROFILES", title_justify="left", title_style=f"bold {ACCENT}",
                  box=TABLE_BOX, border_style=BORDER, header_style=MUTED, pad_edge=False)
        t.add_column("", justify="right", style=f"bold {ACCENT}")
        t.add_column("PROFILE", style="bold white")
        t.add_column("DESCRIPTION")
        t.add_column("ENGINE")
        t.add_column("STATUS")
        for key, p in profiles.items():
            if p["engine"] == "nmap" and not nmap_ok:
                state = "[red]nmap missing[/]"
            elif p["root"] and not admin:
                state = "[yellow]root required[/]"
            else:
                state = "[green]ready[/]"
            t.add_row(tag(key), p["name"], p["desc"], p["engine"], state)
        t.add_row(tag(0), "[dim]Back[/]", "", "", "")
        self.console.print(t)
        self.console.print()

    # ------------------------------------------------------------ settings
    def settings_menu(self, cfg, timing_names):
        onoff = lambda b: "[green]on[/]" if b else "[dim]off[/]"
        t = Table(title="SETTINGS", title_justify="left", title_style=f"bold {ACCENT}",
                  box=TABLE_BOX, border_style=BORDER, header_style=MUTED, pad_edge=False)
        t.add_column("", justify="right", style=f"bold {ACCENT}")
        t.add_column("SETTING", style="bold white")
        t.add_column("VALUE")
        rows = [
            (1, "Port list", escape(cfg.ports)),
            (2, "Timing template", f"T{cfg.timing} ({timing_names[cfg.timing]})"),
            (3, "Service version detection (-sV)", onoff(cfg.version)),
            (4, "Default scripts (-sC)", onoff(cfg.scripts)),
            (5, "OS detection (-O, requires root)", onoff(cfg.os_detect)),
            (6, "Skip host discovery (-Pn)", onoff(cfg.skip_ping)),
            (7, "Thread count (Python TCP)", str(cfg.threads)),
            (8, "Timeout (Python TCP)", f"{cfg.timeout}s"),
            (9, "Report folder", escape(cfg.out_dir)),
            (10, "Open HTML report in Firefox after scan", onoff(cfg.auto_report)),
        ]
        for n, name, val in rows:
            t.add_row(tag(n), name, val)
        t.add_row(tag(0), "[dim]Back[/]", "")
        self.console.print(t)
        self.console.print()

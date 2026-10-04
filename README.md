# Vastrel Port Scanner

A menu-driven, terminal-based port scanner written in Python. It wraps `nmap` for fast/standard/full/stealth/UDP scans, and also ships its own multi-threaded Python TCP scanner that works without `nmap` installed. Scan results can be browsed in the terminal, kept in a session history, and exported to HTML (with an auto-generated, styled report), JSON, or CSV.

- **Developer:** 404invisiblepeople
- **Group:** Vastrel

## Features

- **Menu-driven UI** built with [rich](https://github.com/Textualize/rich) — no flags to memorize
- **Seven scan profiles**: Fast (top 100 ports), Standard (1-1024), Full (1-65535), Custom port list, Stealth SYN (`-sS`), UDP (top 50), and a pure-Python multi-threaded TCP scanner with banner grabbing
- **Network discovery / ping sweep** to find live hosts on a subnet
- Multiple target formats: single IP, domain name, CIDR, IP range (`192.168.1.1-50`), comma/space-separated lists, or a target file (`@targets.txt`)
- Service/version detection (`-sV`), NSE scripts (`-sC`), and OS detection (`-O`, requires root) when using `nmap`
- Scan history for the current session, viewable and re-exportable at any time
- Export to **HTML** (a self-contained, animated, searchable report), **JSON**, or **CSV**
- Auto-generates and opens an HTML report after every scan (opens in Firefox if available, otherwise your default browser)
- Confirmation prompt before scanning any target, to reduce the chance of scanning something by accident

## Requirements

- Python 3.8+
- [`python-nmap`](https://pypi.org/project/python-nmap/) and [`rich`](https://pypi.org/project/rich/)
- `nmap` installed on your system for all profiles except the Python TCP scanner ([nmap.org/download](https://nmap.org/download.html))
- Firefox is optional — if it's not found, reports open in your default browser instead

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

## Project structure

This repository's entry point (`scan.py`) imports a small local module, `menu.py`, which provides the UI building blocks (`Menu`, `ACCENT`, `BORDER`, `MUTED`, `PANEL_BOX`, `TABLE_BOX`, `tag`). Make sure `menu.py` sits next to `scan.py` in the repo — the script will not run without it.

```
.
├── scan.py
├── menu.py
├── requirements.txt
└── README.md
```

## Usage

```bash
python3 scan.py
```

Some scan profiles (Stealth SYN, UDP, and OS detection) require raw-socket privileges:

```bash
sudo python3 scan.py
```

From the main menu you can:

1. **Set target(s)** — IP, domain, CIDR, range, list, or `@file.txt`
2. **Start a scan** — pick one of the seven profiles
3. **Network discovery** — ping-sweep a subnet to find live hosts
4. **Settings** — port list, timing template, version/script/OS detection toggles, ping-skip, threads, timeout, report folder, auto-report
5. **History** — browse past scans from this session
6. **Export** — save any scan as HTML, JSON, or CSV
0. **Exit**

You'll be asked to confirm before any target is actually scanned.

## Scan profiles

| # | Profile     | Description                                   | Engine | Root required |
|---|-------------|------------------------------------------------|--------|:--------------:|
| 1 | Fast        | Top 100 most common ports                       | nmap   |       -        |
| 2 | Standard    | Ports 1-1024                                    | nmap   |       -        |
| 3 | Full        | All ports (1-65535)                             | nmap   |       -        |
| 4 | Custom      | Your own port list (e.g. `22,80,8000-8100`)     | nmap   |       -        |
| 5 | Stealth SYN | Half-open (`-sS`) scan, ports 1-1024            | nmap   |       Yes      |
| 6 | UDP         | Top 50 most common UDP ports                    | nmap   |       Yes      |
| 7 | Python TCP  | No nmap required, multi-threaded, grabs banners | Python |       -        |

## Legal disclaimer

Only scan systems and networks you own or have explicit, written authorization to test. Port scanning systems without permission may be illegal in your jurisdiction. The authors take no responsibility for misuse of this tool.

## License

Feel free to add a license of your choice (e.g. MIT) to this repository.

# NetScan - Network Scanner
# cli/cli.py - Command-line interface and main application logic
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import shutil
import socket
import sys
from pathlib import Path
from typing import Dict

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn
)

from core.scanner import NetworkScanner
from cli.exporter import export_csv, export_json
from cli.renderer import render_summary, render_table
from utils.loadsubnets import load_subnets_from_file
from core.db_updater import FingerprintDBUpdater
from utils.updater import check_for_updates
from version import __author__, __company__, __version__

console = Console()

# -------------------------------------------------
# Banner
# -------------------------------------------------

def print_banner(update_message=None):
    logo = [
        r" _   _      _   _____                 ",
        r"| \ | |    | | /  ___|                ",
        r"|  \| | ___| |_\ `--.  ___ __ _ _ __  ",
        r"| . ` |/ _ \ __|`--. \/ __/ _` | '_ \ ",
        r"| |\  |  __/ |_/\__/ / (_| (_| | | | |",
        r"\_| \_/\___|\__\____/ \___\__,_|_| |_|"
    ]

    info = [
        f"Version {__version__}",
        f"Made by {__company__}",
        "A tool from the NetTools Portfolio",
        f"Author: {__author__}"
    ]

    console.print()
    
    max_logo_width = max(len(line) for line in logo)
    spacing = 8
    info_start_line = len(logo) - len(info)

    for i in range(len(logo)):
        left = logo[i]
        right = info[i - info_start_line] if i >= info_start_line else ""
        padding = max_logo_width - len(left)

        console.print(
            f"[bold cyan]{left}[/bold cyan]"
            + " " * (padding + spacing)
            + f"[bold white]{right}[/bold white]"
        )

    if update_message:
        console.print(f"[dim]{update_message}[/dim]")
    else:
        console.print()


# -------------------------------------------------
# Helpers
# -------------------------------------------------


def sanitize_targets(inputs: list[str]) -> list[str]:
    """
    Accepts:
        - single IP
        - subnet
        - IP range (start-end)

    Returns:
        normalized CIDR list
    """
    targets = []

    for entry in inputs:

        entry = entry.strip()

        # -------------------------
        # IP Range
        # -------------------------
        if "-" in entry:
            start, end = entry.split("-", 1)

            try:
                start_ip = ipaddress.ip_address(start)
                end_ip = ipaddress.ip_address(end)

                if start_ip > end_ip:
                    console.print(f"[red]Invalid range:[/red] {entry}")
                    continue

                current = start_ip
                while current <= end_ip:
                    targets.append(f"{current}/32")
                    current += 1

            except Exception:
                console.print(f"[red]Invalid IP range:[/red] {entry}")

        # -------------------------
        # Subnet
        # -------------------------
        elif "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                targets.append(str(net))
            except Exception:
                console.print(f"[red]Invalid subnet:[/red] {entry}")

        # -------------------------
        # Single IP
        # -------------------------
        else:
            try:
                ip = ipaddress.ip_address(entry)
                targets.append(f"{ip}/32")
            except Exception:
                console.print(f"[red]Invalid IP address:[/red] {entry}")

    return targets

def safe_input(prompt: str, default: str = "n") -> str:
    try:
        return input(prompt).lower()
    except KeyboardInterrupt:
        print()
        return default


def suggest_local_subnet() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return None


# -------------------------------------------------
# Fingerprint DB Path Handling
# -------------------------------------------------

def get_fingerprint_db_path() -> Path:
    """
    Frozen EXE:
        Use ProgramData (writable, survives upgrades)

    Dev/script mode:
        Use project fingerprints folder
    """

    if getattr(sys, "frozen", False):
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        path = program_data / "NetScan" / "fingerprints"
        path.mkdir(parents=True, exist_ok=True)
        return path

    project_root = Path(__file__).resolve().parent.parent
    return project_root / "fingerprints"


def seed_fingerprint_db_if_missing(target_dir: Path) -> None:
    """
    If ProgramData fingerprint directory is empty,
    copy bundled fingerprints from install folder.
    """

    if not getattr(sys, "frozen", False):
        return

    if any(target_dir.glob("*.json")):
        return

    install_dir = Path(sys.executable).parent
    bundled_dir = install_dir / "fingerprints"

    if bundled_dir.exists():
        shutil.copytree(bundled_dir, target_dir, dirs_exist_ok=True)

# -------------------------------------------------
# Parallel Subnet Scanning
# -------------------------------------------------

async def scan_all_subnets_parallel(
    subnets: list[str],
    scanner: NetworkScanner,
    max_parallel_subnets: int
) -> Dict[str, dict]:

    all_results: Dict[str, dict] = {}
    subnet_sem = asyncio.Semaphore(max_parallel_subnets)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False
    ) as progress:

        async def scan_one(subnet: str):
            async with subnet_sem:
                task_id = progress.add_task(f"Scanning {subnet}", total=1)

                def cb(completed, total):
                    progress.update(task_id, completed=completed, total=total)

                res = await scanner.scan(subnet, progress_callback=cb)
                all_results[subnet] = res

        await asyncio.gather(*(scan_one(s) for s in subnets))

    return all_results


# -------------------------------------------------
# Main
# -------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetScan - Network Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
    "targets",
    nargs="*",
    help="""
Targets to scan.
Supported formats:
  Single IP
      netscan 10.1.1.10
  Multiple IPs
      netscan 10.1.1.10 10.1.1.20
  CIDR subnet
      netscan 10.1.1.0/24
  IP range
      netscan 10.1.1.10-10.1.1.50
  Mixed targets
      netscan 10.1.1.0/24 10.2.2.10 10.3.3.10-10.3.3.20
"""
)
    parser.add_argument(
    "--file",
    help="""
File containing scan targets (one per line).

Supported formats inside the file:

    10.1.1.10
    10.1.1.0/24
    10.1.1.10-10.1.1.50
"""
)
    parser.add_argument("--json", help="Export results to JSON")
    parser.add_argument("--csv", help="Export results to CSV")
    parser.add_argument("--parallel-subnets", type=int, default=3, help="Max number of subnets to scan in parallel, default: 3")
    parser.add_argument("--no-update-check", action="store_true",help="Skip application and fingerprint DB update checks") 
    parser.add_argument("--version", action="version", version=f"NetScan {__version__}")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with verbose output")
    parser.add_argument("--learning",action="store_true",help="Enable fingerprint learning mode (extended evidence collection)")
    parser.add_argument("--update-fingerprints",action="store_true",help="Update fingerprint database and exit"
)
    parser.epilog="""
        Examples:

        netscan 10.1.1.0/24
        netscan 10.1.1.10
        netscan 10.1.1.10-10.1.1.100
        netscan 10.1.1.0/24 10.2.2.0/24
        netscan --file targets.txt
        netscan 10.1.1.0/24 --json results.json
        """
    args = parser.parse_args()

    update_message = None

    if not args.no_update_check:
        app_update = check_for_updates()
        if app_update["status"] == "outdated":
            update_message = f"New version available: {app_update['latest']}"
        elif app_update["status"] == "latest":
            update_message = "Application up to date"
        else:
            update_message = "Update check skipped (offline or blocked)"

    # Fingerprint DB handling
    db_path = get_fingerprint_db_path()
    seed_fingerprint_db_if_missing(db_path)
    
    console.print(f"[dim]Using fingerprint DB at: {db_path}[/dim]")

    db_updater = FingerprintDBUpdater(
        local_dir=str(db_path),
        remote_base_url="https://raw.githubusercontent.com/martinarosjorde-byte/netscan/main/fingerprints"
    )

    updates_available = db_updater.check_updates()

    if args.update_fingerprints:

        updated = db_updater.update()

        console.print(f"[green]Updated {len(updated)} fingerprint pack(s).[/green]")
        return


    if updates_available is None:
        pass  # check skipped (recent)

    elif updates_available:
        update_message = (
            f"Fingerprint updates available ({len(updates_available)} packs). "
            f"Run 'netscan --update-fingerprints'"
        )

    else:
        update_message = "Fingerprint DB up to date"
        

    print_banner(update_message)

    # -------------------------------------------------
    # Determine targets
    # -------------------------------------------------

    targets: list[str] = []

    if args.targets:
        targets.extend(args.targets)

    if args.file:
        targets.extend(load_subnets_from_file(args.file))

    if not targets:
        local = suggest_local_subnet()
        if local:
            console.print(f"[dim]No target provided. Auto-scanning {local}[/dim]")
            targets.append(local)
        else:
            console.print("[red]Could not determine local subnet.[/red]")
            return

    validated = sanitize_targets(targets)

    if not validated:
        console.print("[red]No valid targets to scan.[/red]")
        return

    # -------------------------------------------------
    # Scan
    # -------------------------------------------------

    scanner = NetworkScanner(debug=args.debug, fingerprint_db_path=str(db_path), learning=args.learning)

    console.print(
        f"\n[bold cyan]Scanning {len(validated)} target(s) "
        f"in parallel (max {args.parallel_subnets})...[/bold cyan]\n"
    )

    all_results = asyncio.run(
        scan_all_subnets_parallel(validated, scanner, args.parallel_subnets)
    )

    # -------------------------------------------------
    # Render
    # -------------------------------------------------

    for subnet in validated:
        results = all_results.get(subnet, {})
        render_table(subnet, results)
        render_summary(results)

    # -------------------------------------------------
    # Export
    # -------------------------------------------------

    if args.json:
        console.print(f"\n[green]Exporting JSON -> {args.json}[/green]")
        export_json(all_results, args.json)

    if args.csv:
        console.print(f"[green]Exporting CSV  -> {args.csv}[/green]")
        export_csv(all_results, args.csv)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user. Exiting.[/red]")
        sys.exit(0)
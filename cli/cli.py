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
from utils.updater import check_for_updates, FingerprintDBUpdater
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
        Use project fingerprints/fingerprints.json
    """
    if getattr(sys, "frozen", False):
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        return program_data / "NetScan" / "fingerprints.json"

    project_root = Path(__file__).resolve().parent.parent
    return project_root / "fingerprints" / "fingerprints.json"


def seed_fingerprint_db_if_missing(target_db: Path) -> None:
    """
    If ProgramData DB is missing, copy the shipped default DB from install folder.
    Only applies to frozen EXE.
    """
    if target_db.exists():
        return

    if not getattr(sys, "frozen", False):
        return

    target_db.parent.mkdir(parents=True, exist_ok=True)

    install_dir = Path(sys.executable).parent
    bundled_db = install_dir / "fingerprints" / "fingerprints.json"

    if bundled_db.exists():
        shutil.copyfile(bundled_db, target_db)


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

    parser.add_argument("subnets", nargs="*", help="Subnets to scan")
    parser.add_argument("--file", help="File containing subnets")
    parser.add_argument("--json", help="Export results to JSON")
    parser.add_argument("--csv", help="Export results to CSV")
    parser.add_argument("--parallel-subnets", type=int, default=3)
    parser.add_argument("--no-update-check", action="store_true")
    parser.add_argument("--version", action="version", version=f"NetScan {__version__}")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--learning",action="store_true",help="Enable fingerprint learning mode (extended evidence collection)"
)
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

    db_updater = FingerprintDBUpdater(str(db_path))

    if not db_updater.exists():
        console.print(f"[yellow]Fingerprint DB not found at: {db_path}[/yellow]")
        choice = safe_input("Download latest fingerprint DB now? (y/n): ")
        if choice == "y":
            if db_updater.download():
                update_message = "Fingerprint DB downloaded."
            else:
                update_message = "Fingerprint DB download failed."
    else:
        local_version = db_updater.get_local_version()
        if local_version:
            update_message = f"Fingerprint DB version {local_version}"

    print_banner(update_message)

    # -------------------------------------------------
    # Determine subnets
    # -------------------------------------------------

    subnets: list[str] = []
    if args.subnets:
        subnets.extend(args.subnets)
    if args.file:
        subnets.extend(load_subnets_from_file(args.file))

    if not subnets:
        local = suggest_local_subnet()
        if local:
            console.print(f"[dim]No subnet provided. Auto-scanning {local}[/dim]")
            subnets.append(local)
        else:
            console.print("[red]Could not determine local subnet.[/red]")
            return

    validated: list[str] = []
    for s in subnets:
        try:
            ipaddress.ip_network(s, strict=False)
            validated.append(s)
        except Exception:
            console.print(f"[red]Invalid subnet skipped:[/red] {s}")

    if not validated:
        console.print("[red]No valid subnets to scan.[/red]")
        return

    # -------------------------------------------------
    # Scan
    # -------------------------------------------------

    scanner = NetworkScanner(debug=args.debug, fingerprint_db_path=str(db_path), learning=args.learning)

    console.print(
        f"\n[bold cyan]Scanning {len(validated)} subnet(s) "
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
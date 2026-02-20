from __future__ import annotations

import argparse
import asyncio
import ipaddress
import shutil
import socket
import time
from typing import Dict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from core.scanner import NetworkScanner
from cli.exporter import export_csv, export_json
from cli.renderer import render_summary, render_table
from utils.loadsubnets import load_subnets_from_file
from version import __author__, __company__, __version__
from utils.updater import  check_for_updates

console = Console()



from rich.console import Console
import shutil
import time
from version import __version__, __author__, __company__

console = Console()


def print_banner(update_message=None):
    width = shutil.get_terminal_size().columns

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

    if not update_message:
        update_message = "Update check skipped (offline or blocked)"

    console.print()

    max_logo_width = max(len(line) for line in logo)
    spacing = 8

    logo_height = len(logo)
    info_height = len(info)

    # Calculate how many empty lines before info starts
    info_start_line = logo_height - info_height

    for i in range(logo_height):
        left = logo[i]

        # Only print info when reaching bottom-aligned start
        if i >= info_start_line:
            right = info[i - info_start_line]
        else:
            right = ""

        padding = max_logo_width - len(left)

        line = (
            f"[bold cyan]{left}[/bold cyan]"
            + " " * (padding + spacing)
            + f"[bold white]{right}[/bold white]"
        )

        console.print(line)
        #time.sleep(0.05)

    console.print(f"[dim]{update_message}[/dim]")
    

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


async def scan_all_subnets_parallel(
    subnets: list[str],
    scanner: NetworkScanner,
    max_parallel_subnets: int
) -> Dict[str, dict]:
    """
    Runs subnet scans in parallel with a cap on parallel subnets.
    Shows per-subnet progress bars (accurate total set after discovery).
    """
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
                # create a task with placeholder total; scanner will update it after discovery
                task_id = progress.add_task(f"Scanning {subnet}", total=1)

                def cb(completed, total):
                    progress.update(
                        task_id,
                        completed=completed,
                        total=total
                    )

                res = await scanner.scan(subnet, progress_callback=cb)
                all_results[subnet] = res

        await asyncio.gather(*(scan_one(s) for s in subnets))

    return all_results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetScan - Network Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("subnets", nargs="*", help="Subnets to scan (e.g. 10.1.1.0/24 10.2.2.0/24)")
    parser.add_argument("--file", help="File containing subnets (one per line)")
    parser.add_argument("--json", help="Export results to JSON file (merged output)")
    parser.add_argument("--csv", help="Export results to CSV file (merged output)")
    parser.add_argument("--parallel-subnets", type=int, default=3, help="Max subnets scanned in parallel (default: 3)")
    parser.add_argument("--version", action="version", version=f"NetScan {__version__}")

    args = parser.parse_args()

    print_banner()

    # Determine subnets
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

    # Validate subnets early
    validated: list[str] = []
    for s in subnets:
        try:
            ipaddress.ip_network(s, strict=False)
            validated.append(s)
        except Exception:
            console.print(f"[red]Invalid subnet skipped:[/red] {s}")
    subnets = validated
    if not subnets:
        console.print("[red]No valid subnets to scan.[/red]")
        return

    # Run scans (parallel)
    scanner = NetworkScanner()
    console.print(f"\n[bold cyan]Scanning {len(subnets)} subnet(s) in parallel (max {args.parallel_subnets})...[/bold cyan]\n")
    all_results = asyncio.run(scan_all_subnets_parallel(subnets, scanner, args.parallel_subnets))

    # Render results per subnet
    for subnet in subnets:
        results = all_results.get(subnet, {})
        render_table(subnet, results)
        render_summary(results)

    # Export merged output
    if args.json:
        console.print(f"\n[green]Exporting JSON -> {args.json}[/green]")
        export_json(all_results, args.json)

    if args.csv:
        console.print(f"[green]Exporting CSV  -> {args.csv}[/green]")
        export_csv(all_results, args.csv)


if __name__ == "__main__":
    main()

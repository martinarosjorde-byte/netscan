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
from utils import load_subnets_from_file
from version import __author__, __company__, __version__

console = Console()


def print_banner() -> None:
    width = shutil.get_terminal_size().columns

    full_logo = [
        " _   _      _   _____                 ",
        "| \\ | |    | | /  ___|                ",
        "|  \\| | ___| |_\\ `--.  ___ __ _ _ __  ",
        "| . ` |/ _ \\ __|`--. \\/ __/ _` | '_ \\ ",
        "| |\\  |  __/ |_/\__/ / (_| (_| | | | |",
        "\\_| \\_/\\___|\\__\\____/ \\___\\__,_|_| |_|"
    ]

    compact_logo = [
        " _   _      _   _____ ",
        "| \\ | |    | | /  ___|",
        "|  \\| | ___| |_\\ `--. ",
        "| . ` |/ _ \\ __|`--. \\",
        "| |\\  |  __/ |_/\__/ /",
        "\\_| \\_/\\___|\\__\\____/ "
    ]

    logo = full_logo if width >= 80 else compact_logo

    console.print()
    for line in logo:
        console.print(f"[bold cyan]{line}[/bold cyan]")
        time.sleep(0.06)

    console.print(f"[bold white]Version {__version__}[/bold white]")
    console.print(f"[bold white]Made by {__company__}[/bold white]")
    console.print("[dim]A tool from the NetTools Portfolio[/dim]")
    console.print(f"[dim]Author: {__author__}[/dim]")
    console.print()


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

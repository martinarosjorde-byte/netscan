# cli/cli.py

import asyncio
import argparse
import socket
from rich.console import Console
from rich.text import Text
import shutil
import time
from version import __version__, __author__, __company__
from core.scanner import NetworkScanner
from cli.renderer import render_table, render_summary
from cli.exporter import export_json, export_csv
from utils import load_subnets_from_file
from version import __version__, __author__, __company__
console = Console()


# -------------------------------------------------
# Banner
# -------------------------------------------------


def print_banner():

    console = Console()
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

    # Animated reveal
    for line in logo:
        console.print(f"[bold cyan]{line}[/bold cyan]")
        time.sleep(0.08)

    console.print(f"[bold white]Version {__version__}[/bold white]")
    console.print(f"[bold white]Made by {__company__}[/bold white]")
    console.print("[dim]A tool from the NetTools Portfolio[/dim]")
    console.print(f"[dim]Author: {__author__}[/dim]")

    console.print()


# -------------------------------------------------
# Suggest Local Subnet
# -------------------------------------------------

def suggest_local_subnet():
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
# CLI Entry
# -------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="NetScan - Network Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "subnets",
        nargs="*",
        help="Subnets to scan (e.g. 10.1.1.0/24 10.2.2.0/24)"
    )

    parser.add_argument(
        "--file",
        help="File containing subnets (one per line)"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"NetScan {__version__}"
)

    parser.add_argument(
        "--json",
        help="Export results to JSON file"
    )

    parser.add_argument(
        "--csv",
        help="Export results to CSV file"
    )

    args = parser.parse_args()

    print_banner()

    # -------------------------------------------------
    # Determine subnets
    # -------------------------------------------------

    subnets = []

    if args.subnets:
        subnets.extend(args.subnets)

    if args.file:
        subnets.extend(load_subnets_from_file(args.file))

    # Auto scan local network if nothing provided
    if not subnets:
        local = suggest_local_subnet()
        if local:
            console.print(f"[dim]No subnet provided. Auto-scanning {local}[/dim]")
            subnets.append(local)
        else:
            console.print("[red]Could not determine local subnet.[/red]")
            return

    # -------------------------------------------------
    # Scanner
    # -------------------------------------------------

    scanner = NetworkScanner()
    all_results = {}

    for subnet in subnets:
        console.print(f"\n[bold cyan]Scanning {subnet}...[/bold cyan]")
        results = asyncio.run(scanner.scan(subnet))
        render_table(subnet, results)
        render_summary(results)
        all_results[subnet] = results

    if args.json:
        export_json(all_results, args.json)

    if args.csv:
        export_csv(all_results, args.csv)

if __name__ == "__main__":
    main()

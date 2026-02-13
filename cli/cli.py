# cli/cli.py

import asyncio
import argparse
import socket
from rich.console import Console
from rich.text import Text

from core.scanner import NetworkScanner
from cli.renderer import render_table, render_summary
from cli.exporter import export_json, export_csv
from utils import load_subnets_from_file

console = Console()


# -------------------------------------------------
# Banner
# -------------------------------------------------

def print_banner():
    banner = Text()
    banner.append("NetScan Enterprise\n", style="bold cyan")
    banner.append("Made by Humbug Software\n", style="bold white")
    banner.append("A tool from the NetTools Portfolio\n", style="dim")
    banner.append("Author: Martin Røsjorde\n", style="dim")
    console.print(banner)


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
        description="NetScan Enterprise - Multi Network Scanner",
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

    for subnet in subnets:

        console.print(f"\n[bold cyan]Scanning {subnet}...[/bold cyan]")

        results = asyncio.run(scanner.scan(subnet))

        render_table(subnet, results)
        render_summary(results)

        if args.json:
            export_json(results, args.json)
            console.print(f"[green]JSON exported to {args.json}[/green]")

        if args.csv:
            export_csv(results, args.csv)
            console.print(f"[green]CSV exported to {args.csv}[/green]")


if __name__ == "__main__":
    main()

import asyncio
import ipaddress
import socket
import time
from collections import defaultdict

from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress
from rich.console import Console

PORTS = [22, 80, 443, 445, 3389]
TIMEOUT = 0.5
MAX_CONCURRENT = 2000

console = Console()

stats = {
    "checked": 0,
    "open": 0,
    "start": time.time()
}

results = defaultdict(list)


def suggest_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


async def check_port(ip, port, semaphore):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port),
                timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()

            results[str(ip)].append(port)
            stats["open"] += 1

        except:
            pass
        finally:
            stats["checked"] += 1


def build_layout(total_checks):
    layout = Layout()

    layout.split_row(
        Layout(name="hosts", ratio=3),
        Layout(name="stats", ratio=1)
    )

    # Hosts table
    table = Table(title="Discovered Hosts", expand=True)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Open Ports", style="green")

    for ip in sorted(results.keys()):
        ports = sorted(results[ip])
        table.add_row(ip, ", ".join(map(str, ports)))

    layout["hosts"].update(Panel(table))

    # Stats panel
    elapsed = time.time() - stats["start"]
    speed = int(stats["checked"] / elapsed) if elapsed > 0 else 0

    stats_text = (
        f"Total Checks: {total_checks}\n"
        f"Completed: {stats['checked']}\n"
        f"Open Ports: {stats['open']}\n"
        f"Speed: {speed} checks/sec\n"
        f"Elapsed: {int(elapsed)} sec"
    )

    layout["stats"].update(Panel(stats_text, title="Scan Statistics"))

    return layout



async def scan_network(subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    ips = list(network.hosts())
    total_checks = len(ips) * len(PORTS)

    with Live(build_layout(total_checks), refresh_per_second=5) as live:
        tasks = []
        for ip in ips:
            for port in PORTS:
                tasks.append(check_port(ip, port, semaphore))

        for coro in asyncio.as_completed(tasks):
            await coro
            live.update(build_layout(total_checks))


def main():
    subnet = input(f"Enter subnet [{suggest_subnet()}]: ").strip() or suggest_subnet()

    console.print(f"\n[bold green]Scanning {subnet}...[/bold green]\n")

    asyncio.run(scan_network(subnet))

    console.print("\n[bold green]Scan complete.[/bold green]\n")


if __name__ == "__main__":
    main()

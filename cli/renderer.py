# cli/renderer.py

from rich.table import Table
from rich.console import Console

console = Console()


def render_table(subnet, results):

    table = Table(
        title=f"[bold cyan]Results for {subnet}[/bold cyan]",
        header_style="bold white",
        show_lines=False
    )

    table.add_column("IP", style="cyan")
    table.add_column("Hostname")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("Open Ports")
    table.add_column("HTTP")
    table.add_column("SSH")

    for ip, data in results.items():

        ports = ", ".join(map(str, data["ports"]))
        http = (data.get("http") or {}).get("server") or ""
        ssh = data.get("ssh_banner") or ""

        table.add_row(
            ip,
            data.get("hostname") or "",
            data.get("mac") or "",
            data.get("vendor") or "",
            ports,
            http,
            ssh
        )

    console.print(table)


def render_summary(results):

    total_hosts = len(results)
    hosts_with_ports = sum(1 for d in results.values() if d["ports"])
    total_ports = sum(len(d["ports"]) for d in results.values())

    console.print()
    console.print(
        f"[bold]Hosts:[/bold] {total_hosts}  "
        f"[bold]Open:[/bold] {hosts_with_ports}  "
        f"[bold]Ports:[/bold] {total_ports}"
    )

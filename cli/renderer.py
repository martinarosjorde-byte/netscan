# cli/renderer.py

from rich.table import Table
from rich.console import Console

console = Console()


import ipaddress
from rich.table import Table
from rich.console import Console

console = Console()


def render_table(subnet, results):

    if not results:
        return

    # Determine which columns have any data
    show_columns = {
        "hostname": any(d.get("hostname") for d in results.values()),
        "mac": any(d.get("mac") for d in results.values()),
        "vendor": any(d.get("vendor") for d in results.values()),
        "ports": any(d.get("ports") for d in results.values()),
        "http": any(d.get("http_80") or d.get("http_443") for d in results.values()),
        "cert": any(
            (d.get("http_443") and d["http_443"].get("cert"))
            for d in results.values()
        ),
        "ssh": any(d.get("ssh_banner") for d in results.values()),
        "smtp": any(d.get("smtp_banner") for d in results.values()),
        "ftp": any(d.get("ftp_banner") for d in results.values()),
        "pop3": any(d.get("pop3_banner") for d in results.values()),
        "imap": any(d.get("imap_banner") for d in results.values()),
    }

    table = Table(
        title=f"[bold cyan]Results for {subnet}[/bold cyan]",
        header_style="bold white",
        show_lines=False
    )

    # Always show IP
    table.add_column("IP", style="cyan")

    if show_columns["hostname"]:
        table.add_column("Hostname")

    if show_columns["mac"]:
        table.add_column("MAC")

    if show_columns["vendor"]:
        table.add_column("Vendor")

    if show_columns["ports"]:
        table.add_column("Open Ports")

    if show_columns["http"]:
        table.add_column("HTTP")

    if show_columns["cert"]:
        table.add_column("Cert")

    if show_columns["ssh"]:
        table.add_column("SSH")

    if show_columns["smtp"]:
        table.add_column("SMTP")

    if show_columns["ftp"]:
        table.add_column("FTP")

    if show_columns["pop3"]:
        table.add_column("POP3")

    if show_columns["imap"]:
        table.add_column("IMAP")

    # Sort IPs numerically
    for ip in sorted(results.keys(), key=lambda x: ipaddress.ip_address(x)):
        data = results[ip]

        row = [ip]

        if show_columns["hostname"]:
            row.append(data.get("hostname") or "")

        if show_columns["mac"]:
            row.append(data.get("mac") or "")

        if show_columns["vendor"]:
            row.append(data.get("vendor") or "")

        if show_columns["ports"]:
            ports = ", ".join(map(str, data.get("ports") or []))
            row.append(ports)

        if show_columns["http"]:
            http_data = data.get("http_443") or data.get("http_80") or {}
            status = http_data.get("status") or ""
            server = http_data.get("server") or ""
            title = http_data.get("title") or ""

            http_parts = [p for p in [status, server, title] if p]
            row.append(" | ".join(http_parts))

        if show_columns["cert"]:
            cert = (data.get("http_443") or {}).get("cert") or {}
            row.append(cert.get("common_name") or "")

        if show_columns["ssh"]:
            row.append(data.get("ssh_banner") or "")

        if show_columns["smtp"]:
            row.append(data.get("smtp_banner") or "")

        if show_columns["ftp"]:
            row.append(data.get("ftp_banner") or "")

        if show_columns["pop3"]:
            row.append(data.get("pop3_banner") or "")

        if show_columns["imap"]:
            row.append(data.get("imap_banner") or "")

        table.add_row(*row)

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

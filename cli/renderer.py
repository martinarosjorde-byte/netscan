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
    table.add_column("Cert")
    table.add_column("SSH")
    table.add_column("SMTP")
    table.add_column("FTP")
    table.add_column("POP3")
    table.add_column("IMAP")
    

    for ip, data in results.items():

        ports = ", ".join(map(str, data["ports"]))
        http_data = data.get("http_443") or data.get("http_80") or {}
        cert = http_data.get("cert") or {}

        # ---- HTTP Display ----
        http_display = ""

        if http_data:
            status = http_data.get("status") or ""
            server = http_data.get("server") or ""
            title = http_data.get("title") or ""

            http_parts = []
            if status:
                http_parts.append(f"{status}")
            if server:
                http_parts.append(server)
            if title:
                http_parts.append(title)

            http_display = " | ".join(http_parts)

        # ---- Cert Display ----
        cert_cn = cert.get("common_name") or ""
        cert_exp = cert.get("expires") or ""

        cert_display = ""

        if cert_cn:
            cert_display = cert_cn

        # ---- SSH ----
        ssh = data.get("ssh_banner") or ""
        smtp = data.get("smtp_banner") or ""
        ftp = data.get("ftp_banner") or ""
        pop3 = data.get("pop3_banner") or ""
        imap = data.get("imap_banner") or ""

        table.add_row(
        ip,
        data.get("hostname") or "",
        data.get("mac") or "",
        data.get("vendor") or "",
        ports,
        http_display,
        cert_display,
        ssh,
        smtp,
        ftp,
        pop3,
        imap
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

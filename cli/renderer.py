# cli/renderer.py

from rich.table import Table
from rich.console import Console
import ipaddress

console = Console()


# -------------------------------------------------
# Table Renderer
# -------------------------------------------------

def render_table(subnet, results):

    if not results:
        return

    # -----------------------------
    # Determine dynamic columns
    # -----------------------------
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
        "os": any(d.get("os_family") for d in results.values()),
        "identity": any(d.get("device_identity") for d in results.values()),
        "services": any(d.get("services") for d in results.values()),
    }

    table = Table(
        title=f"[bold cyan]Results for {subnet}[/bold cyan]",
        header_style="bold white",
        show_lines=False
    )

    # -----------------------------
    # Column Order (clean layout)
    # -----------------------------

    table.add_column("IP", style="cyan")

    if show_columns["hostname"]:
        table.add_column("Hostname")

    if show_columns["mac"]:
        table.add_column("MAC")

    if show_columns["vendor"]:
        table.add_column("Vendor")

    if show_columns["os"]:
        table.add_column("OS")

    if show_columns["identity"]:
        table.add_column("Identity")

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

    if show_columns["services"]:
        table.add_column("Services")

    # -----------------------------
    # Build Rows
    # -----------------------------

    for ip in sorted(results.keys(), key=lambda x: ipaddress.ip_address(x)):

        data = results[ip]
        row = [ip]

        if show_columns["hostname"]:
            row.append(data.get("hostname") or "")

        if show_columns["mac"]:
            row.append(data.get("mac") or "")

        if show_columns["vendor"]:
            row.append(data.get("vendor") or "")

        # -----------------------------
        # OS Display (color-coded)
        # -----------------------------
        if show_columns["os"]:
            os_name = data.get("os_family") or ""
            os_conf = data.get("os_confidence") or 0

            if os_name:
                if os_conf >= 0.8:
                    os_display = f"[green]{os_name} ({int(os_conf*100)}%)[/green]"
                elif os_conf >= 0.5:
                    os_display = f"[yellow]{os_name} ({int(os_conf*100)}%)[/yellow]"
                else:
                    os_display = f"[red]{os_name} ({int(os_conf*100)}%)[/red]"
            else:
                os_display = ""

            row.append(os_display)

        # -----------------------------
        # Identity
        # -----------------------------
        if show_columns["identity"]:
            row.append(data.get("device_identity") or "")

        # -----------------------------
        # Ports
        # -----------------------------
        if show_columns["ports"]:
            ports = ", ".join(map(str, data.get("ports") or []))
            row.append(ports)

        # -----------------------------
        # HTTP
        # -----------------------------
        if show_columns["http"]:
            http_entries = []

            for port, svc in sorted(data.get("http_services", {}).items()):
                status = svc.get("status") or ""
                server = svc.get("server") or ""
                title = svc.get("title") or ""

                parts = [p for p in [status, server, title] if p]
                if parts:
                    http_entries.append(f"{port}: " + " | ".join(parts))

            row.append("\n".join(http_entries))
        # -----------------------------
        # Certificate
        # -----------------------------
        if show_columns["cert"]:
            cert = (data.get("http_443") or {}).get("cert") or {}
            row.append(cert.get("common_name") or "")

        # -----------------------------
        # Banners
        # -----------------------------
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

    # -----------------------------
    # Services Layer
    # -----------------------------
        if show_columns["services"]:
            services = []

            for s in data.get("services", []):
                name = s.get("name")  # ✅ correct key
                conf = s.get("confidence", 0)

                if not name:
                    continue

                if conf >= 0.8:
                    service_str = f"[green]{name} ({int(conf*100)}%)[/green]"
                elif conf >= 0.5:
                    service_str = f"[yellow]{name} ({int(conf*100)}%)[/yellow]"
                else:
                    service_str = f"[red]{name} ({int(conf*100)}%)[/red]"

                services.append(service_str)

            row.append("\n".join(services))

        table.add_row(*row)
    print("ROW LENGTH:", len(row), "COLUMNS:", len(table.columns))  
    console.print(table)


# -------------------------------------------------
# Summary
# -------------------------------------------------

def render_summary(results):

    total_hosts = len(results)
    hosts_with_ports = sum(1 for d in results.values() if d.get("ports"))
    total_ports = sum(len(d.get("ports") or []) for d in results.values())

    console.print()
    console.print(
        f"[bold]Hosts:[/bold] {total_hosts}  "
        f"[bold]Open Hosts:[/bold] {hosts_with_ports}  "
        f"[bold]Total Open Ports:[/bold] {total_ports}"
    )
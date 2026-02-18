import asyncio
import ipaddress
import socket
import subprocess
import ssl
import re
import manuf
import platform
import sys
import os




DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 80, 110, 143,
    443, 445, 1433, 1521, 3000, 3306,
    3389, 5000, 5432, 5985, 5986, 6443,
    6379, 5900, 8000, 8080, 8443, 9000,
    9090, 9200
]

IS_WINDOWS = platform.system().lower() == "windows"


class NetworkScanner:

    def __init__(self, ports=None, timeout=0.5, max_concurrent=500):
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout
        self.max_concurrent = max_concurrent

        # PyInstaller-safe manuf loading
        if getattr(sys, "frozen", False):
            base_path = sys._MEIPASS
            manuf_path = os.path.join(base_path, "manuf", "manuf")
            self.oui_parser = manuf.MacParser(manuf_path)
        else:
            self.oui_parser = manuf.MacParser()

    # -------------------------------------------------
    # ICMP
    # -------------------------------------------------

    async def icmp_ping(self, ip):
        try:
            if IS_WINDOWS:
                cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            await proc.communicate()
            return proc.returncode == 0

        except Exception:
            return False

    # -------------------------------------------------
    # ARP
    # -------------------------------------------------

    def get_arp_entries(self, subnet):
        network = ipaddress.ip_network(subnet, strict=False)
        arp_data = {}

        try:
            if IS_WINDOWS:
                output = subprocess.check_output(
                    ["arp", "-a"],
                    text=True,
                    errors="ignore"
                )

                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    ip_str = parts[0]
                    mac = parts[1].lower().replace("-", ":")

                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                    except Exception:
                        continue

                    if ip_obj in network:
                        arp_data[ip_str] = mac

            else:
                output = subprocess.check_output(
                    ["ip", "neigh"],
                    text=True,
                    errors="ignore"
                )

                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    ip_str = parts[0]
                    if "lladdr" not in parts:
                        continue

                    mac = parts[parts.index("lladdr") + 1].lower()

                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                    except Exception:
                        continue

                    if ip_obj in network:
                        arp_data[ip_str] = mac

        except Exception:
            pass

        return arp_data

    # -------------------------------------------------
    # Hostname Resolution
    # -------------------------------------------------

    async def resolve_dns_name(self, ip):
        try:
            result = await asyncio.to_thread(socket.gethostbyaddr, ip)
            return result[0]
        except Exception:
            return None

    async def resolve_netbios(self, ip):
        try:
            if IS_WINDOWS:
                proc = await asyncio.create_subprocess_exec(
                    "nbtstat", "-A", ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "nmblookup", "-A", ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )

            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="ignore")

            for line in output.splitlines():
                if "<00>" in line and "UNIQUE" in line:
                    return line.split()[0]

            return None

        except Exception:
            return None

    # -------------------------------------------------
    # Banner Grabbing
    # -------------------------------------------------

        
    async def grab_http_banner(self, ip, port):
        try:
            ssl_ctx = None
            cert_info = None

            if port == 443:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx),
                timeout=3
            )

            # -------------------------
            # Get SSL Certificate (443)
            # -------------------------
            if port == 443:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    cert = ssl_obj.getpeercert()

                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))

                        cert_info = {
                            "common_name": subject.get("commonName"),
                            "organization": subject.get("organizationName"),
                            "issuer": issuer.get("commonName"),
                            "expires": cert.get("notAfter"),
                            "san": []
                        }

                        # SAN extraction
                        for entry in cert.get("subjectAltName", []):
                            if entry[0] == "DNS":
                                cert_info["san"].append(entry[1])

            # -------------------------
            # HTTP Request
            # -------------------------
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            data = await asyncio.wait_for(reader.read(8192), timeout=3)

            writer.close()
            await writer.wait_closed()

            response = data.decode(errors="ignore")

            server = None
            title = None
            status_code = None
            location = None

            lines = response.split("\r\n")

            # HTTP Status
            if lines:
                status_line = lines[0]
                if "HTTP/" in status_line:
                    parts = status_line.split()
                    if len(parts) >= 2:
                        status_code = parts[1]

            # Headers
            for line in lines:
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()

            # Title
            match = re.search(r"<title>(.*?)</title>", response, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()

            return {
                "server": server,
                "title": title,
                "status": status_code,
                "redirect": location,
                "cert": cert_info
            }

        except Exception:
            return None

    async def grab_ssh_banner(self, ip):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 22),
                timeout=2
            )

            banner = await asyncio.wait_for(reader.readline(), timeout=2)

            writer.close()
            await writer.wait_closed()

            return banner.decode(errors="ignore").strip()

        except Exception:
            return None

    # -------------------------------------------------
    # Discovery
    # -------------------------------------------------

    async def discover_hosts(self, subnet):
        network = ipaddress.ip_network(subnet, strict=False)
        ips = list(network.hosts())
        alive = set()

        ping_tasks = [self.icmp_ping(ip) for ip in ips]
        results = await asyncio.gather(*ping_tasks)

        for ip, is_alive in zip(ips, results):
            if is_alive:
                alive.add(str(ip))

        arp_entries = self.get_arp_entries(subnet)
        alive.update(arp_entries.keys())

        cleaned = []

        for ip in alive:
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_multicast or ip_obj.is_loopback:
                continue

            if ip_obj == network.broadcast_address:
                continue

            cleaned.append(ip)

        cleaned.sort(key=lambda x: ipaddress.ip_address(x))

        return cleaned, arp_entries

    # -------------------------------------------------
    # Full Scan
    # -------------------------------------------------

    async def scan(self, subnet: str, progress_callback=None):

        semaphore = asyncio.Semaphore(self.max_concurrent)
        alive_hosts, arp_entries = await self.discover_hosts(subnet)

        results = {}

        for ip in alive_hosts:
            results[ip] = {
            "hostname": None,
            "mac": arp_entries.get(ip),
            "vendor": None,
            "ports": [],
            "http_80": None,
            "http_443": None,
            "ssh_banner": None,
            "smtp_banner": None,
            "ftp_banner": None,
            "pop3_banner": None,
            "imap_banner": None,
            "os": None
        }

            if results[ip]["mac"]:
                results[ip]["vendor"] = self.oui_parser.get_manuf(results[ip]["mac"])

        total_tasks = len(alive_hosts) * len(self.ports)
        completed = 0

        async def check_port(ip, port):
            nonlocal completed

            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    results[ip]["ports"].append(port)
                except:
                    pass

                completed += 1

                if progress_callback:
                    progress_callback(completed, total_tasks)

        tasks = [
            check_port(ip, port)
            for ip in alive_hosts
            for port in self.ports
        ]

        await asyncio.gather(*tasks)

        # Post-processing
        for ip in results:
            results[ip]["ports"].sort()

            if 22 in results[ip]["ports"]:
                results[ip]["ssh_banner"] = await self.grab_ssh_banner(ip)
            if 80 in results[ip]["ports"]:
                results[ip]["http_80"] = await self.grab_http_banner(ip, 80)

            if 443 in results[ip]["ports"]:
                results[ip]["http_443"] = await self.grab_http_banner(ip, 443)
            
            if 25 in results[ip]["ports"]:
                results[ip]["smtp_banner"] = await self.grab_smtp_banner(ip)

            if 21 in results[ip]["ports"]:
                results[ip]["ftp_banner"] = await self.grab_ftp_banner(ip)

            if 110 in results[ip]["ports"]:
                results[ip]["pop3_banner"] = await self.grab_pop3_banner(ip)

            if 143 in results[ip]["ports"]:
                results[ip]["imap_banner"] = await self.grab_imap_banner(ip)
        return results

    # -------------------------------------------------
    # SMTP Banner
    # -------------------------------------------------

    async def grab_smtp_banner(self, ip):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 25),
                timeout=3
            )

            banner = await asyncio.wait_for(reader.readline(), timeout=3)

            writer.close()
            await writer.wait_closed()

            return banner.decode(errors="ignore").strip()

        except Exception:
            return None


    # -------------------------------------------------
    # FTP Banner
    # -------------------------------------------------

    async def grab_ftp_banner(self, ip):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 21),
                timeout=3
            )

            banner = await asyncio.wait_for(reader.readline(), timeout=3)

            writer.close()
            await writer.wait_closed()

            return banner.decode(errors="ignore").strip()

        except Exception:
            return None

    # -------------------------------------------------
    # POP3 Banner
    # -------------------------------------------------

    async def grab_pop3_banner(self, ip):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 110),
                timeout=3
            )

            banner = await asyncio.wait_for(reader.readline(), timeout=3)

            writer.close()
            await writer.wait_closed()

            return banner.decode(errors="ignore").strip()

        except Exception:
            return None


    # -------------------------------------------------
    # IMAP Banner
    # -------------------------------------------------

    async def grab_imap_banner(self, ip):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 143),
                timeout=3
            )

            banner = await asyncio.wait_for(reader.readline(), timeout=3)

            writer.close()
            await writer.wait_closed()

            return banner.decode(errors="ignore").strip()

        except Exception:
            return None

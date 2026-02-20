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
                output = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    ip_str = parts[0]
                    mac = parts[1].lower().replace("-", ":")
                    try:
                        if ipaddress.ip_address(ip_str) in network:
                            arp_data[ip_str] = mac
                    except:
                        continue
            else:
                output = subprocess.check_output(["ip", "neigh"], text=True, errors="ignore")
                for line in output.splitlines():
                    parts = line.split()
                    if "lladdr" not in parts:
                        continue
                    ip_str = parts[0]
                    mac = parts[parts.index("lladdr") + 1].lower()
                    try:
                        if ipaddress.ip_address(ip_str) in network:
                            arp_data[ip_str] = mac
                    except:
                        continue
        except:
            pass

        return arp_data

    # -------------------------------------------------
    # Hostname Resolution
    # -------------------------------------------------

    async def resolve_dns_name(self, ip):
        try:
            result = await asyncio.to_thread(socket.gethostbyaddr, ip)
            return result[0]
        except:
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
        except:
            return None

    # -------------------------------------------------
    # HTTP / HTTPS
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

            if port == 443:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    cert_bin = ssl_obj.getpeercert(binary_form=True)
                    if cert_bin:
                        cert = ssl._ssl._test_decode_cert(cert_bin)

                        cert_info = {
                            "common_name": None,
                            "organization": None,
                            "issuer": None,
                            "expires": cert.get("notAfter"),
                            "san": []
                        }

                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))

                        cert_info["common_name"] = subject.get("commonName")
                        cert_info["organization"] = subject.get("organizationName")
                        cert_info["issuer"] = issuer.get("commonName")

                        for entry in cert.get("subjectAltName", []):
                            if entry[0] == "DNS":
                                cert_info["san"].append(entry[1])

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

            lines = response.split("\r\n")

            if lines and "HTTP/" in lines[0]:
                parts = lines[0].split()
                if len(parts) >= 2:
                    status_code = parts[1]

            for line in lines:
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()

            match = re.search(r"<title>(.*?)</title>", response, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()

            return {
                "server": server,
                "title": title,
                "status": status_code,
                "cert": cert_info
            }

        except:
            return None

    # -------------------------------------------------
    # Generic TCP Banner
    # -------------------------------------------------

    async def grab_tcp_banner(self, ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=3)
            writer.close()
            await writer.wait_closed()
            return banner.decode(errors="ignore").strip()
        except:
            return None

    # -------------------------------------------------
    # Discovery
    # -------------------------------------------------

    async def discover_hosts(self, subnet):
        network = ipaddress.ip_network(subnet, strict=False)

        # Fix for /32 single host scan
        if network.prefixlen == 32:
            ips = [network.network_address]
        else:
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

        # Initialize host structure
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

        # -------------------------------------------------
        # Hostname resolution (DNS + NetBIOS fallback)
        # -------------------------------------------------

        async def resolve_host(ip):
            dns = await self.resolve_dns_name(ip)
            if dns:
                return dns
            return await self.resolve_netbios(ip)

        hostnames = await asyncio.gather(*(resolve_host(ip) for ip in alive_hosts))

        for ip, hostname in zip(alive_hosts, hostnames):
            results[ip]["hostname"] = hostname

        # -------------------------------------------------
        # Port scanning
        # -------------------------------------------------

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

        await asyncio.gather(
            *(check_port(ip, port) for ip in alive_hosts for port in self.ports)
        )

        # -------------------------------------------------
        # Post-processing (banners)
        # -------------------------------------------------

        for ip in results:
            results[ip]["ports"].sort()

            if 80 in results[ip]["ports"]:
                results[ip]["http_80"] = await self.grab_http_banner(ip, 80)

            if 443 in results[ip]["ports"]:
                results[ip]["http_443"] = await self.grab_http_banner(ip, 443)

            if 22 in results[ip]["ports"]:
                results[ip]["ssh_banner"] = await self.grab_tcp_banner(ip, 22)

            if 25 in results[ip]["ports"]:
                results[ip]["smtp_banner"] = await self.grab_tcp_banner(ip, 25)

            if 21 in results[ip]["ports"]:
                results[ip]["ftp_banner"] = await self.grab_tcp_banner(ip, 21)

            if 110 in results[ip]["ports"]:
                results[ip]["pop3_banner"] = await self.grab_tcp_banner(ip, 110)

            if 143 in results[ip]["ports"]:
                results[ip]["imap_banner"] = await self.grab_tcp_banner(ip, 143)

        return results
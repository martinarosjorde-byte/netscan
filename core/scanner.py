import asyncio
import ipaddress
import socket
import subprocess
import ssl
import re
import base64
import mmh3
import manuf
import platform
import sys
import os
from core.fingerprint import FingerprintEngine

CORE_PORTS = [
    22, 80, 443, 25, 445, 3389
]

IS_WINDOWS = platform.system().lower() == "windows"


class NetworkScanner:

    def __init__(self, ports=None, timeout=0.5, max_concurrent=500):
  
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.hostname_semaphore = asyncio.Semaphore(50)
        self.banner_semaphore = asyncio.Semaphore(100)
        self.fingerprint_engine = FingerprintEngine()
  
        db_ports = self._extract_ports_from_fingerprint_db()
        if ports:
            self.ports = sorted(set(ports))
        else:
            self.ports = sorted(set(CORE_PORTS + db_ports))
        print(f"Loaded {len(self.ports)} scan ports from fingerprint DB")
        # PyInstaller-safe manuf
        if getattr(sys, "frozen", False):
            base_path = sys._MEIPASS
            manuf_path = os.path.join(base_path, "manuf", "manuf")
            self.oui_parser = manuf.MacParser(manuf_path)
        else:
            self.oui_parser = manuf.MacParser()

    
    
    def _extract_ports_from_fingerprint_db(self):
        ports = []

        try:
            rules = self.fingerprint_engine.database

            # Support new structure with metadata + rules
            if isinstance(rules, dict):
                rules = rules.get("rules", [])

            for rule in rules:
                rule_ports = rule.get("ports", [])
                for p in rule_ports:
                    if isinstance(p, int):
                        ports.append(p)

        except Exception:
            pass

        return ports
    
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
        except:
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

    async def resolve_host(self, ip):
        async with self.hostname_semaphore:
            try:
                return await asyncio.to_thread(socket.gethostbyaddr, ip)
            except:
                return None

    # -------------------------------------------------
    # HTTP / HTTPS
    # -------------------------------------------------

    async def grab_http_banner(self, ip, port):
        async with self.banner_semaphore:
            try:
                ssl_ctx = None
                cert_info = None
                favicon_hash = None

                if port == 443:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ssl_ctx),
                    timeout=3
                )

                # TLS cert
                if port == 443:
                    ssl_obj = writer.get_extra_info("ssl_object")
                    if ssl_obj:
                        cert = ssl_obj.getpeercert()
                        if cert:
                            subject = dict(x[0] for x in cert.get("subject", []))
                            issuer = dict(x[0] for x in cert.get("issuer", []))

                            cert_info = {
                                "common_name": subject.get("commonName"),
                                "issuer": issuer.get("commonName"),
                                "expires": cert.get("notAfter"),
                            }

                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()

                data = await asyncio.wait_for(reader.read(16384), timeout=3)

                writer.close()
                await writer.wait_closed()

                response = data.decode(errors="ignore")
                lines = response.split("\r\n")

                status_code = None
                if lines and "HTTP/" in lines[0]:
                    parts = lines[0].split()
                    if len(parts) >= 2:
                        status_code = parts[1]

                headers = {}
                for line in lines[1:]:
                    if not line:
                        break
                    if ":" in line:
                        key, value = line.split(":", 1)
                        headers[key.strip().lower()] = value.strip()

                server = headers.get("server")
                location = headers.get("location")

                title = None
                match = re.search(r"<title>(.*?)</title>", response, re.IGNORECASE | re.DOTALL)
                if match:
                    title = re.sub(r"\s+", " ", match.group(1)).strip()

                # Favicon hash
                try:
                    reader2, writer2 = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, ssl=ssl_ctx),
                        timeout=3
                    )

                    favicon_request = f"GET /favicon.ico HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    writer2.write(favicon_request.encode())
                    await writer2.drain()

                    favicon_data = await asyncio.wait_for(reader2.read(32768), timeout=3)

                    writer2.close()
                    await writer2.wait_closed()

                    if b"\r\n\r\n" in favicon_data:
                        body = favicon_data.split(b"\r\n\r\n", 1)[1]
                        if body:
                            encoded = base64.b64encode(body)
                            favicon_hash = mmh3.hash(encoded)
                except:
                    pass

                return {
                    "server": server,
                    "title": title,
                    "status": status_code,
                    "redirect": location,
                    "headers": headers,
                    "cert": cert_info,
                    "favicon_hash": favicon_hash
                }

            except:
                return None

    # -------------------------------------------------
    # Generic TCP Banner
    # -------------------------------------------------

    async def grab_tcp_banner(self, ip, port):
        async with self.banner_semaphore:
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

        ips = (
            [network.network_address]
            if network.prefixlen == 32
            else list(network.hosts())
        )

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
            if ip_obj == network.network_address:
                continue
            if ip_obj == network.broadcast_address:
                continue
            if arp_entries.get(ip, "").lower() == "ff:ff:ff:ff:ff:ff":
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
                "imap_banner": None
            }

            if results[ip]["mac"]:
                results[ip]["vendor"] = self.oui_parser.get_manuf(results[ip]["mac"])

        # Hostnames
        hostname_tasks = [self.resolve_host(ip) for ip in alive_hosts]
        hostname_results = await asyncio.gather(*hostname_tasks)

        for ip, result in zip(alive_hosts, hostname_results):
            if result:
                results[ip]["hostname"] = result[0]

        # Port scanning
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

        # Banner grabbing in parallel per host
        for ip in results:
            results[ip]["ports"].sort()

        banner_tasks = []

        for ip in results:
            if 80 in results[ip]["ports"]:
                banner_tasks.append(self._assign_http(ip, 80, results))
            if 443 in results[ip]["ports"]:
                banner_tasks.append(self._assign_http(ip, 443, results))
            if 22 in results[ip]["ports"]:
                banner_tasks.append(self._assign_banner(ip, 22, "ssh_banner", results))
            if 25 in results[ip]["ports"]:
                banner_tasks.append(self._assign_banner(ip, 25, "smtp_banner", results))
            if 21 in results[ip]["ports"]:
                banner_tasks.append(self._assign_banner(ip, 21, "ftp_banner", results))
            if 110 in results[ip]["ports"]:
                banner_tasks.append(self._assign_banner(ip, 110, "pop3_banner", results))
            if 143 in results[ip]["ports"]:
                banner_tasks.append(self._assign_banner(ip, 143, "imap_banner", results))

        await asyncio.gather(*banner_tasks)

        # Fingerprinting
        for ip in results:
            fp = self.fingerprint_engine.fingerprint(results[ip])
            results[ip]["fingerprint_matches"] = fp.get("matches", [])
            best = fp.get("best_match")

            if best:
                results[ip]["device_type"] = best.get("device_type")
                results[ip]["os_guess"] = best.get("os_guess")
                results[ip]["confidence"] = best.get("confidence")
            else:
                results[ip]["device_type"] = None
                results[ip]["os_guess"] = None
                results[ip]["confidence"] = None

        return results

    async def _assign_http(self, ip, port, results):
        data = await self.grab_http_banner(ip, port)
        results[ip][f"http_{port}"] = data

    async def _assign_banner(self, ip, port, field, results):
        data = await self.grab_tcp_banner(ip, port)
        results[ip][field] = data
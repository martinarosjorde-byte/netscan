# core/scanner.py

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

DEFAULT_PORTS = [22, 80, 443, 445, 3389]
IS_WINDOWS = platform.system().lower() == "windows"


class NetworkScanner:

    def __init__(self, ports=None, timeout=0.5, max_concurrent=500, resolve_dns=True):
            self.ports = ports or DEFAULT_PORTS
            self.timeout = timeout
            self.max_concurrent = max_concurrent
            self.resolve_dns = resolve_dns

            # If running inside PyInstaller bundle
            if getattr(sys, "frozen", False):
                base_path = sys._MEIPASS
                manuf_path = os.path.join(base_path, "manuf", "manuf")
                self.oui_parser = manuf.MacParser(manuf_path)
            else:
                # Normal Python execution
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
                    except:
                        continue

                    if ip_obj in network:
                        arp_data[ip_str] = mac

            else:
                # Linux / macOS
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
                    mac = None

                    if "lladdr" in parts:
                        mac = parts[parts.index("lladdr") + 1]

                    if not mac:
                        continue

                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                    except:
                        continue

                    if ip_obj in network:
                        arp_data[ip_str] = mac.lower()

        except Exception:
            pass

        return arp_data

    # -------------------------------------------------
    # Banner grabbing
    # -------------------------------------------------

    async def grab_http_banner(self, ip, port):
        try:
            ssl_ctx = None
            if port == 443:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx),
                timeout=2
            )

            request = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=2)

            writer.close()
            await writer.wait_closed()

            response = data.decode(errors="ignore")

            server = None
            title = None

            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()

            match = re.search(r"<title>(.*?)</title>", response, re.IGNORECASE)
            if match:
                title = match.group(1).strip()

            return {"server": server, "title": title}

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

        tasks = [self.icmp_ping(ip) for ip in ips]
        results = await asyncio.gather(*tasks)

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

    async def scan(self, subnet):

        semaphore = asyncio.Semaphore(self.max_concurrent)
        alive_hosts, arp_entries = await self.discover_hosts(subnet)

        results = {}

        for ip in alive_hosts:
            results[ip] = {
                "hostname": None,
                "mac": arp_entries.get(ip),
                "vendor": None,
                "ports": [],
                "http": None,
                "ssh_banner": None,
                "os": None
            }

            if results[ip]["mac"]:
                results[ip]["vendor"] = self.oui_parser.get_manuf(results[ip]["mac"])

        async def check_port(ip, port):
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

        tasks = [
            check_port(ip, port)
            for ip in alive_hosts
            for port in self.ports
        ]

        await asyncio.gather(*tasks)

        for ip in results:
            results[ip]["ports"].sort()

            if 22 in results[ip]["ports"]:
                results[ip]["ssh_banner"] = await self.grab_ssh_banner(ip)

            if 80 in results[ip]["ports"]:
                results[ip]["http"] = await self.grab_http_banner(ip, 80)

            if 443 in results[ip]["ports"]:
                results[ip]["http"] = await self.grab_http_banner(ip, 443)

        return results

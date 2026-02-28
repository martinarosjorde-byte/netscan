# Core scanning engine for NetScan
# scanner.py - Main scanning logic for NetScan

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
import json
from pathlib import Path
import sys
from datetime import datetime
import time
import os
import aiohttp
from aiohttp import ClientTimeout
from core.http_scanner import HTTPScanner
from core.fingerprint import FingerprintEngine

CORE_PORTS = [21, 23, 110, 143,443,8443, 587, 53, 139, 10443, 5900, 8080, 8443, 8006]
HTTPS_PORTS = {443, 8443, 9443, 10443, 8006}

IS_WINDOWS = platform.system().lower() == "windows"


class NetworkScanner:

    def __init__(self, ports=None, timeout=0.5, max_concurrent=500, debug=False, fingerprint_db_path: str | None = None, learning=False):
        self.debug = debug
        self.learning = learning
  
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.hostname_semaphore = asyncio.Semaphore(50)
        self.banner_semaphore = asyncio.Semaphore(100)
        self.fingerprint_engine = FingerprintEngine(db_path=fingerprint_db_path, debug=debug)
        self.http_scanner = HTTPScanner(debug=debug)
        
        db_ports = self._extract_ports_from_fingerprint_db()
        if ports:
            self.ports = sorted(set(ports))
        else:
            self.ports = sorted(set(CORE_PORTS + db_ports))
        print(f"Loaded {len(self.ports)} scan ports from fingerprint DB")
        
        # PyInstaller-safe manuf
        self.oui_parser = manuf.MacParser()

        
    def _debug(self, *args):
        if self.debug:
            print("[DEBUG]", *args)
    
    def _extract_ports_from_fingerprint_db(self):
        ports = set()

        try:
            rules = self.fingerprint_engine.database
            if isinstance(rules, dict):
                rules = rules.get("rules", [])

            # Rules imply ports even without explicit "ports"
            IMPLIED = {
                "http_title_contains": [80, 443],
                "server_contains": [80, 443],
                "cert_common_name_contains": [443],
                "cert_issuer_contains": [443],
                "cert_san_contains": [443],
                "favicon_hash": [80, 443],
                "ssh_banner_contains": [22],
                "telnet_banner_contains": [23],
                "smtp_banner_contains": [25],
                "ftp_banner_contains": [21],
                "pop3_banner_contains": [110],
                "imap_banner_contains": [143],
            }

            for rule in rules:
                # explicit ports
                for p in rule.get("ports", []) or []:
                    if isinstance(p, int):
                        ports.add(p)

                # implied ports
                for key, implied_ports in IMPLIED.items():
                    if rule.get(key):
                        for p in implied_ports:
                            ports.add(p)

        except Exception:
            pass

        return sorted(ports)
    
    # -------------------------------------------------
    # ICMP
    # -------------------------------------------------

    async def icmp_ping(self, ip):
        try:
            if IS_WINDOWS:
                cmd = ["ping", "-n", "1", "-w", "300", str(ip)]
            else:
                cmd = ["ping", "-c", "1", str(ip)]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )

            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="ignore")

            ttl = None
            latency = None

            # Linux style: ttl=64 time=0.4 ms
            ttl_match = re.search(r"ttl[=:](\d+)", output, re.IGNORECASE)
            time_match = re.search(r"time[=<]?\s*([\d\.]+)", output, re.IGNORECASE)

            if ttl_match:
                ttl = int(ttl_match.group(1))

            if time_match:
                latency = float(time_match.group(1))
            
            return {
                "alive": proc.returncode == 0,
                "ttl": ttl,
                "latency_ms": latency
            }

        except:
            return {
                "alive": False,
                "ttl": None,
                "latency_ms": None
            }

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
                start = time.perf_counter()
                result = await asyncio.to_thread(socket.gethostbyaddr, ip)
                elapsed = (time.perf_counter() - start) * 1000

                return {
                    "hostname": result[0],
                    "lookup_time_ms": round(elapsed, 2)
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
        ping_results = await asyncio.gather(*ping_tasks)

        icmp_data = {}

        for ip, result in zip(ips, ping_results):
            if result["alive"]:
                ip_str = str(ip)
                alive.add(ip_str)
                icmp_data[ip_str] = result

        arp_entries = self.get_arp_entries(subnet)
        alive.update(arp_entries.keys())

        cleaned = []
        for ip in alive:
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_multicast or ip_obj.is_loopback:
                continue

            # Skip network/broadcast only if prefix < 31
            if network.prefixlen < 31:
                if ip_obj == network.network_address:
                    continue
                if ip_obj == network.broadcast_address:
                    continue

            cleaned.append(ip)

        cleaned.sort(key=lambda x: ipaddress.ip_address(x))
        return cleaned, arp_entries, icmp_data

    # -------------------------------------------------
    # Full Scan
    # -------------------------------------------------

        
    async def scan(self, subnet: str, progress_callback=None):

        semaphore = asyncio.Semaphore(self.max_concurrent)
        alive_hosts, arp_entries, icmp_data = await self.discover_hosts(subnet)

        results = {}

        # -------------------------------------------------
        # Initialize host structure
        # -------------------------------------------------
        for ip in alive_hosts:
            results[ip] = {
            "hostname": None,
            "mac": arp_entries.get(ip),
            "vendor": None,
            "ports": [],
            "http_services": {},  
            "ssh_banner": None,
            "smtp_banner": None,
            "ftp_banner": None,
            "pop3_banner": None,
            "imap_banner": None,

            # Layered classification
            "os_family": None,
            "os_confidence": None,
            "device_identity": None,

            # Fingerprint outputs
            "services": [],
            "fingerprint_matches": [],
            "device_type": None,
            "category": None,
            "os_guess": None,
            "confidence": None,

            # 🔥 FIXED STRUCTURE
            "learning_data": {
                "reverse_dns": None,
                "reverse_dns_time_ms": None,
                "network": {
                    "icmp_ttl": None,
                    "icmp_latency_ms": None,
                    "tcp_connect_times": {}
                },
                "tls": {},
                "http_extended": {}
            },
        }

            mac = results[ip]["mac"]

            if mac and re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac.lower()):
                try:
                    results[ip]["vendor"] = self.oui_parser.get_manuf(mac)
                except Exception:
                    results[ip]["vendor"] = None
            else:
                results[ip]["vendor"] = None

            if self.learning and ip in icmp_data:
                results[ip]["learning_data"]["network"]["icmp_ttl"] = icmp_data[ip]["ttl"]
                results[ip]["learning_data"]["network"]["icmp_latency_ms"] = icmp_data[ip]["latency_ms"]

        # -------------------------------------------------
        # Hostname Resolution
        # -------------------------------------------------
        hostname_tasks = [self.resolve_host(ip) for ip in alive_hosts]
        hostname_results = await asyncio.gather(*hostname_tasks)

        for ip, result in zip(alive_hosts, hostname_results):
            if result:
                results[ip]["hostname"] = result["hostname"]
                if self.learning:
                    results[ip]["learning_data"]["reverse_dns"] = result["hostname"]
                    results[ip]["learning_data"]["reverse_dns_time_ms"] = result["lookup_time_ms"]

        # -------------------------------------------------
        # Port Scanning
        # -------------------------------------------------
        total_tasks = len(alive_hosts) * len(self.ports)
        completed = 0

        async def check_port(ip, port):
            nonlocal completed
            async with semaphore:
                try:
                    start = time.perf_counter()

                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )

                    elapsed = (time.perf_counter() - start) * 1000
                    results[ip]["ports"].append(port)

                    if self.learning:
                        results[ip]["learning_data"]["network"]["tcp_connect_times"][port] = round(elapsed, 2)
                    
                    
                    writer.close()
                    await writer.wait_closed()      
                except:
                    pass

                completed += 1
                if progress_callback:
                    progress_callback(completed, total_tasks)

        await asyncio.gather(
            *(check_port(ip, port) for ip in alive_hosts for port in self.ports)
        )

        for ip in results:
            results[ip]["ports"].sort()

        # -------------------------------------------------
        # Banner Grabbing
        # -------------------------------------------------
        banner_tasks = []

        for ip in results:
            ports = results[ip]["ports"]

            HTTP_PORTS = {80, 8080}
            HTTPS_PORTS = {443, 8443, 9443, 10443, 8006}

            for port in ports:
                if port in HTTP_PORTS or port in HTTPS_PORTS:
                    banner_tasks.append(self._assign_http(ip, port, results))

            if 22 in ports:
                banner_tasks.append(self._assign_banner(ip, 22, "ssh_banner", results))
            if 25 in ports:
                banner_tasks.append(self._assign_banner(ip, 25, "smtp_banner", results))
            if 21 in ports:
                banner_tasks.append(self._assign_banner(ip, 21, "ftp_banner", results))
            if 110 in ports:
                banner_tasks.append(self._assign_banner(ip, 110, "pop3_banner", results))
            if 143 in ports:
                banner_tasks.append(self._assign_banner(ip, 143, "imap_banner", results))

        await asyncio.gather(*banner_tasks)

        # -------------------------------------------------
        # OS + Identity + Fingerprinting
        # -------------------------------------------------
        for ip in results:

            host = results[ip]

            # -------------------------
            # OS Detection
            # -------------------------
            os_info = self.detect_os(host)
            host["os_family"] = os_info["os"]
            host["os_confidence"] = os_info["confidence"]

            # -------------------------
            # Identity Layer
            # -------------------------
            host["device_identity"] = self.detect_device_identity(host, os_info)

            # -------------------------
            # Fingerprinting
            # -------------------------
            fp = self.fingerprint_engine.fingerprint(host)

            matches = fp.get("matches", [])
            best = fp.get("best_match")

            host["fingerprint_matches"] = matches

            # Build Services (filtered)
            services = []
            for m in matches:
                if m.get("confidence", 0) >= 0.6:
                    services.append({
                        "name": m.get("device_type"),
                        "category": m.get("category"),
                        "confidence": m.get("confidence"),
                    })

            host["services"] = services

            # Primary classification
            if best:
                host["device_type"] = best.get("device_type")
                host["category"] = best.get("category")
                host["os_guess"] = best.get("os_guess")
                host["confidence"] = best.get("confidence")

            if best and best["confidence"] >= 0.7:
                host["device_identity"] = best["category"]
            
            
            # DEBUG OUTPUT
            # -------------------------
            if self.debug:
                print("\n[DEBUG] ---------------------------")
                print("[DEBUG] Host:", ip)
                print("[DEBUG] Ports:", host["ports"])
                print("[DEBUG] OS:", host["os_family"], host["os_confidence"])
                print("[DEBUG] Identity:", host["device_identity"])
                print("[DEBUG] Raw FP Matches:", matches)
                print("[DEBUG] Filtered Services:", services)
                print("[DEBUG] Best Match:", best)
                print("[DEBUG] SSH:", host.get("ssh_banner"))
                print("[DEBUG] FTP:", host.get("ftp_banner"))
                print("[DEBUG] SMTP:", host.get("smtp_banner"))

        if self.learning:
            self._save_learning_snapshot(subnet, results)

        return results


    async def _assign_http(self, ip, port, results):
        data = await self.http_scanner.scan(ip, port)

        if not data:
            return

        results[ip]["http_services"][port] = data

        if self.learning:
            results[ip]["learning_data"]["http_extended"][port] = {
                "status": data.get("status"),
                "server": data.get("server"),
                "title": data.get("title"),
                "headers": data.get("headers"),
                "favicon_hash": data.get("favicon_hash"),
            }

            if data.get("cert"):
                results[ip]["learning_data"]["tls"][port] = data.get("cert")

    async def _assign_banner(self, ip, port, field, results):
        data = await self.grab_tcp_banner(ip, port)
        results[ip][field] = data


    def detect_os(self, host):

        score = 0
        ports = host.get("ports", [])
        vendor = (host.get("vendor") or "").lower()

        # Aggregate HTTP server headers (NEW MODEL)
        http_services = host.get("http_services", {})
        server = ""

        for svc in http_services.values():
            server += (svc.get("server") or "") + " "

        server = server.lower()

        # -------------------------
        # Windows indicators
        # -------------------------

        if 445 in ports:
            score += 3
        if 139 in ports:
            score += 6
        if 3389 in ports:
            score += 6
        if "microsoft-iis" in server:
            score += 4
        if 5985 in ports or 5986 in ports:
            score += 2

        if score >= 4:
            return {"os": "Windows", "confidence": min(score / 10, 1.0)}

        # -------------------------
        # Linux indicators
        # -------------------------

        linux_score = 0

        if 22 in ports and 445 not in ports:
            linux_score += 2

        if any(x in server for x in ["nginx", "apache"]):
            linux_score += 3

        if 6443 in ports:
            linux_score += 3

        if linux_score >= 3:
            return {"os": "Linux", "confidence": min(linux_score / 8, 1.0)}

        # -------------------------
        # Network OS
        # -------------------------

        NETWORK_VENDORS = [
            "cisco",
            "aruba",
            "juniper",
            "mikrotik",
            "tp-link",
            "asustek",
            "versanet"
        ]

        if any(v in vendor for v in NETWORK_VENDORS):
            return {"os": "Network OS", "confidence": 0.95}

        # -------------------------
        # Fallback
        # -------------------------

        return {"os": "Unknown", "confidence": 0.2}
    
    def detect_device_identity(self, host, os_info):

        os_guess = os_info["os"]
        ports = host.get("ports", [])
        vendor = (host.get("vendor") or "").lower()
        hostname = (host.get("hostname") or "").lower()

        # Firewalls
        if any(x in vendor for x in ["fortinet", "palo", "check point", "juniper"]):
            return "Firewall"

        # Network Devices
        if any(x in vendor for x in ["cisco", "aruba", "mikrotik", "ubiquiti"]):
            return "Network Device"

        # Hypervisor
        if 8006 in ports:
            return "Hypervisor"

        # Smart TV
        if "lgelectr" in vendor:
            return "Smart TV"

        # Automotive
        if "tesla" in vendor:
            return "Vehicle"

        # SD-WAN
        if "versanet" in vendor:
            return "SD-WAN Device"

        # Management interfaces
        if any(x in vendor for x in ["dell", "hewlett", "lenovo"]) and 443 in ports:
            return "Management Interface"

        if host.get("ftp_banner") and "readynas" in host["ftp_banner"].lower():
            return "NAS"

        # Windows classification
        if os_guess == "Windows":
            if any(x in hostname for x in ["dc", "srv", "sql", "app"]):
                return "Server"
            if 3389 in ports and 445 in ports:
                return "Server"
            return "Workstation"

        # Linux
        if os_guess == "Linux":
            if 22 in ports and 80 in ports:
                return "Server"
            return "Linux Host"

        return "Unknown Device"
    

    def _get_learning_base_path(self) -> Path:
        # Running as packaged executable (PyInstaller)
        if getattr(sys, "frozen", False):
            program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
            return program_data / "NetScan" / "learning"

        # Running from source (Python project)
        project_root = Path(__file__).resolve().parent.parent
        return project_root / "learning"

    def _save_learning_snapshot(self, subnet, results):

        base_path = self._get_learning_base_path()

        try:
            base_path.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback to current working directory
            fallback = Path(os.getcwd()) / "learning"
            fallback.mkdir(parents=True, exist_ok=True)
            base_path = fallback

        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        safe_subnet = subnet.replace("/", "_")
        filename = base_path / f"{safe_subnet}_{timestamp}.json"

        snapshot = {
            "metadata": {
                "subnet": subnet,
                "timestamp": datetime.now().isoformat(),
                "learning_mode": True
            },
            "hosts": {}
        }

        for ip, data in results.items():
            snapshot["hosts"][ip] = {
                "mac": data.get("mac"),
                "vendor": data.get("vendor"),
                "ports_open": data.get("ports"),
                "ssh_banner": data.get("ssh_banner"),
                "device_identity": data.get("device_identity"),
                "os_family": data.get("os_family"),
                "learning_data": data.get("learning_data")
            }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=4, default=str)

        if self.debug:
            print(f"[DEBUG] Learning snapshot saved to {filename}")
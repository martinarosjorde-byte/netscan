import asyncio
import ipaddress
import socket
import sys
from datetime import datetime

PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
TIMEOUT = 1
MAX_CONCURRENT = 1000


def get_local_ip():
    """Detect primary local IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def suggest_subnet():
    local_ip = get_local_ip()
    parts = local_ip.split(".")
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
            return port
        except:
            return None


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except:
        return None


async def scan_host(ip, semaphore):
    tasks = [check_port(ip, port, semaphore) for port in PORTS]
    results = await asyncio.gather(*tasks)

    open_ports = [p for p in results if p]

    if open_ports:
        hostname = await asyncio.to_thread(resolve_hostname, ip)
        if hostname:
            print(f"[+] {ip} ({hostname}) -> {open_ports}")
        else:
            print(f"[+] {ip} -> {open_ports}")

    return ip, open_ports


async def scan_network(subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    tasks = [scan_host(ip, semaphore) for ip in network.hosts()]
    await asyncio.gather(*tasks)


def main():
    suggested = suggest_subnet()
    user_input = input(f"Enter subnet [{suggested}]: ").strip()

    subnet = user_input if user_input else suggested

    print(f"\nScanning {subnet}...\n")
    start = datetime.now()

    asyncio.run(scan_network(subnet))

    print(f"\nFinished in {datetime.now() - start}")


if __name__ == "__main__":
    main()

import asyncio
import ipaddress
import socket
from datetime import datetime
from tqdm import tqdm

PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
TIMEOUT = 0.5
MAX_CONCURRENT = 2000
RESOLVE_DNS = True


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def suggest_subnet():
    ip = get_local_ip()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except:
        return None


async def check_port(ip, port, semaphore, discovered, pbar):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port),
                timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()

            if ip not in discovered:
                discovered[ip] = []
                print(f"\n[+] Host discovered: {ip}")

            discovered[ip].append(port)
            print(f"    -> Port {port} open")

        except:
            pass
        finally:
            pbar.update(1)


async def scan_network(subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    discovered = {}

    total_tasks = len(list(network.hosts())) * len(PORTS)

    print(f"\nTotal checks: {total_tasks}")
    print("Scanning...\n")

    with tqdm(total=total_tasks) as pbar:
        tasks = []
        for ip in network.hosts():
            for port in PORTS:
                tasks.append(
                    check_port(ip, port, semaphore, discovered, pbar)
                )

        await asyncio.gather(*tasks)

    return discovered


def main():
    suggested = suggest_subnet()
    subnet = input(f"Enter subnet [{suggested}]: ").strip() or suggested

    start = datetime.now()

    results = asyncio.run(scan_network(subnet))

    print("\nFinished.")

    print("\n\n--- Results ---\n")

    for ip, ports in sorted(results.items()):
        if RESOLVE_DNS:
            hostname = resolve_hostname(ip)
            if hostname:
                print(f"[+] {ip} ({hostname}) -> {sorted(ports)}")
            else:
                print(f"[+] {ip} -> {sorted(ports)}")
        else:
            print(f"[+] {ip} -> {sorted(ports)}")

    print(f"\nFinished in {datetime.now() - start}")


if __name__ == "__main__":
    main()

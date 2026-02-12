import asyncio
import ipaddress
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime

PORTS = [21, 22, 23, 25, 80, 443, 445, 3389]
TIMEOUT = 1
MAX_CONCURRENT = 1000


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


async def scan_network(subnet, output_widget):
    network = ipaddress.ip_network(subnet, strict=False)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    for ip in network.hosts():
        tasks = [check_port(ip, port, semaphore) for port in PORTS]
        results = await asyncio.gather(*tasks)

        open_ports = [p for p in results if p]

        if open_ports:
            output_widget.insert(tk.END, f"{ip} -> {open_ports}\n")
            output_widget.see(tk.END)


def start_scan(subnet, output_widget):
    asyncio.run(scan_network(subnet, output_widget))


def run_scan(entry, output):
    subnet = entry.get()
    output.delete(1.0, tk.END)
    threading.Thread(target=start_scan, args=(subnet, output), daemon=True).start()


# GUI
root = tk.Tk()
root.title("Nettools NetScanner")
root.geometry("700x500")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Subnet:").pack(side=tk.LEFT)
subnet_entry = tk.Entry(frame, width=25)
subnet_entry.pack(side=tk.LEFT)
subnet_entry.insert(0, "192.168.1.0/24")

scan_button = tk.Button(frame, text="Scan", command=lambda: run_scan(subnet_entry, output_box))
scan_button.pack(side=tk.LEFT, padx=5)

output_box = scrolledtext.ScrolledText(root)
output_box.pack(fill=tk.BOTH, expand=True)

root.mainloop()

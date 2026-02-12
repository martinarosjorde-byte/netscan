import asyncio
import ipaddress
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk
from collections import defaultdict

# -----------------------------
# Configuration
# -----------------------------

PORTS = [22, 80, 443, 445, 3389]
TIMEOUT = 0.5
MAX_CONCURRENT = 2000

# -----------------------------

class NetScanGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("NetScan Enterprise")
        self.root.geometry("900x500")

        default_font = ("Segoe UI", 10)
        self.root.option_add("*Font", default_font)

        self.apply_dark_theme()

        self.results = defaultdict(list)
        self.stats = {
            "checked": 0,
            "open": 0,
            "start": None
        }

        self.running = False
        self.create_widgets()

    # -----------------------------

    def apply_dark_theme(self):
        style = ttk.Style()
        style.theme_use("clam")

        self.root.configure(bg="#1e1e1e")

        # General
        style.configure(".",
                        background="#1e1e1e",
                        foreground="#d4d4d4",
                        fieldbackground="#252526")

        # Frames
        style.configure("TFrame", background="#1e1e1e")

        # Labels
        style.configure("TLabel",
                        background="#1e1e1e",
                        foreground="#d4d4d4")

        # Entry
        style.configure("TEntry",
                        fieldbackground="#252526",
                        foreground="#ffffff")

        # Buttons
        style.configure("TButton",
                        background="#3a3d41",
                        foreground="#ffffff",
                        padding=6)

        style.map("TButton",
                  background=[("active", "#505357")])

        # Treeview
        style.configure("Treeview",
                        background="#252526",
                        foreground="#d4d4d4",
                        fieldbackground="#252526",
                        rowheight=25)

        style.configure("Treeview.Heading",
                        background="#3a3d41",
                        foreground="#ffffff")

        style.map("Treeview",
                  background=[("selected", "#094771")])

    # -----------------------------

    def suggest_subnet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    # -----------------------------
    def toggle_scan(self):
        if not self.running:
            self.start_scan()
        else:
            self.stop_scan()

    def create_widgets(self):

        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(top_frame, text="Subnet:").pack(side="left")

        self.subnet_var = tk.StringVar(value=self.suggest_subnet())
        self.subnet_entry = ttk.Entry(top_frame, textvariable=self.subnet_var, width=25)
        self.subnet_entry.pack(side="left", padx=5)

        self.scan_button = ttk.Button(top_frame, text="Start Scan", command=self.toggle_scan)
        self.scan_button.pack(side="left", padx=5)

        self.clear_button = ttk.Button(top_frame, text="Clear", command=self.clear_results)
        self.clear_button.pack(side="left", padx=5)


        # Main split
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Treeview (Results)
        self.tree = ttk.Treeview(main_frame, columns=("IP", "Ports"), show="headings")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Ports", text="Open Ports")
        self.tree.column("IP", width=200)
        self.tree.column("Ports", width=400)

        self.tree.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="left", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Stats panel
        stats_frame = ttk.Frame(main_frame, width=200)
        stats_frame.pack(side="left", fill="y", padx=10)

        self.stats_label = ttk.Label(stats_frame, text="", justify="left")
        self.stats_label.pack(anchor="nw")

    # -----------------------------

    async def check_port(self, ip, port, semaphore):
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(str(ip), port),
                    timeout=TIMEOUT
                )
                writer.close()
                await writer.wait_closed()

                self.results[str(ip)].append(port)
                self.stats["open"] += 1

                self.update_tree()

            except:
                pass
            finally:
                self.stats["checked"] += 1

    # -----------------------------

    async def scan_network(self, subnet):

        self.results.clear()
        self.tree.delete(*self.tree.get_children())

        network = ipaddress.ip_network(subnet, strict=False)
        ips = list(network.hosts())

        total_checks = len(ips) * len(PORTS)

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        self.stats["checked"] = 0
        self.stats["open"] = 0
        self.stats["start"] = time.time()

        tasks = []
        for ip in ips:
            for port in PORTS:
                if not self.running:
                    return
                tasks.append(self.check_port(ip, port, semaphore))

        for coro in asyncio.as_completed(tasks):
            if not self.running:
                return
            await coro
            self.update_stats(total_checks)

        self.running = False
        self.update_tree()
        self.subnet_entry.config(state="normal")
        self.scan_button.config(text="Start Scan")
    # -----------------------------


    def clear_results(self):
        if self.running:
            return  # Prevent clearing while scanning

        self.results.clear()
        self.tree.delete(*self.tree.get_children())

        self.stats["checked"] = 0
        self.stats["open"] = 0
        self.stats["start"] = None

        self.stats_label.config(text="")


    def update_tree(self):
        self.tree.delete(*self.tree.get_children())

        # Sort IPs numerically
        sorted_ips = sorted(
            self.results.keys(),
            key=lambda ip: ipaddress.ip_address(ip)
        )

        for ip in sorted_ips:
            ports = sorted(self.results[ip])
            self.tree.insert(
                "",
                "end",
                values=(ip, ", ".join(map(str, ports)))
            )


    # -----------------------------

    def update_stats(self, total_checks):
        elapsed = time.time() - self.stats["start"]
        speed = int(self.stats["checked"] / elapsed) if elapsed > 0 else 0

        stats_text = (
            f"Total Checks: {total_checks}\n"
            f"Completed: {self.stats['checked']}\n"
            f"Open Ports: {self.stats['open']}\n"
            f"Speed: {speed} checks/sec\n"
            f"Elapsed: {int(elapsed)} sec"
        )

        self.stats_label.config(text=stats_text)

    # -----------------------------

    def start_scan(self):
        if self.running:
            return

        subnet = self.subnet_var.get().strip()
        self.running = True
        self.scan_button.config(text="Stop Scan")
        self.subnet_entry.config(state="disabled")
        thread = threading.Thread(
            target=lambda: asyncio.run(self.scan_network(subnet)),
            daemon=True
        )
        thread.start()


    def stop_scan(self):
        self.running = False
        self.subnet_entry.config(state="normal")
        self.scan_button.config(text="Start Scan")


# -----------------------------

def main():
    root = tk.Tk()
    app = NetScanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

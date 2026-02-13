# cli/exporter.py

import json
import csv



def export_json(results, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)


def export_csv(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow([
            "Subnet",
            "IP",
            "Hostname",
            "MAC",
            "Vendor",
            "OS",
            "Ports",
            "HTTP Server",
            "HTTP Title",
            "SSH Banner"
        ])

        for subnet, hosts in results.items():
            for ip, data in hosts.items():
                http = data.get("http") or {}

                writer.writerow([
                    subnet,
                    ip,
                    data.get("hostname"),
                    data.get("mac"),
                    data.get("vendor"),
                    data.get("os"),
                    ",".join(map(str, data.get("ports", []))),
                    http.get("server"),
                    http.get("title"),
                    data.get("ssh_banner")
                ])
# cli/exporter.py

import json
import csv


def export_json(results, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)


def export_csv(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow(["IP", "Hostname", "MAC", "Vendor", "Ports"])

        for ip, data in results.items():
            writer.writerow([
                ip,
                data.get("hostname"),
                data.get("mac"),
                data.get("vendor"),
                ",".join(map(str, data.get("ports", [])))
            ])

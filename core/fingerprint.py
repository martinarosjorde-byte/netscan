# Fingerprint Engine for NetScan
# core/fingerprint.py - Implements the fingerprinting logic for device identification
import json
import os
import sys

from rich import rule

class FingerprintEngine:

    STRONG_WEIGHT = 1.0
    MEDIUM_WEIGHT = 0.5
    WEAK_WEIGHT = 0.1
    MIN_CONFIDENCE = 0.6

    def __init__(self, db_path=None, debug=False):

        self.debug = debug

        if db_path is None:
        # Prefer ProgramData when frozen (installer + writable updates)
            if getattr(sys, "frozen", False):
                program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
                db_path = os.path.join(program_data, "NetScan", "fingerprints.json")
            else:
                # dev/script mode: project_root/fingerprints/fingerprints.json
                base_dir = os.path.dirname(os.path.abspath(__file__))
                db_path = os.path.abspath(os.path.join(base_dir, "..", "fingerprints", "fingerprints.json"))

        self.database = []
        self.metadata = {}
        self.version = "unknown"

        if os.path.exists(db_path):
            with open(db_path, "r", encoding="utf-8") as f:
                data = json.load(f)

                if isinstance(data, dict) and "rules" in data:
                    self.database = data.get("rules", [])
                    self.metadata = data.get("metadata", {})
                    self.version = self.metadata.get("version", "unknown")

                elif isinstance(data, list):
                    self.database = data
                    self.version = "legacy"

        print(f"[FingerprintEngine] Loaded fingerprint rules: {len(self.database)}")
        print(f"[FingerprintEngine] DB Version: {self.version}")

    # -------------------------------------------------
    # Public API
    # -------------------------------------------------

    def fingerprint(self, host_data):

        matches = []

        for rule in self.database:
            result = self.evaluate_rule(rule, host_data)
            if result:
                matches.append(result)

        matches.sort(key=lambda x: x["confidence"], reverse=True)

        best = matches[0] if matches else None

        if best and best["confidence"] < self.MIN_CONFIDENCE:
            best = None

        return {
            "matches": matches,
            "best_match": best
        }

    # -------------------------------------------------
    # Enterprise Rule Evaluation
    # -------------------------------------------------

    def evaluate_rule(self, rule, host):

        strong = 0
        medium = 0
        weak = 0

        ports = host.get("ports", [])

        # -------------------------
        # HTTP Aggregation
        # -------------------------

        http_services = host.get("http_services", {})

        title = ""
        server = ""
        body = ""
        favicon_hash = None
        cert = {}

        for svc in http_services.values():
            title += (svc.get("title") or "") + " "
            server += (svc.get("server") or "") + " "
            body += (svc.get("initial_body_preview") or "") + " "
            body += (svc.get("body_preview") or "") + " "

            if svc.get("favicon_hash") is not None:
                favicon_hash = svc.get("favicon_hash")

            if svc.get("cert"):
                cert = svc.get("cert")

        title = title.lower()
        server = server.lower()
        body = body.lower()

        cert_cn = (cert.get("common_name") or "").lower()
        cert_issuer = (cert.get("issuer") or "").lower()
        cert_san = " ".join(cert.get("san", [])).lower()

        ssh_banner = (host.get("ssh_banner") or "").lower()
        smtp_banner = (host.get("smtp_banner") or "").lower()
        ftp_banner = (host.get("ftp_banner") or "").lower()
        pop3_banner = (host.get("pop3_banner") or "").lower()
        imap_banner = (host.get("imap_banner") or "").lower()

        mac_vendor = (host.get("vendor") or "").lower()
        hostname = (host.get("hostname") or "").lower()

       

        # -------------------------
        # STRONG SIGNALS
        # -------------------------

        for k in rule.get("http_title_contains", []):
            if k.lower() in title:
                strong += 1

        for k in rule.get("http_body_contains", []):
            if k.lower() in body:
                strong += 1

        if any(k.lower() in cert_cn for k in rule.get("cert_common_name_contains", [])):
            strong += 1

        if any(k.lower() in cert_san for k in rule.get("cert_san_contains", [])):
            strong += 1

        if rule.get("favicon_hash") is not None and favicon_hash == rule.get("favicon_hash"):
            strong += 1

        if any(k.lower() in ssh_banner for k in rule.get("ssh_banner_contains", [])):
            strong += 1

        if any(k.lower() in ftp_banner for k in rule.get("ftp_banner_contains", [])):
            strong += 1

        if any(k.lower() in smtp_banner for k in rule.get("smtp_banner_contains", [])):
            strong += 1

        if any(k.lower() in pop3_banner for k in rule.get("pop3_banner_contains", [])):
            strong += 1

        if any(k.lower() in imap_banner for k in rule.get("imap_banner_contains", [])):
            strong += 1

        # -------------------------
        # MEDIUM SIGNALS
        # -------------------------

        if any(k.lower() in server for k in rule.get("server_contains", [])):
            medium += 1

        if any(k.lower() in mac_vendor for k in rule.get("mac_vendor_contains", [])):
            medium += 1

        if any(k.lower() in hostname for k in rule.get("hostname_contains", [])):
            medium += 1

        if any(k.lower() in cert_issuer for k in rule.get("cert_issuer_contains", [])):
            medium += 1

        # -------------------------
        # WEAK SIGNALS
        # -------------------------

        if any(p in ports for p in rule.get("ports", [])):
            weak += 1

        # -------------------------
        # Score Calculation
        # -------------------------


        total_score = (
            strong * self.STRONG_WEIGHT +
            medium * self.MEDIUM_WEIGHT +
            weak * self.WEAK_WEIGHT
        )

        max_possible = (
            len(rule.get("http_title_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("http_body_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("cert_common_name_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("cert_san_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("ssh_banner_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("ftp_banner_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("smtp_banner_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("pop3_banner_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("imap_banner_contains", [])) * self.STRONG_WEIGHT +
            (1 * self.STRONG_WEIGHT if rule.get("favicon_hash") is not None else 0) +
            len(rule.get("server_contains", [])) * self.MEDIUM_WEIGHT +
            len(rule.get("mac_vendor_contains", [])) * self.MEDIUM_WEIGHT +
            len(rule.get("hostname_contains", [])) * self.MEDIUM_WEIGHT +
            len(rule.get("cert_issuer_contains", [])) * self.MEDIUM_WEIGHT +
            len(rule.get("ports", [])) * self.WEAK_WEIGHT
        )

        if max_possible == 0:
            return None
        if strong == 0:
            return None

        confidence = min(total_score / max_possible, 1.0)

     

        return {
            "device_type": rule.get("name"),
            "category": rule.get("category"),
            "os_guess": rule.get("os_guess"),
            "confidence": round(confidence, 2)
        }
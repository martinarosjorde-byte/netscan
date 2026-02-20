import json
import os


class FingerprintEngine:

    def __init__(self, db_path=None):

        # Resolve default path relative to this file
        if db_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(base_dir, "..", "fingerprints", "fingerprints.json")
            db_path = os.path.abspath(db_path)

        self.database = []

        if os.path.exists(db_path):
            with open(db_path, "r", encoding="utf-8") as f:
                self.database = json.load(f)
        else:
            print(f"[FingerprintEngine] Database not found: {db_path}")

        print(f"[FingerprintEngine] Loaded fingerprint rules: {len(self.database)}")
    # -------------------------------------------------
    # Public API
    # -------------------------------------------------

    def fingerprint(self, host_data):

        matches = []

        for entry in self.database:
            score = self.evaluate(entry, host_data)

            # Minimum threshold
            if score >= 0.5:
                matches.append({
                    "device_type": entry.get("name"),
                    "category": entry.get("category"),
                    "os_guess": entry.get("os_guess"),
                    "confidence": round(min(score, 1.0), 2)
                })

        matches.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "matches": matches,
            "best_match": matches[0] if matches else None
        }

    # -------------------------------------------------
    # Rule Evaluation
    # -------------------------------------------------

    def evaluate(self, rule, host):

        score = 0.0

        ports = host.get("ports", [])
        http80 = host.get("http_80") or {}
        http443 = host.get("http_443") or {}

        title = (http80.get("title") or "") + " " + (http443.get("title") or "")
        server = (http80.get("server") or "") + " " + (http443.get("server") or "")
        favicon_hash = http80.get("favicon_hash") or http443.get("favicon_hash")

        cert = http443.get("cert") or {}
        cert_cn = cert.get("common_name") or ""
        cert_issuer = cert.get("issuer") or ""
        cert_san = " ".join(cert.get("san", []))

        ssh_banner = host.get("ssh_banner") or ""
        smtp_banner = host.get("smtp_banner") or ""
        ftp_banner = host.get("ftp_banner") or ""
        pop3_banner = host.get("pop3_banner") or ""
        imap_banner = host.get("imap_banner") or ""

        mac_vendor = host.get("vendor") or ""
        hostname = host.get("hostname") or ""

        # Normalize
        title = title.lower()
        server = server.lower()
        cert_cn = cert_cn.lower()
        cert_issuer = cert_issuer.lower()
        cert_san = cert_san.lower()
        ssh_banner = ssh_banner.lower()
        smtp_banner = smtp_banner.lower()
        ftp_banner = ftp_banner.lower()
        pop3_banner = pop3_banner.lower()
        imap_banner = imap_banner.lower()
        mac_vendor = mac_vendor.lower()
        hostname = hostname.lower()

        # -------------------------
        # Strong Signals
        # -------------------------

        # MAC Vendor (very strong for network devices)
        for keyword in rule.get("mac_vendor_contains", []):
            if keyword.lower() in mac_vendor:
                score += 0.5

        # Server Header
        for keyword in rule.get("server_contains", []):
            if keyword.lower() in server:
                score += 0.4

        # HTTP Title
        for keyword in rule.get("http_title_contains", []):
            if keyword.lower() in title:
                score += 0.4

        # -------------------------
        # Medium Signals
        # -------------------------

        # Ports
        for p in rule.get("ports", []):
            if p in ports:
                score += 0.3

        # Certificate CN
        for keyword in rule.get("cert_common_name_contains", []):
            if keyword.lower() in cert_cn:
                score += 0.3

        # Certificate Issuer
        for keyword in rule.get("cert_issuer_contains", []):
            if keyword.lower() in cert_issuer:
                score += 0.2

        # Certificate SAN
        for keyword in rule.get("cert_san_contains", []):
            if keyword.lower() in cert_san:
                score += 0.2

        # -------------------------
        # Banner Signals
        # -------------------------

        banner_fields = [
            ("ssh_banner_contains", ssh_banner),
            ("smtp_banner_contains", smtp_banner),
            ("ftp_banner_contains", ftp_banner),
            ("pop3_banner_contains", pop3_banner),
            ("imap_banner_contains", imap_banner),
        ]

        for field, value in banner_fields:
            for keyword in rule.get(field, []):
                if keyword.lower() in value:
                    score += 0.3

        # -------------------------
        # Favicon Hash (very strong)
        # -------------------------

        if rule.get("favicon_hash") and favicon_hash:
            if rule["favicon_hash"] == favicon_hash:
                score += 1.0

        # -------------------------
        # Hostname match
        # -------------------------

        for keyword in rule.get("hostname_contains", []):
            if keyword.lower() in hostname:
                score += 0.3

        # Apply rule weight
        weight = rule.get("confidence_weight", 1.0)
        score *= weight

        return score
import json
import os


class FingerprintEngine:

    STRONG_WEIGHT = 1.0
    MEDIUM_WEIGHT = 0.5
    WEAK_WEIGHT = 0.1
    MIN_CONFIDENCE = 0.6

    def __init__(self, db_path=None):

        if db_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(base_dir, "..", "fingerprints", "fingerprints.json")
            db_path = os.path.abspath(db_path)

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

            # Extract normalized host fields
        ports = host.get("ports", [])
        
        # -------------------------
        # HTTP Aggregation (NEW MODEL)
        # -------------------------

        http_services = host.get("http_services", {})
        title = ""
        server = ""
        favicon_hash = None
        cert = {}

        for svc in http_services.values():
            title += (svc.get("title") or "") + " "
            server += (svc.get("server") or "") + " "

            if svc.get("favicon_hash"):
                favicon_hash = svc.get("favicon_hash")

            if svc.get("cert"):
                cert = svc.get("cert")

        title = title.lower()
        server = server.lower()

        cert_cn = (cert.get("common_name") or "").lower()
        cert_issuer = (cert.get("issuer") or "").lower()

        ssh_banner = (host.get("ssh_banner") or "").lower()
        smtp_banner = (host.get("smtp_banner") or "").lower()
        ftp_banner = (host.get("ftp_banner") or "").lower()

        mac_vendor = (host.get("vendor") or "").lower()
        hostname = (host.get("hostname") or "").lower()

        # -------------------------
        # STRONG SIGNALS
        # -------------------------

        if any(k.lower() in title for k in rule.get("http_title_contains", [])):
            strong += 1

        if any(k.lower() in cert_cn for k in rule.get("cert_common_name_contains", [])):
            strong += 1

        if rule.get("favicon_hash") and favicon_hash == rule.get("favicon_hash"):
            strong += 1

        if any(k.lower() in ssh_banner for k in rule.get("ssh_banner_contains", [])):
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
        # Compute Weighted Score
        # -------------------------

        total_score = (
            strong * self.STRONG_WEIGHT +
            medium * self.MEDIUM_WEIGHT +
            weak * self.WEAK_WEIGHT
        )

        max_possible = (
            len(rule.get("http_title_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("cert_common_name_contains", [])) * self.STRONG_WEIGHT +
            len(rule.get("ssh_banner_contains", [])) * self.STRONG_WEIGHT +
            (1 if rule.get("favicon_hash") else 0) * self.STRONG_WEIGHT +

            len(rule.get("server_contains", [])) * self.MEDIUM_WEIGHT +
            len(rule.get("mac_vendor_contains", [])) * self.MEDIUM_WEIGHT +
            len(rule.get("hostname_contains", [])) * self.MEDIUM_WEIGHT +
            len(rule.get("cert_issuer_contains", [])) * self.MEDIUM_WEIGHT +

            len(rule.get("ports", [])) * self.WEAK_WEIGHT
        )

        if max_possible == 0:
            return None

        confidence = min(total_score / max_possible, 1.0)

        if confidence < 0.4:
            return None

        
        return {
            "device_type": rule.get("name"),
            "category": rule.get("category"),
            "os_guess": rule.get("os_guess"),
            "confidence": round(confidence, 2)
        }
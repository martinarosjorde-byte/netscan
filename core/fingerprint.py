# core/fingerprint.py
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class MatchResult:
    fingerprint_id: str
    name: str
    category: Optional[str]
    os_guess: Optional[str]
    priority: int
    score: float
    max_score: float
    confidence: float
    confidence_level: str
    matched_signals: List[str]
    negative_hits: List[str]


class FingerprintEngine:
    """
    NetScan Learning Engine 3.0
    - Weighted signals (strong/medium/weak)
    - Negative signals
    - Explainable results
    - Priority + score tie-breaking
    """

    DEFAULT_WEIGHTS = {"strong": 5.0, "medium": 3.0, "weak": 1.0}
    DEFAULT_THRESHOLDS = {"min": 5.0, "high": 12.0}  # score thresholds

    def __init__(self, db_path: str | None = None, debug: bool = False):
        self.debug = debug

        if db_path is None:
            if getattr(sys, "frozen", False):
                program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
                db_path = os.path.join(program_data, "NetScan")
            else:
                base_dir = os.path.dirname(os.path.abspath(__file__))
                db_path = os.path.abspath(os.path.join(base_dir, "..", "fingerprints"))
        
        self.db_path = db_path
        self.metadata: Dict[str, Any] = {}
        self.global_settings: Dict[str, Any] = {}
        self.fingerprints: List[Dict[str, Any]] = []
        self.schema_version: str = "unknown"
        self._load_db()

        self.weights = {
            "strong": float(self.global_settings.get("strong_weight", self.DEFAULT_WEIGHTS["strong"])),
            "medium": float(self.global_settings.get("medium_weight", self.DEFAULT_WEIGHTS["medium"])),
            "weak": float(self.global_settings.get("weak_weight", self.DEFAULT_WEIGHTS["weak"])),
        }

        self.threshold_min = float(self.global_settings.get("confidence_threshold", self.DEFAULT_THRESHOLDS["min"]))
        self.threshold_high = float(self.global_settings.get("high_confidence_threshold", self.DEFAULT_THRESHOLDS["high"]))


        if self.debug:
            print(f"[FingerprintEngine3] Loaded {len(self.fingerprints)} fingerprints")
            print("Threshold Min:", self.threshold_min)

    def _load_db(self) -> None:
        base_path = self.db_path

        if not os.path.exists(base_path):
            self.metadata = {}
            self.global_settings = {}
            self.fingerprints = []
            self.schema_version = "missing"
            return

        # If db_path is a file → load that file only
        if os.path.isfile(base_path):
            with open(base_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self._parse_db_data(data)
            return

        # If db_path is a directory → load all *.json
        if os.path.isdir(base_path):
            merged_fingerprints = []
            merged_metadata = {}
            merged_settings = {}

            for filename in os.listdir(base_path):
                if not filename.endswith(".json"):
                    continue

                full_path = os.path.join(base_path, filename)

                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if "fingerprints" in data:
                    merged_fingerprints.extend(data.get("fingerprints", []))
                    merged_metadata.update(data.get("metadata", {}))
                if filename == "_engine_config.json":
                    merged_settings.update(data.get("global_settings", {}))

            self.metadata = merged_metadata
            self.global_settings = merged_settings
            self.fingerprints = merged_fingerprints
            self.schema_version = str(self.metadata.get("schema_version", "3.0"))

            if self.debug:
                print(f"[FingerprintEngine3] Loaded {len(self.fingerprints)} fingerprints from directory")
                
            return

        self.fingerprints = []
        self.schema_version = "unknown"


    def _parse_db_data(self, data: Dict[str, Any]) -> None:
        if isinstance(data, dict) and "fingerprints" in data:
            self.metadata = data.get("metadata", {})
            self.global_settings = data.get("global_settings", {})
            self.fingerprints = data.get("fingerprints", [])
            self.schema_version = str(self.metadata.get("schema_version", "3.0"))
            return
    # -------------------------
    # Public API
    # -------------------------

    def fingerprint(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(host_data)

        results: List[MatchResult] = []
        for fp in self.fingerprints:
            mr = self._evaluate_fingerprint(fp, features)
            if mr is not None:
                # Only keep matches above minimum threshold
                if mr.score >= self.threshold_min:
                    results.append(mr)

        # Sort: priority desc, then score desc, then confidence desc
        results.sort(key=lambda r: (r.priority, r.score, r.confidence), reverse=True)

        best = results[0] if results else None

        return {
            "best_match": (best.__dict__ if best else None),
            "matches": [r.__dict__ for r in results],
        }

    
    def _legacy_rule_to_fp(self, rule: Dict[str, Any], idx: int) -> Dict[str, Any]:
        """
        Minimal bridge so you can run old DB through new evaluator.
        It maps old keys into signals buckets using your previous semantics.
        """
        def _get_list(k: str) -> List[Any]:
            v = rule.get(k, [])
            return v if isinstance(v, list) else [v]

        strong_http = {}
        if _get_list("http_title_contains"):
            strong_http["title_contains"] = _get_list("http_title_contains")
        if _get_list("http_body_contains"):
            strong_http["body_contains"] = _get_list("http_body_contains")
        if _get_list("http_header_contains"):
            strong_http["header_contains"] = _get_list("http_header_contains")

        strong_ssl = {}
        if _get_list("cert_common_name_contains"):
            strong_ssl["cert_common_name_contains"] = _get_list("cert_common_name_contains")
        if _get_list("cert_san_contains"):
            strong_ssl["cert_san_contains"] = _get_list("cert_san_contains")

        medium_http = {}
        if _get_list("server_contains"):
            medium_http["server_contains"] = _get_list("server_contains")

        medium_device = {}
        if _get_list("mac_vendor_contains"):
            medium_device["mac_vendor_contains"] = _get_list("mac_vendor_contains")
        if _get_list("hostname_contains"):
            medium_device["hostname_contains"] = _get_list("hostname_contains")

        medium_ssl = {}
        if _get_list("cert_issuer_contains"):
            medium_ssl["cert_issuer_contains"] = _get_list("cert_issuer_contains")

        strong_misc = {}
        if rule.get("favicon_hashes"):
            strong_misc["favicon_hashes"] = rule.get("favicon_hashes")

        fp = {
            "id": f"legacy_{idx}",
            "name": rule.get("name", f"legacy_{idx}"),
            "category": rule.get("category"),
            "os_guess": rule.get("os_guess"),
            "priority": int(rule.get("priority", 0)),
            "signals": {
                "strong": {
                    **({"http": strong_http} if strong_http else {}),
                    **({"ssl": strong_ssl} if strong_ssl else {}),
                    **({"misc": strong_misc} if strong_misc else {}),
                    **({"ssh": {"banner_contains": _get_list("ssh_banner_contains")} } if _get_list("ssh_banner_contains") else {}),
                    **({"smtp": {"banner_contains": _get_list("smtp_banner_contains")} } if _get_list("smtp_banner_contains") else {}),
                    **({"ftp": {"banner_contains": _get_list("ftp_banner_contains")} } if _get_list("ftp_banner_contains") else {}),
                    **({"pop3": {"banner_contains": _get_list("pop3_banner_contains")} } if _get_list("pop3_banner_contains") else {}),
                    **({"imap": {"banner_contains": _get_list("imap_banner_contains")} } if _get_list("imap_banner_contains") else {}),
                },
                "medium": {
                    **({"http": medium_http} if medium_http else {}),
                    **({"ssl": medium_ssl} if medium_ssl else {}),
                    **({"device": medium_device} if medium_device else {}),
                },
                "weak": {
                    **({"ports": rule.get("ports")} if rule.get("ports") else {}),
                },
            },
            "negative_signals": rule.get("negative_signals", {}),
        }
        return fp

    # -------------------------
    # Feature extraction
    # -------------------------

    def _extract_features(self, host: Dict[str, Any]) -> Dict[str, Any]:
        ports = host.get("ports") or []
        ports_set = set(int(p) for p in ports)

        # Aggregate HTTP like you already do
        http_services = host.get("http_services") or {}

        title = ""
        server = ""
        body = ""
        headers_combined = ""
        cookies_combined = ""
        favicon_hash = None
        cert: Dict[str, Any] = {}

        for svc in http_services.values():
            title += (svc.get("title") or "") + " "
            server += (svc.get("server") or "") + " "

            body += (svc.get("initial_body_preview") or "") + " "
            body += (svc.get("body_preview") or "") + " "

            headers = svc.get("headers") or {}
            for h_name, h_value in headers.items():
                headers_combined += f"{h_name} {h_value} "
                if str(h_name).lower() == "set-cookie":
                    cookies_combined += f"{h_value} "

            if svc.get("favicon_hash") is not None:
                favicon_hash = svc.get("favicon_hash")

            if svc.get("cert"):
                cert = svc.get("cert") or {}

        # normalize
        def norm(s: Any) -> str:
            return (s or "").strip().lower()

        cert_cn = norm(cert.get("common_name"))
        cert_issuer = norm(cert.get("issuer"))
        cert_san = " ".join([norm(x) for x in (cert.get("san") or [])]).strip()

        features = {
            "ports_set": ports_set,
            "vendor": norm(host.get("vendor")),
            "hostname": norm(host.get("hostname")),
            "ssh_banner": norm(host.get("ssh_banner")),
            "smtp_banner": norm(host.get("smtp_banner")),
            "ftp_banner": norm(host.get("ftp_banner")),
            "pop3_banner": norm(host.get("pop3_banner")),
            "imap_banner": norm(host.get("imap_banner")),

            "http_title": norm(title),
            "http_server": norm(server),
            "http_body": norm(body),
            "http_headers": norm(headers_combined),
            "http_cookies": norm(cookies_combined),

            "favicon_hash": favicon_hash,
            "cert_cn": cert_cn,
            "cert_issuer": cert_issuer,
            "cert_san": cert_san,
        }
        return features

    # -------------------------
    # Matching primitives
    # -------------------------

    def _contains_any(self, haystack: str, needles: List[str]) -> bool:
        if not haystack or not needles:
            return False
        h = haystack
        for n in needles:
            if str(n).lower() in h:
                return True
        return False

    def _count_contains(self, haystack: str, needles: List[str]) -> Tuple[int, List[str]]:
        """Returns (#hits, matched_items_as_strings)"""
        hits = 0
        matched: List[str] = []
        if not haystack or not needles:
            return 0, matched
        h = haystack
        for n in needles:
            ns = str(n).lower()
            if ns in h:
                hits += 1
                matched.append(ns)
        return hits, matched

    def _ports_hit(self, ports_set: set[int], required_ports: List[int] | None) -> bool:
        if not required_ports:
            return False
        for p in required_ports:
            try:
                if int(p) in ports_set:
                    return True
            except Exception:
                continue
        return False

    # -------------------------
    # Fingerprint evaluation
    # -------------------------

    def _evaluate_fingerprint(self, fp: Dict[str, Any], feat: Dict[str, Any]) -> Optional[MatchResult]:
        fp_id = str(fp.get("id") or fp.get("name") or "unknown")
        name = fp.get("name") or fp_id
        category = fp.get("category")
        os_guess = fp.get("os_guess")
        priority = int(fp.get("priority") or 0)

        signals = fp.get("signals") or {}
        negative = fp.get("negative_signals") or {}

        matched_signals: List[str] = []
        negative_hits: List[str] = []

        score = 0.0
        max_score = 0.0

        
        # Evaluate buckets in order
        for bucket in ("strong", "medium", "weak"):
            bucket_weight = self.weights[bucket]
            bucket_signals = signals.get(bucket) or {}

            # Compute theoretical max for this bucket (for confidence derivation if you want it)
            max_score += self._max_bucket_score(bucket_signals, bucket_weight)

            gained, matched = self._eval_bucket(bucket_signals, feat, bucket_weight)
            score += gained
            matched_signals.extend([f"{bucket}.{m}" for m in matched])

        # Negative signals: if hit -> invalidate or penalty
        neg_hit, neg_details = self._eval_negative(negative, feat)
        if neg_hit:
            negative_hits.extend(neg_details)
            # Option A (strict): invalidate
            return None
            # Option B (penalty) could be:
            # score *= 0.5

        if max_score <= 0:
            return None


        strong_hits = self._strong_hits_count(signals.get("strong") or {}, feat)

        if strong_hits >= 2:
            confidence = 0.9
        elif strong_hits == 1:
            confidence = 0.75
        else:
            confidence = min(score / max_score, 0.6)

        # Confidence level for display
        if confidence >= 0.75:
            conf_level = "High"
        elif confidence >= 0.45:
            conf_level = "Medium"
        else:
            conf_level = "Low"

        if self.debug and score >= self.threshold_min:
            print(f"\n[FP HIT] {name}")
            print(f"  Score: {score} / {max_score}")
            print(f"  Matched Signals: {matched_signals}")

            if negative_hits:
                print(f"  Negative Signals: {negative_hits}")

        # Optional guard: require at least 1 strong hit (prevents port-only matches)
        # (Keep this if you want the old behavior)
        if self._strong_hits_count(signals.get("strong") or {}, feat) == 0:
            return None

        return MatchResult(
            fingerprint_id=fp_id,
            name=name,
            category=category,
            os_guess=os_guess,
            priority=priority,
            score=round(score, 2),
            max_score=round(max_score, 2),
            confidence=round(confidence, 2),
            confidence_level=conf_level,
            matched_signals=matched_signals,
            negative_hits=negative_hits,
        )

    def _strong_hits_count(self, strong_bucket: Dict[str, Any], feat: Dict[str, Any]) -> int:
        gained, matched = self._eval_bucket(strong_bucket, feat, self.weights["strong"])
        # Each hit contributes weight; convert back into approx count
        return int(round(gained / self.weights["strong"])) if self.weights["strong"] else 0

    def _max_bucket_score(self, bucket_signals: Dict[str, Any], weight: float) -> float:
        if not bucket_signals:
            return 0.0

        count = 0

        # HTTP groups
        http = bucket_signals.get("http") or {}
        for k in ("title_contains", "body_contains", "header_contains",
                "cookie_contains", "server_contains"):
            if http.get(k):
                count += 1

        # SSL groups
        ssl = bucket_signals.get("ssl") or {}
        for k in ("cert_common_name_contains",
                "cert_issuer_contains",
                "cert_san_contains"):
            if ssl.get(k):
                count += 1

        # Banner groups
        for proto in ("ssh", "smtp", "ftp", "pop3", "imap"):
            block = bucket_signals.get(proto) or {}
            if block.get("banner_contains"):
                count += 1

        # Device groups
        device = bucket_signals.get("device") or {}
        for k in ("mac_vendor_contains", "hostname_contains"):
            if device.get(k):
                count += 1

        # Misc
        misc = bucket_signals.get("misc") or {}
        if misc.get("favicon_hashes"):
            count += 1

        # Ports
        if bucket_signals.get("ports"):
            count += 1

        return float(count) * weight
    

    def _eval_bucket(self, bucket_signals: Dict[str, Any], feat: Dict[str, Any], weight: float) -> Tuple[float, List[str]]:
        """
        Returns (gained_score, matched_signal_labels)
        Each atomic match adds weight (not per-field weight).
        """
        if not bucket_signals:
            return 0.0, []

        gained = 0.0
        matched_labels: List[str] = []

        # HTTP
        http = bucket_signals.get("http") or {}
        gained, matched_labels = self._eval_http(http, feat, weight, gained, matched_labels)

        # SSL
        ssl = bucket_signals.get("ssl") or {}
        gained, matched_labels = self._eval_ssl(ssl, feat, weight, gained, matched_labels)

        # Banners
        for proto, feat_key in (
            ("ssh", "ssh_banner"),
            ("smtp", "smtp_banner"),
            ("ftp", "ftp_banner"),
            ("pop3", "pop3_banner"),
            ("imap", "imap_banner"),
        ):
            block = bucket_signals.get(proto) or {}
            needles = block.get("banner_contains") or []
            hits, items = self._count_contains(feat.get(feat_key, ""), needles)
            if hits:
                gained += hits * weight
                for it in items:
                    matched_labels.append(f"{proto}.banner_contains:{it}")

        # Device
        device = bucket_signals.get("device") or {}
        needles = device.get("mac_vendor_contains") or []
        hits, items = self._count_contains(feat.get("vendor", ""), needles)
        if hits:
            gained += hits * weight
            for it in items:
                matched_labels.append(f"device.mac_vendor_contains:{it}")

        needles = device.get("hostname_contains") or []
        hits, items = self._count_contains(feat.get("hostname", ""), needles)
        if hits:
            gained += hits * weight
            for it in items:
                matched_labels.append(f"device.hostname_contains:{it}")

        # Misc
        misc = bucket_signals.get("misc") or {}
        favs = misc.get("favicon_hashes") or []
        if isinstance(favs, list) and favs and feat.get("favicon_hash") is not None:
            if feat["favicon_hash"] in favs:
                gained += 1 * weight
                matched_labels.append("misc.favicon_hashes")

        # Ports (treat as single check)
        ports = bucket_signals.get("ports")
        if isinstance(ports, list) and ports:
            if self._ports_hit(feat["ports_set"], ports):
                gained += 1 * weight
                matched_labels.append("ports.any")

        return gained, matched_labels

    def _eval_http(self, http: Dict[str, Any], feat: Dict[str, Any], weight: float, gained: float, labels: List[str]):
        # title_contains
        hits, items = self._count_contains(feat.get("http_title", ""), http.get("title_contains") or [])
        if hits:
            gained += hits * weight
            for it in items:
                labels.append(f"http.title_contains:{it}")

        # body_contains
        hits, items = self._count_contains(feat.get("http_body", ""), http.get("body_contains") or [])
        if hits:
            gained += hits * weight
            labels.append("http.body_contains")

        # header_contains
        hits, items = self._count_contains(feat.get("http_headers", ""), http.get("header_contains") or [])
        if hits:
            gained += hits * weight
            for it in items:
                labels.append(f"http.header_contains:{it}")

        # cookie_contains
        hits, items = self._count_contains(feat.get("http_cookies", ""), http.get("cookie_contains") or [])
        if hits:
            gained += hits * weight
            for it in items:
                labels.append(f"http.cookie_contains:{it}")

        # server_contains
        hits, items = self._count_contains(feat.get("http_server", ""), http.get("server_contains") or [])
        if hits:
            gained += hits * weight
            for it in items:
                labels.append(f"http.server_contains:{it}")

        return gained, labels

    def _eval_ssl(self, ssl: Dict[str, Any], feat: Dict[str, Any], weight: float, gained: float, labels: List[str]):
        hits, items = self._count_contains(feat.get("cert_cn", ""), ssl.get("cert_common_name_contains") or [])
        if hits:
            gained += hits * weight
            for it in items:
                labels.append(f"ssl.cert_common_name_contains:{it}")

        hits, items = self._count_contains(feat.get("cert_issuer", ""), ssl.get("cert_issuer_contains") or [])
        if hits:
            gained += hits * weight
            for it in items:
                labels.append(f"ssl.cert_issuer_contains:{it}")

        hits, items = self._count_contains(feat.get("cert_san", ""), ssl.get("cert_san_contains") or [])
        if hits:
            gained += hits * weight
            for it in items:
                labels.append(f"ssl.cert_san_contains:{it}")

        return gained, labels

    def _eval_negative(self, negative: Dict[str, Any], feat: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        If ANY negative signal hits -> return (True, details)
        You can make this more nuanced (penalty scores), but strict invalidation is simplest.
        """
        if not negative:
            return False, []

        hits: List[str] = []

        http = negative.get("http") or {}
        if self._contains_any(feat.get("http_server", ""), http.get("server_contains") or []):
            hits.append("negative.http.server_contains")
        if self._contains_any(feat.get("http_title", ""), http.get("title_contains") or []):
            hits.append("negative.http.title_contains")
        if self._contains_any(feat.get("http_body", ""), http.get("body_contains") or []):
            hits.append("negative.http.body_contains")

        ssl = negative.get("ssl") or {}
        if self._contains_any(feat.get("cert_cn", ""), ssl.get("cert_common_name_contains") or []):
            hits.append("negative.ssl.cert_common_name_contains")
        if self._contains_any(feat.get("cert_issuer", ""), ssl.get("cert_issuer_contains") or []):
            hits.append("negative.ssl.cert_issuer_contains")

        device = negative.get("device") or {}
        if self._contains_any(feat.get("vendor", ""), device.get("mac_vendor_contains") or []):
            hits.append("negative.device.mac_vendor_contains")

        ports = negative.get("ports")
        if isinstance(ports, list) and ports and self._ports_hit(feat["ports_set"], ports):
            hits.append("negative.ports.any")

        return (len(hits) > 0), hits
from __future__ import annotations

import os
import json
from dataclasses import dataclass
from typing import List, Dict, Any


# ---------------------------------------------------------
# Database container returned to the engine
# ---------------------------------------------------------

@dataclass
class FingerprintDatabase:
    fingerprints: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    global_settings: Dict[str, Any]
    schema_version: str
    pack_count: int = 0
    fingerprint_count: int = 0


# ---------------------------------------------------------
# Loader Class
# ---------------------------------------------------------

class FingerprintPackLoader:
    """
    Responsible ONLY for:
    - Loading JSON fingerprint packs
    - Flattening nested lists
    - Validating schema
    - Detecting duplicate IDs
    - Loading optional _engine_config.json
    """

    REQUIRED_FIELDS = ["id", "name", "signals"]

    def __init__(self, strict: bool = False, verbose: bool = True):
        self.strict = strict
        self.verbose = verbose

    # =========================================================
    # Public API
    # =========================================================

    def load(self, path: str) -> FingerprintDatabase:
        if not os.path.exists(path):
            self._warn(f"Fingerprint path not found: {path}")
            return FingerprintDatabase([], {}, {}, "missing")

        if os.path.isfile(path):
            return self._load_file(path)

        if os.path.isdir(path):
            return self._load_directory(path)

        return FingerprintDatabase([], {}, {}, "unknown")

    # =========================================================
    # Directory Loader
    # =========================================================

    def _load_directory(self, directory: str) -> FingerprintDatabase:

        pack_count = 0
        fingerprints: List[Dict[str, Any]] = []
        metadata: Dict[str, Any] = {}
        global_settings: Dict[str, Any] = {}
        seen_ids: Dict[str, str] = {}

        for filename in sorted(os.listdir(directory)):

            # Ignore hidden/system files
            if filename.startswith("."):
                continue

            if not filename.endswith(".json"):
                continue

            full_path = os.path.join(directory, filename)

            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception as e:
                self._error(f"Failed to load {filename}: {e}")
                continue

            # ---------------------------------
            # Engine config special case
            # ---------------------------------

            if filename == "_engine_config.json":
                if isinstance(raw, dict):
                    global_settings.update(raw.get("global_settings", {}))
                continue

            pack_count += 1

            extracted = self._extract_fingerprints(raw, filename)

            for fp in extracted:

                fp_id = fp.get("id")

                # Track which pack it came from (useful for debugging)
                fp["_pack"] = filename

                if fp_id in seen_ids:

                    original_file = seen_ids[fp_id]

                    self._warn(
                        f"Duplicate fingerprint ID '{fp_id}'\n"
                        f"   First seen in: {original_file}\n"
                        f"   Duplicate in : {filename}\n"
                        f"   → Skipping duplicate"
                    )

                    continue

                seen_ids[fp_id] = filename
                fingerprints.append(fp)

            if isinstance(raw, dict):
                metadata.update(raw.get("metadata", {}))

        if self.verbose:
            self._info(
                f"Loaded {len(fingerprints)} fingerprints from {pack_count} pack(s)"
            )

        return FingerprintDatabase(
            fingerprints=fingerprints,
            metadata=metadata,
            global_settings=global_settings,
            schema_version=str(metadata.get("schema_version", "3.0")),
            pack_count=pack_count,
            fingerprint_count=len(fingerprints),
        )

    # =========================================================
    # Single File Loader
    # =========================================================

    def _load_file(self, path: str) -> FingerprintDatabase:

        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            self._error(f"Failed to load file {path}: {e}")
            return FingerprintDatabase([], {}, {}, "invalid")

        fingerprints = self._extract_fingerprints(raw, os.path.basename(path))

        metadata = raw.get("metadata", {}) if isinstance(raw, dict) else {}
        global_settings = raw.get("global_settings", {}) if isinstance(raw, dict) else {}

        if self.verbose:
            self._info(f"Loaded {len(fingerprints)} fingerprints from file")

        return FingerprintDatabase(
            fingerprints=fingerprints,
            metadata=metadata,
            global_settings=global_settings,
            schema_version=str(metadata.get("schema_version", "3.0")),
            pack_count=1,
            fingerprint_count=len(fingerprints),
        )

    # =========================================================
    # Fingerprint Extraction
    # =========================================================

    def _extract_fingerprints(self, raw: Any, filename: str) -> List[Dict[str, Any]]:
        """
        Supports:
        - { metadata, fingerprints: [...] }
        - [ ... ]
        - single fingerprint dict
        - nested lists
        """

        if isinstance(raw, dict) and "fingerprints" in raw:
            raw = raw["fingerprints"]

        flattened = self._flatten(raw)

        valid: List[Dict[str, Any]] = []

        for fp in flattened:
            if not self._validate_schema(fp, filename):
                continue
            valid.append(fp)

        return valid

    def _flatten(self, obj: Any) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        if isinstance(obj, list):
            for item in obj:
                result.extend(self._flatten(item))

        elif isinstance(obj, dict):
            result.append(obj)

        else:
            self._warn(f"Ignoring unsupported structure: {type(obj)}")

        return result

    # =========================================================
    # Validation
    # =========================================================

    def _validate_schema(self, fp: Dict[str, Any], filename: str) -> bool:

        if not isinstance(fp, dict):
            self._error(f"Invalid fingerprint type in {filename}: not a dict")
            return False

        for field in self.REQUIRED_FIELDS:
            if field not in fp:
                self._error(
                    f"Fingerprint missing '{field}' in {filename} "
                    f"({fp.get('id', 'unknown')})"
                )
                return False

        if not isinstance(fp["signals"], dict):
            self._error(
                f"'signals' must be dict in {filename} ({fp.get('id')})"
            )
            return False

        return True

    # =========================================================
    # Logging Helpers
    # =========================================================

    def _info(self, msg: str):
        if self.verbose:
            print(f"[FingerprintLoader] {msg}")

    def _warn(self, msg: str):
        print(f"[FingerprintLoader] ⚠️  {msg}")

    def _error(self, msg: str):
        if self.strict:
            raise ValueError(msg)
        print(f"[FingerprintLoader] ❌ {msg}")
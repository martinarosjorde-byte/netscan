import urllib.request
import json
import os
from version import __version__

GITHUB_API = "https://api.github.com/repos/martinarosjorde-byte/netscan/releases/latest"
FINGERPRINT_DB_URL = "https://raw.githubusercontent.com/martinarosjorde-byte/netscan/main/fingerprints/fingerprints.json"


# -------------------------------------------------
# Application Update Check
# -------------------------------------------------
def check_for_updates(timeout=3):
    try:
        req = urllib.request.Request(
            GITHUB_API,
            headers={"User-Agent": "NetScan-Enterprise"}
        )

        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode())

        latest_version = data.get("tag_name", "").lstrip("v")

        if not latest_version:
            return {"status": "unknown"}

        if latest_version != __version__:
            return {
                "status": "outdated",
                "latest": latest_version
            }

        return {
            "status": "latest",
            "latest": latest_version
        }

    except Exception:
        return {"status": "error"}


# -------------------------------------------------
# Fingerprint DB Update System
# -------------------------------------------------
class FingerprintDBUpdater:

    def __init__(self, local_path: str):
        self.local_path = local_path
        self.remote_url = FINGERPRINT_DB_URL

    def exists(self):
        return os.path.exists(self.local_path)

    def get_local_version(self):
        if not self.exists():
            return None
        try:
            with open(self.local_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("metadata", {}).get("version")
        except Exception:
            return None

    def get_remote_version(self, timeout=5):
        try:
            req = urllib.request.Request(
                self.remote_url,
                headers={"User-Agent": "NetScan-Enterprise"}
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())

            return data.get("metadata", {}).get("version")

        except Exception:
            return None

    def download(self, timeout=10):
        try:
            req = urllib.request.Request(
                self.remote_url,
                headers={"User-Agent": "NetScan-Enterprise"}
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                content = response.read().decode()

            # Ensure directory exists
            os.makedirs(os.path.dirname(self.local_path), exist_ok=True)

            with open(self.local_path, "w", encoding="utf-8") as f:
                f.write(content)

            return True

        except Exception:
            return False

    def is_newer(self, local, remote):
        if not local:
            return True
        return remote != local
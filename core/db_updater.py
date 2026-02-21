import os
import requests
import json


class FingerprintDBUpdater:

    def __init__(self, local_path, remote_url):
        self.local_path = local_path
        self.remote_url = remote_url

    # -----------------------------------
    # Check if local DB exists
    # -----------------------------------
    def exists(self):
        return os.path.exists(self.local_path)

    # -----------------------------------
    # Get local DB version
    # -----------------------------------
    def get_local_version(self):
        if not self.exists():
            return None

        try:
            with open(self.local_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data.get("metadata", {}).get("version")
        except Exception:
            return None

        return None

    # -----------------------------------
    # Get remote DB version
    # -----------------------------------
    def get_remote_version(self):
        try:
            r = requests.get(self.remote_url, timeout=5)
            if r.status_code == 200:
                data = r.json()
                return data.get("metadata", {}).get("version")
        except Exception:
            return None

        return None

    # -----------------------------------
    # Download DB
    # -----------------------------------
    def download(self):
        try:
            r = requests.get(self.remote_url, timeout=10)
            if r.status_code == 200:
                with open(self.local_path, "w", encoding="utf-8") as f:
                    f.write(r.text)
                return True
        except Exception:
            pass

        return False

    # -----------------------------------
    # Version comparison (simple)
    # -----------------------------------
    def is_newer(self, local, remote):
        if not local:
            return True
        return remote != local
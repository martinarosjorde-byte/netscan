from __future__ import annotations

import requests
from pathlib import Path


class FingerprintDBUpdater:

    def __init__(self, local_dir: str, remote_base_url: str):

        self.local_dir = Path(local_dir)
        self.remote_base_url = remote_base_url.rstrip("/")

        self.api_url = "https://api.github.com/repos/martinarosjorde-byte/netscan/contents/fingerprints"

        self.local_dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # Get remote fingerprint files + SHA
    # ---------------------------------------------------------

    def get_remote_files(self):

        try:

            r = requests.get(self.api_url, timeout=5)

            if r.status_code == 200:

                data = r.json()

                return {
                    file["name"]: file["sha"]
                    for file in data
                    if file["type"] == "file" and file["name"].endswith(".json")
                }

        except Exception:
            pass

        return {}

    # ---------------------------------------------------------
    # Get stored local SHA
    # ---------------------------------------------------------

    def get_local_sha(self, filename):

        sha_file = self.local_dir / f"{filename}.sha"

        if sha_file.exists():
            return sha_file.read_text().strip()

        return None

    # ---------------------------------------------------------
    # Save SHA locally
    # ---------------------------------------------------------

    def save_local_sha(self, filename, sha):

        sha_file = self.local_dir / f"{filename}.sha"
        sha_file.write_text(sha)

    # ---------------------------------------------------------
    # Determine which packs need update
    # ---------------------------------------------------------

    def check_updates(self):

        updates = []

        remote_files = self.get_remote_files()

        for filename, remote_sha in remote_files.items():

            local_file = self.local_dir / filename
            local_sha = self.get_local_sha(filename)

            if not local_file.exists():
                updates.append(filename)
                continue

            if local_sha != remote_sha:
                updates.append(filename)

        return updates

    # ---------------------------------------------------------
    # Download fingerprint pack
    # ---------------------------------------------------------

    def download_pack(self, filename, sha):

        url = f"{self.remote_base_url}/{filename}"
        local_path = self.local_dir / filename

        try:

            r = requests.get(url, timeout=10)

            if r.status_code == 200:

                with open(local_path, "wb") as f:
                    f.write(r.content)

                self.save_local_sha(filename, sha)

                return True

        except Exception:
            pass

        return False

    # ---------------------------------------------------------
    # Update fingerprint database
    # ---------------------------------------------------------

    def update(self):

        updated = []

        remote_files = self.get_remote_files()

        for filename, sha in remote_files.items():

            local_file = self.local_dir / filename
            local_sha = self.get_local_sha(filename)

            if not local_file.exists() or local_sha != sha:

                if self.download_pack(filename, sha):
                    updated.append(filename)

        return updated
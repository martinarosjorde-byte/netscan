#file: core/db_updater.py

from __future__ import annotations

import requests
import hashlib
from pathlib import Path


class FingerprintDBUpdater:

    def __init__(self, local_dir: str, remote_base_url: str):

        self.local_dir = Path(local_dir)
        self.remote_base_url = remote_base_url.rstrip("/")
        self.index_url = f"{self.remote_base_url}/index.json"

        self.local_dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # Get remote index
    # ---------------------------------------------------------

    def get_remote_index(self):

        try:
            r = requests.get(self.index_url, timeout=5)

            if r.status_code == 200:
                return r.json()

        except Exception:
            pass

        return None

    # ---------------------------------------------------------
    # Hash local files
    # ---------------------------------------------------------

    def file_hash(self, path: Path):

        if not path.exists():
            return None

        sha = hashlib.sha256()

        with open(path, "rb") as f:
            while True:

                chunk = f.read(8192)

                if not chunk:
                    break

                sha.update(chunk)

        return sha.hexdigest()

    # ---------------------------------------------------------
    # Check for updates
    # ---------------------------------------------------------

    def check_updates(self):

        remote_index = self.get_remote_index()

        if not remote_index:
            return []

        updates = []

        for filename, remote_hash in remote_index["packs"].items():

            local_file = self.local_dir / filename

            local_hash = self.file_hash(local_file)

            remote_hash = remote_hash.replace("sha256:", "")

            if local_hash != remote_hash:
                updates.append(filename)

        return updates

    # ---------------------------------------------------------
    # Download a pack
    # ---------------------------------------------------------

    def download_pack(self, filename):

        url = f"{self.remote_base_url}/{filename}"
        local_path = self.local_dir / filename

        try:

            r = requests.get(url, timeout=10)

            if r.status_code == 200:

                with open(local_path, "wb") as f:
                    f.write(r.content)

                return True

        except Exception:
            pass

        return False

    # ---------------------------------------------------------
    # Update database
    # ---------------------------------------------------------

    def update(self):

        updates = self.check_updates()

        if not updates:
            return []

        updated = []

        for pack in updates:

            if self.download_pack(pack):
                updated.append(pack)

        return updated
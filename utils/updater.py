import urllib.request
import json
from version import __version__

GITHUB_API = "https://api.github.com/repos/martinarosjorde-byte/netscan/releases/latest"


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
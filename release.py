import subprocess
import zipfile
import os
import re
from datetime import datetime

VERSION_FILE = "version.py"
DIST_FOLDER = "dist"
EXE_NAME = "netscan.exe"


def update_version(new_version):
    with open(VERSION_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    content = re.sub(
        r'__version__\s*=\s*".*?"',
        f'__version__ = "{new_version}"',
        content
    )

    with open(VERSION_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"✔ Version updated to {new_version}")


def run(cmd):
    print(f"> {cmd}")
    subprocess.check_call(cmd, shell=True)


def build_exe():
    run("pyinstaller --onefile --name netscan --collect-all manuf cli/cli.py")


def zip_build(version):
    zip_name = f"netscan-windows-x64-v{version}.zip"
    zip_path = os.path.join(DIST_FOLDER, zip_name)

    exe_path = os.path.join(DIST_FOLDER, EXE_NAME)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(exe_path, EXE_NAME)

    print(f"✔ Created {zip_name}")
    return zip_path


def git_commit_tag(version):
    run("git add .")
    run(f'git commit -m "Release v{version}"')
    run(f"git tag v{version}")
    run("git push")
    run("git push --tags")


def publish_release(version, zip_path):
    run(
        f'gh release create v{version} "{zip_path}" '
        f'--title "v{version}" '
        f'--notes "NetScan Enterprise v{version} release"'
    )


def main():
    version = input("Enter new version (e.g. 1.1.0): ").strip()

    if not version:
        print("Version required.")
        return

    update_version(version)
    build_exe()
    zip_path = zip_build(version)
    git_commit_tag(version)
    publish_release(version, zip_path)

    print("\n🚀 Release completed successfully.")


if __name__ == "__main__":
    main()

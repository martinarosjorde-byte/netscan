import subprocess
import zipfile
import os
import re
import shutil
from pathlib import Path

VERSION_FILE = "version.py"
DIST_FOLDER = "dist"
BUILD_FOLDER = "build"
EXE_NAME = "netscan.exe"
INSTALLER_SCRIPT = "netscan.iss"  # your Inno script filename
INNO_COMPILER = r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"


def run(cmd):
    print(f"> {cmd}")
    subprocess.check_call(cmd, shell=True)


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


def clean():
    if os.path.exists(DIST_FOLDER):
        shutil.rmtree(DIST_FOLDER)
    if os.path.exists(BUILD_FOLDER):
        shutil.rmtree(BUILD_FOLDER)


def build_exe():
    # Use your spec file (important!)
    run("pyinstaller netscan.spec")


def build_installer(version):
    run(f'set NETSCAN_VERSION={version} && "{INNO_COMPILER}" {INSTALLER_SCRIPT}')

def zip_portable(version):
    zip_name = f"netscan-windows-x64-portable-v{version}.zip"
    zip_path = os.path.join(DIST_FOLDER, zip_name)

    folder_to_zip = os.path.join(DIST_FOLDER, "netscan")

    shutil.make_archive(
        zip_path.replace(".zip", ""),
        'zip',
        folder_to_zip
    )

    print(f"✔ Created {zip_name}")
    return zip_path


def find_installer(version):
    filename = f"NetScan-Installer-v{version}.exe"
    if os.path.exists(filename):
        return os.path.abspath(filename)
    return None


def git_commit_tag(version):
    run("git add .")
    run(f'git commit -m "Release v{version}"')
    run(f"git tag v{version}")
    run("git push")
    run("git push --tags")


def publish_release(version, assets):
    asset_str = " ".join(f'"{a}"' for a in assets)

    run(
        f'gh release create v{version} {asset_str} '
        f'--title "v{version}" '
        f'--notes "NetScan Enterprise v{version} release"'
    )


def main():
    version = input("Enter new version (e.g. 1.2.0): ").strip()

    if not version:
        print("Version required.")
        return

    clean()
    update_version(version)
    build_exe()
    build_installer(version)

    portable_zip = zip_portable(version)
    installer = find_installer(version)

    assets = [portable_zip]
    if installer:
        assets.append(installer)

    git_commit_tag(version)
    publish_release(version, assets)

    print("\n🚀 Release completed successfully.")


if __name__ == "__main__":
    main()
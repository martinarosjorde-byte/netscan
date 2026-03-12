import subprocess
import os
import re
import shutil
import argparse
from pathlib import Path

VERSION_FILE = "version.py"
DIST_FOLDER = "dist"
BUILD_FOLDER = "build"
EXE_NAME = "netscan.exe"
INSTALLER_SCRIPT = "netscan.iss"
INNO_COMPILER = r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def run(cmd):
    print(f"> {cmd}")
    subprocess.check_call(cmd, shell=True)


# -------------------------------------------------
# Version Handling
# -------------------------------------------------

def get_current_version():
    with open(VERSION_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    match = re.search(r'__version__\s*=\s*"(.+?)"', content)

    if not match:
        raise RuntimeError("Could not find version in version.py")

    return match.group(1)


def bump_version(version, level="patch"):
    major, minor, patch = map(int, version.split("."))

    if level == "major":
        major += 1
        minor = 0
        patch = 0

    elif level == "minor":
        minor += 1
        patch = 0

    else:
        patch += 1

    return f"{major}.{minor}.{patch}"


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


# -------------------------------------------------
# Build
# -------------------------------------------------

def clean():
    print("Cleaning previous builds...")

    if os.path.exists(DIST_FOLDER):
        shutil.rmtree(DIST_FOLDER)

    if os.path.exists(BUILD_FOLDER):
        shutil.rmtree(BUILD_FOLDER)


def build_exe():
    print("Building PyInstaller executable...")
    run("pyinstaller netscan.spec")


def build_installer(version):
    print("Building installer...")
    run(f'set NETSCAN_VERSION={version} && "{INNO_COMPILER}" {INSTALLER_SCRIPT}')


def zip_portable(version):
    print("Creating portable ZIP...")

    zip_name = f"netscan-windows-x64-portable-v{version}.zip"
    zip_path = os.path.join(DIST_FOLDER, zip_name)

    folder_to_zip = os.path.join(DIST_FOLDER, "netscan")

    shutil.make_archive(
        zip_path.replace(".zip", ""),
        'zip',
        folder_to_zip
    )

    print(f"✔ Created {zip_name}")

    return os.path.abspath(zip_path)


def find_installer(version):
    filename = f"NetScan-Installer-v{version}.exe"

    if os.path.exists(filename):
        return os.path.abspath(filename)

    return None


# -------------------------------------------------
# Git / GitHub
# -------------------------------------------------

def git_commit_tag(version):
    print("Creating git commit + tag...")

    run("git add .")
    run(f'git commit -m "Release v{version}"')
    run(f"git tag v{version}")
    run("git push")
    run("git push --tags")


def publish_release(version, assets):

    print("Publishing GitHub release...")

    asset_str = " ".join(f'"{a}"' for a in assets)

    run(
        f'gh release create v{version} {asset_str} '
        f'--title "v{version}" '
        f'--notes "NetScan Enterprise v{version} release"'
    )


# -------------------------------------------------
# Main
# -------------------------------------------------

def main():

    parser = argparse.ArgumentParser(description="NetScan Release Tool")

    group = parser.add_mutually_exclusive_group()

    group.add_argument("--major", action="store_true", help="Bump major version")
    group.add_argument("--minor", action="store_true", help="Bump minor version")

    args = parser.parse_args()

    bump_level = "patch"

    if args.major:
        bump_level = "major"
    elif args.minor:
        bump_level = "minor"

    current_version = get_current_version()
    new_version = bump_version(current_version, bump_level)

    print("\nNetScan Release Builder")
    print("------------------------")
    print(f"Current version : {current_version}")
    print(f"Bump type       : {bump_level}")
    print(f"Next version    : {new_version}\n")

    confirm = input("Continue with release? [Y/n]: ").lower()

    if confirm not in ("", "y", "yes"):
        print("Cancelled.")
        return

    clean()
    update_version(new_version)

    build_exe()
    build_installer(new_version)

    portable_zip = zip_portable(new_version)
    installer = find_installer(new_version)

    assets = [portable_zip]

    if installer:
        assets.append(installer)

    git_commit_tag(new_version)
    publish_release(new_version, assets)

    print("\n🚀 Release completed successfully.")


if __name__ == "__main__":
    main()
"""Build portable binaries with bundled policies and optional cryptography support."""

from pathlib import Path
import platform
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
os_name = {"Windows": "Windows", "Darwin": "macOS", "Linux": "Linux"}[platform.system()]
arch = {"AMD64": "x86_64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
name = f"RSAT_{os_name}_{arch}"
args = [
    sys.executable,
    "-m",
    "PyInstaller",
    "--onefile",
    "--console",
    "--clean",
    "--noconfirm",
    "--name",
    name,
    "--paths",
    str(root / "src"),
    "--collect-data",
    "rsat",
    "--collect-all",
    "cryptography",
    str(root / "src/audit_tool.py"),
]
subprocess.run(args, cwd=root, check=True)

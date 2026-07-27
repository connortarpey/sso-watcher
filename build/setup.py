"""py2app config — builds `SSO Watcher.app` from sso_watcher.py + dashboard.html.

Invoke via ../build/build.sh (do not run this directly).
"""
from pathlib import Path
from setuptools import setup

HERE = Path(__file__).parent.resolve()
ROOT = HERE.parent

APP        = [str(ROOT / "sso_watcher.py")]
DATA_FILES = [str(ROOT / "dashboard.html")]

OPTIONS = {
    "argv_emulation": False,
    "plist": {
        "CFBundleName":               "SSO Watcher",
        "CFBundleDisplayName":        "SSO Watcher",
        "CFBundleIdentifier":         "com.sso-watcher.app",
        "CFBundleShortVersionString": "0.1.0",
        "CFBundleVersion":            "0.1.0",
        "NSHighResolutionCapable":    True,
        "LSMinimumSystemVersion":     "11.0",
        "NSHumanReadableCopyright":   "SSO Watcher",
    },
    "packages": ["scapy", "aiohttp", "manuf"],
    "includes": ["asyncio"],
    "excludes": ["tkinter"],
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)

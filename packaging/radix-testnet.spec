# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Radix testnet app.

One file, no console on Windows would hide the banner, so the console stays: this
is a testnet harness and the operator should see the node URL and the data
directory. The GUI is served on localhost and shown by the user's own browser,
which is why there is no embedded webview and no browser engine in the bundle.
"""

from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent if "SPECPATH" in globals() else Path.cwd().resolve().parent
ROOT = Path(".").resolve().parent if not (ROOT / "radix_testnet").exists() else ROOT

block_cipher = None

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / "radix_testnet" / "static"), "radix_testnet/static"),
        (str(ROOT / "TESTNET.md"), "."),
    ],
    hiddenimports=["segno"],
    hookspath=[],
    runtime_hooks=[],
    # Only the GUI toolkits: http.server genuinely needs email, and excluding it
    # produced an executable that died on import.
    excludes=["tkinter", "unittest", "pydoc"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="RadixTestnet",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "packaging" / "icon.ico"),
    version=str(ROOT / "packaging" / "version_info.txt"),
)

# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller specification for macOS build.
Creates ExplainableAdaptiveIDS.app bundle containing model artifacts,
feature schemas, and static frontend assets.
"""
from pathlib import Path
import sys

block_cipher = None
ROOT_DIR = Path.cwd()

datas = [
    (str(ROOT_DIR / "frontend"), "frontend"),
    (str(ROOT_DIR / "models" / "trained"), "models/trained"),
    (str(ROOT_DIR / "datasets" / "sample"), "datasets/sample"),
]

hiddenimports = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespans",
    "uvicorn.lifespans.on",
    "fastapi",
    "pydantic",
    "shap",
    "sklearn",
    "sklearn.ensemble",
    "scipy",
    "scipy.stats",
    "scapy",
    "scapy.layers.inet",
    "webview",
]

a = Analysis(
    [str(ROOT_DIR / "app" / "launcher.py")],
    pathex=[str(ROOT_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ExplainableAdaptiveIDS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="ExplainableAdaptiveIDS",
)

app = BUNDLE(
    coll,
    name="ExplainableAdaptiveIDS.app",
    icon=None,
    bundle_identifier="com.academic.ids.explainable",
)

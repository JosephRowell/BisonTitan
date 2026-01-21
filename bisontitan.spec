# -*- mode: python ; coding: utf-8 -*-
"""
BisonTitan PyInstaller Spec File
Builds a single-file executable for Windows.

Usage:
    pyinstaller bisontitan.spec

Output:
    dist/bisontitan.exe

Icon:
    Run 'python assets/generate_icon.py' first to create icon.ico
"""

import sys
import os
from pathlib import Path

# Get the project root directory
SPEC_ROOT = Path(SPECPATH).resolve()
SRC_DIR = SPEC_ROOT / "src"
BISONTITAN_DIR = SRC_DIR / "bisontitan"
ASSETS_DIR = SPEC_ROOT / "assets"

# Icon path
ICON_PATH = ASSETS_DIR / "icon.ico"
if not ICON_PATH.exists():
    print(f"WARNING: Icon not found at {ICON_PATH}")
    print("Run: python assets/generate_icon.py")
    ICON_PATH = None

# Determine if we're building for Windows
is_windows = sys.platform == "win32"

# =============================================================================
# Analysis - Collect all modules and dependencies
# =============================================================================
a = Analysis(
    # Entry point script
    [str(SRC_DIR / "bisontitan" / "cli.py")],

    # Additional paths to search for imports
    pathex=[
        str(SRC_DIR),
        str(BISONTITAN_DIR),
    ],

    # Binary files to include (DLLs, shared libraries)
    binaries=[],

    # Data files to include (non-Python files)
    datas=[
        # Include GUI app
        (str(BISONTITAN_DIR / "gui"), "bisontitan/gui"),

        # Include YARA rules if they exist
        # (str(BISONTITAN_DIR / "rules"), "bisontitan/rules"),

        # Include data files if they exist
        # (str(BISONTITAN_DIR / "data"), "bisontitan/data"),
    ],

    # Hidden imports (modules that PyInstaller can't detect)
    hiddenimports=[
        # BisonTitan modules
        "bisontitan",
        "bisontitan.cli",
        "bisontitan.config",
        "bisontitan.scanner",
        "bisontitan.utils",
        "bisontitan.traffic_analyzer",
        "bisontitan.fingerprint_viewer",
        "bisontitan.fingerprint_tui",
        "bisontitan.log_analyzer",
        "bisontitan.vuln_checker",
        "bisontitan.attack_sim",
        "bisontitan.gui",
        "bisontitan.gui.app",

        # Click and Rich
        "click",
        "rich",
        "rich.console",
        "rich.table",
        "rich.panel",
        "rich.box",
        "rich.progress",

        # Textual TUI
        "textual",
        "textual.app",
        "textual.widgets",

        # Data processing
        "pandas",
        "pandas.io.formats.style",

        # Network analysis
        "scapy",
        "scapy.all",
        "scapy.layers",
        "scapy.layers.inet",
        "scapy.layers.l2",

        # System utilities
        "psutil",
        "yaml",
        "dotenv",
        "requests",
        "schedule",

        # Optional but commonly used
        "json",
        "csv",
        "logging",
        "datetime",
        "pathlib",
        "socket",
        "struct",
        "hashlib",
        "base64",
        "re",
        "threading",
        "queue",
        "typing",

        # Windows-specific (conditional)
        "win32api",
        "win32con",
        "win32evtlog",
        "win32security",
        "pywintypes",

        # Streamlit/Plotly (for GUI command)
        "streamlit",
        "plotly",
        "plotly.express",
        "plotly.graph_objects",
    ],

    # Modules to exclude (reduce size)
    excludes=[
        # Testing
        "pytest",
        "pytest_asyncio",
        "pytest_cov",
        "_pytest",

        # Development tools
        "black",
        "mypy",
        "ruff",

        # Unused heavy modules
        "tkinter",
        "matplotlib",
        "scipy",
        "numpy.testing",
        "IPython",
        "jupyter",
        "notebook",

        # Debug/profiling
        "pdb",
        "profile",
        "cProfile",
    ],

    # Hook configuration
    hookspath=[],
    hooksconfig={},

    # Runtime hooks
    runtime_hooks=[],

    # Don't warn about missing imports
    noarchive=False,

    # Optimize bytecode
    optimize=2,
)

# =============================================================================
# PYZ - Create compressed archive of pure Python modules
# =============================================================================
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=None,  # No encryption
)

# =============================================================================
# EXE - Build the executable
# =============================================================================
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,

    # Exclude certain binaries from the executable
    exclude_binaries=False,

    # Executable name
    name="bisontitan",

    # Debug mode (set to False for release)
    debug=False,

    # Boot loader ignore signals
    bootloader_ignore_signals=False,

    # Strip symbols (smaller file)
    strip=False,

    # UPX compression (requires UPX installed)
    upx=True,
    upx_exclude=[],

    # Runtime temp directory name
    runtime_tmpdir=None,

    # Console application (not windowed)
    console=True,

    # Disable windowed mode
    disable_windowed_traceback=False,

    # Argument passed to the executable
    argv_emulation=False,

    # Target architecture
    target_arch=None,

    # Code signing (Windows)
    codesign_identity=None,
    entitlements_file=None,

    # Windows-specific options
    icon=str(ICON_PATH) if ICON_PATH and ICON_PATH.exists() else None,

    # Version info for Windows (optional - create version_info.txt for file properties)
    version=str(SPEC_ROOT / "version_info.txt") if (SPEC_ROOT / "version_info.txt").exists() else None,

    # Manifest for Windows UAC
    uac_admin=False,  # Don't require admin by default
    uac_uiaccess=False,
)

# =============================================================================
# COLLECT - For directory mode (not used in onefile mode)
# =============================================================================
# Uncomment if you want directory mode instead of single file
# coll = COLLECT(
#     exe,
#     a.binaries,
#     a.zipfiles,
#     a.datas,
#     strip=False,
#     upx=True,
#     upx_exclude=[],
#     name="bisontitan",
# )

"""
BisonTitan Security Suite
A robust, modular security application for Windows (extensible to other OS).

Modules:
    - scanner: File and process scanning with YARA rules
    - traffic_analyzer: Network traffic labeling and analysis
    - fingerprint_viewer: Browser/machine fingerprint simulation
    - log_analyzer: Windows event log analysis
    - vuln_checker: Vulnerability and port scanning
    - attack_sim: Ethical attack simulation for testing
"""

# Version is managed by setuptools_scm from git tags
# Auto-generated to _version.py on install
try:
    from bisontitan._version import __version__, __version_tuple__
except ImportError:
    # Fallback for development without install or outside git repo
    __version__ = "1.0.0.dev0"
    __version_tuple__ = (1, 0, 0, "dev0")

__author__ = "BisonTitan Team"

# Lazy imports to avoid circular dependencies and speed up CLI startup
def __getattr__(name):
    """Lazy import modules on first access."""
    if name == "Config":
        from bisontitan.config import Config
        return Config
    elif name == "FileScanner":
        from bisontitan.scanner import FileScanner
        return FileScanner
    elif name == "ProcessScanner":
        from bisontitan.scanner import ProcessScanner
        return ProcessScanner
    elif name == "setup_logging":
        from bisontitan.utils import setup_logging
        return setup_logging
    elif name == "is_admin":
        from bisontitan.utils import is_admin
        return is_admin
    elif name == "get_platform":
        from bisontitan.utils import get_platform
        return get_platform
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "Config",
    "FileScanner",
    "ProcessScanner",
    "setup_logging",
    "is_admin",
    "get_platform",
    "__version__",
    "__version_tuple__",
]

"""
BisonTitan Utilities Module
Provides logging, admin checks, platform detection, and common helpers.
"""

import ctypes
import hashlib
import logging
import os
import platform
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Literal

# Platform type
PlatformType = Literal["windows", "linux", "darwin", "unknown"]


def get_platform() -> PlatformType:
    """Detect the current operating system."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "linux":
        return "linux"
    elif system == "darwin":
        return "darwin"
    return "unknown"


def is_admin() -> bool:
    """Check if the current process has administrator/root privileges."""
    current_platform = get_platform()

    if current_platform == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    else:
        # Unix-like systems
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def require_admin(func):
    """Decorator to require admin privileges for a function."""
    def wrapper(*args, **kwargs):
        if not is_admin():
            raise PermissionError(
                "This operation requires administrator/root privileges. "
                "Please run BisonTitan with elevated permissions."
            )
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


def setup_logging(
    log_file: Path | None = None,
    level: int = logging.INFO,
    console: bool = True,
) -> logging.Logger:
    """
    Configure logging for BisonTitan.

    Args:
        log_file: Path to log file (optional)
        level: Logging level (default: INFO)
        console: Whether to also log to console (default: True)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("bisontitan")
    logger.setLevel(level)
    logger.handlers.clear()

    # Log format
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_file_hash(filepath: Path, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file.

    Args:
        filepath: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Hex digest of file hash
    """
    hash_func = hashlib.new(algorithm)

    with open(filepath, "rb") as f:
        # Read in chunks for large files
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def get_multiple_hashes(filepath: Path) -> dict[str, str]:
    """
    Calculate multiple hashes for a file in a single pass.

    Args:
        filepath: Path to file

    Returns:
        Dictionary with md5, sha1, sha256 hashes
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def safe_move(src: Path, dst: Path, preserve_metadata: bool = True) -> Path:
    """
    Safely move a file with error handling.

    Args:
        src: Source file path
        dst: Destination path
        preserve_metadata: Whether to preserve file metadata

    Returns:
        Final destination path
    """
    src = Path(src)
    dst = Path(dst)

    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")

    # Create destination directory if needed
    dst.parent.mkdir(parents=True, exist_ok=True)

    # Handle name conflicts
    if dst.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = dst.parent / f"{dst.stem}_{timestamp}{dst.suffix}"

    if preserve_metadata:
        shutil.move(str(src), str(dst))
    else:
        shutil.copy2(str(src), str(dst))
        src.unlink()

    return dst


def format_bytes(size: int) -> str:
    """Format byte size to human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def sanitize_filename(filename: str) -> str:
    """Remove or replace invalid characters from filename."""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")
    return filename


def print_banner():
    """Print BisonTitan ASCII banner."""
    banner = r"""
    ____  _                 _____ _ _
   | __ )(_)___  ___  _ __ |_   _(_) |_ __ _ _ __
   |  _ \| / __|/ _ \| '_ \  | | | | __/ _` | '_ \
   | |_) | \__ \ (_) | | | | | | | | || (_| | | | |
   |____/|_|___/\___/|_| |_| |_| |_|\__\__,_|_| |_|

   Security Suite v0.1.0 - Defensive Security Toolkit
    """
    print(banner)

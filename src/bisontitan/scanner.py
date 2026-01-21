"""
BisonTitan File and Process Scanner Module
Provides YARA-based malware detection and process monitoring.
"""

import fnmatch
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Generator, Iterator

import psutil

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

from bisontitan.config import ScannerConfig
from bisontitan.utils import get_file_hash, get_multiple_hashes, format_bytes, safe_move


logger = logging.getLogger("bisontitan.scanner")


class ThreatLevel(Enum):
    """Threat severity levels."""
    CLEAN = "clean"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanMatch:
    """Represents a YARA rule match or hash match."""
    rule_name: str
    description: str
    severity: ThreatLevel
    matched_strings: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class FileScanResult:
    """Result of scanning a single file."""
    filepath: Path
    size: int
    hashes: dict[str, str]
    threat_level: ThreatLevel
    matches: list[ScanMatch] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    error: str | None = None
    quarantined: bool = False
    quarantine_path: Path | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "filepath": str(self.filepath),
            "size": self.size,
            "size_human": format_bytes(self.size),
            "hashes": self.hashes,
            "threat_level": self.threat_level.value,
            "matches": [
                {
                    "rule": m.rule_name,
                    "description": m.description,
                    "severity": m.severity.value,
                    "matched_strings": m.matched_strings,
                    "metadata": m.metadata,
                }
                for m in self.matches
            ],
            "scan_time": self.scan_time.isoformat(),
            "error": self.error,
            "quarantined": self.quarantined,
            "quarantine_path": str(self.quarantine_path) if self.quarantine_path else None,
        }


@dataclass
class ProcessScanResult:
    """Result of scanning a running process."""
    pid: int
    name: str
    exe_path: Path | None
    cmdline: list[str]
    username: str | None
    threat_level: ThreatLevel
    matches: list[ScanMatch] = field(default_factory=list)
    memory_info: dict = field(default_factory=dict)
    connections: list[dict] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    error: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": str(self.exe_path) if self.exe_path else None,
            "cmdline": self.cmdline,
            "username": self.username,
            "threat_level": self.threat_level.value,
            "matches": [
                {
                    "rule": m.rule_name,
                    "description": m.description,
                    "severity": m.severity.value,
                }
                for m in self.matches
            ],
            "memory_info": self.memory_info,
            "connections": self.connections,
            "scan_time": self.scan_time.isoformat(),
            "error": self.error,
        }


class FileScanner:
    """
    Scans files for malware using YARA rules and hash checking.
    """

    def __init__(self, config: ScannerConfig | None = None):
        """
        Initialize file scanner.

        Args:
            config: Scanner configuration (uses defaults if None)
        """
        self.config = config or ScannerConfig()
        self._compiled_rules: yara.Rules | None = None
        self._rules_loaded = False

    def load_yara_rules(self) -> bool:
        """
        Load and compile YARA rules from configured directory.

        Returns:
            True if rules loaded successfully, False otherwise
        """
        if not YARA_AVAILABLE:
            logger.warning("yara-python not available. YARA scanning disabled.")
            return False

        if not self.config.yara_scan_enabled:
            logger.info("YARA scanning disabled in configuration.")
            return False

        rules_dir = Path(self.config.yara_rules_dir)
        if not rules_dir.exists():
            logger.warning(f"YARA rules directory not found: {rules_dir}")
            return False

        # Find all .yar and .yara files
        rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
        if not rule_files:
            logger.warning(f"No YARA rule files found in {rules_dir}")
            return False

        try:
            # Compile rules from all files
            filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
            self._compiled_rules = yara.compile(filepaths=filepaths)
            self._rules_loaded = True
            logger.info(f"Loaded YARA rules from {len(rule_files)} file(s)")
            return True
        except yara.Error as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            return False

    def _should_scan(self, filepath: Path) -> bool:
        """Check if file should be scanned based on config exclusions."""
        # Check file extension
        if filepath.suffix.lower() in self.config.excluded_extensions:
            return False

        # Check excluded paths
        filepath_str = str(filepath)
        for pattern in self.config.excluded_paths:
            if fnmatch.fnmatch(filepath_str, pattern):
                return False

        # Check file size
        try:
            size_mb = filepath.stat().st_size / (1024 * 1024)
            if size_mb > self.config.max_file_size_mb:
                logger.debug(f"Skipping large file: {filepath} ({size_mb:.1f} MB)")
                return False
        except OSError:
            return False

        return True

    def _parse_severity(self, severity_str: str | None) -> ThreatLevel:
        """Parse severity string from YARA metadata."""
        if not severity_str:
            return ThreatLevel.MEDIUM

        severity_map = {
            "info": ThreatLevel.INFO,
            "low": ThreatLevel.LOW,
            "medium": ThreatLevel.MEDIUM,
            "high": ThreatLevel.HIGH,
            "critical": ThreatLevel.CRITICAL,
        }
        return severity_map.get(severity_str.lower(), ThreatLevel.MEDIUM)

    def _check_hash(self, hashes: dict[str, str]) -> ScanMatch | None:
        """Check file hashes against known malware list."""
        if not self.config.hash_check_enabled:
            return None

        for known_hash in self.config.known_malware_hashes:
            known_hash = known_hash.lower()
            for algo, file_hash in hashes.items():
                if file_hash.lower() == known_hash:
                    return ScanMatch(
                        rule_name="Known_Malware_Hash",
                        description=f"File matches known malware hash ({algo})",
                        severity=ThreatLevel.CRITICAL,
                        metadata={"matched_hash": known_hash, "algorithm": algo},
                    )
        return None

    def scan_file(self, filepath: Path | str) -> FileScanResult:
        """
        Scan a single file for threats.

        Args:
            filepath: Path to file to scan

        Returns:
            FileScanResult with scan details
        """
        filepath = Path(filepath)
        matches: list[ScanMatch] = []
        error = None
        hashes = {}
        size = 0

        try:
            if not filepath.exists():
                raise FileNotFoundError(f"File not found: {filepath}")

            if not filepath.is_file():
                raise ValueError(f"Not a file: {filepath}")

            size = filepath.stat().st_size

            # Calculate hashes
            hashes = get_multiple_hashes(filepath)

            # Check against known malware hashes
            hash_match = self._check_hash(hashes)
            if hash_match:
                matches.append(hash_match)

            # YARA scan
            if self._rules_loaded and self._compiled_rules:
                try:
                    yara_matches = self._compiled_rules.match(str(filepath))
                    for match in yara_matches:
                        severity = self._parse_severity(
                            match.meta.get("severity")
                        )
                        matched_strings = [
                            s[2].decode("utf-8", errors="replace")
                            if isinstance(s[2], bytes) else str(s[2])
                            for s in match.strings[:5]  # Limit to first 5
                        ]
                        matches.append(ScanMatch(
                            rule_name=match.rule,
                            description=match.meta.get("description", "No description"),
                            severity=severity,
                            matched_strings=matched_strings,
                            metadata=dict(match.meta),
                        ))
                except yara.Error as e:
                    logger.warning(f"YARA scan error for {filepath}: {e}")

        except Exception as e:
            error = str(e)
            logger.error(f"Error scanning {filepath}: {e}")

        # Determine overall threat level
        if matches:
            threat_level = max(m.severity for m in matches)
        else:
            threat_level = ThreatLevel.CLEAN

        return FileScanResult(
            filepath=filepath,
            size=size,
            hashes=hashes,
            threat_level=threat_level,
            matches=matches,
            error=error,
        )

    def scan_directory(
        self,
        directory: Path | str,
        recursive: bool = True,
    ) -> Generator[FileScanResult, None, None]:
        """
        Scan all files in a directory.

        Args:
            directory: Path to directory to scan
            recursive: Whether to scan subdirectories

        Yields:
            FileScanResult for each scanned file
        """
        directory = Path(directory)

        if not directory.exists():
            logger.error(f"Directory not found: {directory}")
            return

        if not directory.is_dir():
            logger.error(f"Not a directory: {directory}")
            return

        # Ensure rules are loaded
        if not self._rules_loaded:
            self.load_yara_rules()

        # Get files to scan
        if recursive:
            files = directory.rglob("*")
        else:
            files = directory.glob("*")

        for filepath in files:
            if filepath.is_file() and self._should_scan(filepath):
                yield self.scan_file(filepath)

    def quarantine_file(
        self,
        filepath: Path | str,
        scan_result: FileScanResult | None = None,
    ) -> tuple[bool, Path | None]:
        """
        Move a file to quarantine.

        Args:
            filepath: Path to file to quarantine
            scan_result: Optional scan result to update

        Returns:
            Tuple of (success, quarantine_path)
        """
        filepath = Path(filepath)

        if not filepath.exists():
            logger.error(f"Cannot quarantine non-existent file: {filepath}")
            return False, None

        quarantine_dir = Path(self.config.quarantine_dir)
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        # Create unique quarantine filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = filepath.name.replace(".", "_")
        quarantine_name = f"{timestamp}_{safe_name}.quarantine"
        quarantine_path = quarantine_dir / quarantine_name

        try:
            # Move file to quarantine
            shutil.move(str(filepath), str(quarantine_path))

            # Write metadata file
            metadata_path = quarantine_path.with_suffix(".json")
            metadata = {
                "original_path": str(filepath),
                "quarantine_time": datetime.now().isoformat(),
                "threat_level": scan_result.threat_level.value if scan_result else "unknown",
                "hashes": scan_result.hashes if scan_result else {},
                "matches": [m.rule_name for m in scan_result.matches] if scan_result else [],
            }
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Quarantined: {filepath} -> {quarantine_path}")

            if scan_result:
                scan_result.quarantined = True
                scan_result.quarantine_path = quarantine_path

            return True, quarantine_path

        except Exception as e:
            logger.error(f"Failed to quarantine {filepath}: {e}")
            return False, None

    def restore_from_quarantine(self, quarantine_path: Path | str) -> tuple[bool, Path | None]:
        """
        Restore a file from quarantine.

        Args:
            quarantine_path: Path to quarantined file

        Returns:
            Tuple of (success, restored_path)
        """
        quarantine_path = Path(quarantine_path)

        if not quarantine_path.exists():
            logger.error(f"Quarantine file not found: {quarantine_path}")
            return False, None

        # Load metadata
        metadata_path = quarantine_path.with_suffix(".json")
        if not metadata_path.exists():
            logger.error(f"Quarantine metadata not found: {metadata_path}")
            return False, None

        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)

            original_path = Path(metadata["original_path"])

            # Handle name conflicts
            if original_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                original_path = original_path.parent / f"{original_path.stem}_restored_{timestamp}{original_path.suffix}"

            # Restore file
            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantine_path), str(original_path))
            metadata_path.unlink()

            logger.info(f"Restored: {quarantine_path} -> {original_path}")
            return True, original_path

        except Exception as e:
            logger.error(f"Failed to restore {quarantine_path}: {e}")
            return False, None


class ProcessScanner:
    """
    Scans running processes for suspicious behavior.
    """

    def __init__(self, config: ScannerConfig | None = None):
        """
        Initialize process scanner.

        Args:
            config: Scanner configuration (uses defaults if None)
        """
        self.config = config or ScannerConfig()
        self.file_scanner = FileScanner(config)
        self._rules_loaded = False

    def load_yara_rules(self) -> bool:
        """Load YARA rules for process memory scanning."""
        result = self.file_scanner.load_yara_rules()
        self._rules_loaded = result
        return result

    def get_process_list(self) -> list[dict]:
        """
        Get list of all running processes.

        Returns:
            List of process info dictionaries
        """
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline']):
            try:
                info = proc.info
                processes.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "username": info['username'],
                    "exe": info['exe'],
                    "cmdline": info['cmdline'] or [],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes

    def _get_process_connections(self, proc: psutil.Process) -> list[dict]:
        """Get network connections for a process."""
        connections = []
        try:
            for conn in proc.connections():
                connections.append({
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return connections

    def _check_suspicious_behavior(self, proc: psutil.Process, info: dict) -> list[ScanMatch]:
        """Check process for suspicious behavior patterns."""
        matches = []
        cmdline = " ".join(info.get("cmdline", []))

        # Check for suspicious command line patterns
        suspicious_patterns = [
            ("PowerShell -EncodedCommand", "Obfuscated PowerShell", ThreatLevel.HIGH),
            ("powershell -ep bypass", "PowerShell bypass", ThreatLevel.HIGH),
            ("-WindowStyle Hidden", "Hidden window execution", ThreatLevel.MEDIUM),
            ("certutil -urlcache", "Certutil download abuse", ThreatLevel.HIGH),
            ("bitsadmin /transfer", "BITS download abuse", ThreatLevel.MEDIUM),
            ("mshta vbscript:", "MSHTA script execution", ThreatLevel.HIGH),
            ("regsvr32 /s /n", "Regsvr32 script bypass", ThreatLevel.HIGH),
        ]

        for pattern, description, severity in suspicious_patterns:
            if pattern.lower() in cmdline.lower():
                matches.append(ScanMatch(
                    rule_name="Suspicious_Cmdline",
                    description=description,
                    severity=severity,
                    matched_strings=[cmdline[:200]],
                ))

        # Check for suspicious parent-child relationships
        try:
            parent = proc.parent()
            if parent:
                parent_name = parent.name().lower()
                proc_name = info.get("name", "").lower()

                # Suspicious spawns
                if parent_name == "winword.exe" and proc_name in ["cmd.exe", "powershell.exe"]:
                    matches.append(ScanMatch(
                        rule_name="Suspicious_Spawn",
                        description="Office application spawning shell",
                        severity=ThreatLevel.HIGH,
                    ))
                elif parent_name == "services.exe" and proc_name == "cmd.exe":
                    matches.append(ScanMatch(
                        rule_name="Suspicious_Spawn",
                        description="Services spawning command shell",
                        severity=ThreatLevel.MEDIUM,
                    ))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        return matches

    def scan_process(self, pid: int) -> ProcessScanResult:
        """
        Scan a specific process by PID.

        Args:
            pid: Process ID to scan

        Returns:
            ProcessScanResult with scan details
        """
        matches: list[ScanMatch] = []
        error = None
        exe_path = None
        cmdline: list[str] = []
        username = None
        memory_info = {}
        connections = []
        name = "Unknown"

        try:
            proc = psutil.Process(pid)
            info = proc.as_dict(attrs=['name', 'exe', 'cmdline', 'username'])

            name = info.get('name', 'Unknown')
            exe_path = Path(info['exe']) if info.get('exe') else None
            cmdline = info.get('cmdline') or []
            username = info.get('username')

            # Get memory info
            try:
                mem = proc.memory_info()
                memory_info = {
                    "rss": mem.rss,
                    "rss_human": format_bytes(mem.rss),
                    "vms": mem.vms,
                    "vms_human": format_bytes(mem.vms),
                }
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Get connections
            connections = self._get_process_connections(proc)

            # Check for suspicious behavior
            matches.extend(self._check_suspicious_behavior(proc, info))

            # Scan executable file if accessible
            if exe_path and exe_path.exists():
                file_result = self.file_scanner.scan_file(exe_path)
                matches.extend(file_result.matches)

        except psutil.NoSuchProcess:
            error = f"Process {pid} no longer exists"
        except psutil.AccessDenied:
            error = f"Access denied to process {pid}"
        except Exception as e:
            error = str(e)
            logger.error(f"Error scanning process {pid}: {e}")

        # Determine overall threat level
        if matches:
            threat_level = max(m.severity for m in matches)
        else:
            threat_level = ThreatLevel.CLEAN

        return ProcessScanResult(
            pid=pid,
            name=name,
            exe_path=exe_path,
            cmdline=cmdline,
            username=username,
            threat_level=threat_level,
            matches=matches,
            memory_info=memory_info,
            connections=connections,
            error=error,
        )

    def scan_all_processes(self) -> Generator[ProcessScanResult, None, None]:
        """
        Scan all running processes.

        Yields:
            ProcessScanResult for each process
        """
        # Ensure rules are loaded
        if not self._rules_loaded:
            self.load_yara_rules()

        for proc in psutil.process_iter(['pid']):
            try:
                yield self.scan_process(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def find_suspicious_processes(self) -> list[ProcessScanResult]:
        """
        Find all processes with suspicious indicators.

        Returns:
            List of ProcessScanResult for suspicious processes
        """
        suspicious = []
        for result in self.scan_all_processes():
            if result.threat_level != ThreatLevel.CLEAN:
                suspicious.append(result)
        return suspicious

    def kill_process(self, pid: int, force: bool = False) -> bool:
        """
        Terminate a process.

        Args:
            pid: Process ID to terminate
            force: Use SIGKILL instead of SIGTERM

        Returns:
            True if process was terminated
        """
        try:
            proc = psutil.Process(pid)
            if force:
                proc.kill()
            else:
                proc.terminate()

            # Wait for process to end
            proc.wait(timeout=5)
            logger.info(f"Terminated process {pid}")
            return True

        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return True  # Already gone
        except psutil.AccessDenied:
            logger.error(f"Access denied to terminate process {pid}")
            return False
        except psutil.TimeoutExpired:
            logger.warning(f"Process {pid} did not terminate in time")
            return False
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
            return False

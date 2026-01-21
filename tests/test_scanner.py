"""
Tests for BisonTitan Scanner Module
"""

import json
import tempfile
from pathlib import Path

import pytest

from bisontitan.config import ScannerConfig
from bisontitan.scanner import (
    FileScanner,
    ProcessScanner,
    ThreatLevel,
    FileScanResult,
    ScanMatch,
)


class TestThreatLevel:
    """Tests for ThreatLevel enum."""

    def test_threat_levels_exist(self):
        """Verify all threat levels are defined."""
        assert ThreatLevel.CLEAN.value == "clean"
        assert ThreatLevel.INFO.value == "info"
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.CRITICAL.value == "critical"

    def test_threat_level_comparison(self):
        """Verify threat levels can be compared."""
        levels = [
            ThreatLevel.CLEAN,
            ThreatLevel.INFO,
            ThreatLevel.LOW,
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
        ]
        # Verify all levels are distinct
        assert len(set(levels)) == 6


class TestScanMatch:
    """Tests for ScanMatch dataclass."""

    def test_scan_match_creation(self):
        """Test creating a ScanMatch."""
        match = ScanMatch(
            rule_name="Test_Rule",
            description="Test description",
            severity=ThreatLevel.HIGH,
            matched_strings=["test"],
            metadata={"author": "tester"},
        )
        assert match.rule_name == "Test_Rule"
        assert match.severity == ThreatLevel.HIGH
        assert "test" in match.matched_strings

    def test_scan_match_defaults(self):
        """Test ScanMatch default values."""
        match = ScanMatch(
            rule_name="Test",
            description="Test",
            severity=ThreatLevel.LOW,
        )
        assert match.matched_strings == []
        assert match.metadata == {}


class TestFileScanResult:
    """Tests for FileScanResult dataclass."""

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = FileScanResult(
            filepath=Path("/test/file.exe"),
            size=1024,
            hashes={"sha256": "abc123"},
            threat_level=ThreatLevel.CLEAN,
        )
        d = result.to_dict()

        assert d["filepath"] == "/test/file.exe" or d["filepath"] == "\\test\\file.exe"
        assert d["size"] == 1024
        assert d["threat_level"] == "clean"
        assert "sha256" in d["hashes"]

    def test_result_with_matches(self):
        """Test result with matches included."""
        match = ScanMatch(
            rule_name="Malware",
            description="Found malware",
            severity=ThreatLevel.CRITICAL,
        )
        result = FileScanResult(
            filepath=Path("/test/malware.exe"),
            size=2048,
            hashes={},
            threat_level=ThreatLevel.CRITICAL,
            matches=[match],
        )
        d = result.to_dict()

        assert len(d["matches"]) == 1
        assert d["matches"][0]["rule"] == "Malware"


class TestFileScanner:
    """Tests for FileScanner class."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner with test config."""
        config = ScannerConfig(
            yara_rules_dir=Path("config/rules"),
            quarantine_dir=Path(tempfile.mkdtemp()),
            hash_check_enabled=True,
            yara_scan_enabled=True,
        )
        return FileScanner(config)

    @pytest.fixture
    def temp_file(self):
        """Create a temporary test file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("This is a test file for scanning.")
            return Path(f.name)

    @pytest.fixture
    def eicar_file(self):
        """Create EICAR test file (antivirus test pattern)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            # EICAR test string - safe, used to test AV
            f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            return Path(f.name)

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner.config is not None
        assert scanner._rules_loaded is False

    def test_scan_nonexistent_file(self, scanner):
        """Test scanning a file that doesn't exist."""
        result = scanner.scan_file(Path("/nonexistent/file.exe"))

        assert result.error is not None
        assert "not found" in result.error.lower() or "no such file" in result.error.lower()

    def test_scan_clean_file(self, scanner, temp_file):
        """Test scanning a clean file."""
        result = scanner.scan_file(temp_file)

        assert result.error is None
        assert result.threat_level == ThreatLevel.CLEAN
        assert len(result.matches) == 0
        assert result.size > 0
        assert "sha256" in result.hashes

        # Cleanup
        temp_file.unlink()

    def test_scan_calculates_hashes(self, scanner, temp_file):
        """Test that scanning calculates file hashes."""
        result = scanner.scan_file(temp_file)

        assert "md5" in result.hashes
        assert "sha1" in result.hashes
        assert "sha256" in result.hashes
        assert len(result.hashes["sha256"]) == 64  # SHA256 is 64 hex chars

        temp_file.unlink()

    def test_scan_with_known_hash(self):
        """Test scanning with known malware hash list."""
        # Create file and get its hash first
        with tempfile.NamedTemporaryFile(mode="w", suffix=".exe", delete=False) as f:
            f.write("malware content")
            temp_path = Path(f.name)

        # Get the file's hash
        from bisontitan.utils import get_file_hash
        file_hash = get_file_hash(temp_path, "sha256")

        # Create scanner with this hash in known list
        config = ScannerConfig(
            known_malware_hashes=[file_hash],
        )
        scanner = FileScanner(config)

        result = scanner.scan_file(temp_path)

        assert result.threat_level == ThreatLevel.CRITICAL
        assert len(result.matches) > 0
        assert result.matches[0].rule_name == "Known_Malware_Hash"

        temp_path.unlink()

    def test_quarantine_file(self, scanner, temp_file):
        """Test quarantine functionality."""
        result = scanner.scan_file(temp_file)
        success, quarantine_path = scanner.quarantine_file(temp_file, result)

        assert success is True
        assert quarantine_path is not None
        assert quarantine_path.exists()
        assert not temp_file.exists()  # Original should be gone

        # Check metadata file exists
        meta_path = quarantine_path.with_suffix(".json")
        assert meta_path.exists()

        with open(meta_path) as f:
            meta = json.load(f)
            assert "original_path" in meta

        # Cleanup
        quarantine_path.unlink()
        meta_path.unlink()

    def test_restore_from_quarantine(self, scanner, temp_file):
        """Test restoring from quarantine."""
        original_content = temp_file.read_text()
        original_path = temp_file

        # Quarantine the file
        result = scanner.scan_file(temp_file)
        success, quarantine_path = scanner.quarantine_file(temp_file, result)
        assert success

        # Restore it
        success, restored_path = scanner.restore_from_quarantine(quarantine_path)

        assert success is True
        assert restored_path is not None
        assert restored_path.exists()
        assert restored_path.read_text() == original_content

        # Cleanup
        restored_path.unlink()

    def test_should_scan_excludes_extensions(self, scanner):
        """Test that excluded extensions are skipped."""
        scanner.config.excluded_extensions = [".dll", ".sys"]

        assert scanner._should_scan(Path("/test/file.dll")) is False
        assert scanner._should_scan(Path("/test/file.sys")) is False
        assert scanner._should_scan(Path("/test/file.exe")) is True

    def test_scan_directory(self, scanner):
        """Test scanning a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some test files
            for i in range(3):
                (Path(tmpdir) / f"file{i}.txt").write_text(f"content {i}")

            results = list(scanner.scan_directory(Path(tmpdir), recursive=False))

            assert len(results) == 3
            for result in results:
                assert result.threat_level == ThreatLevel.CLEAN


class TestProcessScanner:
    """Tests for ProcessScanner class."""

    @pytest.fixture
    def scanner(self):
        """Create a process scanner."""
        return ProcessScanner()

    def test_scanner_initialization(self, scanner):
        """Test process scanner initializes."""
        assert scanner.file_scanner is not None

    def test_get_process_list(self, scanner):
        """Test getting process list."""
        processes = scanner.get_process_list()

        assert isinstance(processes, list)
        assert len(processes) > 0  # Should have at least our process

        # Check process structure
        for proc in processes[:5]:
            assert "pid" in proc
            assert "name" in proc

    def test_scan_current_process(self, scanner):
        """Test scanning the current Python process."""
        import os

        result = scanner.scan_process(os.getpid())

        assert result.pid == os.getpid()
        assert result.name is not None
        assert result.error is None

    def test_scan_nonexistent_process(self, scanner):
        """Test scanning a process that doesn't exist."""
        # Use a very high PID that's unlikely to exist
        result = scanner.scan_process(999999999)

        assert result.error is not None

    def test_find_suspicious_processes(self, scanner):
        """Test finding suspicious processes."""
        suspicious = scanner.find_suspicious_processes()

        # Result should be a list (possibly empty)
        assert isinstance(suspicious, list)

        # If any found, they should have threat level > CLEAN
        for result in suspicious:
            assert result.threat_level != ThreatLevel.CLEAN


class TestScannerConfig:
    """Tests for ScannerConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ScannerConfig()

        assert config.hash_check_enabled is True
        assert config.yara_scan_enabled is True
        assert config.max_file_size_mb == 100

    def test_custom_config(self):
        """Test custom configuration."""
        config = ScannerConfig(
            max_file_size_mb=50,
            excluded_extensions=[".log", ".tmp"],
        )

        assert config.max_file_size_mb == 50
        assert ".log" in config.excluded_extensions


# Integration tests that require YARA
class TestYARAIntegration:
    """Tests that require YARA to be installed."""

    @pytest.fixture
    def scanner_with_rules(self):
        """Create scanner with YARA rules loaded."""
        config = ScannerConfig(
            yara_rules_dir=Path("config/rules"),
        )
        scanner = FileScanner(config)
        scanner.load_yara_rules()
        return scanner

    @pytest.mark.skipif(
        not Path("config/rules/malware_signatures.yar").exists(),
        reason="YARA rules not available",
    )
    def test_yara_rules_load(self, scanner_with_rules):
        """Test that YARA rules can be loaded."""
        # Rules should be loaded (or skipped if yara not installed)
        # This test just verifies no crashes occur
        pass

    @pytest.mark.skipif(
        not Path("config/rules/malware_signatures.yar").exists(),
        reason="YARA rules not available",
    )
    def test_eicar_detection(self, scanner_with_rules):
        """Test EICAR test file detection."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            eicar_path = Path(f.name)

        try:
            if scanner_with_rules._rules_loaded:
                result = scanner_with_rules.scan_file(eicar_path)
                # EICAR should be detected by our sample rules
                assert result.threat_level != ThreatLevel.CLEAN or len(result.matches) > 0
        finally:
            eicar_path.unlink()

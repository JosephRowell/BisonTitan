"""
Tests for BisonTitan Utils Module
"""

import hashlib
import logging
import tempfile
from pathlib import Path

import pytest

from bisontitan.utils import (
    get_platform,
    is_admin,
    setup_logging,
    get_file_hash,
    get_multiple_hashes,
    format_bytes,
    sanitize_filename,
)


class TestPlatformDetection:
    """Tests for platform detection."""

    def test_get_platform_returns_string(self):
        """Test that get_platform returns a valid platform string."""
        platform = get_platform()
        assert platform in ["windows", "linux", "darwin", "unknown"]

    def test_is_admin_returns_bool(self):
        """Test that is_admin returns a boolean."""
        result = is_admin()
        assert isinstance(result, bool)


class TestLogging:
    """Tests for logging setup."""

    def test_setup_logging_returns_logger(self):
        """Test that setup_logging returns a logger."""
        logger = setup_logging()
        assert isinstance(logger, logging.Logger)
        assert logger.name == "bisontitan"

    def test_setup_logging_with_file(self):
        """Test logging to a file."""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            log_path = Path(f.name)

        logger = setup_logging(log_file=log_path, console=False)
        logger.info("Test message")

        # Verify log file has content
        assert log_path.exists()
        content = log_path.read_text()
        assert "Test message" in content

        log_path.unlink()

    def test_setup_logging_levels(self):
        """Test different logging levels."""
        logger = setup_logging(level=logging.DEBUG, console=False)
        assert logger.level == logging.DEBUG

        logger = setup_logging(level=logging.WARNING, console=False)
        assert logger.level == logging.WARNING


class TestHashFunctions:
    """Tests for hash calculation functions."""

    @pytest.fixture
    def test_file(self):
        """Create a test file with known content."""
        content = b"test content for hashing"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            return Path(f.name), content

    def test_get_file_hash_sha256(self, test_file):
        """Test SHA256 hash calculation."""
        filepath, content = test_file

        result = get_file_hash(filepath, "sha256")
        expected = hashlib.sha256(content).hexdigest()

        assert result == expected
        filepath.unlink()

    def test_get_file_hash_md5(self, test_file):
        """Test MD5 hash calculation."""
        filepath, content = test_file

        result = get_file_hash(filepath, "md5")
        expected = hashlib.md5(content).hexdigest()

        assert result == expected
        filepath.unlink()

    def test_get_multiple_hashes(self, test_file):
        """Test calculating multiple hashes at once."""
        filepath, content = test_file

        hashes = get_multiple_hashes(filepath)

        assert "md5" in hashes
        assert "sha1" in hashes
        assert "sha256" in hashes

        assert hashes["md5"] == hashlib.md5(content).hexdigest()
        assert hashes["sha1"] == hashlib.sha1(content).hexdigest()
        assert hashes["sha256"] == hashlib.sha256(content).hexdigest()

        filepath.unlink()

    def test_hash_large_file(self):
        """Test hashing a larger file."""
        # Create a 1MB file
        content = b"x" * (1024 * 1024)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            filepath = Path(f.name)

        hashes = get_multiple_hashes(filepath)

        assert len(hashes["sha256"]) == 64
        filepath.unlink()


class TestFormatBytes:
    """Tests for byte formatting."""

    def test_format_bytes_basic(self):
        """Test basic byte formatting."""
        assert "0.00 B" == format_bytes(0)
        assert "100.00 B" == format_bytes(100)
        assert "1.00 KB" == format_bytes(1024)
        assert "1.00 MB" == format_bytes(1024 * 1024)
        assert "1.00 GB" == format_bytes(1024 * 1024 * 1024)

    def test_format_bytes_fractional(self):
        """Test fractional byte formatting."""
        result = format_bytes(1536)  # 1.5 KB
        assert "KB" in result
        assert "1.50" in result


class TestSanitizeFilename:
    """Tests for filename sanitization."""

    def test_sanitize_basic(self):
        """Test basic filename sanitization."""
        assert sanitize_filename("test.txt") == "test.txt"
        assert sanitize_filename("file:name.exe") == "file_name.exe"
        assert sanitize_filename("a<b>c.txt") == "a_b_c.txt"

    def test_sanitize_all_invalid(self):
        """Test sanitizing all invalid characters."""
        invalid = '<>:"/\\|?*'
        result = sanitize_filename(f"file{invalid}name.txt")
        for char in invalid:
            assert char not in result

    def test_sanitize_preserves_valid(self):
        """Test that valid characters are preserved."""
        valid = "file-name_2024.test.txt"
        assert sanitize_filename(valid) == valid

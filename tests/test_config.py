"""
Tests for BisonTitan Config Module
"""

import tempfile
from pathlib import Path

import pytest
import yaml

from bisontitan.config import (
    Config,
    ScannerConfig,
    TrafficConfig,
    FingerprintConfig,
    LogAnalyzerConfig,
    VulnCheckerConfig,
    AttackSimConfig,
)


class TestScannerConfig:
    """Tests for ScannerConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ScannerConfig()

        assert config.hash_check_enabled is True
        assert config.yara_scan_enabled is True
        assert config.scan_archives is False
        assert config.max_file_size_mb == 100
        assert ".dll" in config.excluded_extensions

    def test_custom_values(self):
        """Test custom configuration."""
        config = ScannerConfig(
            hash_check_enabled=False,
            max_file_size_mb=200,
            excluded_paths=["/tmp/*"],
        )

        assert config.hash_check_enabled is False
        assert config.max_file_size_mb == 200
        assert "/tmp/*" in config.excluded_paths


class TestTrafficConfig:
    """Tests for TrafficConfig."""

    def test_default_values(self):
        """Test default traffic config."""
        config = TrafficConfig()

        assert config.capture_duration_sec == 5
        assert config.interface is None
        assert 4444 in config.high_risk_ports  # Metasploit default

    def test_proxy_whitelist(self):
        """Test proxy whitelist configuration."""
        config = TrafficConfig(
            proxy_whitelist=["10.0.0.1", "192.168.1.1"],
        )

        assert len(config.proxy_whitelist) == 2
        assert "10.0.0.1" in config.proxy_whitelist


class TestConfig:
    """Tests for main Config class."""

    @pytest.fixture
    def sample_config_dict(self):
        """Sample configuration dictionary."""
        return {
            "log_file": "logs/test.log",
            "log_level": "DEBUG",
            "require_admin": True,
            "scanner": {
                "max_file_size_mb": 50,
                "hash_check_enabled": True,
                "excluded_extensions": [".log"],
            },
            "traffic": {
                "capture_duration_sec": 10,
                "proxy_whitelist": ["1.2.3.4"],
            },
        }

    @pytest.fixture
    def config_file(self, sample_config_dict):
        """Create a temporary config file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(sample_config_dict, f)
            return Path(f.name)

    def test_default_config(self):
        """Test creating default config."""
        config = Config()

        assert config.log_level == "INFO"
        assert config.require_admin is False
        assert isinstance(config.scanner, ScannerConfig)
        assert isinstance(config.traffic, TrafficConfig)

    def test_load_from_file(self, config_file):
        """Test loading config from file."""
        config = Config.load(config_file)

        assert config.log_level == "DEBUG"
        assert config.require_admin is True
        assert config.scanner.max_file_size_mb == 50
        assert config.traffic.capture_duration_sec == 10

        config_file.unlink()

    def test_load_nonexistent_file(self):
        """Test loading from nonexistent file raises error."""
        with pytest.raises(FileNotFoundError):
            Config.load(Path("/nonexistent/config.yaml"))

    def test_load_or_default_missing(self):
        """Test load_or_default returns defaults when file missing."""
        config = Config.load_or_default(Path("/nonexistent/config.yaml"))

        # Should return default config, not raise
        assert config.log_level == "INFO"

    def test_to_dict(self):
        """Test converting config to dictionary."""
        config = Config()
        d = config.to_dict()

        assert "log_file" in d
        assert "scanner" in d
        assert "traffic" in d
        assert "fingerprint" in d
        assert "vuln_checker" in d

    def test_save_and_load(self):
        """Test saving and reloading config."""
        config = Config()
        config.log_level = "WARNING"
        config.scanner.max_file_size_mb = 75

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            config_path = Path(f.name)

        config.save(config_path)

        # Reload and verify
        loaded = Config.load(config_path)
        assert loaded.log_level == "WARNING"
        assert loaded.scanner.max_file_size_mb == 75

        config_path.unlink()

    def test_config_sections(self):
        """Test all config sections are present."""
        config = Config()

        assert hasattr(config, "scanner")
        assert hasattr(config, "traffic")
        assert hasattr(config, "fingerprint")
        assert hasattr(config, "log_analyzer")
        assert hasattr(config, "vuln_checker")
        assert hasattr(config, "attack_sim")


class TestFingerprintConfig:
    """Tests for FingerprintConfig."""

    def test_default_values(self):
        """Test default fingerprint config."""
        config = FingerprintConfig()

        assert config.browser_type == "chromium"
        assert config.headless is True
        assert config.viewport_width == 1920
        assert config.viewport_height == 1080


class TestLogAnalyzerConfig:
    """Tests for LogAnalyzerConfig."""

    def test_default_values(self):
        """Test default log analyzer config."""
        config = LogAnalyzerConfig()

        assert "Security" in config.event_logs
        assert config.failed_login_threshold == 5
        assert config.time_window_minutes == 15

    def test_excluded_users(self):
        """Test excluded users configuration."""
        config = LogAnalyzerConfig(
            excluded_users=["admin", "test_user"],
        )

        assert "admin" in config.excluded_users


class TestVulnCheckerConfig:
    """Tests for VulnCheckerConfig."""

    def test_default_values(self):
        """Test default vuln checker config."""
        config = VulnCheckerConfig()

        assert "127.0.0.1" in config.target_hosts
        assert config.check_netbios is True
        assert config.check_smb is True


class TestAttackSimConfig:
    """Tests for AttackSimConfig."""

    def test_default_values(self):
        """Test default attack sim config."""
        config = AttackSimConfig()

        assert config.safe_mode is True
        assert config.require_confirmation is True
        assert "port_scan" in config.enabled_scenarios

    def test_target_default_localhost(self):
        """Test target defaults to localhost for safety."""
        config = AttackSimConfig()

        assert config.target_host == "127.0.0.1"

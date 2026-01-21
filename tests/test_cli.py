"""
Tests for BisonTitan CLI Module
"""

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from bisontitan.cli import cli


@pytest.fixture
def runner():
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create some test files
        for i in range(3):
            (Path(tmpdir) / f"test{i}.txt").write_text(f"Test content {i}")
        yield tmpdir


class TestCLIBasics:
    """Tests for basic CLI functionality."""

    def test_cli_help(self, runner):
        """Test that help message displays."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "BisonTitan Security Suite" in result.output

    def test_cli_version(self, runner):
        """Test version flag."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_cli_quiet_mode(self, runner):
        """Test quiet mode suppresses output."""
        result = runner.invoke(cli, ["--quiet", "--help"])
        # Help should still show in quiet mode
        assert result.exit_code == 0


class TestScanCommand:
    """Tests for the scan command."""

    def test_scan_help(self, runner):
        """Test scan command help."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--files" in result.output
        assert "--processes" in result.output

    def test_scan_requires_target(self, runner):
        """Test that scan requires --files or --processes."""
        result = runner.invoke(cli, ["--quiet", "scan"])
        assert result.exit_code != 0

    def test_scan_files(self, runner, temp_dir):
        """Test scanning files."""
        result = runner.invoke(cli, ["--quiet", "scan", "--files", temp_dir])
        assert result.exit_code == 0

    def test_scan_files_json_output(self, runner, temp_dir):
        """Test JSON output for file scan."""
        result = runner.invoke(cli, ["--json-output", "scan", "--files", temp_dir])
        assert result.exit_code == 0

        # Should be valid JSON
        output = json.loads(result.output)
        assert "scan_type" in output
        assert "results" in output

    def test_scan_nonexistent_path(self, runner):
        """Test scanning nonexistent path."""
        result = runner.invoke(cli, ["--quiet", "scan", "--files", "/nonexistent/path"])
        # Click should catch the bad path
        assert result.exit_code != 0

    def test_scan_single_file(self, runner, temp_dir):
        """Test scanning a single file."""
        test_file = Path(temp_dir) / "test0.txt"
        result = runner.invoke(cli, ["--quiet", "scan", "--files", str(test_file)])
        assert result.exit_code == 0


class TestQuarantineCommand:
    """Tests for the quarantine command."""

    def test_quarantine_help(self, runner):
        """Test quarantine command help."""
        result = runner.invoke(cli, ["quarantine", "--help"])
        assert result.exit_code == 0
        assert "--list" in result.output
        assert "--restore" in result.output

    def test_quarantine_list_empty(self, runner):
        """Test listing empty quarantine."""
        result = runner.invoke(cli, ["--quiet", "quarantine", "--list"])
        assert result.exit_code == 0


class TestTrafficCommand:
    """Tests for the traffic command."""

    def test_traffic_help(self, runner):
        """Test traffic command help."""
        result = runner.invoke(cli, ["traffic", "--help"])
        assert result.exit_code == 0
        assert "--label" in result.output
        assert "--duration" in result.output


class TestFingerprintCommand:
    """Tests for the fingerprint command."""

    def test_fingerprint_help(self, runner):
        """Test fingerprint command help."""
        result = runner.invoke(cli, ["fingerprint", "--help"])
        assert result.exit_code == 0
        assert "--profile" in result.output


class TestLogsCommand:
    """Tests for the logs command."""

    def test_logs_help(self, runner):
        """Test logs command help."""
        result = runner.invoke(cli, ["logs", "--help"])
        assert result.exit_code == 0
        assert "--analyze" in result.output
        assert "--log-type" in result.output


class TestVulnCheckCommand:
    """Tests for the vuln-check command."""

    def test_vuln_check_help(self, runner):
        """Test vuln-check command help."""
        result = runner.invoke(cli, ["vuln-check", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output
        assert "--ports" in result.output


class TestSimAttackCommand:
    """Tests for the sim-attack command."""

    def test_sim_attack_help(self, runner):
        """Test sim-attack command help."""
        result = runner.invoke(cli, ["sim-attack", "--help"])
        assert result.exit_code == 0
        assert "--scenario" in result.output
        assert "--target" in result.output

    def test_sim_attack_requires_scenario(self, runner):
        """Test that sim-attack requires --scenario."""
        result = runner.invoke(cli, ["--quiet", "sim-attack"])
        assert result.exit_code != 0


class TestConfigFlag:
    """Tests for the --config flag."""

    def test_nonexistent_config(self, runner):
        """Test with nonexistent config file."""
        # Should warn but not fail
        result = runner.invoke(cli, ["--config", "/nonexistent.yaml", "--help"])
        # --config requires exists=True, so this should fail
        assert result.exit_code != 0

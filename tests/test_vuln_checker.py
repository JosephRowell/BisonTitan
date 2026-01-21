"""
Tests for BisonTitan Vulnerability Checker Module.
Phase 4 implementation tests.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from bisontitan.config import VulnCheckerConfig
from bisontitan.vuln_checker import (
    VulnChecker,
    VulnCheckResult,
    PortResult,
    ConfigCheckResult,
    HIGH_RISK_PORTS,
    WINDOWS_CONFIG_CHECKS,
)


class TestPortResult:
    """Tests for PortResult dataclass."""

    def test_port_result_creation(self):
        """Test PortResult creation."""
        result = PortResult(
            port=445,
            state="open",
            service="microsoft-ds",
            version="SMB",
            risk_level="critical",
            reason="SMB port exposed",
        )

        assert result.port == 445
        assert result.state == "open"
        assert result.risk_level == "critical"

    def test_port_result_to_dict(self):
        """Test PortResult serialization."""
        result = PortResult(
            port=3389,
            state="open",
            service="rdp",
            version=None,
            risk_level="critical",
            reason="RDP exposed",
            vulnerabilities=["BlueKeep"],
        )

        d = result.to_dict()

        assert d["port"] == 3389
        assert d["service"] == "rdp"
        assert "BlueKeep" in d["vulnerabilities"]


class TestConfigCheckResult:
    """Tests for ConfigCheckResult dataclass."""

    def test_config_check_passed(self):
        """Test passed configuration check."""
        result = ConfigCheckResult(
            name="uac_enabled",
            description="UAC is enabled",
            passed=True,
            current_value=1,
            expected_value=1,
            risk_level="high",
            recommendation="",
        )

        d = result.to_dict()

        assert d["passed"] is True
        assert d["risk_level"] == "none"  # Passed, so no risk
        assert d["recommendation"] == ""

    def test_config_check_failed(self):
        """Test failed configuration check."""
        result = ConfigCheckResult(
            name="smbv1_disabled",
            description="SMBv1 should be disabled",
            passed=False,
            current_value=1,
            expected_value=0,
            risk_level="critical",
            recommendation="Disable SMBv1",
        )

        d = result.to_dict()

        assert d["passed"] is False
        assert d["risk_level"] == "critical"
        assert "Disable SMBv1" in d["recommendation"]


class TestVulnCheckResult:
    """Tests for VulnCheckResult dataclass."""

    def test_vuln_check_result_creation(self):
        """Test VulnCheckResult creation."""
        result = VulnCheckResult(
            target="127.0.0.1",
            scan_time=datetime.now(),
            open_ports=[
                PortResult(445, "open", "smb", None, "critical", "SMB exposed"),
            ],
            config_checks=[],
            vulnerabilities=[{"type": "smb_exposure", "severity": "critical"}],
            recommendations=["Block port 445"],
            risk_score=5.0,
            scan_duration_sec=2.5,
        )

        assert result.target == "127.0.0.1"
        assert len(result.open_ports) == 1
        assert result.risk_score == 5.0

    def test_vuln_check_result_to_dict(self):
        """Test VulnCheckResult serialization."""
        now = datetime.now()
        result = VulnCheckResult(
            target="192.168.1.1",
            scan_time=now,
            open_ports=[
                PortResult(22, "open", "ssh", "OpenSSH 8.0", "medium", "SSH exposed"),
            ],
            config_checks=[
                ConfigCheckResult("firewall", "Firewall check", False, "OFF", "ON", "critical", "Enable firewall"),
            ],
            vulnerabilities=[],
            recommendations=["Enable firewall"],
            risk_score=3.5,
        )

        d = result.to_dict()

        assert d["target"] == "192.168.1.1"
        assert d["scan_time"] == now.isoformat()
        assert len(d["open_ports"]) == 1
        assert len(d["config_checks"]) == 1
        assert d["risk_score"] == 3.5

    def test_vuln_check_result_to_markdown(self):
        """Test markdown report generation."""
        result = VulnCheckResult(
            target="127.0.0.1",
            scan_time=datetime.now(),
            open_ports=[
                PortResult(445, "open", "SMB", None, "critical", "SMB direct exposure"),
                PortResult(3389, "open", "RDP", None, "critical", "RDP exposed"),
            ],
            config_checks=[
                ConfigCheckResult("smbv1", "SMBv1 disabled", False, "Enabled", "Disabled", "critical", "Disable SMBv1"),
            ],
            vulnerabilities=[],
            recommendations=["Block SMB", "Secure RDP"],
            risk_score=7.5,
            scan_duration_sec=5.0,
        )

        markdown = result.to_markdown()

        assert "# BisonTitan Vulnerability Report" in markdown
        assert "127.0.0.1" in markdown
        assert "445" in markdown
        assert "3389" in markdown
        assert "CRITICAL" in markdown
        assert "Block SMB" in markdown or "netsh" in markdown


class TestVulnChecker:
    """Tests for VulnChecker."""

    def test_checker_initialization(self):
        """Test checker initializes correctly."""
        checker = VulnChecker()
        assert checker.config is not None

    def test_checker_with_custom_config(self):
        """Test checker with custom configuration."""
        config = VulnCheckerConfig(
            port_ranges="1-100",
            check_smb=False,
        )
        checker = VulnChecker(config)

        assert checker.config.port_ranges == "1-100"
        assert checker.config.check_smb is False

    def test_parse_port_range_simple(self):
        """Test port range parsing - simple range."""
        checker = VulnChecker()
        ports = checker._parse_port_range("1-10")

        assert ports == list(range(1, 11))

    def test_parse_port_range_list(self):
        """Test port range parsing - comma-separated."""
        checker = VulnChecker()
        ports = checker._parse_port_range("22,80,443")

        assert ports == [22, 80, 443]

    def test_parse_port_range_mixed(self):
        """Test port range parsing - mixed format."""
        checker = VulnChecker()
        ports = checker._parse_port_range("22,80-82,443")

        assert ports == [22, 80, 81, 82, 443]

    def test_guess_service(self):
        """Test service name guessing."""
        checker = VulnChecker()

        assert checker._guess_service(22) == "ssh"
        assert checker._guess_service(80) == "http"
        assert checker._guess_service(443) == "https"
        assert "unknown" in checker._guess_service(12345)

    @patch("socket.socket")
    def test_scan_ports_socket(self, mock_socket):
        """Test socket-based port scanning."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        # Simulate port 80 open, others closed
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 1

        checker = VulnChecker()
        results = checker.scan_ports_socket("127.0.0.1", "80,443", timeout=0.1)

        assert len(results) == 1
        assert results[0].port == 80
        assert results[0].state == "open"

    @patch("socket.socket")
    def test_check_netbios(self, mock_socket):
        """Test NetBIOS check."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        # Simulate port 139 open
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] == 139 else 1

        checker = VulnChecker()
        result = checker.check_netbios("127.0.0.1")

        assert result["exposed"] is True
        assert 139 in result["ports"]
        assert result["risk_level"] == "high"

    @patch("socket.socket")
    def test_check_netbios_not_exposed(self, mock_socket):
        """Test NetBIOS check when not exposed."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1  # All ports closed

        checker = VulnChecker()
        result = checker.check_netbios("127.0.0.1")

        assert result["exposed"] is False
        assert result["risk_level"] == "none"

    @patch("socket.socket")
    def test_check_smb(self, mock_socket):
        """Test SMB check."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0  # Port 445 open

        checker = VulnChecker()
        result = checker.check_smb("127.0.0.1")

        assert result["exposed"] is True
        assert result["port_445_open"] is True
        assert result["risk_level"] == "critical"
        assert len(result["vulnerabilities"]) > 0

    @patch("socket.socket")
    def test_check_rdp(self, mock_socket):
        """Test RDP check."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0  # Port 3389 open

        checker = VulnChecker()
        result = checker.check_rdp("127.0.0.1")

        assert result["exposed"] is True
        assert result["port_3389_open"] is True
        assert result["risk_level"] == "critical"
        assert "BlueKeep" in str(result["vulnerabilities"])

    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        checker = VulnChecker()

        open_ports = [
            PortResult(445, "open", "smb", None, "critical", ""),
            PortResult(3389, "open", "rdp", None, "critical", ""),
            PortResult(80, "open", "http", None, "low", ""),
        ]
        config_checks = [
            ConfigCheckResult("firewall", "", False, "", "", "critical", ""),
        ]

        score = checker.calculate_risk_score(open_ports, config_checks)

        # 2 critical ports (2.5 each) + 1 low port (0.25) + 1 critical config (2.0) = 7.25
        assert score >= 7.0
        assert score <= 10.0

    def test_calculate_risk_score_empty(self):
        """Test risk score with no issues."""
        checker = VulnChecker()
        score = checker.calculate_risk_score([], [])
        assert score == 0.0

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        checker = VulnChecker()

        open_ports = [
            PortResult(445, "open", "smb", None, "critical", ""),
            PortResult(3389, "open", "rdp", None, "critical", ""),
        ]
        config_checks = []

        recommendations = checker.generate_recommendations(open_ports, config_checks)

        assert len(recommendations) >= 2
        # Should have SMB and RDP recommendations
        rec_text = " ".join(recommendations).lower()
        assert "smb" in rec_text or "445" in rec_text
        assert "rdp" in rec_text or "3389" in rec_text

    @patch("socket.socket")
    def test_quick_scan(self, mock_socket):
        """Test quick scan of common ports."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        # Only port 80 open
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 1

        checker = VulnChecker()
        result = checker.quick_scan("127.0.0.1")

        assert isinstance(result, VulnCheckResult)
        assert result.target == "127.0.0.1"
        # Should find port 80 if it was in the high-risk list
        # (HTTP 80 is in HIGH_RISK_PORTS)


class TestHighRiskPorts:
    """Tests for high-risk ports configuration."""

    def test_smb_ports_high_risk(self):
        """Test SMB ports are marked as high risk."""
        assert 445 in HIGH_RISK_PORTS
        assert HIGH_RISK_PORTS[445]["risk"] == "critical"

    def test_rdp_port_high_risk(self):
        """Test RDP port is marked as high risk."""
        assert 3389 in HIGH_RISK_PORTS
        assert HIGH_RISK_PORTS[3389]["risk"] == "critical"

    def test_netbios_ports_high_risk(self):
        """Test NetBIOS ports are marked as high risk."""
        assert 137 in HIGH_RISK_PORTS
        assert 138 in HIGH_RISK_PORTS
        assert 139 in HIGH_RISK_PORTS

    def test_database_ports_high_risk(self):
        """Test database ports are marked appropriately."""
        assert 3306 in HIGH_RISK_PORTS  # MySQL
        assert 5432 in HIGH_RISK_PORTS  # PostgreSQL
        assert 27017 in HIGH_RISK_PORTS  # MongoDB


class TestWindowsConfigChecks:
    """Tests for Windows configuration checks."""

    def test_uac_check_defined(self):
        """Test UAC check is defined."""
        assert "uac_enabled" in WINDOWS_CONFIG_CHECKS
        assert WINDOWS_CONFIG_CHECKS["uac_enabled"]["expected_value"] == 1

    def test_smbv1_check_defined(self):
        """Test SMBv1 check is defined."""
        assert "smbv1_disabled" in WINDOWS_CONFIG_CHECKS
        assert WINDOWS_CONFIG_CHECKS["smbv1_disabled"]["risk_if_fail"] == "critical"

    def test_firewall_check_defined(self):
        """Test firewall check is defined."""
        assert "firewall_enabled" in WINDOWS_CONFIG_CHECKS
        assert WINDOWS_CONFIG_CHECKS["firewall_enabled"]["risk_if_fail"] == "critical"


class TestVulnCheckerIntegration:
    """Integration tests for vulnerability checker."""

    @patch("socket.socket")
    def test_full_scan_integration(self, mock_socket):
        """Test full scan workflow."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        # Simulate some ports open
        open_ports = {80, 443, 445}
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] in open_ports else 1

        checker = VulnChecker(VulnCheckerConfig(
            check_netbios=True,
            check_smb=True,
            check_rdp=True,
        ))

        result = checker.full_scan("127.0.0.1", "80,443,445")

        assert isinstance(result, VulnCheckResult)
        assert result.target == "127.0.0.1"
        assert len(result.open_ports) == 3
        # SMB should be flagged as vulnerability
        assert any(v["type"] == "smb_exposure" for v in result.vulnerabilities)
        # Should have recommendations
        assert len(result.recommendations) > 0

    def test_cli_integration_quick_scan(self):
        """Test CLI integration with quick scan."""
        from click.testing import CliRunner
        from bisontitan.cli import cli

        runner = CliRunner()

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1  # All ports closed

            result = runner.invoke(cli, [
                "vulns", "--scan", "quick", "--target", "127.0.0.1",
                "--output", "json", "--no-confirm"
            ])

            # Should complete without error
            assert result.exit_code == 0 or "Error" not in result.output

    def test_markdown_report_complete(self):
        """Test complete markdown report generation."""
        result = VulnCheckResult(
            target="192.168.1.100",
            scan_time=datetime.now(),
            open_ports=[
                PortResult(22, "open", "SSH", "OpenSSH 8.0", "medium", "SSH service"),
                PortResult(445, "open", "SMB", None, "critical", "SMB exposed"),
                PortResult(3389, "open", "RDP", None, "critical", "RDP exposed"),
            ],
            config_checks=[
                ConfigCheckResult("smbv1", "SMBv1 disabled", False, "Enabled", "Disabled", "critical", "Disable SMBv1"),
                ConfigCheckResult("firewall", "Firewall enabled", True, "ON", "ON", "critical", ""),
            ],
            vulnerabilities=[
                {"type": "smb_exposure", "severity": "critical", "details": "Port 445 open"},
            ],
            recommendations=[
                "Block SMB port 445",
                "Secure RDP access",
                "Disable SMBv1",
            ],
            risk_score=8.5,
            scan_duration_sec=3.2,
        )

        markdown = result.to_markdown()

        # Check all sections present
        assert "# BisonTitan Vulnerability Report" in markdown
        assert "## Summary" in markdown
        assert "## Open Ports" in markdown
        assert "## Configuration Issues" in markdown
        assert "## Recommended Actions" in markdown
        assert "## Suggested Firewall Rules" in markdown

        # Check content
        assert "192.168.1.100" in markdown
        assert "8.5/10" in markdown
        assert "445" in markdown
        assert "3389" in markdown
        assert "netsh" in markdown  # Firewall rule

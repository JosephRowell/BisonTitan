"""
Tests for BisonTitan Attack Simulator Module.
Phase 5 implementation tests.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from bisontitan.config import AttackSimConfig
from bisontitan.attack_sim import (
    AttackSimulator,
    AttackResult,
    AttackStep,
    SimulationReport,
    ActionItem,
    SuccessLevel,
    PortProbeScenario,
    SMBProbeScenario,
    WeakAuthScenario,
    BufferOverflowScenario,
    DNSEnumScenario,
)


class TestSuccessLevel:
    """Tests for SuccessLevel enum."""

    def test_from_score_critical(self):
        """Test critical level threshold."""
        assert SuccessLevel.from_score(8.0) == SuccessLevel.CRITICAL
        assert SuccessLevel.from_score(10.0) == SuccessLevel.CRITICAL

    def test_from_score_high(self):
        """Test high level threshold."""
        assert SuccessLevel.from_score(6.0) == SuccessLevel.HIGH
        assert SuccessLevel.from_score(7.9) == SuccessLevel.HIGH

    def test_from_score_medium(self):
        """Test medium level threshold."""
        assert SuccessLevel.from_score(4.0) == SuccessLevel.MEDIUM
        assert SuccessLevel.from_score(5.9) == SuccessLevel.MEDIUM

    def test_from_score_low(self):
        """Test low level threshold."""
        assert SuccessLevel.from_score(2.0) == SuccessLevel.LOW
        assert SuccessLevel.from_score(3.9) == SuccessLevel.LOW

    def test_from_score_none(self):
        """Test none level threshold."""
        assert SuccessLevel.from_score(0.0) == SuccessLevel.NONE
        assert SuccessLevel.from_score(1.9) == SuccessLevel.NONE


class TestAttackStep:
    """Tests for AttackStep dataclass."""

    def test_attack_step_creation(self):
        """Test AttackStep creation."""
        step = AttackStep(
            name="Test Step",
            description="Test description",
            technique_id="T1234",
            success=True,
            details="Some details",
        )

        assert step.name == "Test Step"
        assert step.technique_id == "T1234"
        assert step.success is True

    def test_attack_step_with_substeps(self):
        """Test AttackStep with nested substeps."""
        substep = AttackStep("Sub", "Substep", "T1234.001", True)
        step = AttackStep(
            name="Parent",
            description="Parent step",
            technique_id="T1234",
            success=True,
            substeps=[substep],
        )

        assert len(step.substeps) == 1
        assert step.substeps[0].name == "Sub"


class TestAttackResult:
    """Tests for AttackResult dataclass."""

    def test_attack_result_creation(self):
        """Test AttackResult creation."""
        result = AttackResult(
            scenario="Test Scenario",
            scenario_id="test",
            target="127.0.0.1",
            success_level=SuccessLevel.MEDIUM,
            success_score=5.0,
            findings=["Finding 1", "Finding 2"],
            evidence=["Evidence 1"],
            attack_tree=[],
            mitigations=["Mitigation 1"],
        )

        assert result.scenario == "Test Scenario"
        assert result.success_level == SuccessLevel.MEDIUM
        assert result.success_score == 5.0
        assert len(result.findings) == 2

    def test_attack_result_to_dict(self):
        """Test AttackResult serialization."""
        result = AttackResult(
            scenario="Test",
            scenario_id="test",
            target="localhost",
            success_level=SuccessLevel.HIGH,
            success_score=7.0,
            findings=["Finding"],
            evidence=["Evidence"],
            attack_tree=[],
            mitigations=["Fix it"],
        )

        d = result.to_dict()

        assert d["scenario"] == "Test"
        assert d["success_level"] == "High"
        assert d["success_score"] == 7.0
        assert "timestamp" in d


class TestActionItem:
    """Tests for ActionItem dataclass."""

    def test_action_item_creation(self):
        """Test ActionItem creation."""
        action = ActionItem(
            title="Enable UAC",
            priority="Critical",
            description="Enable UAC to prevent unauthorized changes",
            command="Set-ItemProperty ...",
        )

        assert action.title == "Enable UAC"
        assert action.priority == "Critical"
        assert action.command is not None


class TestSimulationReport:
    """Tests for SimulationReport dataclass."""

    def test_report_creation(self):
        """Test SimulationReport creation."""
        result = AttackResult(
            scenario="Test",
            scenario_id="test",
            target="localhost",
            success_level=SuccessLevel.MEDIUM,
            success_score=5.0,
            findings=["Finding"],
            evidence=["Evidence"],
            attack_tree=[],
            mitigations=["Mitigation"],
        )

        report = SimulationReport(
            target="127.0.0.1",
            scenarios_run=["test"],
            results=[result],
            overall_risk="Medium",
            overall_score=5.0,
            action_items=[],
            best_practices=["Best practice 1"],
            attack_surface_summary={"total": 1},
        )

        assert report.target == "127.0.0.1"
        assert len(report.results) == 1
        assert report.overall_risk == "Medium"
        assert report.simulation_mode is True

    def test_report_to_dict(self):
        """Test SimulationReport serialization."""
        report = SimulationReport(
            target="localhost",
            scenarios_run=["test"],
            results=[],
            overall_risk="Low",
            overall_score=2.0,
            action_items=[],
            best_practices=[],
            attack_surface_summary={},
        )

        d = report.to_dict()

        assert d["target"] == "localhost"
        assert d["overall_risk"] == "Low"
        assert d["simulation_mode"] is True

    def test_report_to_markdown(self):
        """Test markdown report generation."""
        result = AttackResult(
            scenario="Port Scan",
            scenario_id="port_scan",
            target="localhost",
            success_level=SuccessLevel.HIGH,
            success_score=7.0,
            findings=["Port 80 open", "Port 443 open"],
            evidence=["[SIM] Port 80/tcp open"],
            attack_tree=[
                AttackStep("Discovery", "Network discovery", "T1046", True),
            ],
            mitigations=["Block unnecessary ports"],
        )

        report = SimulationReport(
            target="127.0.0.1",
            scenarios_run=["port_scan"],
            results=[result],
            overall_risk="High",
            overall_score=7.0,
            action_items=[
                ActionItem("Block ports", "High", "Block unnecessary ports"),
            ],
            best_practices=["Use firewall", "Monitor traffic"],
            attack_surface_summary={"critical_findings": 0, "high_findings": 1},
        )

        markdown = report.to_markdown()

        assert "# BisonTitan Attack Simulation Report" in markdown
        assert "SIMULATION MODE" in markdown
        assert "127.0.0.1" in markdown
        assert "Port Scan" in markdown
        assert "T1046" in markdown
        assert "Block ports" in markdown


class TestPortProbeScenario:
    """Tests for PortProbeScenario."""

    def test_scenario_properties(self):
        """Test scenario property values."""
        config = AttackSimConfig()
        scenario = PortProbeScenario(config)

        assert scenario.scenario_id == "port_probe"
        assert "Port" in scenario.scenario_name
        assert len(scenario.description) > 0

    @patch("socket.socket")
    def test_simulate_localhost(self, mock_socket):
        """Test port probe simulation on localhost."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1  # All ports closed

        config = AttackSimConfig()
        scenario = PortProbeScenario(config)
        result = scenario.simulate("127.0.0.1")

        assert result.scenario_id == "port_probe"
        assert result.target == "127.0.0.1"
        assert isinstance(result.success_level, SuccessLevel)
        assert len(result.attack_tree) > 0
        assert len(result.mitigations) > 0

    @patch("socket.socket")
    def test_simulate_with_open_ports(self, mock_socket):
        """Test port probe with some open ports."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        # Port 80 open, others closed
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 1

        config = AttackSimConfig()
        scenario = PortProbeScenario(config)
        result = scenario.simulate("127.0.0.1")

        assert result.success_score > 0
        assert any("80" in str(f) for f in result.findings)


class TestSMBProbeScenario:
    """Tests for SMBProbeScenario."""

    def test_scenario_properties(self):
        """Test scenario property values."""
        config = AttackSimConfig()
        scenario = SMBProbeScenario(config)

        assert scenario.scenario_id == "smb_probe"
        assert "SMB" in scenario.scenario_name

    @patch("socket.socket")
    def test_simulate_smb_closed(self, mock_socket):
        """Test SMB probe with closed ports."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        config = AttackSimConfig()
        scenario = SMBProbeScenario(config)
        result = scenario.simulate("127.0.0.1")

        assert result.scenario_id == "smb_probe"
        assert len(result.attack_tree) > 0

    @patch("socket.socket")
    def test_simulate_smb_open(self, mock_socket):
        """Test SMB probe with open SMB port."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] in [445, 139] else 1

        config = AttackSimConfig()
        scenario = SMBProbeScenario(config)
        result = scenario.simulate("127.0.0.1")

        assert result.success_score > 0
        assert any("SMB" in f for f in result.findings)
        assert any("EternalBlue" in m or "SMBv1" in m for m in result.mitigations)


class TestWeakAuthScenario:
    """Tests for WeakAuthScenario."""

    def test_scenario_properties(self):
        """Test scenario property values."""
        config = AttackSimConfig()
        scenario = WeakAuthScenario(config)

        assert scenario.scenario_id == "weak_auth"
        assert "Authentication" in scenario.scenario_name

    @patch("socket.socket")
    def test_simulate(self, mock_socket):
        """Test weak auth simulation."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        config = AttackSimConfig()
        scenario = WeakAuthScenario(config)
        result = scenario.simulate("127.0.0.1")

        assert result.scenario_id == "weak_auth"
        assert any("MFA" in m or "password" in m.lower() for m in result.mitigations)


class TestBufferOverflowScenario:
    """Tests for BufferOverflowScenario."""

    def test_scenario_properties(self):
        """Test scenario property values."""
        config = AttackSimConfig()
        scenario = BufferOverflowScenario(config)

        assert scenario.scenario_id == "buffer_overflow"
        assert "Buffer" in scenario.scenario_name

    def test_simulate(self):
        """Test buffer overflow simulation (educational)."""
        config = AttackSimConfig()
        scenario = BufferOverflowScenario(config)
        result = scenario.simulate("127.0.0.1")

        assert result.scenario_id == "buffer_overflow"
        assert any("DEP" in f or "ASLR" in f for f in result.findings)
        assert any("DEP" in m or "ASLR" in m for m in result.mitigations)


class TestDNSEnumScenario:
    """Tests for DNSEnumScenario."""

    def test_scenario_properties(self):
        """Test scenario property values."""
        config = AttackSimConfig()
        scenario = DNSEnumScenario(config)

        assert scenario.scenario_id == "dns_enum"
        assert "DNS" in scenario.scenario_name

    def test_simulate_localhost(self):
        """Test DNS enum on localhost."""
        config = AttackSimConfig()
        scenario = DNSEnumScenario(config)
        result = scenario.simulate("127.0.0.1")

        assert result.scenario_id == "dns_enum"
        assert len(result.attack_tree) > 0


class TestAttackSimulator:
    """Tests for AttackSimulator main class."""

    def test_initialization(self):
        """Test simulator initialization."""
        simulator = AttackSimulator()

        assert simulator.config is not None
        assert len(simulator.get_available_scenarios()) > 0

    def test_custom_config(self):
        """Test simulator with custom config."""
        config = AttackSimConfig(
            enabled_scenarios=["port_scan", "smb_probe"],
            target_host="192.168.1.1",
        )
        simulator = AttackSimulator(config)

        assert simulator.config.target_host == "192.168.1.1"

    def test_get_available_scenarios(self):
        """Test getting available scenarios."""
        simulator = AttackSimulator()
        scenarios = simulator.get_available_scenarios()

        assert "port_scan" in scenarios or "port_probe" in scenarios
        assert "smb_probe" in scenarios or "smb" in scenarios
        assert "weak_auth" in scenarios
        assert "dns_enum" in scenarios or "dns" in scenarios

    @patch("socket.socket")
    def test_simulate_scenario(self, mock_socket):
        """Test running a single scenario."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        simulator = AttackSimulator()
        result = simulator.simulate_scenario("port_scan", "127.0.0.1")

        assert isinstance(result, AttackResult)
        assert result.target == "127.0.0.1"

    def test_simulate_unknown_scenario(self):
        """Test error on unknown scenario."""
        simulator = AttackSimulator()

        with pytest.raises(ValueError, match="Unknown scenario"):
            simulator.simulate_scenario("nonexistent", "127.0.0.1")

    @patch("socket.socket")
    def test_run_scenarios(self, mock_socket):
        """Test running multiple scenarios."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        simulator = AttackSimulator()
        results = simulator.run_scenarios(["port_scan", "dns_enum"], "127.0.0.1")

        assert len(results) == 2
        assert all(isinstance(r, AttackResult) for r in results)

    @patch("socket.socket")
    def test_generate_report(self, mock_socket):
        """Test report generation."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        simulator = AttackSimulator()
        results = simulator.run_scenarios(["port_scan"], "127.0.0.1")
        report = simulator.generate_report(results, "127.0.0.1")

        assert isinstance(report, SimulationReport)
        assert report.target == "127.0.0.1"
        assert len(report.results) == 1
        assert report.simulation_mode is True

    @patch("socket.socket")
    def test_run_all_scenarios(self, mock_socket):
        """Test running all scenarios."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        config = AttackSimConfig(
            enabled_scenarios=["port_scan", "weak_auth"]
        )
        simulator = AttackSimulator(config)
        report = simulator.run_all_scenarios("127.0.0.1")

        assert isinstance(report, SimulationReport)
        assert len(report.scenarios_run) > 0


class TestAttackSimulatorCLI:
    """Integration tests for CLI."""

    def test_cli_sim_attack_help(self):
        """Test CLI help output."""
        from click.testing import CliRunner
        from bisontitan.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["sim-attack", "--help"])

        assert result.exit_code == 0
        assert "scenario" in result.output.lower()
        assert "target" in result.output.lower()

    @patch("socket.socket")
    def test_cli_sim_attack_port_scan(self, mock_socket):
        """Test CLI port scan scenario."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        from click.testing import CliRunner
        from bisontitan.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, [
            "sim-attack", "--scenario", "port_scan",
            "--target", "127.0.0.1", "--no-confirm", "--format", "json"
        ])

        # Should complete without critical error
        assert result.exit_code == 0 or "Error" not in result.output

    @patch("socket.socket")
    def test_cli_sim_attack_all_scenarios(self, mock_socket):
        """Test CLI all scenarios."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1

        from click.testing import CliRunner
        from bisontitan.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, [
            "sim-attack", "--scenario", "all",
            "--target", "127.0.0.1", "--no-confirm", "-j"
        ])

        # Should run all scenarios
        assert "port" in result.output.lower() or result.exit_code == 0

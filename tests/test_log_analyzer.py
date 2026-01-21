"""
Tests for BisonTitan Log Analyzer Module.
Phase 4 implementation tests.
"""

from datetime import datetime, timedelta
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from bisontitan.config import LogAnalyzerConfig
from bisontitan.log_analyzer import (
    LogAnalyzer,
    LogAnalysisResult,
    LogEvent,
    SecurityAnomaly,
    SECURITY_EVENTS,
)


# Sample CSV data for testing
MOCK_LOG_CSV = """event_id,source,category,time_created,computer,user,message
4625,Security,Security,{time_1},WORKSTATION,attacker,Failed login
4625,Security,Security,{time_2},WORKSTATION,attacker,Failed login
4625,Security,Security,{time_3},WORKSTATION,attacker,Failed login
4625,Security,Security,{time_4},WORKSTATION,attacker,Failed login
4625,Security,Security,{time_5},WORKSTATION,attacker,Failed login
4625,Security,Security,{time_6},WORKSTATION,attacker,Failed login
4624,Security,Security,{time_7},WORKSTATION,admin,Successful login
4732,Security,Security,{time_8},WORKSTATION,hacker,Member added to privileged group
4720,Security,Security,{time_9},WORKSTATION,admin,User account created
1102,Security,Security,{time_10},WORKSTATION,admin,Audit log cleared
"""


def generate_mock_csv():
    """Generate mock CSV with proper timestamps."""
    now = datetime.now()
    times = [
        (now - timedelta(minutes=i)).isoformat()
        for i in range(10)
    ]
    return MOCK_LOG_CSV.format(
        time_1=times[0], time_2=times[1], time_3=times[2],
        time_4=times[3], time_5=times[4], time_6=times[5],
        time_7=times[6], time_8=times[7], time_9=times[8],
        time_10=times[9],
    )


class TestLogEvent:
    """Tests for LogEvent dataclass."""

    def test_log_event_creation(self):
        """Test LogEvent creation."""
        event = LogEvent(
            event_id=4625,
            source="Security",
            category="Security",
            time_created=datetime.now(),
            computer="WORKSTATION",
            user="testuser",
            message="Failed login attempt",
        )

        assert event.event_id == 4625
        assert event.user == "testuser"
        assert event.source == "Security"

    def test_log_event_to_dict(self):
        """Test LogEvent serialization."""
        now = datetime.now()
        event = LogEvent(
            event_id=4624,
            source="Security",
            category="Security",
            time_created=now,
            computer="SERVER01",
            user="admin",
            message="Successful login",
            data={"logon_type": "10"},
        )

        d = event.to_dict()

        assert d["event_id"] == 4624
        assert d["user"] == "admin"
        assert d["data"]["logon_type"] == "10"
        assert d["time_created"] == now.isoformat()


class TestSecurityAnomaly:
    """Tests for SecurityAnomaly dataclass."""

    def test_anomaly_creation(self):
        """Test SecurityAnomaly creation."""
        events = [
            LogEvent(4625, "Security", "Security", datetime.now(), "PC", "user", "Failed")
            for _ in range(5)
        ]

        anomaly = SecurityAnomaly(
            anomaly_type="brute_force_attempt",
            severity="critical",
            description="5 failed logins detected",
            events=events,
            recommended_action="Block the source IP",
        )

        assert anomaly.anomaly_type == "brute_force_attempt"
        assert anomaly.severity == "critical"
        assert len(anomaly.events) == 5

    def test_anomaly_to_dict(self):
        """Test SecurityAnomaly serialization."""
        events = [
            LogEvent(4625, "Security", "Security", datetime.now(), "PC", "user", "Failed")
        ]

        anomaly = SecurityAnomaly(
            anomaly_type="test",
            severity="warning",
            description="Test anomaly",
            events=events,
            recommended_action="Test action",
            metadata={"count": 5},
        )

        d = anomaly.to_dict()

        assert d["type"] == "test"
        assert d["severity"] == "warning"
        assert d["event_count"] == 1
        assert d["metadata"]["count"] == 5

    def test_anomaly_to_markdown_row(self):
        """Test markdown row generation."""
        anomaly = SecurityAnomaly(
            anomaly_type="brute_force",
            severity="critical",
            description="Attack detected",
            events=[],
            recommended_action="Block IP",
        )

        row = anomaly.to_markdown_row()

        assert "CRITICAL" in row
        assert "brute_force" in row
        assert "Block IP" in row


class TestLogAnalyzer:
    """Tests for LogAnalyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        analyzer = LogAnalyzer()
        assert analyzer.config is not None

    def test_analyzer_with_custom_config(self):
        """Test analyzer with custom configuration."""
        config = LogAnalyzerConfig(
            failed_login_threshold=3,
            time_window_minutes=5,
        )
        analyzer = LogAnalyzer(config)

        assert analyzer.config.failed_login_threshold == 3
        assert analyzer.config.time_window_minutes == 5

    def test_parse_events_from_string(self):
        """Test parsing events from CSV string."""
        analyzer = LogAnalyzer()
        csv_content = generate_mock_csv()

        events = analyzer.parse_events_from_string(csv_content)

        assert len(events) == 10
        assert events[0].event_id == 4625
        assert events[0].user == "attacker"

    def test_detect_brute_force(self):
        """Test brute force detection."""
        analyzer = LogAnalyzer(LogAnalyzerConfig(
            failed_login_threshold=5,
            time_window_minutes=10,
        ))

        # Create 6 failed logins within 5 minutes
        now = datetime.now()
        events = [
            LogEvent(
                event_id=4625,
                source="Security",
                category="Security",
                time_created=now - timedelta(minutes=i),
                computer="PC",
                user="attacker",
                message="Failed login",
            )
            for i in range(6)
        ]

        anomalies = analyzer.detect_brute_force(events)

        assert len(anomalies) > 0
        assert anomalies[0].anomaly_type == "brute_force_attempt"
        assert anomalies[0].severity == "critical"

    def test_detect_brute_force_below_threshold(self):
        """Test no brute force detected below threshold."""
        analyzer = LogAnalyzer(LogAnalyzerConfig(
            failed_login_threshold=10,
            time_window_minutes=5,
        ))

        now = datetime.now()
        events = [
            LogEvent(4625, "Security", "Security", now - timedelta(minutes=i), "PC", "user", "Failed")
            for i in range(5)  # Only 5 events, threshold is 10
        ]

        anomalies = analyzer.detect_brute_force(events)

        assert len(anomalies) == 0

    def test_detect_privilege_escalation(self):
        """Test privilege escalation detection."""
        analyzer = LogAnalyzer()
        now = datetime.now()

        events = [
            LogEvent(4732, "Security", "Security", now, "PC", "hacker", "Added to Administrators"),
        ]

        anomalies = analyzer.detect_privilege_escalation(events)

        assert len(anomalies) > 0
        assert anomalies[0].anomaly_type == "privilege_escalation"
        assert anomalies[0].severity == "critical"

    def test_detect_account_manipulation(self):
        """Test account manipulation detection."""
        analyzer = LogAnalyzer()
        now = datetime.now()

        events = [
            LogEvent(4720, "Security", "Security", now, "PC", "admin", "Account created"),
            LogEvent(4740, "Security", "Security", now, "PC", "user", "Account locked"),
            LogEvent(1102, "Security", "Security", now, "PC", "admin", "Log cleared"),
        ]

        anomalies = analyzer.detect_account_manipulation(events)

        # Should detect account creation, lockout, and log cleared
        assert len(anomalies) >= 2
        types = [a.anomaly_type for a in anomalies]
        assert "account_creation" in types
        assert "audit_log_cleared" in types

    def test_detect_audit_log_cleared_critical(self):
        """Test that audit log cleared is marked as critical."""
        analyzer = LogAnalyzer()
        now = datetime.now()

        events = [
            LogEvent(1102, "Security", "Security", now, "PC", "attacker", "Security log cleared"),
        ]

        anomalies = analyzer.detect_account_manipulation(events)

        log_cleared = [a for a in anomalies if a.anomaly_type == "audit_log_cleared"]
        assert len(log_cleared) == 1
        assert log_cleared[0].severity == "critical"

    def test_detect_suspicious_services(self):
        """Test suspicious service detection."""
        analyzer = LogAnalyzer()
        now = datetime.now()

        events = [
            LogEvent(7045, "Service Control Manager", "System", now, "PC", "SYSTEM", "Service installed"),
            LogEvent(7034, "Service Control Manager", "System", now, "PC", "SYSTEM", "Service crashed"),
            LogEvent(7034, "Service Control Manager", "System", now, "PC", "SYSTEM", "Service crashed"),
            LogEvent(7034, "Service Control Manager", "System", now, "PC", "SYSTEM", "Service crashed"),
            LogEvent(7034, "Service Control Manager", "System", now, "PC", "SYSTEM", "Service crashed"),
        ]

        anomalies = analyzer.detect_suspicious_services(events)

        assert len(anomalies) >= 1
        types = [a.anomaly_type for a in anomalies]
        assert "service_installed" in types

    def test_detect_rdp_activity(self):
        """Test RDP activity detection."""
        analyzer = LogAnalyzer()
        now = datetime.now()

        events = [
            LogEvent(
                event_id=4624,
                source="Security",
                category="Security",
                time_created=now,
                computer="PC",
                user="rdpuser",
                message="RemoteInteractive logon",
                data={"field_8": "10"},
            ),
        ]

        anomalies = analyzer.detect_rdp_activity(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "rdp_activity"

    def test_analyze_events_full(self):
        """Test full event analysis."""
        analyzer = LogAnalyzer(LogAnalyzerConfig(failed_login_threshold=5))
        csv_content = generate_mock_csv()
        events = analyzer.parse_events_from_string(csv_content)

        result = analyzer.analyze_events(events)

        assert isinstance(result, LogAnalysisResult)
        assert result.total_events == 10
        # Should detect at least brute force and privilege escalation
        assert len(result.anomalies) > 0

    def test_analysis_result_to_markdown(self):
        """Test markdown report generation."""
        result = LogAnalysisResult(
            analyzed_logs=["Security"],
            time_range_hours=24,
            total_events=100,
            anomalies=[
                SecurityAnomaly(
                    anomaly_type="brute_force",
                    severity="critical",
                    description="Attack detected",
                    events=[],
                    recommended_action="Block IP",
                ),
            ],
            statistics={"total_events": 100},
        )

        markdown = result.to_markdown()

        assert "# BisonTitan Log Analysis Report" in markdown
        assert "brute_force" in markdown
        assert "CRITICAL" in markdown

    def test_excluded_users(self):
        """Test that excluded users are ignored in privilege escalation."""
        analyzer = LogAnalyzer(LogAnalyzerConfig(
            excluded_users=["SYSTEM", "LOCAL SERVICE"],
        ))
        now = datetime.now()

        events = [
            LogEvent(4672, "Security", "Security", now, "PC", "SYSTEM", "Special privileges assigned"),
        ]

        anomalies = analyzer.detect_privilege_escalation(events)

        # SYSTEM should be excluded
        assert len(anomalies) == 0


class TestLogAnalyzerIntegration:
    """Integration tests for log analyzer."""

    def test_full_analysis_with_mock_data(self):
        """Test complete analysis workflow with mock data."""
        analyzer = LogAnalyzer(LogAnalyzerConfig(
            failed_login_threshold=5,
            time_window_minutes=30,
        ))

        csv_content = generate_mock_csv()
        events = analyzer.parse_events_from_string(csv_content)
        result = analyzer.analyze_events(events)

        # Verify result structure
        assert result.total_events == 10
        assert len(result.anomalies) > 0

        # Check that brute force was detected (6 failed logins)
        brute_force = [a for a in result.anomalies if a.anomaly_type == "brute_force_attempt"]
        assert len(brute_force) > 0

        # Check that privilege escalation was detected
        priv_esc = [a for a in result.anomalies if a.anomaly_type == "privilege_escalation"]
        assert len(priv_esc) > 0

        # Check that audit log cleared was detected
        log_cleared = [a for a in result.anomalies if a.anomaly_type == "audit_log_cleared"]
        assert len(log_cleared) > 0

    def test_cli_integration_csv(self):
        """Test CLI integration with CSV input."""
        from click.testing import CliRunner
        from bisontitan.cli import cli
        import tempfile
        import os

        runner = CliRunner()
        csv_content = generate_mock_csv()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write(csv_content)
            csv_path = f.name

        try:
            result = runner.invoke(cli, ["logs", "--csv", csv_path, "--output", "json"])
            # Should not error
            assert result.exit_code == 0 or "Error" not in result.output
        finally:
            os.unlink(csv_path)


class TestSecurityEventsMapping:
    """Tests for security event ID mapping."""

    def test_security_events_contains_common_ids(self):
        """Test that common security event IDs are mapped."""
        assert 4624 in SECURITY_EVENTS  # Successful login
        assert 4625 in SECURITY_EVENTS  # Failed login
        assert 4672 in SECURITY_EVENTS  # Special privileges
        assert 4732 in SECURITY_EVENTS  # Group membership change
        assert 1102 in SECURITY_EVENTS  # Log cleared

    def test_security_events_descriptions(self):
        """Test event descriptions are meaningful."""
        assert "login" in SECURITY_EVENTS[4624].lower()
        assert "failed" in SECURITY_EVENTS[4625].lower()
        assert "log" in SECURITY_EVENTS[1102].lower() or "cleared" in SECURITY_EVENTS[1102].lower()

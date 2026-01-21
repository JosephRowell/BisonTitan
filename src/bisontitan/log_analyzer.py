"""
BisonTitan Log Analyzer Module
Windows event log analysis for security threats with REAL threat intelligence.

Phase 4+ implementation - Uses pywin32 for Windows Event Viewer,
pandas for anomaly detection, and threat intel APIs for:
- MITRE ATT&CK technique mapping
- IP reputation checking via AbuseIPDB
- Real-time correlation with known threat patterns
"""

import csv
import io
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Generator

from bisontitan.config import LogAnalyzerConfig
from bisontitan.utils import get_platform

# Import threat intelligence for IP reputation
try:
    from bisontitan.threat_intel import ThreatIntelligence, IPReputation
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False


logger = logging.getLogger("bisontitan.logs")


# Windows Security Event IDs
SECURITY_EVENTS = {
    # Login events
    4624: "Successful login",
    4625: "Failed login attempt",
    4634: "Logoff",
    4647: "User initiated logoff",
    4648: "Explicit credential logon",
    4672: "Special privileges assigned",
    4776: "Credential validation",

    # Account management
    4720: "User account created",
    4722: "User account enabled",
    4723: "Password change attempt",
    4724: "Password reset attempt",
    4725: "User account disabled",
    4726: "User account deleted",
    4738: "User account changed",
    4740: "User account locked out",

    # Privilege escalation
    4728: "Member added to security-enabled global group",
    4732: "Member added to security-enabled local group",
    4756: "Member added to security-enabled universal group",
    4735: "Security-enabled local group changed",

    # Process/Service
    4688: "New process created",
    4689: "Process exited",
    7034: "Service crashed unexpectedly",
    7036: "Service started or stopped",
    7045: "Service installed",

    # System
    1102: "Audit log cleared",
    4616: "System time changed",
    4697: "Service installed in the system",
}

# Logon Types
LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}

# MITRE ATT&CK Technique Mapping for Windows Events
# Maps event IDs to ATT&CK techniques for threat contextualization
MITRE_ATTACK_MAP = {
    # Initial Access
    4624: {"techniques": ["T1078"], "tactic": "Initial Access", "name": "Valid Accounts"},
    4625: {"techniques": ["T1110"], "tactic": "Credential Access", "name": "Brute Force"},

    # Persistence
    4720: {"techniques": ["T1136.001"], "tactic": "Persistence", "name": "Create Account: Local Account"},
    7045: {"techniques": ["T1543.003"], "tactic": "Persistence", "name": "Create/Modify System Process: Windows Service"},
    4697: {"techniques": ["T1543.003"], "tactic": "Persistence", "name": "Create/Modify System Process: Windows Service"},

    # Privilege Escalation
    4672: {"techniques": ["T1134"], "tactic": "Privilege Escalation", "name": "Access Token Manipulation"},
    4728: {"techniques": ["T1098"], "tactic": "Persistence", "name": "Account Manipulation"},
    4732: {"techniques": ["T1098"], "tactic": "Persistence", "name": "Account Manipulation"},
    4756: {"techniques": ["T1098"], "tactic": "Persistence", "name": "Account Manipulation"},

    # Defense Evasion
    1102: {"techniques": ["T1070.001"], "tactic": "Defense Evasion", "name": "Indicator Removal: Clear Windows Event Logs"},
    4616: {"techniques": ["T1070.006"], "tactic": "Defense Evasion", "name": "Indicator Removal: Timestomp"},

    # Credential Access
    4648: {"techniques": ["T1550.002"], "tactic": "Credential Access", "name": "Use Alternate Authentication Material: Pass the Hash"},
    4776: {"techniques": ["T1110"], "tactic": "Credential Access", "name": "Brute Force"},

    # Lateral Movement
    # Event 4624 with logon type 3 or 10
}


@dataclass
class LogEvent:
    """Represents a Windows event log entry."""
    event_id: int
    source: str
    category: str
    time_created: datetime
    computer: str
    user: str | None
    message: str
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "source": self.source,
            "category": self.category,
            "time_created": self.time_created.isoformat(),
            "computer": self.computer,
            "user": self.user,
            "message": self.message,
            "data": self.data,
        }


@dataclass
class SecurityAnomaly:
    """Detected security anomaly in logs with threat intelligence enrichment."""
    anomaly_type: str
    severity: str  # "info", "warning", "critical"
    description: str
    events: list[LogEvent]
    recommended_action: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs
    mitre_tactic: str = ""  # ATT&CK tactic
    ip_reputation: dict | None = None  # IP reputation data from AbuseIPDB

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "event_count": len(self.events),
            "recommended_action": self.recommended_action,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactic": self.mitre_tactic,
            "ip_reputation": self.ip_reputation,
            "events": [e.to_dict() for e in self.events[:10]],
        }

    def to_markdown_row(self) -> str:
        """Convert to markdown table row."""
        severity_emoji = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}.get(self.severity, "")
        mitre = f" [{', '.join(self.mitre_techniques)}]" if self.mitre_techniques else ""
        return f"| {severity_emoji} {self.severity.upper()} | {self.anomaly_type}{mitre} | {self.description} | {self.recommended_action} |"


@dataclass
class LogAnalysisResult:
    """Complete log analysis result."""
    analyzed_logs: list[str]
    time_range_hours: int
    total_events: int
    anomalies: list[SecurityAnomaly]
    statistics: dict[str, Any]
    analyzed_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "analyzed_logs": self.analyzed_logs,
            "time_range_hours": self.time_range_hours,
            "total_events": self.total_events,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "statistics": self.statistics,
            "analyzed_at": self.analyzed_at.isoformat(),
        }

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            "# BisonTitan Log Analysis Report",
            "",
            f"**Generated:** {self.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Time Range:** Last {self.time_range_hours} hours",
            f"**Logs Analyzed:** {', '.join(self.analyzed_logs)}",
            f"**Total Events:** {self.total_events:,}",
            "",
            "## Summary",
            "",
            f"- **Critical Anomalies:** {sum(1 for a in self.anomalies if a.severity == 'critical')}",
            f"- **Warnings:** {sum(1 for a in self.anomalies if a.severity == 'warning')}",
            f"- **Informational:** {sum(1 for a in self.anomalies if a.severity == 'info')}",
            "",
        ]

        if self.anomalies:
            lines.extend([
                "## Detected Anomalies",
                "",
                "| Severity | Type | Description | Recommended Action |",
                "|----------|------|-------------|-------------------|",
            ])
            for anomaly in sorted(self.anomalies, key=lambda a: {"critical": 0, "warning": 1, "info": 2}.get(a.severity, 3)):
                lines.append(anomaly.to_markdown_row())
            lines.append("")

            # MITRE ATT&CK Summary
            mitre_techniques = set()
            mitre_tactics = set()
            for anomaly in self.anomalies:
                mitre_techniques.update(anomaly.mitre_techniques)
                if anomaly.mitre_tactic:
                    mitre_tactics.add(anomaly.mitre_tactic)

            if mitre_techniques:
                lines.extend([
                    "## MITRE ATT&CK Coverage",
                    "",
                    f"**Tactics Observed:** {', '.join(sorted(mitre_tactics))}",
                    "",
                    f"**Techniques Detected:** {', '.join(sorted(mitre_techniques))}",
                    "",
                    "Reference: https://attack.mitre.org/",
                    "",
                ])

            # IP Reputation Summary (if any malicious IPs detected)
            malicious_ips = []
            for anomaly in self.anomalies:
                if anomaly.ip_reputation and anomaly.ip_reputation.get("is_malicious"):
                    malicious_ips.append({
                        "ip": anomaly.ip_reputation.get("ip"),
                        "confidence": anomaly.ip_reputation.get("abuse_confidence"),
                        "country": anomaly.ip_reputation.get("country"),
                    })

            if malicious_ips:
                lines.extend([
                    "## Malicious IPs Detected (via AbuseIPDB)",
                    "",
                    "| IP Address | Abuse Confidence | Country |",
                    "|------------|------------------|---------|",
                ])
                for ip_info in malicious_ips:
                    lines.append(f"| {ip_info['ip']} | {ip_info['confidence']}% | {ip_info['country'] or 'Unknown'} |")
                lines.append("")

        # Statistics section
        if self.statistics:
            lines.extend([
                "## Statistics",
                "",
            ])
            for key, value in self.statistics.items():
                if isinstance(value, dict):
                    lines.append(f"### {key.replace('_', ' ').title()}")
                    for k, v in list(value.items())[:10]:
                        lines.append(f"- {k}: {v}")
                else:
                    lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
            lines.append("")

        return "\n".join(lines)


@dataclass
class ServiceInstallDetail:
    """
    Detailed service installation information for verbose log analysis.
    Sprint 5 - Provides actionable service install details.
    """
    service_name: str
    display_name: str
    binary_path: str
    install_time: datetime
    installing_user: str | None
    installing_sid: str | None
    startup_type: str  # auto, manual, disabled, boot, system
    service_type: str  # kernel_driver, file_system_driver, win32_own, win32_share
    is_signed: bool | None  # None if unknown
    signature_publisher: str | None
    file_hash: str | None  # SHA256
    risk_level: str  # low, medium, high, critical
    risk_reasons: list[str] = field(default_factory=list)
    is_whitelisted: bool = False
    whitelist_category: str | None = None
    mitre_technique: str = "T1543.003"
    mitre_tactic: str = "Persistence"
    correlated_events: list[dict] = field(default_factory=list)  # Related logins/processes

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON/database storage."""
        return {
            "service_name": self.service_name,
            "display_name": self.display_name,
            "binary_path": self.binary_path,
            "install_time": self.install_time.isoformat(),
            "installing_user": self.installing_user,
            "installing_sid": self.installing_sid,
            "startup_type": self.startup_type,
            "service_type": self.service_type,
            "is_signed": self.is_signed,
            "signature_publisher": self.signature_publisher,
            "file_hash": self.file_hash,
            "risk_level": self.risk_level,
            "risk_reasons": self.risk_reasons,
            "is_whitelisted": self.is_whitelisted,
            "whitelist_category": self.whitelist_category,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "correlated_events": self.correlated_events,
        }

    def to_table_row(self) -> dict[str, str]:
        """Convert to GUI table row format."""
        risk_emoji = {
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴",
        }.get(self.risk_level, "⚪")

        signed_status = "✅ Signed" if self.is_signed else ("❌ Unsigned" if self.is_signed is False else "❓ Unknown")
        whitelisted = "✅" if self.is_whitelisted else ""

        return {
            "Risk": f"{risk_emoji} {self.risk_level.upper()}",
            "Service Name": self.service_name,
            "Display Name": self.display_name,
            "Binary Path": self.binary_path[:60] + "..." if len(self.binary_path) > 60 else self.binary_path,
            "Install Time": self.install_time.strftime("%Y-%m-%d %H:%M:%S"),
            "User": self.installing_user or "SYSTEM",
            "Startup": self.startup_type,
            "Signed": signed_status,
            "Publisher": self.signature_publisher or "-",
            "Whitelisted": whitelisted,
            "MITRE": self.mitre_technique,
        }

    def get_mitre_url(self) -> str:
        """Get MITRE ATT&CK URL for this technique."""
        return f"https://attack.mitre.org/techniques/{self.mitre_technique.replace('.', '/')}/"

    def get_recommended_action(self) -> str:
        """Get recommended action based on risk level."""
        if self.is_whitelisted:
            return "No action needed - known legitimate service"

        actions = {
            "low": "Monitor - appears legitimate but verify if expected",
            "medium": "Investigate - verify service purpose and installation source",
            "high": "URGENT: Verify immediately - unsigned binary or suspicious location",
            "critical": "CRITICAL: Isolate system - potential malware persistence mechanism",
        }
        return actions.get(self.risk_level, "Investigate service installation")


# Service startup type mappings (from event data)
SERVICE_START_TYPES = {
    "0": "boot",
    "1": "system",
    "2": "auto",
    "3": "manual",
    "4": "disabled",
    "boot": "boot",
    "system": "system",
    "auto start": "auto",
    "auto": "auto",
    "demand start": "manual",
    "manual": "manual",
    "disabled": "disabled",
}

# Service type mappings
SERVICE_TYPES = {
    "1": "kernel_driver",
    "2": "file_system_driver",
    "16": "win32_own_process",
    "32": "win32_share_process",
    "kernel driver": "kernel_driver",
    "file system driver": "file_system_driver",
    "user mode service": "win32_own_process",
}


# =============================================================================
# Sprint 7: Logon Event Verbosity
# =============================================================================

# Extended logon type classification
LOGON_TYPE_CLASSIFICATION = {
    2: {"name": "Interactive", "is_remote": False, "risk": "low", "description": "Local console login"},
    3: {"name": "Network", "is_remote": True, "risk": "medium", "description": "Network share/service access"},
    4: {"name": "Batch", "is_remote": False, "risk": "low", "description": "Scheduled task execution"},
    5: {"name": "Service", "is_remote": False, "risk": "low", "description": "Service startup"},
    7: {"name": "Unlock", "is_remote": False, "risk": "low", "description": "Workstation unlock"},
    8: {"name": "NetworkCleartext", "is_remote": True, "risk": "high", "description": "Network login with cleartext password"},
    9: {"name": "NewCredentials", "is_remote": False, "risk": "medium", "description": "RunAs with different credentials"},
    10: {"name": "RemoteInteractive", "is_remote": True, "risk": "high", "description": "RDP/Terminal Services login"},
    11: {"name": "CachedInteractive", "is_remote": False, "risk": "low", "description": "Cached domain credentials"},
    12: {"name": "CachedRemoteInteractive", "is_remote": True, "risk": "medium", "description": "Cached RDP credentials"},
    13: {"name": "CachedUnlock", "is_remote": False, "risk": "low", "description": "Cached unlock"},
}

# MITRE T1078 sub-techniques for different logon scenarios
LOGON_MITRE_MAPPING = {
    "remote_rdp": {"technique": "T1078.001", "name": "Valid Accounts: Default Accounts", "tactic": "Initial Access"},
    "remote_network": {"technique": "T1078.002", "name": "Valid Accounts: Domain Accounts", "tactic": "Lateral Movement"},
    "local_interactive": {"technique": "T1078.003", "name": "Valid Accounts: Local Accounts", "tactic": "Initial Access"},
    "failed_brute": {"technique": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "failed_spray": {"technique": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
}


@dataclass
class LogonEventDetail:
    """
    Detailed logon event information for verbose log analysis.
    Sprint 7 - Provides actionable logon event details with local/remote differentiation.
    """
    event_id: int  # 4624 (success) or 4625 (failure)
    event_time: datetime
    username: str
    domain: str | None
    logon_type: int
    logon_type_name: str
    is_remote: bool
    is_success: bool
    source_ip: str | None
    source_hostname: str | None
    target_hostname: str | None
    logon_process: str | None
    auth_package: str | None
    elevated_token: bool
    risk_level: str  # low, medium, high, critical
    risk_reasons: list[str] = field(default_factory=list)
    mitre_technique: str = "T1078"
    mitre_tactic: str = "Initial Access"
    correlated_services: list[dict] = field(default_factory=list)  # Services installed after login
    failure_reason: str | None = None  # For 4625 events

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON/database storage."""
        return {
            "event_id": self.event_id,
            "event_time": self.event_time.isoformat(),
            "username": self.username,
            "domain": self.domain,
            "logon_type": self.logon_type,
            "logon_type_name": self.logon_type_name,
            "is_remote": self.is_remote,
            "is_success": self.is_success,
            "source_ip": self.source_ip,
            "source_hostname": self.source_hostname,
            "target_hostname": self.target_hostname,
            "logon_process": self.logon_process,
            "auth_package": self.auth_package,
            "elevated_token": self.elevated_token,
            "risk_level": self.risk_level,
            "risk_reasons": self.risk_reasons,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "correlated_services": self.correlated_services,
            "failure_reason": self.failure_reason,
        }

    def to_table_row(self) -> dict[str, str]:
        """Convert to GUI table row format."""
        risk_emoji = {
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴",
        }.get(self.risk_level, "⚪")

        status = "✅ Success" if self.is_success else "❌ Failed"
        remote_badge = "🌐 REMOTE" if self.is_remote else "🏠 LOCAL"
        elevated = "👑" if self.elevated_token else ""

        return {
            "Risk": f"{risk_emoji} {self.risk_level.upper()}",
            "Time": self.event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Status": status,
            "Location": remote_badge,
            "User": f"{self.domain}\\{self.username}" if self.domain else self.username,
            "Logon Type": self.logon_type_name,
            "Source IP": self.source_ip or "-",
            "Elevated": elevated,
            "MITRE": self.mitre_technique,
        }

    def get_mitre_url(self) -> str:
        """Get MITRE ATT&CK URL for this technique."""
        return f"https://attack.mitre.org/techniques/{self.mitre_technique.replace('.', '/')}/"

    def get_recommended_action(self) -> str:
        """Get recommended action based on risk level and event type."""
        if not self.is_success:
            if self.risk_level == "critical":
                return "CRITICAL: Multiple failed logins - potential brute force attack. Block source IP."
            return "Monitor for additional failed attempts from this source."

        if self.is_remote and self.risk_level in ["high", "critical"]:
            return "URGENT: Verify this remote access was authorized. Check for lateral movement."

        actions = {
            "low": "Normal activity - no action required",
            "medium": "Review if this access pattern is expected",
            "high": "Investigate source and verify authorization",
            "critical": "IMMEDIATE: Verify legitimacy, check for compromise indicators",
        }
        return actions.get(self.risk_level, "Review logon event")


# Windows logon failure status codes
LOGON_FAILURE_CODES = {
    "0xC0000064": "User does not exist",
    "0xC000006A": "Incorrect password",
    "0xC000006D": "Bad username or authentication info",
    "0xC000006E": "Account restriction",
    "0xC000006F": "Logon outside allowed hours",
    "0xC0000070": "Logon from unauthorized workstation",
    "0xC0000071": "Password expired",
    "0xC0000072": "Account disabled",
    "0xC00000DC": "Server unavailable",
    "0xC0000133": "Clocks out of sync",
    "0xC000015B": "Logon type not granted",
    "0xC000018C": "Trust relationship failure",
    "0xC0000192": "NetLogon service not started",
    "0xC0000193": "Account expired",
    "0xC0000224": "Password must change at next logon",
    "0xC0000234": "Account locked out",
    "0xC00002EE": "Account issue occurred",
    "0xC0000413": "Authentication firewall blocked",
}


class LogAnalyzer:
    """
    Analyzes Windows event logs for security threats.

    Uses pywin32 to read event logs and pandas for
    pattern detection and anomaly analysis.
    """

    def __init__(self, config: LogAnalyzerConfig | None = None):
        """
        Initialize log analyzer.

        Args:
            config: Log analyzer configuration
        """
        self.config = config or LogAnalyzerConfig()
        self._pywin32_available = False
        self._pandas_available = False

        if get_platform() == "windows":
            try:
                import win32evtlog
                import win32evtlogutil
                import win32con
                self._pywin32_available = True
            except ImportError:
                logger.warning("pywin32 not available. Install with: pip install pywin32")

        try:
            import pandas as pd
            self._pandas_available = True
        except ImportError:
            logger.warning("pandas not available. Install with: pip install pandas")

        # Initialize threat intelligence for IP reputation
        self._threat_intel = None
        if THREAT_INTEL_AVAILABLE:
            try:
                self._threat_intel = ThreatIntelligence()
                logger.info("Threat intelligence enabled for IP reputation checks")
            except Exception as e:
                logger.warning(f"Threat intelligence unavailable: {e}")

        # Load service whitelist for Sprint 5 verbose logs
        self._service_whitelist = self._load_service_whitelist()

        # Sprint 8 - Load baseline for noise filtering
        self._baseline = self._load_baseline()
        self._baseline_enabled = True  # Default to enabled
        self._baseline_stats = {"total_events": 0, "suppressed": 0, "flagged": 0}

    def _load_baseline(self) -> dict:
        """
        Load baseline configuration from YAML.
        Sprint 8 - Advanced noise filtering.

        Returns:
            Baseline configuration dict
        """
        baseline = {
            "benign_events": [],
            "benign_users": {"system_accounts": [], "machine_account_pattern": "", "service_account_patterns": []},
            "benign_sources": {"localhost": [], "private_ranges": []},
            "event_filters": {},
            "noise_thresholds": {},
            "ai_suggested_rules": {"enabled": False, "suggestions": []},
            "quick_filters": {},
            "version": "1.0",
        }

        # Try multiple paths
        baseline_paths = [
            Path(__file__).parent.parent.parent / "config" / "baseline.yaml",
            Path("config/baseline.yaml"),
            Path("baseline.yaml"),
        ]

        for path in baseline_paths:
            if path.exists():
                try:
                    import yaml
                    with open(path, "r", encoding="utf-8") as f:
                        loaded = yaml.safe_load(f)
                        if loaded:
                            baseline.update(loaded)
                    logger.info(f"Loaded baseline from {path}")
                    break
                except Exception as e:
                    logger.warning(f"Failed to load baseline from {path}: {e}")

        return baseline

    def set_baseline_enabled(self, enabled: bool) -> None:
        """Enable or disable baseline filtering."""
        self._baseline_enabled = enabled
        logger.info(f"Baseline filtering {'enabled' if enabled else 'disabled'}")

    def get_baseline_stats(self) -> dict:
        """Get baseline filtering statistics."""
        if self._baseline_stats["total_events"] > 0:
            suppression_rate = self._baseline_stats["suppressed"] / self._baseline_stats["total_events"]
        else:
            suppression_rate = 0.0

        return {
            **self._baseline_stats,
            "suppression_rate": suppression_rate,
            "baseline_enabled": self._baseline_enabled,
            "baseline_version": self._baseline.get("version", "unknown"),
        }

    def _is_benign_user(self, username: str) -> bool:
        """
        Check if username is a benign system/service account.
        Sprint 8 - Noise filtering.

        Args:
            username: Username to check

        Returns:
            True if user is benign (should be suppressed)
        """
        if not username:
            return False

        username_upper = username.upper()
        benign_users = self._baseline.get("benign_users", {})

        # Check system accounts
        system_accounts = benign_users.get("system_accounts", [])
        if username_upper in [a.upper() for a in system_accounts]:
            return True

        # Check machine account pattern (ends with $)
        machine_pattern = benign_users.get("machine_account_pattern", "")
        if machine_pattern:
            import re
            if re.match(machine_pattern, username):
                return True

        # Check service account patterns
        service_patterns = benign_users.get("service_account_patterns", [])
        import re
        for pattern in service_patterns:
            try:
                if re.match(pattern, username, re.IGNORECASE):
                    return True
            except re.error:
                pass

        return False

    def _is_benign_source(self, source_ip: str | None) -> bool:
        """
        Check if source IP is from a benign source.
        Sprint 8 - Noise filtering.

        Args:
            source_ip: Source IP address

        Returns:
            True if source is benign
        """
        if not source_ip:
            return True  # No source IP means local

        benign_sources = self._baseline.get("benign_sources", {})

        # Check localhost
        localhost = benign_sources.get("localhost", [])
        if source_ip in localhost:
            return True

        # Check private ranges (simplified check)
        private_ranges = benign_sources.get("private_ranges", {})
        if isinstance(private_ranges, dict):
            ranges = private_ranges.get("ranges", [])
        elif isinstance(private_ranges, list):
            ranges = private_ranges
        else:
            ranges = []

        for cidr in ranges:
            if isinstance(cidr, str):
                # Simplified check for common private ranges
                if "10.0.0.0" in cidr and source_ip.startswith("10."):
                    return True
                if "172.16.0.0" in cidr and source_ip.startswith("172."):
                    return True
                if "192.168.0.0" in cidr and source_ip.startswith("192.168."):
                    return True

        return False

    def _should_suppress_event(self, event: "LogEvent") -> tuple[bool, str]:
        """
        Check if event should be suppressed based on baseline rules.
        Sprint 8 - Advanced noise filtering.

        Args:
            event: Event to check

        Returns:
            Tuple of (should_suppress, reason)
        """
        if not self._baseline_enabled:
            return False, ""

        # Check benign events list
        benign_events = self._baseline.get("benign_events", [])
        for rule in benign_events:
            if rule.get("event_id") == event.event_id:
                if rule.get("suppress", False):
                    return True, f"Benign event: {rule.get('description', 'whitelisted')}"

                # Check conditional suppression
                suppress_if = rule.get("suppress_if", {})
                if suppress_if:
                    user_pattern = suppress_if.get("user_pattern", "")
                    if user_pattern and event.user:
                        import re
                        if re.match(user_pattern, event.user, re.IGNORECASE):
                            return True, f"Benign event with matching user: {event.user}"

        # Check benign users
        if event.user and self._is_benign_user(event.user):
            # Don't suppress all events from system users, just routine ones
            routine_events = [4634, 4647, 7036]  # Logoff, service state
            if event.event_id in routine_events:
                return True, f"Routine event from system account: {event.user}"

        # Check event-specific filters
        event_filters = self._baseline.get("event_filters", {})

        # Login filters
        if event.event_id == 4624:
            login_filters = event_filters.get("login_filters", [])
            for rule in login_filters:
                if rule.get("event_id") != 4624:
                    continue

                # Check logon type filter
                logon_types = rule.get("logon_types", [])
                if logon_types:
                    logon_type = event.data.get("field_8", "")
                    try:
                        if int(logon_type) in logon_types:
                            if rule.get("action") == "suppress":
                                return True, f"Filtered logon type: {logon_type}"
                    except (ValueError, TypeError):
                        pass

        # Failed login filters
        if event.event_id == 4625:
            failed_filters = event_filters.get("failed_login_filters", [])
            for rule in failed_filters:
                if rule.get("threshold", 1) > 1:
                    continue  # Threshold rules handled elsewhere
                if rule.get("action") == "suppress":
                    return True, "Single failed login suppressed"

        # Service filters
        if event.event_id in [7045, 4697]:
            service_filters = event_filters.get("service_filters", [])
            for rule in service_filters:
                if event.event_id not in rule.get("event_ids", [rule.get("event_id")]):
                    continue

                # Check publisher pattern
                publisher_pattern = rule.get("publisher_pattern", "")
                if publisher_pattern:
                    # Would need to extract publisher from event data
                    pass

                if rule.get("action") == "suppress" and rule.get("signed", False):
                    # Check if service is signed (from data)
                    pass

        return False, ""

    def filter_with_baseline(
        self,
        events: list["LogEvent"],
        quick_filter: str | None = None,
    ) -> tuple[list["LogEvent"], dict]:
        """
        Filter events using baseline rules.
        Sprint 8 - Advanced noise filtering.

        Args:
            events: List of events to filter
            quick_filter: Optional quick filter preset name

        Returns:
            Tuple of (filtered_events, filter_stats)
        """
        if not self._baseline_enabled:
            return events, {"suppressed": 0, "total": len(events), "filter_rate": 0.0}

        # Apply quick filter if specified
        min_risk = "low"
        if quick_filter:
            quick_filters = self._baseline.get("quick_filters", {})
            if quick_filter in quick_filters:
                preset = quick_filters[quick_filter]
                min_risk = preset.get("min_risk", "low")

        filtered = []
        suppressed_count = 0
        suppression_reasons = defaultdict(int)

        for event in events:
            should_suppress, reason = self._should_suppress_event(event)

            if should_suppress:
                suppressed_count += 1
                suppression_reasons[reason] += 1
            else:
                filtered.append(event)

        # Update stats
        self._baseline_stats["total_events"] += len(events)
        self._baseline_stats["suppressed"] += suppressed_count

        filter_rate = suppressed_count / len(events) if events else 0.0

        return filtered, {
            "suppressed": suppressed_count,
            "total": len(events),
            "remaining": len(filtered),
            "filter_rate": filter_rate,
            "suppression_reasons": dict(suppression_reasons),
        }

    def suggest_baseline_rules(
        self,
        events: list["LogEvent"],
        min_occurrences: int = 10,
    ) -> list[dict]:
        """
        Suggest new baseline rules based on event patterns.
        Sprint 8 - AI-suggested rules from scan analysis.

        Args:
            events: Events to analyze for patterns
            min_occurrences: Minimum occurrences to suggest rule

        Returns:
            List of suggested rules
        """
        suggestions = []
        patterns = defaultdict(lambda: {"count": 0, "first_seen": None, "last_seen": None, "events": []})

        # Analyze login patterns
        login_events = [e for e in events if e.event_id == 4624]
        for event in login_events:
            logon_type = event.data.get("field_8", "")
            source_ip = event.data.get("field_18", "") or self._extract_ip_from_event(event)
            user = event.user or event.data.get("field_5", "")

            # Pattern: same user, same source, same type
            pattern_key = f"login_{user}_{source_ip}_{logon_type}"
            patterns[pattern_key]["count"] += 1
            patterns[pattern_key]["events"].append({
                "event_id": 4624,
                "user": user,
                "source_ip": source_ip,
                "logon_type": logon_type,
                "time": event.time_created,
            })
            if patterns[pattern_key]["first_seen"] is None:
                patterns[pattern_key]["first_seen"] = event.time_created
            patterns[pattern_key]["last_seen"] = event.time_created

        # Generate suggestions for frequent patterns
        for pattern_key, data in patterns.items():
            if data["count"] >= min_occurrences:
                if pattern_key.startswith("login_"):
                    parts = pattern_key.split("_")
                    if len(parts) >= 4:
                        user = parts[1]
                        source_ip = parts[2]
                        logon_type = parts[3]

                        # Don't suggest for already benign
                        if self._is_benign_user(user):
                            continue

                        try:
                            logon_type_int = int(logon_type)
                        except (ValueError, TypeError):
                            logon_type_int = 0

                        suggestion = {
                            "rule_name": f"auto_{pattern_key[:30]}",
                            "description": f"AI-suggested: Frequent logins from {source_ip} as {user}",
                            "event_id": 4624,
                            "logon_type": logon_type_int,
                            "source_ip": source_ip,
                            "user": user,
                            "action": "suppress",
                            "confidence": min(0.9, data["count"] / 100),
                            "occurrences": data["count"],
                            "suggested_at": datetime.now().isoformat(),
                            "reason": f"{data['count']} identical events detected",
                        }
                        suggestions.append(suggestion)

        return suggestions

    def _load_service_whitelist(self) -> dict:
        """Load service whitelist from YAML config."""
        whitelist = {"microsoft": [], "third_party_signed": [], "custom": [], "suspicious_patterns": {}}

        # Try multiple paths
        whitelist_paths = [
            Path(__file__).parent.parent.parent / "config" / "service_whitelist.yaml",
            Path("config/service_whitelist.yaml"),
            Path("service_whitelist.yaml"),
        ]

        for path in whitelist_paths:
            if path.exists():
                try:
                    import yaml
                    with open(path, "r") as f:
                        whitelist = yaml.safe_load(f) or whitelist
                    logger.info(f"Loaded service whitelist from {path}")
                    break
                except Exception as e:
                    logger.warning(f"Failed to load whitelist from {path}: {e}")

        return whitelist

    def _check_service_in_whitelist(self, service_name: str, binary_path: str) -> tuple[bool, str | None]:
        """
        Check if a service is in the whitelist.

        Returns:
            Tuple of (is_whitelisted, category)
        """
        import fnmatch

        service_lower = service_name.lower()
        path_lower = binary_path.lower()

        # Check each category
        for category in ["microsoft", "third_party_signed", "custom"]:
            services = self._service_whitelist.get(category, [])
            for entry in services:
                entry_name = entry.get("name", "").lower()
                entry_pattern = entry.get("binary_pattern", "").lower()

                # Match service name (supports wildcards)
                if fnmatch.fnmatch(service_lower, entry_name):
                    # Also verify binary path if pattern provided
                    if entry_pattern:
                        if fnmatch.fnmatch(path_lower, entry_pattern.replace("\\", "/")):
                            return True, category
                    else:
                        return True, category

        return False, None

    def _check_suspicious_patterns(self, service_name: str, binary_path: str) -> list[str]:
        """Check if service matches suspicious patterns."""
        import fnmatch

        reasons = []
        patterns = self._service_whitelist.get("suspicious_patterns", {})

        # Check suspicious paths
        for pattern in patterns.get("paths", []):
            if fnmatch.fnmatch(binary_path.lower(), pattern.lower().replace("\\", "/")):
                reasons.append(f"Suspicious binary location: {pattern}")

        # Check suspicious names (impostor detection)
        for name in patterns.get("names", []):
            if service_name.lower() == name.lower():
                # These names should only exist in System32
                if "system32" not in binary_path.lower():
                    reasons.append(f"Potential impostor: '{name}' not in System32")

        return reasons

    def _get_binary_signature(self, binary_path: str) -> tuple[bool | None, str | None]:
        """
        Check if a binary is digitally signed.

        Returns:
            Tuple of (is_signed, publisher)
        """
        if get_platform() != "windows":
            return None, None

        try:
            import subprocess
            # Use sigcheck or PowerShell to verify signature
            result = subprocess.run(
                ["powershell", "-Command",
                 f"(Get-AuthenticodeSignature '{binary_path}').Status -eq 'Valid'"],
                capture_output=True, text=True, timeout=10
            )
            is_signed = result.stdout.strip().lower() == "true"

            publisher = None
            if is_signed:
                pub_result = subprocess.run(
                    ["powershell", "-Command",
                     f"(Get-AuthenticodeSignature '{binary_path}').SignerCertificate.Subject"],
                    capture_output=True, text=True, timeout=10
                )
                publisher = pub_result.stdout.strip()
                # Extract CN from subject
                if "CN=" in publisher:
                    publisher = publisher.split("CN=")[1].split(",")[0]

            return is_signed, publisher
        except Exception as e:
            logger.debug(f"Signature check failed for {binary_path}: {e}")
            return None, None

    def _get_file_hash(self, binary_path: str) -> str | None:
        """Calculate SHA256 hash of a file."""
        import hashlib

        try:
            # Expand environment variables
            expanded_path = os.path.expandvars(binary_path)
            if not os.path.exists(expanded_path):
                return None

            sha256 = hashlib.sha256()
            with open(expanded_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.debug(f"Hash calculation failed for {binary_path}: {e}")
            return None

    def _calculate_service_risk(
        self,
        service_name: str,
        binary_path: str,
        is_signed: bool | None,
        is_whitelisted: bool,
        startup_type: str,
        suspicious_reasons: list[str],
    ) -> tuple[str, list[str]]:
        """
        Calculate risk level for a service installation.

        Returns:
            Tuple of (risk_level, reasons)
        """
        reasons = list(suspicious_reasons)
        score = 0

        # Whitelisted services get low risk
        if is_whitelisted:
            return "low", ["Whitelisted service"]

        # Unsigned binary = HIGH risk
        if is_signed is False:
            score += 60
            reasons.append("Binary is not digitally signed")

        # Unknown signature status = medium risk
        if is_signed is None:
            score += 20
            reasons.append("Signature status unknown")

        # Auto-start from suspicious location
        if startup_type in ["auto", "boot", "system"]:
            if any(loc in binary_path.lower() for loc in ["temp", "appdata", "programdata"]):
                score += 40
                reasons.append(f"Auto-start service in suspicious location")

        # Kernel driver = extra scrutiny
        if "driver" in binary_path.lower() or startup_type in ["boot", "system"]:
            if is_signed is False:
                score += 30
                reasons.append("Unsigned kernel-level service")

        # Suspicious patterns already identified
        score += len(suspicious_reasons) * 25

        # Determine risk level
        if score >= 80:
            return "critical", reasons
        elif score >= 50:
            return "high", reasons
        elif score >= 25:
            return "medium", reasons
        else:
            if not reasons:
                reasons.append("Service appears legitimate")
            return "low", reasons

    def _extract_service_details_from_event(self, event: LogEvent) -> ServiceInstallDetail | None:
        """
        Extract detailed service information from a 7045/4697 event.

        Event 7045 (System log) fields:
        - field_0: Service Name
        - field_1: Image Path (binary)
        - field_2: Service Type
        - field_3: Start Type
        - field_4: Account Name

        Event 4697 (Security log) fields:
        - field_0: Subject Security ID
        - field_1: Subject Account Name
        - field_2: Subject Account Domain
        - field_3: Subject Logon ID
        - field_4: Service Name
        - field_5: Service File Name
        - field_6: Service Type
        - field_7: Service Start Type
        - field_8: Service Account
        """
        try:
            if event.event_id == 7045:
                # System log format
                service_name = event.data.get("field_0", "Unknown")
                binary_path = event.data.get("field_1", "Unknown")
                service_type_raw = event.data.get("field_2", "")
                startup_type_raw = event.data.get("field_3", "")
                account = event.data.get("field_4", event.user)
            elif event.event_id == 4697:
                # Security log format
                service_name = event.data.get("field_4", "Unknown")
                binary_path = event.data.get("field_5", "Unknown")
                service_type_raw = event.data.get("field_6", "")
                startup_type_raw = event.data.get("field_7", "")
                account = event.data.get("field_1", event.user)
            else:
                return None

            # Parse from message if fields are missing
            if service_name == "Unknown" and event.message:
                # Try to extract from message text
                if "Service Name:" in event.message:
                    match = re.search(r"Service Name:\s*(.+?)(?:\r|\n|$)", event.message)
                    if match:
                        service_name = match.group(1).strip()
                if "Service File Name:" in event.message or "Service Path:" in event.message:
                    match = re.search(r"(?:Service File Name|Service Path):\s*(.+?)(?:\r|\n|$)", event.message)
                    if match:
                        binary_path = match.group(1).strip()

            # Normalize startup type
            startup_type = SERVICE_START_TYPES.get(
                startup_type_raw.lower().strip() if startup_type_raw else "manual",
                "manual"
            )

            # Normalize service type
            service_type = SERVICE_TYPES.get(
                service_type_raw.lower().strip() if service_type_raw else "win32_own_process",
                "win32_own_process"
            )

            # Check whitelist
            is_whitelisted, whitelist_category = self._check_service_in_whitelist(service_name, binary_path)

            # Check suspicious patterns
            suspicious_reasons = self._check_suspicious_patterns(service_name, binary_path)

            # Get signature info (only for non-whitelisted services to save time)
            is_signed, publisher = (True, "Whitelisted") if is_whitelisted else self._get_binary_signature(binary_path)

            # Get file hash for non-whitelisted services
            file_hash = None if is_whitelisted else self._get_file_hash(binary_path)

            # Calculate risk
            risk_level, risk_reasons = self._calculate_service_risk(
                service_name, binary_path, is_signed, is_whitelisted, startup_type, suspicious_reasons
            )

            return ServiceInstallDetail(
                service_name=service_name,
                display_name=service_name,  # 7045/4697 don't always have display name
                binary_path=binary_path,
                install_time=event.time_created,
                installing_user=account,
                installing_sid=event.data.get("field_0") if event.event_id == 4697 else None,
                startup_type=startup_type,
                service_type=service_type,
                is_signed=is_signed,
                signature_publisher=publisher,
                file_hash=file_hash,
                risk_level=risk_level,
                risk_reasons=risk_reasons,
                is_whitelisted=is_whitelisted,
                whitelist_category=whitelist_category,
            )

        except Exception as e:
            logger.error(f"Failed to extract service details from event: {e}")
            return None

    def read_events(
        self,
        log_type: str = "Security",
        hours: int = 24,
    ) -> Generator[LogEvent, None, None]:
        """
        Read events from Windows event log.

        Args:
            log_type: Log to read ("Security", "System", "Application")
            hours: How many hours of logs to read

        Yields:
            LogEvent for each event
        """
        if not self._pywin32_available:
            raise RuntimeError("pywin32 not available. Install with: pip install pywin32")

        import win32evtlog
        import win32evtlogutil

        server = None  # Local machine
        cutoff_time = datetime.now() - timedelta(hours=hours)

        try:
            handle = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            while True:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break

                for event in events:
                    # Parse event time
                    event_time = datetime(
                        event.TimeGenerated.year,
                        event.TimeGenerated.month,
                        event.TimeGenerated.day,
                        event.TimeGenerated.hour,
                        event.TimeGenerated.minute,
                        event.TimeGenerated.second,
                    )

                    # Skip events outside time range
                    if event_time < cutoff_time:
                        win32evtlog.CloseEventLog(handle)
                        return

                    # Get formatted message
                    try:
                        message = win32evtlogutil.SafeFormatMessage(event, log_type)
                    except Exception:
                        message = str(event.StringInserts) if event.StringInserts else ""

                    # Extract user if available
                    user = None
                    if event.Sid:
                        try:
                            import win32security
                            user = win32security.LookupAccountSid(None, event.Sid)[0]
                        except Exception:
                            pass

                    # Parse additional data from StringInserts
                    data = {}
                    if event.StringInserts:
                        for i, insert in enumerate(event.StringInserts):
                            data[f"field_{i}"] = insert

                    yield LogEvent(
                        event_id=event.EventID & 0xFFFF,  # Mask to get actual ID
                        source=event.SourceName,
                        category=log_type,
                        time_created=event_time,
                        computer=event.ComputerName,
                        user=user,
                        message=message[:500] if message else "",
                        data=data,
                    )

            win32evtlog.CloseEventLog(handle)

        except Exception as e:
            logger.error(f"Error reading {log_type} log: {e}")
            raise

    def read_events_from_csv(self, csv_path: str) -> list[LogEvent]:
        """
        Read events from CSV file (for testing/cross-platform).

        Expected columns: event_id, source, category, time_created, computer, user, message

        Args:
            csv_path: Path to CSV file

        Returns:
            List of LogEvent objects
        """
        events = []
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(LogEvent(
                    event_id=int(row.get("event_id", 0)),
                    source=row.get("source", ""),
                    category=row.get("category", "Security"),
                    time_created=datetime.fromisoformat(row.get("time_created", datetime.now().isoformat())),
                    computer=row.get("computer", ""),
                    user=row.get("user"),
                    message=row.get("message", ""),
                    data={"raw": row},
                ))
        return events

    def parse_events_from_string(self, csv_content: str) -> list[LogEvent]:
        """Parse events from CSV string content."""
        events = []
        reader = csv.DictReader(io.StringIO(csv_content))
        for row in reader:
            events.append(LogEvent(
                event_id=int(row.get("event_id", 0)),
                source=row.get("source", ""),
                category=row.get("category", "Security"),
                time_created=datetime.fromisoformat(row.get("time_created", datetime.now().isoformat())),
                computer=row.get("computer", ""),
                user=row.get("user"),
                message=row.get("message", ""),
                data={"raw": row},
            ))
        return events

    def _extract_ip_from_event(self, event: LogEvent) -> str | None:
        """Extract IP address from event data."""
        # Common fields where IP might be stored
        ip_fields = ["field_18", "field_19", "field_5", "IpAddress", "SourceNetworkAddress"]

        for field_name in ip_fields:
            value = event.data.get(field_name, "")
            if value and self._is_valid_ip(value):
                return value

        # Try to find IP in message
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if event.message:
            match = re.search(ip_pattern, event.message)
            if match:
                ip = match.group()
                if self._is_valid_ip(ip) and ip != "127.0.0.1":
                    return ip

        return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid non-local IP address."""
        if not ip or ip in ["-", "::1", "127.0.0.1", "0.0.0.0"]:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _check_ip_reputation(self, ip: str) -> dict | None:
        """Check IP reputation using threat intelligence."""
        if not self._threat_intel or not ip:
            return None
        try:
            result = self._threat_intel.check_ip(ip)
            return result.to_dict()
        except Exception as e:
            logger.debug(f"IP reputation check failed for {ip}: {e}")
            return None

    def detect_brute_force(
        self,
        events: list[LogEvent],
        threshold: int | None = None,
        window_minutes: int | None = None,
    ) -> list[SecurityAnomaly]:
        """
        Detect brute force login attempts with MITRE ATT&CK mapping and IP reputation.

        Flags when there are more than threshold failed logins
        from the same source within the time window.

        Args:
            events: List of events to analyze
            threshold: Failed login threshold (default from config)
            window_minutes: Time window in minutes (default from config)

        Returns:
            List of detected anomalies
        """
        threshold = threshold or self.config.failed_login_threshold
        window_minutes = window_minutes or self.config.time_window_minutes

        anomalies = []

        # Filter for failed login events (4625)
        failed_logins = [e for e in events if e.event_id == 4625]

        if not failed_logins:
            return anomalies

        # Get MITRE ATT&CK info for event 4625
        mitre_info = MITRE_ATTACK_MAP.get(4625, {})

        # Group by source (user or IP if available)
        by_source: dict[str, list[LogEvent]] = defaultdict(list)
        source_ips: dict[str, str | None] = {}

        for event in failed_logins:
            # Try to extract source IP first, then user
            source_ip = self._extract_ip_from_event(event)
            source = source_ip or event.user or event.data.get("field_5", "unknown")
            by_source[source].append(event)
            if source_ip:
                source_ips[source] = source_ip

        # Check each source for threshold violations
        for source, source_events in by_source.items():
            # Sort by time
            source_events.sort(key=lambda e: e.time_created)

            # Sliding window analysis
            for i, event in enumerate(source_events):
                window_end = event.time_created + timedelta(minutes=window_minutes)
                window_events = [
                    e for e in source_events[i:]
                    if e.time_created <= window_end
                ]

                if len(window_events) >= threshold:
                    # Check IP reputation if we have an IP
                    ip_rep = None
                    source_ip = source_ips.get(source)
                    if source_ip:
                        ip_rep = self._check_ip_reputation(source_ip)
                        if ip_rep and ip_rep.get("is_malicious"):
                            logger.warning(f"MALICIOUS IP detected: {source_ip} (Abuse confidence: {ip_rep.get('abuse_confidence')}%)")

                    anomalies.append(SecurityAnomaly(
                        anomaly_type="brute_force_attempt",
                        severity="critical",
                        description=f"{len(window_events)} failed logins from '{source}' within {window_minutes} minutes",
                        events=window_events,
                        recommended_action=f"Block source '{source}', review account security, enable account lockout policy",
                        timestamp=event.time_created,
                        metadata={
                            "source": source,
                            "source_ip": source_ip,
                            "failed_attempts": len(window_events),
                            "window_minutes": window_minutes,
                        },
                        mitre_techniques=mitre_info.get("techniques", []),
                        mitre_tactic=mitre_info.get("tactic", ""),
                        ip_reputation=ip_rep,
                    ))
                    break  # Only report once per source

        return anomalies

    def detect_privilege_escalation(self, events: list[LogEvent]) -> list[SecurityAnomaly]:
        """
        Detect privilege escalation attempts with MITRE ATT&CK mapping.

        Monitors for:
        - Special privileges assigned (4672) - T1134 Access Token Manipulation
        - Group membership changes (4728, 4732, 4756) - T1098 Account Manipulation
        - Account modifications (4738)

        Args:
            events: List of events to analyze

        Returns:
            List of detected anomalies
        """
        anomalies = []
        priv_event_ids = {4672, 4728, 4732, 4756, 4738}

        priv_events = [e for e in events if e.event_id in priv_event_ids]

        # Group by user
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for event in priv_events:
            user = event.user or "SYSTEM"
            # Skip excluded users
            if user in self.config.excluded_users:
                continue
            by_user[user].append(event)

        for user, user_events in by_user.items():
            # Check for group membership changes (high severity)
            group_changes = [e for e in user_events if e.event_id in {4728, 4732, 4756}]
            if group_changes:
                # Get MITRE info for first event
                first_event_id = group_changes[0].event_id
                mitre_info = MITRE_ATTACK_MAP.get(first_event_id, {})

                anomalies.append(SecurityAnomaly(
                    anomaly_type="privilege_escalation",
                    severity="critical",
                    description=f"User '{user}' added to privileged group(s)",
                    events=group_changes,
                    recommended_action="Verify group membership changes were authorized, review change management logs",
                    metadata={"user": user, "change_count": len(group_changes)},
                    mitre_techniques=mitre_info.get("techniques", ["T1098"]),
                    mitre_tactic=mitre_info.get("tactic", "Persistence"),
                ))

            # Check for special privileges (medium severity)
            special_priv = [e for e in user_events if e.event_id == 4672]
            if special_priv and self.config.alert_on_admin_login:
                # Only flag if many special privilege events
                if len(special_priv) > 5:
                    mitre_info = MITRE_ATTACK_MAP.get(4672, {})
                    anomalies.append(SecurityAnomaly(
                        anomaly_type="excessive_privileges",
                        severity="warning",
                        description=f"User '{user}' received special privileges {len(special_priv)} times",
                        events=special_priv[:5],
                        recommended_action="Review if user requires elevated privileges, consider least privilege principle",
                        metadata={"user": user, "privilege_grants": len(special_priv)},
                        mitre_techniques=mitre_info.get("techniques", ["T1134"]),
                        mitre_tactic=mitre_info.get("tactic", "Privilege Escalation"),
                    ))

        return anomalies

    def detect_account_manipulation(self, events: list[LogEvent]) -> list[SecurityAnomaly]:
        """
        Detect suspicious account manipulation with MITRE ATT&CK mapping.

        Monitors for:
        - Account creation (4720) - T1136.001 Create Account: Local Account
        - Account deletion (4726)
        - Account lockouts (4740)
        - Password changes/resets (4723, 4724)
        - Audit log cleared (1102) - T1070.001 Indicator Removal

        Args:
            events: List of events to analyze

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Account creation
        account_created = [e for e in events if e.event_id == 4720]
        if account_created:
            mitre_info = MITRE_ATTACK_MAP.get(4720, {})
            anomalies.append(SecurityAnomaly(
                anomaly_type="account_creation",
                severity="warning",
                description=f"{len(account_created)} new user account(s) created",
                events=account_created,
                recommended_action="Verify account creation was authorized through proper change management",
                metadata={"accounts_created": len(account_created)},
                mitre_techniques=mitre_info.get("techniques", ["T1136.001"]),
                mitre_tactic=mitre_info.get("tactic", "Persistence"),
            ))

        # Account lockouts (may indicate brute force)
        lockouts = [e for e in events if e.event_id == 4740]
        if lockouts:
            anomalies.append(SecurityAnomaly(
                anomaly_type="account_lockout",
                severity="warning",
                description=f"{len(lockouts)} account lockout(s) detected",
                events=lockouts,
                recommended_action="Investigate cause of lockouts, may indicate brute force or password policy issues",
                metadata={"lockouts": len(lockouts)},
                mitre_techniques=["T1110"],
                mitre_tactic="Credential Access",
            ))

        # Audit log cleared (CRITICAL - Defense Evasion!)
        log_cleared = [e for e in events if e.event_id == 1102]
        if log_cleared:
            mitre_info = MITRE_ATTACK_MAP.get(1102, {})
            anomalies.append(SecurityAnomaly(
                anomaly_type="audit_log_cleared",
                severity="critical",
                description="Security audit log was cleared - potential evidence tampering",
                events=log_cleared,
                recommended_action="IMMEDIATE: Investigate who cleared logs and why, restore from backup if available",
                metadata={"cleared_count": len(log_cleared)},
                mitre_techniques=mitre_info.get("techniques", ["T1070.001"]),
                mitre_tactic=mitre_info.get("tactic", "Defense Evasion"),
            ))

        return anomalies

    def detect_suspicious_services(self, events: list[LogEvent]) -> list[SecurityAnomaly]:
        """
        Detect suspicious service activity with MITRE ATT&CK mapping.
        Sprint 5 Enhanced: Provides verbose per-service details with risk scoring.

        Monitors for:
        - New service installations (7045, 4697) - T1543.003 Create/Modify System Process
        - Service crashes (7034)

        Args:
            events: List of events to analyze

        Returns:
            List of detected anomalies with detailed service information
        """
        anomalies = []

        # Extract verbose service details
        service_details = self.extract_service_install_details(events)

        if service_details:
            # Group by risk level
            by_risk: dict[str, list[ServiceInstallDetail]] = defaultdict(list)
            for detail in service_details:
                by_risk[detail.risk_level].append(detail)

            # Correlate with login/process events
            service_details = self._correlate_service_installs(service_details, events)

            # Create anomaly for each risk category
            mitre_info = MITRE_ATTACK_MAP.get(7045, {})

            # Critical risk services
            critical_services = by_risk.get("critical", [])
            if critical_services:
                service_names = [s.service_name for s in critical_services]
                anomalies.append(SecurityAnomaly(
                    anomaly_type="service_installed_critical",
                    severity="critical",
                    description=f"{len(critical_services)} CRITICAL risk service(s): {', '.join(service_names[:3])}{'...' if len(service_names) > 3 else ''}",
                    events=[e for e in events if e.event_id in {7045, 4697}][:len(critical_services)],
                    recommended_action="IMMEDIATE: Isolate system, verify binaries, check for malware persistence",
                    metadata={
                        "services_installed": len(critical_services),
                        "service_details": [s.to_dict() for s in critical_services],
                        "risk_level": "critical",
                    },
                    mitre_techniques=mitre_info.get("techniques", ["T1543.003"]),
                    mitre_tactic=mitre_info.get("tactic", "Persistence"),
                ))

            # High risk services
            high_services = by_risk.get("high", [])
            if high_services:
                service_names = [s.service_name for s in high_services]
                anomalies.append(SecurityAnomaly(
                    anomaly_type="service_installed_high",
                    severity="critical",
                    description=f"{len(high_services)} HIGH risk service(s): {', '.join(service_names[:3])}{'...' if len(service_names) > 3 else ''}",
                    events=[e for e in events if e.event_id in {7045, 4697}][:len(high_services)],
                    recommended_action="URGENT: Verify service binaries are signed and from trusted sources",
                    metadata={
                        "services_installed": len(high_services),
                        "service_details": [s.to_dict() for s in high_services],
                        "risk_level": "high",
                    },
                    mitre_techniques=mitre_info.get("techniques", ["T1543.003"]),
                    mitre_tactic=mitre_info.get("tactic", "Persistence"),
                ))

            # Medium risk services
            medium_services = by_risk.get("medium", [])
            if medium_services:
                service_names = [s.service_name for s in medium_services]
                anomalies.append(SecurityAnomaly(
                    anomaly_type="service_installed_medium",
                    severity="warning",
                    description=f"{len(medium_services)} MEDIUM risk service(s): {', '.join(service_names[:3])}{'...' if len(service_names) > 3 else ''}",
                    events=[e for e in events if e.event_id in {7045, 4697}][:len(medium_services)],
                    recommended_action="Investigate service purpose and verify installation source",
                    metadata={
                        "services_installed": len(medium_services),
                        "service_details": [s.to_dict() for s in medium_services],
                        "risk_level": "medium",
                    },
                    mitre_techniques=mitre_info.get("techniques", ["T1543.003"]),
                    mitre_tactic=mitre_info.get("tactic", "Persistence"),
                ))

            # Low risk / whitelisted services (informational)
            low_services = by_risk.get("low", [])
            if low_services:
                # Only show if there are also suspicious services, otherwise skip
                if critical_services or high_services or medium_services:
                    anomalies.append(SecurityAnomaly(
                        anomaly_type="service_installed_benign",
                        severity="info",
                        description=f"{len(low_services)} low-risk/whitelisted service(s) installed",
                        events=[],
                        recommended_action="No action required - services appear legitimate",
                        metadata={
                            "services_installed": len(low_services),
                            "service_details": [s.to_dict() for s in low_services],
                            "risk_level": "low",
                        },
                        mitre_techniques=[],
                        mitre_tactic="",
                    ))

        # Service crashes - may indicate exploitation attempts
        crashes = [e for e in events if e.event_id == 7034]
        if len(crashes) > 3:  # Only flag if multiple crashes
            anomalies.append(SecurityAnomaly(
                anomaly_type="service_crashes",
                severity="info",
                description=f"{len(crashes)} service crashes detected",
                events=crashes[:5],
                recommended_action="Investigate service stability, may indicate exploitation attempts",
                metadata={"crash_count": len(crashes)},
            ))

        return anomalies

    def extract_service_install_details(self, events: list[LogEvent]) -> list[ServiceInstallDetail]:
        """
        Extract detailed information for all service installations.
        Sprint 5 - Verbose service install analysis.

        Args:
            events: List of events to analyze

        Returns:
            List of ServiceInstallDetail objects with full context
        """
        service_details = []

        # Filter for service installation events
        service_events = [e for e in events if e.event_id in {7045, 4697}]

        for event in service_events:
            detail = self._extract_service_details_from_event(event)
            if detail:
                service_details.append(detail)

        return service_details

    def _correlate_service_installs(
        self,
        service_details: list[ServiceInstallDetail],
        events: list[LogEvent],
    ) -> list[ServiceInstallDetail]:
        """
        Correlate service installations with login and process events.
        Sprint 5 - Anomaly correlation for threat hunting.

        Looks for:
        - Logins (4624) within 5 minutes before service install
        - Process creation (4688) within 5 minutes before service install

        Args:
            service_details: List of service install details
            events: All events for correlation

        Returns:
            Updated service_details with correlated events
        """
        # Get login and process events
        logins = [e for e in events if e.event_id == 4624]
        processes = [e for e in events if e.event_id == 4688]

        correlation_window = timedelta(minutes=5)

        for detail in service_details:
            install_time = detail.install_time
            window_start = install_time - correlation_window

            # Find logins before install
            related_logins = []
            for login in logins:
                if window_start <= login.time_created <= install_time:
                    # Extract login info
                    logon_type = login.data.get("field_8", "")
                    logon_type_name = LOGON_TYPES.get(int(logon_type) if logon_type.isdigit() else 0, logon_type)
                    related_logins.append({
                        "event_id": 4624,
                        "time": login.time_created.isoformat(),
                        "user": login.user or login.data.get("field_5", "Unknown"),
                        "logon_type": logon_type_name,
                        "source_ip": self._extract_ip_from_event(login),
                        "seconds_before_install": (install_time - login.time_created).total_seconds(),
                    })

            # Find process creations before install
            related_processes = []
            for proc in processes:
                if window_start <= proc.time_created <= install_time:
                    # Extract process info
                    process_name = proc.data.get("field_5", proc.message[:50] if proc.message else "Unknown")
                    related_processes.append({
                        "event_id": 4688,
                        "time": proc.time_created.isoformat(),
                        "user": proc.user or proc.data.get("field_1", "Unknown"),
                        "process": process_name,
                        "command_line": proc.data.get("field_8", "")[:100],
                        "seconds_before_install": (install_time - proc.time_created).total_seconds(),
                    })

            # Add correlated events to detail
            correlated = []
            if related_logins:
                correlated.extend(related_logins[:3])  # Limit to most recent 3
            if related_processes:
                correlated.extend(related_processes[:3])

            detail.correlated_events = correlated

            # Elevate risk if suspicious correlation found
            if related_logins:
                for login in related_logins:
                    # Remote login followed by service install is suspicious
                    if login.get("logon_type") in ["RemoteInteractive (RDP)", "Network"]:
                        if detail.risk_level == "low":
                            detail.risk_level = "medium"
                            detail.risk_reasons.append(f"Service installed after {login.get('logon_type')} login")
                        elif detail.risk_level == "medium":
                            detail.risk_level = "high"
                            detail.risk_reasons.append(f"Service installed after {login.get('logon_type')} login")

        return service_details

    def get_service_install_summary(self, events: list[LogEvent]) -> dict[str, Any]:
        """
        Get a summary of service installations for GUI display.
        Sprint 5 - Verbose summary with actionable info.

        Args:
            events: List of events to analyze

        Returns:
            Dictionary with summary statistics and service list
        """
        details = self.extract_service_install_details(events)

        # Count by risk level
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for d in details:
            risk_counts[d.risk_level] = risk_counts.get(d.risk_level, 0) + 1

        # Count whitelisted
        whitelisted_count = sum(1 for d in details if d.is_whitelisted)

        # Get table rows for GUI
        table_rows = [d.to_table_row() for d in sorted(
            details,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.risk_level, 4)
        )]

        return {
            "total_services": len(details),
            "risk_breakdown": risk_counts,
            "whitelisted_count": whitelisted_count,
            "needs_investigation": risk_counts["critical"] + risk_counts["high"] + risk_counts["medium"],
            "service_details": [d.to_dict() for d in details],
            "table_rows": table_rows,
            "mitre_technique": "T1543.003",
            "mitre_url": "https://attack.mitre.org/techniques/T1543/003/",
        }

    # =========================================================================
    # Sprint 7: Verbose Logon Analysis
    # =========================================================================

    def _extract_logon_details_from_event(self, event: LogEvent) -> LogonEventDetail | None:
        """
        Extract detailed logon information from a 4624/4625 event.
        Sprint 7 - Provides verbose logon details with local/remote differentiation.

        Event 4624/4625 fields (Security log):
        - field_0: Subject Security ID
        - field_1: Subject Account Name
        - field_2: Subject Account Domain
        - field_3: Subject Logon ID
        - field_4: Target Security ID
        - field_5: Target Account Name
        - field_6: Target Account Domain
        - field_7: Target Logon ID
        - field_8: Logon Type
        - field_9: Logon Process
        - field_10: Authentication Package
        - field_11: Workstation Name
        - field_12: Logon GUID
        - field_13: Transmitted Services
        - field_14: LM Package Name
        - field_15: Key Length
        - field_16: Process ID
        - field_17: Process Name
        - field_18: Source Network Address (IP)
        - field_19: Source Port
        """
        try:
            is_success = event.event_id == 4624

            # Extract username and domain
            username = event.data.get("field_5", event.user or "Unknown")
            domain = event.data.get("field_6", "")

            # Parse from message if fields missing
            if username == "Unknown" and event.message:
                if "Account Name:" in event.message:
                    match = re.search(r"Account Name:\s*(\S+)", event.message)
                    if match:
                        username = match.group(1)

            # Skip system/service accounts for noise filtering
            if username.upper() in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-", "ANONYMOUS LOGON"]:
                return None

            # Extract logon type
            logon_type_raw = event.data.get("field_8", "")
            try:
                logon_type = int(logon_type_raw) if logon_type_raw.isdigit() else 0
            except (ValueError, AttributeError):
                logon_type = 0

            # Get classification
            classification = LOGON_TYPE_CLASSIFICATION.get(logon_type, {
                "name": f"Unknown ({logon_type})",
                "is_remote": False,
                "risk": "medium",
                "description": "Unknown logon type"
            })

            logon_type_name = classification["name"]
            is_remote = classification["is_remote"]
            base_risk = classification["risk"]

            # Extract source IP
            source_ip = event.data.get("field_18", "")
            if not source_ip or source_ip == "-":
                source_ip = self._extract_ip_from_event(event)

            # Check if this is actually remote based on IP
            if source_ip and source_ip not in ["127.0.0.1", "-", "::1", ""]:
                is_remote = True

            # Extract other fields
            source_hostname = event.data.get("field_11", "")
            logon_process = event.data.get("field_9", "")
            auth_package = event.data.get("field_10", "")

            # Check for elevated token (field varies)
            elevated_token = False
            if "Elevated Token" in event.message:
                elevated_token = "Yes" in event.message

            # Calculate risk level
            risk_level, risk_reasons = self._calculate_logon_risk(
                event, is_success, is_remote, logon_type, base_risk, source_ip
            )

            # Get MITRE mapping
            if not is_success:
                mitre_info = LOGON_MITRE_MAPPING.get("failed_brute", {})
            elif is_remote and logon_type == 10:
                mitre_info = LOGON_MITRE_MAPPING.get("remote_rdp", {})
            elif is_remote:
                mitre_info = LOGON_MITRE_MAPPING.get("remote_network", {})
            else:
                mitre_info = LOGON_MITRE_MAPPING.get("local_interactive", {})

            # Failure reason for 4625
            failure_reason = None
            if not is_success:
                status_code = event.data.get("field_7", "") or event.data.get("field_9", "")
                failure_reason = LOGON_FAILURE_CODES.get(status_code, "Unknown failure reason")
                if "Status:" in event.message:
                    match = re.search(r"Status:\s*(0x[0-9A-Fa-f]+)", event.message)
                    if match:
                        failure_reason = LOGON_FAILURE_CODES.get(match.group(1), failure_reason)

            return LogonEventDetail(
                event_id=event.event_id,
                event_time=event.time_created,
                username=username,
                domain=domain if domain and domain != "-" else None,
                logon_type=logon_type,
                logon_type_name=logon_type_name,
                is_remote=is_remote,
                is_success=is_success,
                source_ip=source_ip if source_ip and source_ip != "-" else None,
                source_hostname=source_hostname if source_hostname and source_hostname != "-" else None,
                target_hostname=event.computer,
                logon_process=logon_process if logon_process else None,
                auth_package=auth_package if auth_package else None,
                elevated_token=elevated_token,
                risk_level=risk_level,
                risk_reasons=risk_reasons,
                mitre_technique=mitre_info.get("technique", "T1078"),
                mitre_tactic=mitre_info.get("tactic", "Initial Access"),
                failure_reason=failure_reason,
            )

        except Exception as e:
            logger.error(f"Failed to extract logon details from event: {e}")
            return None

    def _calculate_logon_risk(
        self,
        event: LogEvent,
        is_success: bool,
        is_remote: bool,
        logon_type: int,
        base_risk: str,
        source_ip: str | None,
    ) -> tuple[str, list[str]]:
        """
        Calculate risk level for a logon event.
        Sprint 7 - Risk scoring for logon events.

        Returns:
            Tuple of (risk_level, reasons)
        """
        reasons = []
        score = 0

        # Base score from classification
        base_scores = {"low": 0, "medium": 20, "high": 40, "critical": 60}
        score += base_scores.get(base_risk, 20)

        # Failed login increases risk
        if not is_success:
            score += 30
            reasons.append("Failed login attempt")

        # Remote access increases risk
        if is_remote:
            score += 20
            reasons.append("Remote access")

        # RDP is higher risk
        if logon_type == 10:
            score += 15
            reasons.append("RDP/Terminal Services login")

        # Network cleartext is very risky
        if logon_type == 8:
            score += 30
            reasons.append("Cleartext password over network")

        # After hours login (simplified check)
        hour = event.time_created.hour
        if hour < 6 or hour > 22:
            score += 10
            reasons.append("After-hours login")

        # External IP source
        if source_ip and source_ip not in ["127.0.0.1", "::1", "-", ""]:
            # Check if it's a private IP
            if not (source_ip.startswith("10.") or
                    source_ip.startswith("192.168.") or
                    source_ip.startswith("172.16.") or
                    source_ip.startswith("172.17.") or
                    source_ip.startswith("172.18.") or
                    source_ip.startswith("172.19.") or
                    source_ip.startswith("172.2") or
                    source_ip.startswith("172.30.") or
                    source_ip.startswith("172.31.")):
                score += 25
                reasons.append(f"External IP source: {source_ip}")

        # Determine risk level
        if score >= 70:
            return "critical", reasons
        elif score >= 50:
            return "high", reasons
        elif score >= 25:
            return "medium", reasons
        else:
            if not reasons:
                reasons.append("Normal logon activity")
            return "low", reasons

    def extract_logon_details(
        self,
        events: list[LogEvent],
        include_local: bool = True,
        min_risk: str = "low",
    ) -> list[LogonEventDetail]:
        """
        Extract detailed logon information from events.
        Sprint 7 - Verbose logon analysis with filtering.

        Args:
            events: List of events to analyze
            include_local: Include local (non-remote) logons
            min_risk: Minimum risk level to include ("low", "medium", "high", "critical")

        Returns:
            List of LogonEventDetail objects
        """
        logon_details = []
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_risk_level = risk_order.get(min_risk, 0)

        # Filter for logon events
        logon_events = [e for e in events if e.event_id in {4624, 4625}]

        for event in logon_events:
            detail = self._extract_logon_details_from_event(event)
            if detail:
                # Apply filters
                if not include_local and not detail.is_remote:
                    continue

                if risk_order.get(detail.risk_level, 0) < min_risk_level:
                    continue

                logon_details.append(detail)

        return logon_details

    def correlate_logins_with_services(
        self,
        events: list[LogEvent],
    ) -> list[LogonEventDetail]:
        """
        Correlate logon events with subsequent service installations.
        Sprint 7 - Find logins followed by service installs (persistence).

        Args:
            events: All events for correlation

        Returns:
            List of LogonEventDetail with correlated service installs
        """
        # Get logon details (remote only, medium+ risk)
        logon_details = self.extract_logon_details(events, include_local=False, min_risk="low")

        # Get service installations
        service_events = [e for e in events if e.event_id in {7045, 4697}]

        correlation_window = timedelta(minutes=30)

        for logon in logon_details:
            login_time = logon.event_time
            window_end = login_time + correlation_window

            # Find services installed after this login
            correlated_services = []
            for svc_event in service_events:
                if login_time <= svc_event.time_created <= window_end:
                    # Extract service info
                    service_name = svc_event.data.get("field_0", svc_event.data.get("field_4", "Unknown"))
                    binary_path = svc_event.data.get("field_1", svc_event.data.get("field_5", "Unknown"))

                    correlated_services.append({
                        "service_name": service_name,
                        "binary_path": binary_path,
                        "install_time": svc_event.time_created.isoformat(),
                        "minutes_after_login": (svc_event.time_created - login_time).total_seconds() / 60,
                    })

            if correlated_services:
                logon.correlated_services = correlated_services
                # Elevate risk if service installed after login
                if logon.risk_level == "low":
                    logon.risk_level = "medium"
                    logon.risk_reasons.append(f"Service installed after login: {correlated_services[0]['service_name']}")
                elif logon.risk_level == "medium":
                    logon.risk_level = "high"
                    logon.risk_reasons.append(f"Service installed after login: {correlated_services[0]['service_name']}")

        return logon_details

    def get_logon_summary(
        self,
        events: list[LogEvent],
        include_local: bool = False,
    ) -> dict[str, Any]:
        """
        Get a summary of logon events for GUI display.
        Sprint 7 - Verbose summary with actionable info.

        Args:
            events: List of events to analyze
            include_local: Include local logons in summary

        Returns:
            Dictionary with summary statistics and logon list
        """
        # Get all logon details with correlation
        details = self.correlate_logins_with_services(events)

        if not include_local:
            details = [d for d in details if d.is_remote]

        # Count by risk level
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for d in details:
            risk_counts[d.risk_level] = risk_counts.get(d.risk_level, 0) + 1

        # Count by type
        success_count = sum(1 for d in details if d.is_success)
        failed_count = sum(1 for d in details if not d.is_success)
        remote_count = sum(1 for d in details if d.is_remote)

        # Count with correlated services
        with_services = sum(1 for d in details if d.correlated_services)

        # Get table rows for GUI
        table_rows = [d.to_table_row() for d in sorted(
            details,
            key=lambda x: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.risk_level, 4),
                not x.is_remote,  # Remote first
                x.event_time
            )
        )]

        return {
            "total_logons": len(details),
            "success_count": success_count,
            "failed_count": failed_count,
            "remote_count": remote_count,
            "risk_breakdown": risk_counts,
            "with_service_install": with_services,
            "needs_investigation": risk_counts["critical"] + risk_counts["high"],
            "logon_details": [d.to_dict() for d in details],
            "table_rows": table_rows,
            "mitre_technique": "T1078",
            "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        }

    def detect_rdp_activity(self, events: list[LogEvent]) -> list[SecurityAnomaly]:
        """
        Detect suspicious RDP activity.

        Monitors for remote interactive logins (logon type 10).

        Args:
            events: List of events to analyze

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Filter for successful logins
        logins = [e for e in events if e.event_id == 4624]

        # Check for RDP logins (logon type 10)
        rdp_logins = []
        for event in logins:
            # Logon type is usually in field_8 or message
            logon_type = event.data.get("field_8", "")
            if logon_type == "10" or "RemoteInteractive" in event.message:
                rdp_logins.append(event)

        if rdp_logins:
            # Group by user
            by_user: dict[str, int] = defaultdict(int)
            for event in rdp_logins:
                user = event.user or "unknown"
                by_user[user] += 1

            anomalies.append(SecurityAnomaly(
                anomaly_type="rdp_activity",
                severity="info",
                description=f"{len(rdp_logins)} RDP login(s) from {len(by_user)} user(s)",
                events=rdp_logins[:5],
                recommended_action="Verify RDP access is authorized, consider enabling NLA and restricting RDP access",
                metadata={"rdp_logins": len(rdp_logins), "users": dict(by_user)},
            ))

        return anomalies

    def compute_statistics(self, events: list[LogEvent]) -> dict[str, Any]:
        """
        Compute log statistics using pandas.

        Args:
            events: List of events to analyze

        Returns:
            Statistics dictionary
        """
        if not self._pandas_available or not events:
            return {}

        import pandas as pd

        # Convert to DataFrame
        df = pd.DataFrame([e.to_dict() for e in events])
        df["time_created"] = pd.to_datetime(df["time_created"])

        stats = {
            "total_events": len(df),
            "unique_users": df["user"].nunique(),
            "unique_computers": df["computer"].nunique(),
            "time_span": {
                "start": df["time_created"].min().isoformat(),
                "end": df["time_created"].max().isoformat(),
            },
        }

        # Event type distribution
        event_counts = df["event_id"].value_counts().head(10).to_dict()
        stats["top_event_ids"] = {
            SECURITY_EVENTS.get(int(k), f"Event {k}"): v
            for k, v in event_counts.items()
        }

        # User activity
        if "user" in df.columns:
            user_counts = df["user"].value_counts().head(10).to_dict()
            stats["top_users"] = user_counts

        # Hourly distribution
        df["hour"] = df["time_created"].dt.hour
        hourly = df.groupby("hour").size().to_dict()
        stats["hourly_distribution"] = hourly

        # Event type counts for GUI display
        stats["event_type_counts"] = stats.get("top_event_ids", {})

        # Sprint 5 - Service install summary
        try:
            service_summary = self.get_service_install_summary(events)
            stats["service_summary"] = service_summary
        except Exception as e:
            logger.debug(f"Service summary failed: {e}")

        # Sprint 7 - Logon event summary
        try:
            logon_summary = self.get_logon_summary(events, include_local=True)
            stats["logon_summary"] = logon_summary
        except Exception as e:
            logger.debug(f"Logon summary failed: {e}")

        # Failed logins count for backward compat
        failed_logins = len([e for e in events if e.event_id == 4625])
        stats["failed_logins"] = failed_logins

        # Privilege changes count
        priv_events = len([e for e in events if e.event_id == 4672])
        stats["privilege_changes"] = priv_events

        return stats

    def analyze_all(
        self,
        log_types: list[str] | None = None,
        hours: int = 24,
    ) -> LogAnalysisResult:
        """
        Run all security analyses.

        Args:
            log_types: List of logs to analyze (default: config)
            hours: Hours of logs to analyze

        Returns:
            Complete analysis result
        """
        log_types = log_types or self.config.event_logs
        all_events: list[LogEvent] = []
        anomalies: list[SecurityAnomaly] = []

        # Collect events from all log types
        for log_type in log_types:
            try:
                events = list(self.read_events(log_type, hours))
                all_events.extend(events)
                logger.info(f"Read {len(events)} events from {log_type}")
            except Exception as e:
                logger.error(f"Failed to read {log_type}: {e}")

        if not all_events:
            return LogAnalysisResult(
                analyzed_logs=log_types,
                time_range_hours=hours,
                total_events=0,
                anomalies=[],
                statistics={},
            )

        # Run all detection methods
        anomalies.extend(self.detect_brute_force(all_events))
        anomalies.extend(self.detect_privilege_escalation(all_events))
        anomalies.extend(self.detect_account_manipulation(all_events))
        anomalies.extend(self.detect_suspicious_services(all_events))
        anomalies.extend(self.detect_rdp_activity(all_events))

        # Compute statistics
        statistics = self.compute_statistics(all_events)

        return LogAnalysisResult(
            analyzed_logs=log_types,
            time_range_hours=hours,
            total_events=len(all_events),
            anomalies=anomalies,
            statistics=statistics,
        )

    def analyze_events(self, events: list[LogEvent]) -> LogAnalysisResult:
        """
        Analyze a provided list of events (for testing/cross-platform).

        Args:
            events: List of events to analyze

        Returns:
            Complete analysis result
        """
        anomalies: list[SecurityAnomaly] = []

        # Run all detection methods
        anomalies.extend(self.detect_brute_force(events))
        anomalies.extend(self.detect_privilege_escalation(events))
        anomalies.extend(self.detect_account_manipulation(events))
        anomalies.extend(self.detect_suspicious_services(events))
        anomalies.extend(self.detect_rdp_activity(events))

        # Compute statistics
        statistics = self.compute_statistics(events)

        # Determine time range from events
        if events:
            hours = int((max(e.time_created for e in events) - min(e.time_created for e in events)).total_seconds() / 3600) + 1
        else:
            hours = 0

        return LogAnalysisResult(
            analyzed_logs=["provided_events"],
            time_range_hours=hours,
            total_events=len(events),
            anomalies=anomalies,
            statistics=statistics,
        )

    def check_admin_access(self) -> tuple[bool, str]:
        """
        Check if we have admin access for reading event logs.

        Returns:
            Tuple of (has_access, message)
        """
        if get_platform() != "windows":
            return False, "Windows event logs only available on Windows"

        if not self._pywin32_available:
            return False, "pywin32 not installed. Run: pip install pywin32"

        # Check if running as admin
        try:
            from bisontitan.utils import is_admin
            if not is_admin():
                return False, "Admin privileges required for Security log access. Run as Administrator."
        except ImportError:
            # Fallback admin check
            import ctypes
            try:
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    return False, "Admin privileges required. Run as Administrator."
            except Exception:
                pass

        return True, "Admin access confirmed"

    def full_analysis(
        self,
        log_type: str = "Security",
        hours: int = 24,
    ) -> LogAnalysisResult:
        """
        Run full analysis on a single log type.

        Convenience method that wraps analyze_all for single log type.
        Includes admin check and better error handling.

        Args:
            log_type: Log to analyze ("Security", "System", "Application")
            hours: Hours of logs to analyze

        Returns:
            Complete analysis result
        """
        # Check admin access for Security log
        if log_type == "Security":
            has_access, message = self.check_admin_access()
            if not has_access:
                logger.warning(f"Admin check failed: {message}")
                # Return empty result with error info
                return LogAnalysisResult(
                    analyzed_logs=[log_type],
                    time_range_hours=hours,
                    total_events=0,
                    anomalies=[],
                    statistics={"error": message, "admin_required": True},
                )

        # Use analyze_all with single log type
        return self.analyze_all(log_types=[log_type], hours=hours)

    def get_available_log_types(self) -> list[dict]:
        """
        Get list of available log types with their requirements.

        Returns:
            List of dicts with log type info
        """
        log_info = [
            {
                "name": "Security",
                "description": "Security events (logins, privilege changes)",
                "requires_admin": True,
                "event_examples": [4624, 4625, 4672, 4720],
            },
            {
                "name": "System",
                "description": "System events (services, drivers)",
                "requires_admin": False,
                "event_examples": [7034, 7036, 7045],
            },
            {
                "name": "Application",
                "description": "Application events (crashes, errors)",
                "requires_admin": False,
                "event_examples": [1000, 1001, 1002],
            },
        ]
        return log_info

    def analyze_all_types(
        self,
        hours: int = 24,
        include_security: bool = True,
    ) -> LogAnalysisResult:
        """
        Analyze all log types (Security, System, Application) in one call.
        Sprint 10 - Convenience method for comprehensive analysis.

        Args:
            hours: Hours of logs to analyze
            include_security: Whether to include Security logs (requires admin)

        Returns:
            Combined analysis result from all log types
        """
        log_types = ["System", "Application"]

        # Only include Security if requested and we have admin access
        if include_security:
            has_admin, _ = self.check_admin_access()
            if has_admin:
                log_types.insert(0, "Security")
            else:
                logger.info("Skipping Security log - admin access required")

        return self.analyze_all(log_types=log_types, hours=hours)

    def safe_full_analysis(
        self,
        log_type: str = "Security",
        hours: int = 24,
    ) -> LogAnalysisResult:
        """
        Safe wrapper for full_analysis with error handling.
        Sprint 10 - Handles attribute and runtime errors gracefully.

        Args:
            log_type: Log to analyze ("Security", "System", "Application")
            hours: Hours of logs to analyze

        Returns:
            Analysis result or empty result on error
        """
        try:
            return self.full_analysis(log_type=log_type, hours=hours)
        except AttributeError as e:
            logger.error(f"Attribute error in full_analysis: {e}")
            return LogAnalysisResult(
                analyzed_logs=[log_type],
                time_range_hours=hours,
                total_events=0,
                anomalies=[],
                statistics={
                    "error": f"Attribute error: {e}",
                    "error_type": "AttributeError",
                },
            )
        except PermissionError as e:
            logger.error(f"Permission error in full_analysis: {e}")
            return LogAnalysisResult(
                analyzed_logs=[log_type],
                time_range_hours=hours,
                total_events=0,
                anomalies=[],
                statistics={
                    "error": f"Permission denied: {e}",
                    "admin_required": True,
                },
            )
        except Exception as e:
            logger.error(f"Unexpected error in full_analysis: {e}")
            return LogAnalysisResult(
                analyzed_logs=[log_type],
                time_range_hours=hours,
                total_events=0,
                anomalies=[],
                statistics={
                    "error": f"Unexpected error: {e}",
                    "error_type": type(e).__name__,
                },
            )

"""
BisonTitan Vulnerability Checker Module
Port scanning and vulnerability detection with REAL CVE enrichment.

Phase 4+ implementation - Uses python-nmap for port scanning,
registry checks for Windows configuration vulnerabilities,
and NVD API for real CVE lookups.
"""

import logging
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from bisontitan.config import VulnCheckerConfig
from bisontitan.utils import get_platform, is_admin

# Import threat intelligence for real CVE lookups
try:
    from bisontitan.threat_intel import (
        ThreatIntelligence,
        ServiceVulnMapper,
        CVEInfo,
    )
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False


logger = logging.getLogger("bisontitan.vuln")


# High-risk ports and their associated risks
HIGH_RISK_PORTS = {
    21: {"service": "FTP", "risk": "high", "reason": "Unencrypted file transfer, anonymous access possible"},
    22: {"service": "SSH", "risk": "medium", "reason": "Secure but brute-force target"},
    23: {"service": "Telnet", "risk": "critical", "reason": "Unencrypted, cleartext credentials"},
    25: {"service": "SMTP", "risk": "medium", "reason": "Email relay, spam potential"},
    53: {"service": "DNS", "risk": "medium", "reason": "DNS amplification attacks"},
    80: {"service": "HTTP", "risk": "low", "reason": "Unencrypted web traffic"},
    110: {"service": "POP3", "risk": "high", "reason": "Unencrypted email retrieval"},
    135: {"service": "RPC", "risk": "high", "reason": "Windows RPC, exploitation target"},
    137: {"service": "NetBIOS-NS", "risk": "high", "reason": "NetBIOS name service, info disclosure"},
    138: {"service": "NetBIOS-DGM", "risk": "high", "reason": "NetBIOS datagram service"},
    139: {"service": "NetBIOS-SSN", "risk": "high", "reason": "NetBIOS session, SMB over NetBIOS"},
    143: {"service": "IMAP", "risk": "high", "reason": "Unencrypted email access"},
    443: {"service": "HTTPS", "risk": "low", "reason": "Encrypted web traffic"},
    445: {"service": "SMB", "risk": "critical", "reason": "SMB direct, ransomware target (WannaCry, EternalBlue)"},
    1433: {"service": "MSSQL", "risk": "high", "reason": "Database exposure"},
    1434: {"service": "MSSQL-UDP", "risk": "high", "reason": "SQL Server Browser"},
    3306: {"service": "MySQL", "risk": "high", "reason": "Database exposure"},
    3389: {"service": "RDP", "risk": "critical", "reason": "Remote Desktop, brute-force and BlueKeep"},
    5432: {"service": "PostgreSQL", "risk": "high", "reason": "Database exposure"},
    5900: {"service": "VNC", "risk": "critical", "reason": "Remote access, often weak auth"},
    5985: {"service": "WinRM-HTTP", "risk": "high", "reason": "Windows Remote Management"},
    5986: {"service": "WinRM-HTTPS", "risk": "medium", "reason": "Windows Remote Management (encrypted)"},
    6379: {"service": "Redis", "risk": "critical", "reason": "Often no authentication"},
    8080: {"service": "HTTP-Alt", "risk": "medium", "reason": "Alternative HTTP, dev servers"},
    27017: {"service": "MongoDB", "risk": "critical", "reason": "Database exposure, often no auth"},
}

# Windows configuration checks
WINDOWS_CONFIG_CHECKS = {
    "uac_enabled": {
        "description": "User Account Control (UAC) enabled",
        "registry_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "registry_key": "EnableLUA",
        "expected_value": 1,
        "risk_if_fail": "high",
        "recommendation": "Enable UAC: Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA to 1",
    },
    "smbv1_disabled": {
        "description": "SMBv1 protocol disabled",
        "registry_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "registry_key": "SMB1",
        "expected_value": 0,
        "risk_if_fail": "critical",
        "recommendation": "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
    },
    "rdp_nla_enabled": {
        "description": "RDP Network Level Authentication enabled",
        "registry_path": r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "registry_key": "UserAuthentication",
        "expected_value": 1,
        "risk_if_fail": "high",
        "recommendation": "Enable NLA for RDP in System Properties > Remote",
    },
    "guest_account_disabled": {
        "description": "Guest account disabled",
        "registry_path": r"SAM\SAM\Domains\Account\Users\000001F5",
        "registry_key": "F",
        "check_type": "guest_disabled",
        "risk_if_fail": "medium",
        "recommendation": "Disable Guest account: net user guest /active:no",
    },
    "firewall_enabled": {
        "description": "Windows Firewall enabled",
        "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "registry_key": "EnableFirewall",
        "expected_value": 1,
        "risk_if_fail": "critical",
        "recommendation": "Enable Windows Firewall: netsh advfirewall set allprofiles state on",
    },
    "auto_updates_enabled": {
        "description": "Windows Update enabled",
        "registry_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "registry_key": "NoAutoUpdate",
        "expected_value": 0,
        "risk_if_fail": "high",
        "recommendation": "Enable Windows Update in Settings > Update & Security",
    },
}


@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int
    state: str  # "open", "closed", "filtered"
    service: str | None
    version: str | None
    risk_level: str  # "info", "low", "medium", "high", "critical"
    reason: str = ""
    vulnerabilities: list[str] = field(default_factory=list)
    cve_details: list[dict] = field(default_factory=list)  # Real CVE data from NVD

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "vulnerabilities": self.vulnerabilities,
            "cve_details": self.cve_details,
        }


@dataclass
class ConfigCheckResult:
    """Result of a configuration check."""
    name: str
    description: str
    passed: bool
    current_value: Any
    expected_value: Any
    risk_level: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "passed": self.passed,
            "current_value": self.current_value,
            "expected_value": self.expected_value,
            "risk_level": self.risk_level if not self.passed else "none",
            "recommendation": self.recommendation if not self.passed else "",
        }


@dataclass
class VulnCheckResult:
    """Result of vulnerability check."""
    target: str
    scan_time: datetime
    open_ports: list[PortResult]
    config_checks: list[ConfigCheckResult]
    vulnerabilities: list[dict]
    recommendations: list[str]
    risk_score: float  # 0-10
    scan_duration_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "scan_time": self.scan_time.isoformat(),
            "open_ports": [p.to_dict() for p in self.open_ports],
            "config_checks": [c.to_dict() for c in self.config_checks],
            "vulnerabilities": self.vulnerabilities,
            "recommendations": self.recommendations,
            "risk_score": self.risk_score,
            "scan_duration_sec": self.scan_duration_sec,
        }

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            "# BisonTitan Vulnerability Report",
            "",
            f"**Target:** {self.target}",
            f"**Scan Time:** {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {self.scan_duration_sec:.1f}s",
            f"**Risk Score:** {self.risk_score:.1f}/10",
            "",
            "## Summary",
            "",
            f"- **Open Ports:** {len(self.open_ports)}",
            f"- **Critical Risks:** {sum(1 for p in self.open_ports if p.risk_level == 'critical')}",
            f"- **High Risks:** {sum(1 for p in self.open_ports if p.risk_level == 'high')}",
            f"- **Config Issues:** {sum(1 for c in self.config_checks if not c.passed)}",
            "",
        ]

        # Open ports table
        if self.open_ports:
            lines.extend([
                "## Open Ports",
                "",
                "| Port | Service | Risk | Reason |",
                "|------|---------|------|--------|",
            ])
            for port in sorted(self.open_ports, key=lambda p: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(p.risk_level, 4)):
                risk_emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(port.risk_level, "")
                lines.append(f"| {port.port} | {port.service or 'unknown'} | {risk_emoji} {port.risk_level.upper()} | {port.reason} |")
            lines.append("")

        # CVE Details section (from real NVD lookups)
        ports_with_cves = [p for p in self.open_ports if p.cve_details]
        if ports_with_cves:
            lines.extend([
                "## Detected CVEs (from NVD)",
                "",
            ])
            for port in ports_with_cves:
                lines.append(f"### {port.service or 'Unknown'} (Port {port.port})")
                lines.append("")
                for cve in port.cve_details[:5]:  # Limit to top 5
                    exploit_warn = " **EXPLOIT AVAILABLE**" if cve.get("exploit_available") else ""
                    lines.append(f"- **{cve['cve_id']}** [{cve['severity']}] (CVSS: {cve.get('cvss_score', 'N/A')}){exploit_warn}")
                    lines.append(f"  - {cve.get('description', 'No description')}")
                    if cve.get("references"):
                        lines.append(f"  - Refs: {cve['references'][0]}")
                lines.append("")

        # Configuration checks
        failed_checks = [c for c in self.config_checks if not c.passed]
        if failed_checks:
            lines.extend([
                "## Configuration Issues",
                "",
                "| Check | Risk | Recommendation |",
                "|-------|------|----------------|",
            ])
            for check in failed_checks:
                risk_emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡"}.get(check.risk_level, "")
                lines.append(f"| {check.description} | {risk_emoji} {check.risk_level.upper()} | {check.recommendation} |")
            lines.append("")

        # Recommendations
        if self.recommendations:
            lines.extend([
                "## Recommended Actions",
                "",
            ])
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Firewall rules for critical ports
        critical_ports = [p for p in self.open_ports if p.risk_level in ["critical", "high"]]
        if critical_ports:
            lines.extend([
                "## Suggested Firewall Rules",
                "",
                "```powershell",
            ])
            for port in critical_ports:
                service_name = port.service or f"Port{port.port}"
                lines.append(f"# Block {service_name} ({port.port})")
                lines.append(f"netsh advfirewall firewall add rule name=\"Block {service_name}\" dir=in action=block protocol=TCP localport={port.port}")
            lines.extend([
                "```",
                "",
            ])

        return "\n".join(lines)


class VulnChecker:
    """
    Checks for common vulnerabilities and misconfigurations.

    Uses python-nmap for port scanning and custom checks
    for common Windows vulnerabilities.
    """

    def __init__(self, config: VulnCheckerConfig | None = None):
        """
        Initialize vulnerability checker.

        Args:
            config: Vulnerability checker configuration
        """
        self.config = config or VulnCheckerConfig()
        self._nmap_available = False
        self._winreg_available = False

        try:
            import nmap
            self._nmap_available = True
        except ImportError:
            logger.warning("python-nmap not available. Using socket-based scanning.")

        if get_platform() == "windows":
            try:
                import winreg
                self._winreg_available = True
            except ImportError:
                pass

        # Initialize threat intelligence for CVE enrichment
        self._threat_intel = None
        if THREAT_INTEL_AVAILABLE:
            try:
                self._threat_intel = ThreatIntelligence()
                logger.info("Threat intelligence enabled for CVE enrichment")
            except Exception as e:
                logger.warning(f"Threat intelligence unavailable: {e}")

    def enrich_with_cves(self, port_results: list[PortResult]) -> list[PortResult]:
        """
        Enrich port scan results with real CVE data from NVD.

        Args:
            port_results: List of scanned ports to enrich

        Returns:
            Port results with CVE information added
        """
        if not self._threat_intel:
            logger.debug("Threat intel not available, skipping CVE enrichment")
            return port_results

        for port in port_results:
            if port.service and port.state == "open":
                try:
                    # Look up CVEs for this service/version
                    cves = self._threat_intel.get_service_vulns(
                        service=port.service,
                        version=port.version,
                        limit=5
                    )

                    for cve in cves:
                        # Add CVE ID to simple vulnerabilities list
                        cve_summary = f"{cve.cve_id} ({cve.severity})"
                        if cve_summary not in port.vulnerabilities:
                            port.vulnerabilities.append(cve_summary)

                        # Add detailed CVE info
                        port.cve_details.append({
                            "cve_id": cve.cve_id,
                            "severity": cve.severity,
                            "cvss_score": cve.cvss_score,
                            "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                            "exploit_available": cve.exploit_available,
                            "references": cve.references[:3],
                        })

                    # Upgrade risk level if critical CVEs found
                    if cves:
                        max_severity = max(
                            cves, key=lambda c: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(c.severity, 0)
                        ).severity
                        if max_severity == "CRITICAL":
                            port.risk_level = "critical"
                        elif max_severity == "HIGH" and port.risk_level not in ["critical"]:
                            port.risk_level = "high"

                    logger.info(f"Found {len(cves)} CVEs for {port.service}:{port.port}")

                except Exception as e:
                    logger.debug(f"CVE lookup failed for {port.service}: {e}")

        return port_results

    def _parse_port_range(self, ports: str) -> list[int]:
        """Parse port range string to list of ports."""
        port_list = []
        for part in ports.split(","):
            if "-" in part:
                start, end = part.split("-")
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        return port_list

    def scan_ports_socket(self, target: str, ports: str = "1-1024", timeout: float = 0.5) -> list[PortResult]:
        """
        Scan ports using socket (fallback when nmap not available).

        Args:
            target: Target IP or hostname
            ports: Port range (e.g., "1-1024" or "22,80,443")
            timeout: Socket timeout in seconds

        Returns:
            List of PortResult for open ports
        """
        results = []
        port_list = self._parse_port_range(ports)

        # Limit ports for socket scanning
        if len(port_list) > 1000:
            logger.warning("Socket scanning limited to first 1000 ports")
            port_list = port_list[:1000]

        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    port_info = HIGH_RISK_PORTS.get(port, {})
                    results.append(PortResult(
                        port=port,
                        state="open",
                        service=port_info.get("service", self._guess_service(port)),
                        version=None,
                        risk_level=port_info.get("risk", "low"),
                        reason=port_info.get("reason", "Open port detected"),
                    ))
            except socket.error:
                pass

        return results

    def _guess_service(self, port: int) -> str:
        """Guess service name from common port numbers."""
        common_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
            993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql",
        }
        return common_ports.get(port, f"unknown-{port}")

    def scan_ports(self, target: str, ports: str = "1-1024") -> list[PortResult]:
        """
        Scan ports on target.

        Args:
            target: Target IP or hostname
            ports: Port range (e.g., "1-1024" or "22,80,443")

        Returns:
            List of PortResult for open ports
        """
        if not self._nmap_available:
            logger.info("Using socket-based scanning (nmap not available)")
            return self.scan_ports_socket(target, ports)

        import nmap

        results = []
        nm = nmap.PortScanner()

        try:
            # Use arguments from config
            arguments = self.config.nmap_arguments if hasattr(self.config, 'nmap_arguments') else "-sV"
            nm.scan(target, ports, arguments=arguments)

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports_list = nm[host][proto].keys()
                    for port in ports_list:
                        port_data = nm[host][proto][port]
                        state = port_data.get("state", "unknown")

                        if state == "open":
                            service = port_data.get("name", "unknown")
                            version = port_data.get("version", "")
                            product = port_data.get("product", "")
                            version_str = f"{product} {version}".strip() if product or version else None

                            port_info = HIGH_RISK_PORTS.get(port, {})
                            risk = port_info.get("risk", "low")
                            reason = port_info.get("reason", f"{service} service open")

                            results.append(PortResult(
                                port=port,
                                state=state,
                                service=service,
                                version=version_str,
                                risk_level=risk,
                                reason=reason,
                            ))

        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {e}")
            # Fallback to socket scanning
            return self.scan_ports_socket(target, ports)
        except Exception as e:
            logger.error(f"Scan error: {e}")
            raise

        return results

    def check_netbios(self, target: str) -> dict[str, Any]:
        """
        Check for NetBIOS exposure.

        Args:
            target: Target IP

        Returns:
            NetBIOS check results
        """
        result = {
            "exposed": False,
            "ports": [],
            "risk_level": "none",
            "recommendation": "",
        }

        netbios_ports = [137, 138, 139]

        for port in netbios_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target, port)) == 0:
                    result["exposed"] = True
                    result["ports"].append(port)
                sock.close()
            except socket.error:
                pass

        if result["exposed"]:
            result["risk_level"] = "high"
            result["recommendation"] = (
                "Disable NetBIOS over TCP/IP in network adapter settings, "
                "or block ports 137-139 with firewall rules"
            )

        return result

    def check_smb(self, target: str) -> dict[str, Any]:
        """
        Check for SMB vulnerabilities.

        Args:
            target: Target IP

        Returns:
            SMB check results
        """
        result = {
            "exposed": False,
            "port_445_open": False,
            "risk_level": "none",
            "recommendation": "",
            "vulnerabilities": [],
        }

        # Check port 445
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((target, 445)) == 0:
                result["exposed"] = True
                result["port_445_open"] = True
                result["risk_level"] = "critical"
                result["vulnerabilities"].append("SMB port 445 exposed - potential EternalBlue/WannaCry target")
                result["recommendation"] = (
                    "Block port 445: netsh advfirewall firewall add rule "
                    "name='Block SMB' dir=in action=block protocol=TCP localport=445"
                )
            sock.close()
        except socket.error:
            pass

        return result

    def check_rdp(self, target: str) -> dict[str, Any]:
        """
        Check for RDP vulnerabilities.

        Args:
            target: Target IP

        Returns:
            RDP check results
        """
        result = {
            "exposed": False,
            "port_3389_open": False,
            "risk_level": "none",
            "recommendation": "",
            "vulnerabilities": [],
        }

        # Check port 3389
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((target, 3389)) == 0:
                result["exposed"] = True
                result["port_3389_open"] = True
                result["risk_level"] = "critical"
                result["vulnerabilities"].extend([
                    "RDP port 3389 exposed",
                    "Potential BlueKeep vulnerability (CVE-2019-0708)",
                    "Brute-force attack target",
                ])
                result["recommendation"] = (
                    "Restrict RDP access via firewall, enable NLA, use VPN for remote access. "
                    "Block external: netsh advfirewall firewall add rule "
                    "name='Block RDP External' dir=in action=block protocol=TCP localport=3389"
                )
            sock.close()
        except socket.error:
            pass

        return result

    def check_windows_config(self) -> list[ConfigCheckResult]:
        """
        Check Windows configuration for security issues.

        Returns:
            List of configuration check results
        """
        if not self._winreg_available:
            logger.warning("Windows registry access not available")
            return []

        import winreg

        results = []

        for check_name, check_info in WINDOWS_CONFIG_CHECKS.items():
            try:
                # Try to read registry value
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    check_info["registry_path"],
                    0,
                    winreg.KEY_READ
                )

                try:
                    value, _ = winreg.QueryValueEx(key, check_info["registry_key"])
                except FileNotFoundError:
                    value = None

                winreg.CloseKey(key)

                # Special check types
                if check_info.get("check_type") == "guest_disabled":
                    # Guest account check is complex, simplified here
                    passed = True  # Assume passed if we can't check
                    current_value = "Could not verify"
                else:
                    expected = check_info.get("expected_value")
                    passed = value == expected
                    current_value = value

                results.append(ConfigCheckResult(
                    name=check_name,
                    description=check_info["description"],
                    passed=passed,
                    current_value=current_value,
                    expected_value=check_info.get("expected_value"),
                    risk_level=check_info["risk_if_fail"],
                    recommendation=check_info["recommendation"],
                ))

            except PermissionError:
                results.append(ConfigCheckResult(
                    name=check_name,
                    description=check_info["description"],
                    passed=False,
                    current_value="Access Denied",
                    expected_value=check_info.get("expected_value"),
                    risk_level="info",
                    recommendation="Run as Administrator to check this setting",
                ))
            except FileNotFoundError:
                # Registry key doesn't exist - may indicate the feature isn't installed
                results.append(ConfigCheckResult(
                    name=check_name,
                    description=check_info["description"],
                    passed=True,  # If key doesn't exist, often means default/safe
                    current_value="Not Configured",
                    expected_value=check_info.get("expected_value"),
                    risk_level="info",
                    recommendation="",
                ))
            except Exception as e:
                logger.debug(f"Config check {check_name} failed: {e}")

        return results

    def check_config_simple(self) -> list[ConfigCheckResult]:
        """
        Perform simple configuration checks without registry access.

        Uses PowerShell/command line tools available on Windows.
        """
        results = []

        if get_platform() != "windows":
            return results

        # Check Windows Firewall status
        try:
            output = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True,
                text=True,
                timeout=10
            )
            firewall_on = "ON" in output.stdout.upper()
            results.append(ConfigCheckResult(
                name="firewall_enabled",
                description="Windows Firewall enabled",
                passed=firewall_on,
                current_value="ON" if firewall_on else "OFF",
                expected_value="ON",
                risk_level="critical",
                recommendation="Enable firewall: netsh advfirewall set allprofiles state on",
            ))
        except Exception as e:
            logger.debug(f"Firewall check failed: {e}")

        # Check SMBv1 status
        try:
            output = subprocess.run(
                ["powershell", "-Command", "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol"],
                capture_output=True,
                text=True,
                timeout=10
            )
            smb1_disabled = "False" in output.stdout
            results.append(ConfigCheckResult(
                name="smbv1_disabled",
                description="SMBv1 protocol disabled",
                passed=smb1_disabled,
                current_value="Disabled" if smb1_disabled else "Enabled",
                expected_value="Disabled",
                risk_level="critical",
                recommendation="Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            ))
        except Exception as e:
            logger.debug(f"SMBv1 check failed: {e}")

        return results

    def calculate_risk_score(
        self,
        open_ports: list[PortResult],
        config_checks: list[ConfigCheckResult]
    ) -> float:
        """
        Calculate overall risk score (0-10).

        Args:
            open_ports: List of open port results
            config_checks: List of configuration check results

        Returns:
            Risk score from 0 (safe) to 10 (critical)
        """
        score = 0.0

        # Port risk weights
        port_weights = {"critical": 2.5, "high": 1.5, "medium": 0.75, "low": 0.25}
        for port in open_ports:
            score += port_weights.get(port.risk_level, 0)

        # Config check weights
        config_weights = {"critical": 2.0, "high": 1.0, "medium": 0.5}
        for check in config_checks:
            if not check.passed:
                score += config_weights.get(check.risk_level, 0)

        # Cap at 10
        return min(10.0, score)

    def generate_recommendations(
        self,
        open_ports: list[PortResult],
        config_checks: list[ConfigCheckResult]
    ) -> list[str]:
        """
        Generate prioritized recommendations.

        Args:
            open_ports: List of open port results
            config_checks: List of configuration check results

        Returns:
            List of recommendations sorted by priority
        """
        recommendations = []

        # Critical port recommendations
        critical_ports = [p for p in open_ports if p.risk_level == "critical"]
        if critical_ports:
            port_list = ", ".join(str(p.port) for p in critical_ports)
            recommendations.append(f"CRITICAL: Block exposed high-risk ports ({port_list}) immediately")

        # Specific port recommendations
        smb_open = any(p.port == 445 for p in open_ports)
        if smb_open:
            recommendations.append(
                "Block SMB (445): netsh advfirewall firewall add rule "
                "name='Block SMB' dir=in action=block protocol=TCP localport=445"
            )

        rdp_open = any(p.port == 3389 for p in open_ports)
        if rdp_open:
            recommendations.append(
                "Secure RDP: Enable NLA, use VPN, restrict access by IP, or disable if not needed"
            )

        netbios_open = any(p.port in [137, 138, 139] for p in open_ports)
        if netbios_open:
            recommendations.append(
                "Disable NetBIOS: In Network Adapter Properties > IPv4 > Advanced > WINS"
            )

        # Config recommendations
        for check in config_checks:
            if not check.passed and check.recommendation:
                recommendations.append(check.recommendation)

        # General recommendations
        if len(open_ports) > 10:
            recommendations.append("Consider implementing a deny-by-default firewall policy")

        return recommendations

    def full_scan(self, target: str, ports: str | None = None) -> VulnCheckResult:
        """
        Run full vulnerability scan.

        Args:
            target: Target IP or hostname
            ports: Port range (default from config)

        Returns:
            Complete vulnerability check result
        """
        start_time = datetime.now()
        ports = ports or self.config.port_ranges

        # Port scan
        logger.info(f"Scanning ports {ports} on {target}")
        open_ports = self.scan_ports(target, ports)

        # Enrich with real CVE data from NVD
        if self.config.enrich_cves if hasattr(self.config, 'enrich_cves') else True:
            logger.info("Enriching scan results with CVE data from NVD...")
            open_ports = self.enrich_with_cves(open_ports)

        # Service-specific checks
        vulnerabilities = []

        if self.config.check_netbios:
            netbios = self.check_netbios(target)
            if netbios["exposed"]:
                vulnerabilities.append({
                    "type": "netbios_exposure",
                    "severity": netbios["risk_level"],
                    "details": f"NetBIOS ports exposed: {netbios['ports']}",
                    "recommendation": netbios["recommendation"],
                })

        if self.config.check_smb:
            smb = self.check_smb(target)
            if smb["exposed"]:
                vulnerabilities.append({
                    "type": "smb_exposure",
                    "severity": smb["risk_level"],
                    "details": "; ".join(smb["vulnerabilities"]),
                    "recommendation": smb["recommendation"],
                })

        if self.config.check_rdp:
            rdp = self.check_rdp(target)
            if rdp["exposed"]:
                vulnerabilities.append({
                    "type": "rdp_exposure",
                    "severity": rdp["risk_level"],
                    "details": "; ".join(rdp["vulnerabilities"]),
                    "recommendation": rdp["recommendation"],
                })

        # Config checks (localhost only)
        config_checks = []
        if target in ["127.0.0.1", "localhost", socket.gethostname()]:
            if is_admin():
                config_checks = self.check_windows_config()
            else:
                config_checks = self.check_config_simple()

        # Calculate risk score and generate recommendations
        risk_score = self.calculate_risk_score(open_ports, config_checks)
        recommendations = self.generate_recommendations(open_ports, config_checks)

        duration = (datetime.now() - start_time).total_seconds()

        return VulnCheckResult(
            target=target,
            scan_time=start_time,
            open_ports=open_ports,
            config_checks=config_checks,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            risk_score=risk_score,
            scan_duration_sec=duration,
        )

    def quick_scan(self, target: str) -> VulnCheckResult:
        """
        Run quick scan of common vulnerable ports only.

        Args:
            target: Target IP or hostname

        Returns:
            Vulnerability check result
        """
        # Scan only high-risk ports
        high_risk_port_list = ",".join(str(p) for p in HIGH_RISK_PORTS.keys())
        return self.full_scan(target, high_risk_port_list)

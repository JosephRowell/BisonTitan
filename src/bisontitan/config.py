"""
BisonTitan Configuration Module
Handles loading and managing YAML configuration files.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ScannerConfig:
    """Configuration for file/process scanner."""
    yara_rules_dir: Path = field(default_factory=lambda: Path("config/rules"))
    quarantine_dir: Path = field(default_factory=lambda: Path("quarantine"))
    hash_check_enabled: bool = True
    yara_scan_enabled: bool = True
    scan_archives: bool = False
    max_file_size_mb: int = 100
    excluded_paths: list[str] = field(default_factory=list)
    excluded_extensions: list[str] = field(default_factory=lambda: [".dll", ".sys"])
    known_malware_hashes: list[str] = field(default_factory=list)


@dataclass
class TrafficConfig:
    """Configuration for network traffic analyzer."""
    capture_duration_sec: int = 5
    interface: str | None = None
    proxy_whitelist: list[str] = field(default_factory=list)
    trusted_domains: list[str] = field(default_factory=list)
    high_risk_ports: list[int] = field(default_factory=lambda: [
        4444, 5555, 6666, 31337, 12345, 6667, 6697  # Common malware ports
    ])
    abuseipdb_api_key: str | None = None
    enable_threat_feeds: bool = False


@dataclass
class FingerprintConfig:
    """Configuration for fingerprint viewer."""
    browser_type: str = "chromium"
    headless: bool = True
    user_agent: str | None = None
    viewport_width: int = 1920
    viewport_height: int = 1080
    proxy: str | None = None
    gologin_api_key: str | None = None  # Or use GOLOGIN_API_KEY env var
    default_profile: str | None = None  # Default GoLogin profile name
    simulate_mode: bool = False  # Use local simulation by default


@dataclass
class LogAnalyzerConfig:
    """Configuration for Windows log analyzer."""
    event_logs: list[str] = field(default_factory=lambda: ["Security", "System", "Application"])
    failed_login_threshold: int = 5
    time_window_minutes: int = 15
    alert_on_admin_login: bool = True
    excluded_users: list[str] = field(default_factory=list)


@dataclass
class VulnCheckerConfig:
    """Configuration for vulnerability checker."""
    target_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1"])
    port_ranges: str = "1-1024"
    check_netbios: bool = True
    check_smb: bool = True
    check_rdp: bool = True
    nmap_arguments: str = "-sV -sC"


@dataclass
class AttackSimConfig:
    """Configuration for attack simulation."""
    enabled_scenarios: list[str] = field(default_factory=lambda: [
        "port_scan", "smb_probe", "weak_auth"
    ])
    target_host: str = "127.0.0.1"
    safe_mode: bool = True
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    require_confirmation: bool = True


@dataclass
class Config:
    """Main BisonTitan configuration."""
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    traffic: TrafficConfig = field(default_factory=TrafficConfig)
    fingerprint: FingerprintConfig = field(default_factory=FingerprintConfig)
    log_analyzer: LogAnalyzerConfig = field(default_factory=LogAnalyzerConfig)
    vuln_checker: VulnCheckerConfig = field(default_factory=VulnCheckerConfig)
    attack_sim: AttackSimConfig = field(default_factory=AttackSimConfig)

    # Global settings
    log_file: Path = field(default_factory=lambda: Path("logs/bisontitan.log"))
    log_level: str = "INFO"
    require_admin: bool = False

    @classmethod
    def load(cls, config_path: Path | str) -> "Config":
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to YAML config file

        Returns:
            Config instance with loaded values
        """
        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return cls._from_dict(data)

    @classmethod
    def load_or_default(cls, config_path: Path | str | None = None) -> "Config":
        """
        Load configuration from file or return defaults.

        Args:
            config_path: Optional path to config file

        Returns:
            Config instance
        """
        if config_path is None:
            # Check default locations
            default_paths = [
                Path("config/config.yaml"),
                Path("config.yaml"),
                Path.home() / ".config" / "bisontitan" / "config.yaml",
            ]
            for path in default_paths:
                if path.exists():
                    return cls.load(path)
            return cls()

        return cls.load(config_path)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "Config":
        """Create Config from dictionary."""
        config = cls()

        # Scanner config
        if "scanner" in data:
            sc = data["scanner"]
            config.scanner = ScannerConfig(
                yara_rules_dir=Path(sc.get("yara_rules_dir", "config/rules")),
                quarantine_dir=Path(sc.get("quarantine_dir", "quarantine")),
                hash_check_enabled=sc.get("hash_check_enabled", True),
                yara_scan_enabled=sc.get("yara_scan_enabled", True),
                scan_archives=sc.get("scan_archives", False),
                max_file_size_mb=sc.get("max_file_size_mb", 100),
                excluded_paths=sc.get("excluded_paths", []),
                excluded_extensions=sc.get("excluded_extensions", [".dll", ".sys"]),
                known_malware_hashes=sc.get("known_malware_hashes", []),
            )

        # Traffic config
        if "traffic" in data:
            tc = data["traffic"]
            config.traffic = TrafficConfig(
                capture_duration_sec=tc.get("capture_duration_sec", 5),
                interface=tc.get("interface"),
                proxy_whitelist=tc.get("proxy_whitelist", []),
                trusted_domains=tc.get("trusted_domains", []),
                high_risk_ports=tc.get("high_risk_ports", [4444, 5555, 6666, 31337, 12345, 6667, 6697]),
                abuseipdb_api_key=tc.get("abuseipdb_api_key"),
                enable_threat_feeds=tc.get("enable_threat_feeds", False),
            )

        # Fingerprint config
        if "fingerprint" in data:
            fc = data["fingerprint"]
            config.fingerprint = FingerprintConfig(
                browser_type=fc.get("browser_type", "chromium"),
                headless=fc.get("headless", True),
                user_agent=fc.get("user_agent"),
                viewport_width=fc.get("viewport_width", 1920),
                viewport_height=fc.get("viewport_height", 1080),
                proxy=fc.get("proxy"),
                gologin_api_key=fc.get("gologin_api_key") or os.environ.get("GOLOGIN_API_KEY"),
                default_profile=fc.get("default_profile"),
                simulate_mode=fc.get("simulate_mode", False),
            )

        # Log analyzer config
        if "log_analyzer" in data:
            lc = data["log_analyzer"]
            config.log_analyzer = LogAnalyzerConfig(
                event_logs=lc.get("event_logs", ["Security", "System", "Application"]),
                failed_login_threshold=lc.get("failed_login_threshold", 5),
                time_window_minutes=lc.get("time_window_minutes", 15),
                alert_on_admin_login=lc.get("alert_on_admin_login", True),
                excluded_users=lc.get("excluded_users", []),
            )

        # Vuln checker config
        if "vuln_checker" in data:
            vc = data["vuln_checker"]
            config.vuln_checker = VulnCheckerConfig(
                target_hosts=vc.get("target_hosts", ["127.0.0.1"]),
                port_ranges=vc.get("port_ranges", "1-1024"),
                check_netbios=vc.get("check_netbios", True),
                check_smb=vc.get("check_smb", True),
                check_rdp=vc.get("check_rdp", True),
                nmap_arguments=vc.get("nmap_arguments", "-sV -sC"),
            )

        # Attack sim config
        if "attack_sim" in data:
            ac = data["attack_sim"]
            config.attack_sim = AttackSimConfig(
                enabled_scenarios=ac.get("enabled_scenarios", ["port_scan", "smb_probe", "weak_auth"]),
                target_host=ac.get("target_host", "127.0.0.1"),
                safe_mode=ac.get("safe_mode", True),
                output_dir=Path(ac.get("output_dir", "reports")),
                require_confirmation=ac.get("require_confirmation", True),
            )

        # Global settings
        config.log_file = Path(data.get("log_file", "logs/bisontitan.log"))
        config.log_level = data.get("log_level", "INFO")
        config.require_admin = data.get("require_admin", False)

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary for serialization."""
        return {
            "log_file": str(self.log_file),
            "log_level": self.log_level,
            "require_admin": self.require_admin,
            "scanner": {
                "yara_rules_dir": str(self.scanner.yara_rules_dir),
                "quarantine_dir": str(self.scanner.quarantine_dir),
                "hash_check_enabled": self.scanner.hash_check_enabled,
                "yara_scan_enabled": self.scanner.yara_scan_enabled,
                "scan_archives": self.scanner.scan_archives,
                "max_file_size_mb": self.scanner.max_file_size_mb,
                "excluded_paths": self.scanner.excluded_paths,
                "excluded_extensions": self.scanner.excluded_extensions,
                "known_malware_hashes": self.scanner.known_malware_hashes,
            },
            "traffic": {
                "capture_duration_sec": self.traffic.capture_duration_sec,
                "interface": self.traffic.interface,
                "proxy_whitelist": self.traffic.proxy_whitelist,
                "trusted_domains": self.traffic.trusted_domains,
                "high_risk_ports": self.traffic.high_risk_ports,
                "abuseipdb_api_key": self.traffic.abuseipdb_api_key,
                "enable_threat_feeds": self.traffic.enable_threat_feeds,
            },
            "fingerprint": {
                "browser_type": self.fingerprint.browser_type,
                "headless": self.fingerprint.headless,
                "user_agent": self.fingerprint.user_agent,
                "viewport_width": self.fingerprint.viewport_width,
                "viewport_height": self.fingerprint.viewport_height,
                "proxy": self.fingerprint.proxy,
                "gologin_api_key": self.fingerprint.gologin_api_key,
                "default_profile": self.fingerprint.default_profile,
                "simulate_mode": self.fingerprint.simulate_mode,
            },
            "log_analyzer": {
                "event_logs": self.log_analyzer.event_logs,
                "failed_login_threshold": self.log_analyzer.failed_login_threshold,
                "time_window_minutes": self.log_analyzer.time_window_minutes,
                "alert_on_admin_login": self.log_analyzer.alert_on_admin_login,
                "excluded_users": self.log_analyzer.excluded_users,
            },
            "vuln_checker": {
                "target_hosts": self.vuln_checker.target_hosts,
                "port_ranges": self.vuln_checker.port_ranges,
                "check_netbios": self.vuln_checker.check_netbios,
                "check_smb": self.vuln_checker.check_smb,
                "check_rdp": self.vuln_checker.check_rdp,
                "nmap_arguments": self.vuln_checker.nmap_arguments,
            },
            "attack_sim": {
                "enabled_scenarios": self.attack_sim.enabled_scenarios,
                "target_host": self.attack_sim.target_host,
                "safe_mode": self.attack_sim.safe_mode,
                "output_dir": str(self.attack_sim.output_dir),
                "require_confirmation": self.attack_sim.require_confirmation,
            },
        }

    def save(self, config_path: Path | str) -> None:
        """Save configuration to YAML file."""
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)

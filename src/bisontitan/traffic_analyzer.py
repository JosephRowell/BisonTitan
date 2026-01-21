"""
BisonTitan Traffic Analyzer Module
Network traffic capture and analysis with threat detection.

Features:
    - Packet capture via scapy
    - IP geolocation (stub + optional geocoder)
    - Threat intelligence via AbuseIPDB (opt-in)
    - High-risk port detection
    - Proxy/VPN whitelist support
"""

import ipaddress
import logging
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Generator

import requests
from dotenv import load_dotenv

from bisontitan.config import TrafficConfig

# Load environment variables
load_dotenv()

logger = logging.getLogger("bisontitan.traffic")

# Check for scapy availability
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, ICMP, sniff, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("scapy not installed. Install with: pip install scapy")

# Check for geocoder availability
GEOCODER_AVAILABLE = False
try:
    import geocoder
    GEOCODER_AVAILABLE = True
except ImportError:
    logger.debug("geocoder not installed. GeoIP will use stub. Install with: pip install geocoder")


class TrafficCategory(Enum):
    """Categories for network traffic classification."""
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    WHITELISTED = "whitelisted"
    UNKNOWN = "unknown"


@dataclass
class PacketInfo:
    """Information about a captured packet."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    size: int
    flags: str | None = None
    payload_preview: str | None = None
    raw_packet: Any = None  # Store raw scapy packet for advanced analysis

    def to_dict(self) -> dict:
        """Convert to dictionary (excluding raw packet)."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "size": self.size,
            "flags": self.flags,
            "payload_preview": self.payload_preview,
        }


@dataclass
class GeoInfo:
    """Geographic information for an IP address."""
    ip: str
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    region: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    isp: str | None = None
    org: str | None = None
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "region": self.region,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "isp": self.isp,
            "org": self.org,
            "is_proxy": self.is_proxy,
            "is_vpn": self.is_vpn,
            "is_tor": self.is_tor,
        }


@dataclass
class ThreatIntel:
    """Threat intelligence data for an IP address."""
    ip: str
    is_malicious: bool = False
    abuse_confidence: int = 0  # 0-100 from AbuseIPDB
    total_reports: int = 0
    last_reported: datetime | None = None
    categories: list[str] = field(default_factory=list)
    source: str = "unknown"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "is_malicious": self.is_malicious,
            "abuse_confidence": self.abuse_confidence,
            "total_reports": self.total_reports,
            "last_reported": self.last_reported.isoformat() if self.last_reported else None,
            "categories": self.categories,
            "source": self.source,
        }


@dataclass
class TrafficLabel:
    """Complete label for network traffic."""
    ip: str
    category: TrafficCategory
    confidence: float  # 0.0 - 1.0
    reasons: list[str] = field(default_factory=list)
    geo_info: GeoInfo | None = None
    threat_intel: ThreatIntel | None = None
    risk_score: int = 0  # 0-100

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "category": self.category.value,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "geo_info": self.geo_info.to_dict() if self.geo_info else None,
            "threat_intel": self.threat_intel.to_dict() if self.threat_intel else None,
            "risk_score": self.risk_score,
        }


@dataclass
class CaptureStats:
    """Statistics from a packet capture session."""
    duration_sec: float
    total_packets: int
    unique_ips: set[str] = field(default_factory=set)
    protocols: dict[str, int] = field(default_factory=dict)
    suspicious_count: int = 0
    malicious_count: int = 0
    whitelisted_count: int = 0
    bytes_captured: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "duration_sec": self.duration_sec,
            "total_packets": self.total_packets,
            "unique_ips": len(self.unique_ips),
            "protocols": self.protocols,
            "suspicious_count": self.suspicious_count,
            "malicious_count": self.malicious_count,
            "whitelisted_count": self.whitelisted_count,
            "bytes_captured": self.bytes_captured,
        }


class AbuseIPDBClient:
    """
    Client for AbuseIPDB threat intelligence API.

    Free tier: 1000 checks/day
    Docs: https://docs.abuseipdb.com/
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str | None = None):
        """
        Initialize AbuseIPDB client.

        Args:
            api_key: API key (or set ABUSEIPDB_API_KEY env var)
        """
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self._enabled = bool(self.api_key and self.api_key.strip())
        self._cache: dict[str, ThreatIntel] = {}

        if not self._enabled:
            logger.info("AbuseIPDB API key not configured. Threat intel disabled.")

    @property
    def is_enabled(self) -> bool:
        """Check if API is configured."""
        return self._enabled

    def check_ip(self, ip: str, max_age_days: int = 90) -> ThreatIntel:
        """
        Check IP against AbuseIPDB.

        Args:
            ip: IP address to check
            max_age_days: Max age of reports to consider

        Returns:
            ThreatIntel with results
        """
        # Return cached result if available
        if ip in self._cache:
            return self._cache[ip]

        # Return empty result if not enabled
        if not self._enabled:
            return ThreatIntel(ip=ip, source="none")

        # Skip private IPs
        try:
            if ipaddress.ip_address(ip).is_private:
                return ThreatIntel(ip=ip, source="private_ip")
        except ValueError:
            return ThreatIntel(ip=ip, source="invalid_ip")

        try:
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True,
                },
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            # Map AbuseIPDB categories to readable names
            category_map = {
                1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
                4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
                7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
                11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
                15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
                18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
                21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
            }

            categories = []
            for report in data.get("reports", [])[:5]:  # Limit to recent 5
                for cat_id in report.get("categories", []):
                    cat_name = category_map.get(cat_id, f"Category-{cat_id}")
                    if cat_name not in categories:
                        categories.append(cat_name)

            last_reported = None
            if data.get("lastReportedAt"):
                try:
                    last_reported = datetime.fromisoformat(
                        data["lastReportedAt"].replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass

            result = ThreatIntel(
                ip=ip,
                is_malicious=data.get("abuseConfidenceScore", 0) >= 50,
                abuse_confidence=data.get("abuseConfidenceScore", 0),
                total_reports=data.get("totalReports", 0),
                last_reported=last_reported,
                categories=categories,
                source="abuseipdb",
            )

            # Cache the result
            self._cache[ip] = result
            return result

        except requests.RequestException as e:
            logger.warning(f"AbuseIPDB API error for {ip}: {e}")
            return ThreatIntel(ip=ip, source="error")


class GeoIPLookup:
    """
    Geographic IP lookup using geocoder or stub.
    """

    def __init__(self):
        """Initialize GeoIP lookup."""
        self._cache: dict[str, GeoInfo] = {}

    def lookup(self, ip: str) -> GeoInfo:
        """
        Look up geographic info for an IP.

        Args:
            ip: IP address to look up

        Returns:
            GeoInfo with location data
        """
        # Return cached result
        if ip in self._cache:
            return self._cache[ip]

        # Skip private/local IPs
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return GeoInfo(ip=ip, country="Local", country_code="--")
        except ValueError:
            return GeoInfo(ip=ip)

        if GEOCODER_AVAILABLE:
            try:
                g = geocoder.ip(ip)
                if g.ok:
                    result = GeoInfo(
                        ip=ip,
                        country=g.country,
                        country_code=g.country_code,
                        city=g.city,
                        region=g.state,
                        latitude=g.lat,
                        longitude=g.lng,
                        org=g.org,
                    )
                    self._cache[ip] = result
                    return result
            except Exception as e:
                logger.debug(f"Geocoder lookup failed for {ip}: {e}")

        # Stub response - use ip-api.com free endpoint
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,city,regionName,lat,lon,isp,org,proxy"},
                timeout=5,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    result = GeoInfo(
                        ip=ip,
                        country=data.get("country"),
                        country_code=data.get("countryCode"),
                        city=data.get("city"),
                        region=data.get("regionName"),
                        latitude=data.get("lat"),
                        longitude=data.get("lon"),
                        isp=data.get("isp"),
                        org=data.get("org"),
                        is_proxy=data.get("proxy", False),
                    )
                    self._cache[ip] = result
                    return result
        except requests.RequestException as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")

        return GeoInfo(ip=ip)


class TrafficAnalyzer:
    """
    Captures and analyzes network traffic for suspicious activity.

    Uses scapy for packet capture, optional threat intelligence feeds
    for labeling traffic as legitimate or malicious.
    """

    # High-risk ports commonly used by malware
    HIGH_RISK_PORTS = {
        4444: "Metasploit default",
        5555: "Common RAT",
        6666: "IRC bots",
        6667: "IRC",
        6697: "IRC SSL",
        31337: "Back Orifice",
        12345: "NetBus",
        1337: "Leet port",
        8080: "HTTP Proxy (suspicious if unexpected)",
        3389: "RDP (verify if expected)",
        445: "SMB (verify if expected)",
        23: "Telnet (insecure)",
        21: "FTP (verify security)",
    }

    # Suspicious countries (high malware origin - for flagging, not blocking)
    SUSPICIOUS_COUNTRY_CODES = {"RU", "CN", "KP", "IR"}  # Use cautiously

    def __init__(self, config: TrafficConfig | None = None):
        """
        Initialize traffic analyzer.

        Args:
            config: Traffic analyzer configuration
        """
        self.config = config or TrafficConfig()
        self._scapy_available = SCAPY_AVAILABLE

        # Initialize sub-components
        self.geoip = GeoIPLookup()
        self.threat_intel = AbuseIPDBClient(
            api_key=self.config.abuseipdb_api_key
        )

        # Build whitelist set for fast lookups
        self._whitelist: set[str] = set(self.config.proxy_whitelist)
        self._trusted_domains: set[str] = set(self.config.trusted_domains)

        # Override high-risk ports from config if provided
        if self.config.high_risk_ports:
            self.HIGH_RISK_PORTS = {
                port: "Configured high-risk" for port in self.config.high_risk_ports
            }

        if not self._scapy_available:
            logger.warning(
                "scapy not available. Traffic capture disabled.\n"
                "Install with: pip install scapy\n"
                "On Windows, also install Npcap: https://npcap.com/"
            )

    def get_interfaces(self) -> list[str]:
        """Get available network interfaces."""
        if not self._scapy_available:
            return []
        return get_if_list()

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist."""
        return ip in self._whitelist

    def _is_high_risk_port(self, port: int | None) -> tuple[bool, str]:
        """Check if port is high-risk."""
        if port is None:
            return False, ""
        if port in self.HIGH_RISK_PORTS:
            return True, self.HIGH_RISK_PORTS[port]
        return False, ""

    def _parse_packet(self, packet: Any) -> PacketInfo | None:
        """
        Parse a scapy packet into PacketInfo.

        Args:
            packet: Raw scapy packet

        Returns:
            PacketInfo or None if not IP packet
        """
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "OTHER"
        src_port = None
        dst_port = None
        flags = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = str(tcp.flags)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        # Get payload preview (first 50 bytes, hex)
        payload_preview = None
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            try:
                payload = bytes(packet.payload.payload)
                if payload:
                    payload_preview = payload[:50].hex()
            except Exception:
                pass

        return PacketInfo(
            timestamp=datetime.now(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            size=len(packet),
            flags=flags,
            payload_preview=payload_preview,
            raw_packet=packet,
        )

    def capture_packets(
        self,
        duration: int | None = None,
        interface: str | None = None,
        packet_callback: Callable[[PacketInfo], None] | None = None,
    ) -> Generator[PacketInfo, None, None]:
        """
        Capture network packets.

        Args:
            duration: Capture duration in seconds (default: from config)
            interface: Network interface to capture on
            packet_callback: Optional callback for each packet

        Yields:
            PacketInfo for each captured packet

        Raises:
            RuntimeError: If scapy is not available
            PermissionError: If not running with admin/root privileges
        """
        if not self._scapy_available:
            raise RuntimeError(
                "scapy not available. Install with: pip install scapy"
            )

        duration = duration or self.config.capture_duration_sec
        interface = interface or self.config.interface

        logger.info(f"Starting packet capture for {duration}s on interface: {interface or 'default'}")

        captured_packets: list[Any] = []

        def _packet_handler(pkt):
            captured_packets.append(pkt)

        try:
            # Capture packets
            sniff(
                iface=interface,
                timeout=duration,
                prn=_packet_handler,
                store=False,
            )
        except PermissionError:
            raise PermissionError(
                "Packet capture requires administrator/root privileges.\n"
                "Run BisonTitan with elevated permissions."
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            raise

        logger.info(f"Captured {len(captured_packets)} packets")

        # Process and yield packets
        for raw_packet in captured_packets:
            packet_info = self._parse_packet(raw_packet)
            if packet_info:
                if packet_callback:
                    packet_callback(packet_info)
                yield packet_info

    def label_traffic(self, packet: PacketInfo) -> TrafficLabel:
        """
        Label a packet's traffic as legitimate/suspicious/malicious.

        Args:
            packet: Packet information to analyze

        Returns:
            TrafficLabel with classification
        """
        reasons: list[str] = []
        risk_score = 0

        # Check both source and destination IPs
        for ip, direction in [(packet.src_ip, "source"), (packet.dst_ip, "destination")]:
            # Skip local IPs for detailed analysis
            try:
                if ipaddress.ip_address(ip).is_private:
                    continue
            except ValueError:
                continue

            # Check whitelist first
            if self._is_whitelisted(ip):
                return TrafficLabel(
                    ip=ip,
                    category=TrafficCategory.WHITELISTED,
                    confidence=1.0,
                    reasons=[f"IP {ip} is whitelisted"],
                    risk_score=0,
                )

            # Check high-risk ports
            port = packet.dst_port if direction == "destination" else packet.src_port
            is_risky, port_reason = self._is_high_risk_port(port)
            if is_risky:
                reasons.append(f"High-risk port {port} ({port_reason})")
                risk_score += 30

            # Get geo info
            geo_info = self.geoip.lookup(ip)

            # Check for suspicious country (informational, not conclusive)
            if geo_info.country_code in self.SUSPICIOUS_COUNTRY_CODES:
                reasons.append(f"Traffic from/to high-risk country: {geo_info.country}")
                risk_score += 15

            # Check for proxy/VPN
            if geo_info.is_proxy or geo_info.is_vpn:
                reasons.append(f"IP {ip} is a proxy/VPN")
                risk_score += 10

            # Threat intelligence check (if enabled)
            threat_info = None
            if self.config.enable_threat_feeds and self.threat_intel.is_enabled:
                threat_info = self.threat_intel.check_ip(ip)
                if threat_info.is_malicious:
                    reasons.append(
                        f"IP {ip} flagged malicious by AbuseIPDB "
                        f"(confidence: {threat_info.abuse_confidence}%)"
                    )
                    risk_score += threat_info.abuse_confidence
                elif threat_info.total_reports > 0:
                    reasons.append(
                        f"IP {ip} has {threat_info.total_reports} abuse reports"
                    )
                    risk_score += min(threat_info.total_reports * 2, 20)

        # Determine category based on risk score
        if risk_score >= 70:
            category = TrafficCategory.MALICIOUS
            confidence = min(risk_score / 100, 1.0)
        elif risk_score >= 30:
            category = TrafficCategory.SUSPICIOUS
            confidence = risk_score / 100
        elif reasons:
            category = TrafficCategory.SUSPICIOUS
            confidence = 0.3
        else:
            category = TrafficCategory.LEGITIMATE
            confidence = 0.8
            reasons.append("No suspicious indicators detected")

        return TrafficLabel(
            ip=packet.dst_ip,  # Primary IP of interest
            category=category,
            confidence=confidence,
            reasons=reasons,
            geo_info=geo_info if 'geo_info' in dir() else None,
            threat_intel=threat_info if 'threat_info' in dir() else None,
            risk_score=min(risk_score, 100),
        )

    def analyze_capture(
        self,
        duration: int | None = None,
        interface: str | None = None,
    ) -> tuple[list[tuple[PacketInfo, TrafficLabel]], CaptureStats]:
        """
        Capture and analyze traffic in one operation.

        Args:
            duration: Capture duration in seconds
            interface: Network interface

        Returns:
            Tuple of (labeled_packets, stats)
        """
        duration = duration or self.config.capture_duration_sec
        start_time = datetime.now()

        labeled_packets: list[tuple[PacketInfo, TrafficLabel]] = []
        stats = CaptureStats(duration_sec=0, total_packets=0)

        for packet in self.capture_packets(duration, interface):
            label = self.label_traffic(packet)
            labeled_packets.append((packet, label))

            # Update stats
            stats.total_packets += 1
            stats.bytes_captured += packet.size
            stats.unique_ips.add(packet.src_ip)
            stats.unique_ips.add(packet.dst_ip)

            # Count by protocol
            stats.protocols[packet.protocol] = stats.protocols.get(packet.protocol, 0) + 1

            # Count by category
            if label.category == TrafficCategory.SUSPICIOUS:
                stats.suspicious_count += 1
            elif label.category == TrafficCategory.MALICIOUS:
                stats.malicious_count += 1
            elif label.category == TrafficCategory.WHITELISTED:
                stats.whitelisted_count += 1

        stats.duration_sec = (datetime.now() - start_time).total_seconds()
        return labeled_packets, stats

    def check_threat_feeds(self, ip: str) -> ThreatIntel:
        """
        Check IP against threat intelligence feeds.

        Args:
            ip: IP address to check

        Returns:
            ThreatIntel with results
        """
        return self.threat_intel.check_ip(ip)

    def get_geo_info(self, ip: str) -> GeoInfo:
        """
        Get geographic information for an IP.

        Args:
            ip: IP address to lookup

        Returns:
            GeoInfo with location data
        """
        return self.geoip.lookup(ip)


# Convenience function for quick analysis
def quick_traffic_scan(duration: int = 5) -> dict:
    """
    Quick traffic scan with default settings.

    Args:
        duration: Capture duration in seconds

    Returns:
        Dictionary with scan results
    """
    analyzer = TrafficAnalyzer()
    packets, stats = analyzer.analyze_capture(duration=duration)

    return {
        "stats": stats.to_dict(),
        "suspicious_traffic": [
            {
                "packet": p.to_dict(),
                "label": l.to_dict(),
            }
            for p, l in packets
            if l.category in [TrafficCategory.SUSPICIOUS, TrafficCategory.MALICIOUS]
        ],
    }

"""
Tests for BisonTitan Traffic Analyzer Module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from bisontitan.config import TrafficConfig
from bisontitan.traffic_analyzer import (
    TrafficAnalyzer,
    TrafficCategory,
    PacketInfo,
    TrafficLabel,
    GeoInfo,
    ThreatIntel,
    CaptureStats,
    AbuseIPDBClient,
    GeoIPLookup,
    SCAPY_AVAILABLE,
)


class TestTrafficCategory:
    """Tests for TrafficCategory enum."""

    def test_categories_exist(self):
        """Verify all traffic categories are defined."""
        assert TrafficCategory.LEGITIMATE.value == "legitimate"
        assert TrafficCategory.SUSPICIOUS.value == "suspicious"
        assert TrafficCategory.MALICIOUS.value == "malicious"
        assert TrafficCategory.WHITELISTED.value == "whitelisted"
        assert TrafficCategory.UNKNOWN.value == "unknown"


class TestPacketInfo:
    """Tests for PacketInfo dataclass."""

    def test_packet_info_creation(self):
        """Test creating PacketInfo."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            size=1500,
        )
        assert packet.src_ip == "192.168.1.100"
        assert packet.dst_ip == "8.8.8.8"
        assert packet.protocol == "TCP"

    def test_packet_info_to_dict(self):
        """Test PacketInfo serialization."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="10.0.0.1",
            dst_ip="1.1.1.1",
            src_port=80,
            dst_port=8080,
            protocol="TCP",
            size=500,
            flags="SYN",
        )
        d = packet.to_dict()

        assert "src_ip" in d
        assert "dst_ip" in d
        assert "protocol" in d
        assert d["flags"] == "SYN"
        assert "raw_packet" not in d  # Should not serialize raw packet


class TestGeoInfo:
    """Tests for GeoInfo dataclass."""

    def test_geo_info_creation(self):
        """Test creating GeoInfo."""
        geo = GeoInfo(
            ip="8.8.8.8",
            country="United States",
            country_code="US",
            city="Mountain View",
        )
        assert geo.country == "United States"
        assert geo.country_code == "US"

    def test_geo_info_to_dict(self):
        """Test GeoInfo serialization."""
        geo = GeoInfo(ip="1.1.1.1", is_proxy=True)
        d = geo.to_dict()

        assert d["ip"] == "1.1.1.1"
        assert d["is_proxy"] is True


class TestThreatIntel:
    """Tests for ThreatIntel dataclass."""

    def test_threat_intel_creation(self):
        """Test creating ThreatIntel."""
        threat = ThreatIntel(
            ip="1.2.3.4",
            is_malicious=True,
            abuse_confidence=85,
            total_reports=10,
            categories=["Port Scan", "Brute-Force"],
            source="abuseipdb",
        )
        assert threat.is_malicious is True
        assert threat.abuse_confidence == 85
        assert "Port Scan" in threat.categories

    def test_threat_intel_to_dict(self):
        """Test ThreatIntel serialization."""
        threat = ThreatIntel(ip="1.2.3.4", source="test")
        d = threat.to_dict()

        assert d["ip"] == "1.2.3.4"
        assert d["source"] == "test"


class TestTrafficLabel:
    """Tests for TrafficLabel dataclass."""

    def test_traffic_label_creation(self):
        """Test creating TrafficLabel."""
        label = TrafficLabel(
            ip="192.168.1.1",
            category=TrafficCategory.SUSPICIOUS,
            confidence=0.75,
            reasons=["High-risk port detected"],
            risk_score=45,
        )
        assert label.category == TrafficCategory.SUSPICIOUS
        assert label.confidence == 0.75
        assert label.risk_score == 45

    def test_traffic_label_to_dict(self):
        """Test TrafficLabel serialization."""
        label = TrafficLabel(
            ip="10.0.0.1",
            category=TrafficCategory.LEGITIMATE,
            confidence=0.9,
        )
        d = label.to_dict()

        assert d["category"] == "legitimate"
        assert d["confidence"] == 0.9


class TestCaptureStats:
    """Tests for CaptureStats dataclass."""

    def test_capture_stats_creation(self):
        """Test creating CaptureStats."""
        stats = CaptureStats(
            duration_sec=5.0,
            total_packets=100,
        )
        stats.unique_ips.add("1.1.1.1")
        stats.protocols["TCP"] = 80

        assert stats.total_packets == 100
        assert "1.1.1.1" in stats.unique_ips

    def test_capture_stats_to_dict(self):
        """Test CaptureStats serialization."""
        stats = CaptureStats(
            duration_sec=10.0,
            total_packets=50,
            suspicious_count=5,
            malicious_count=1,
        )
        stats.unique_ips.add("1.1.1.1")
        stats.unique_ips.add("2.2.2.2")

        d = stats.to_dict()
        assert d["total_packets"] == 50
        assert d["unique_ips"] == 2  # Count, not the set


class TestGeoIPLookup:
    """Tests for GeoIPLookup class."""

    @pytest.fixture
    def geoip(self):
        """Create GeoIPLookup instance."""
        return GeoIPLookup()

    def test_private_ip_lookup(self, geoip):
        """Test lookup for private IP returns local."""
        result = geoip.lookup("192.168.1.1")
        assert result.country == "Local"
        assert result.country_code == "--"

    def test_loopback_lookup(self, geoip):
        """Test lookup for loopback returns local."""
        result = geoip.lookup("127.0.0.1")
        assert result.country == "Local"

    def test_caching(self, geoip):
        """Test that results are cached."""
        # First lookup
        result1 = geoip.lookup("192.168.1.1")
        # Second lookup should hit cache
        result2 = geoip.lookup("192.168.1.1")

        assert result1.ip == result2.ip


class TestAbuseIPDBClient:
    """Tests for AbuseIPDBClient class."""

    def test_client_disabled_without_key(self):
        """Test client is disabled without API key."""
        with patch.dict("os.environ", {}, clear=True):
            client = AbuseIPDBClient(api_key=None)
            assert client.is_enabled is False

    def test_client_enabled_with_key(self):
        """Test client is enabled with API key."""
        client = AbuseIPDBClient(api_key="test_key_123")
        assert client.is_enabled is True

    def test_private_ip_skipped(self):
        """Test private IPs are not checked."""
        client = AbuseIPDBClient(api_key="test_key")
        result = client.check_ip("192.168.1.1")
        assert result.source == "private_ip"

    def test_disabled_client_returns_empty(self):
        """Test disabled client returns empty result."""
        client = AbuseIPDBClient(api_key=None)
        result = client.check_ip("8.8.8.8")
        assert result.source == "none"

    def test_caching(self):
        """Test that results are cached."""
        client = AbuseIPDBClient(api_key=None)
        # Lookup twice
        client.check_ip("10.0.0.1")
        client.check_ip("10.0.0.1")
        # Should be in cache
        assert "10.0.0.1" in client._cache


class TestTrafficAnalyzer:
    """Tests for TrafficAnalyzer class."""

    @pytest.fixture
    def config(self):
        """Create test config."""
        return TrafficConfig(
            capture_duration_sec=1,
            proxy_whitelist=["10.0.0.100", "172.16.0.1"],
            high_risk_ports=[4444, 6667, 31337],
            enable_threat_feeds=False,
        )

    @pytest.fixture
    def analyzer(self, config):
        """Create TrafficAnalyzer instance."""
        return TrafficAnalyzer(config)

    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes correctly."""
        assert analyzer.config is not None
        assert "10.0.0.100" in analyzer._whitelist

    def test_whitelist_check(self, analyzer):
        """Test whitelist checking."""
        assert analyzer._is_whitelisted("10.0.0.100") is True
        assert analyzer._is_whitelisted("1.1.1.1") is False

    def test_high_risk_port_detection(self, analyzer):
        """Test high-risk port detection."""
        is_risky, reason = analyzer._is_high_risk_port(4444)
        assert is_risky is True

        is_risky, reason = analyzer._is_high_risk_port(443)
        assert is_risky is False

        is_risky, reason = analyzer._is_high_risk_port(None)
        assert is_risky is False

    def test_label_whitelisted_traffic(self, analyzer):
        """Test labeling whitelisted traffic."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.100",  # Whitelisted IP
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            size=1000,
        )

        label = analyzer.label_traffic(packet)
        assert label.category == TrafficCategory.WHITELISTED
        assert label.risk_score == 0

    def test_label_high_risk_port_traffic(self, analyzer):
        """Test labeling traffic to high-risk ports."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=4444,  # High-risk port
            protocol="TCP",
            size=1000,
        )

        label = analyzer.label_traffic(packet)
        assert label.category in [TrafficCategory.SUSPICIOUS, TrafficCategory.MALICIOUS]
        assert label.risk_score > 0
        assert any("4444" in r for r in label.reasons)

    def test_label_clean_traffic(self, analyzer):
        """Test labeling clean traffic."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",  # Private IP
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            size=1000,
        )

        label = analyzer.label_traffic(packet)
        assert label.category == TrafficCategory.LEGITIMATE
        assert label.risk_score == 0

    def test_get_geo_info(self, analyzer):
        """Test geo info lookup."""
        geo = analyzer.get_geo_info("127.0.0.1")
        assert geo.ip == "127.0.0.1"
        assert geo.country == "Local"

    def test_check_threat_feeds(self, analyzer):
        """Test threat feed check."""
        # With disabled client
        result = analyzer.check_threat_feeds("8.8.8.8")
        assert result.ip == "8.8.8.8"


class TestTrafficAnalyzerWithScapy:
    """Tests that require scapy."""

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
    def test_get_interfaces(self):
        """Test getting network interfaces."""
        analyzer = TrafficAnalyzer()
        interfaces = analyzer.get_interfaces()
        assert isinstance(interfaces, list)

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
    def test_capture_without_admin(self):
        """Test capture fails without admin (in most cases)."""
        analyzer = TrafficAnalyzer()

        # This may or may not raise depending on privileges
        # Just verify it doesn't crash unexpectedly
        try:
            list(analyzer.capture_packets(duration=1))
        except (PermissionError, RuntimeError):
            pass  # Expected without admin


class TestPacketParsing:
    """Tests for packet parsing (mocked)."""

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
    def test_parse_tcp_packet(self):
        """Test parsing a TCP packet."""
        from scapy.all import IP, TCP, Raw

        # Create mock packet
        packet = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=12345, dport=80, flags="S")

        analyzer = TrafficAnalyzer()
        result = analyzer._parse_packet(packet)

        assert result is not None
        assert result.src_ip == "1.1.1.1"
        assert result.dst_ip == "2.2.2.2"
        assert result.src_port == 12345
        assert result.dst_port == 80
        assert result.protocol == "TCP"
        assert "S" in result.flags

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
    def test_parse_udp_packet(self):
        """Test parsing a UDP packet."""
        from scapy.all import IP, UDP

        packet = IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=5000, dport=53)

        analyzer = TrafficAnalyzer()
        result = analyzer._parse_packet(packet)

        assert result is not None
        assert result.protocol == "UDP"
        assert result.dst_port == 53

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
    def test_parse_non_ip_packet_returns_none(self):
        """Test that non-IP packets return None."""
        from scapy.all import Ether

        packet = Ether()

        analyzer = TrafficAnalyzer()
        result = analyzer._parse_packet(packet)

        assert result is None


class TestIntegration:
    """Integration tests for traffic analyzer."""

    def test_full_labeling_pipeline(self):
        """Test complete labeling with all components."""
        config = TrafficConfig(
            proxy_whitelist=["trusted.example.com"],
            high_risk_ports=[4444, 6667],
            enable_threat_feeds=False,
        )
        analyzer = TrafficAnalyzer(config)

        # Test various packets
        packets = [
            PacketInfo(  # Clean
                timestamp=datetime.now(),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=443, dst_port=54321,
                protocol="TCP", size=100,
            ),
            PacketInfo(  # Suspicious port
                timestamp=datetime.now(),
                src_ip="192.168.1.1",
                dst_ip="8.8.8.8",
                src_port=54321, dst_port=4444,
                protocol="TCP", size=100,
            ),
        ]

        labels = [analyzer.label_traffic(p) for p in packets]

        # First should be legitimate (both IPs are private)
        assert labels[0].category == TrafficCategory.LEGITIMATE

        # Second should be suspicious (high-risk port)
        assert labels[1].category in [
            TrafficCategory.SUSPICIOUS,
            TrafficCategory.MALICIOUS,
        ]

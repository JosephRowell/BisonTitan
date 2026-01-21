"""
Tests for BisonTitan Fingerprint Viewer Module.
Phase 3 implementation tests.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from bisontitan.config import FingerprintConfig
from bisontitan.fingerprint_viewer import (
    FingerprintResult,
    FingerprintViewer,
    GoLoginClient,
)


class TestFingerprintResult:
    """Tests for FingerprintResult dataclass."""

    def test_result_to_dict(self):
        """Test FingerprintResult conversion to dictionary."""
        result = FingerprintResult(
            ua="Mozilla/5.0 Test",
            ip={"origin": "1.2.3.4"},
            resolution="1920x1080",
            geo={"timezone": "-05:00 America/New_York"},
            hardware={"memory": "8GB", "threads": "4", "canvas": "Real", "webgl": "Real"},
            storage={"save_tabs": True, "save_history": True, "local_storage": True},
            browser={"plugins": True, "extensions": False, "fonts": "Masked (100)"},
            fingerprint_score=0.75,
            risk="Medium",
        )

        d = result.to_dict()

        assert d["ua"] == "Mozilla/5.0 Test"
        assert d["ip"]["origin"] == "1.2.3.4"
        assert d["resolution"] == "1920x1080"
        assert d["fingerprint_score"] == 0.75
        assert d["risk"] == "Medium"
        assert d["hardware"]["memory"] == "8GB"

    def test_result_to_json(self):
        """Test FingerprintResult JSON serialization."""
        result = FingerprintResult(
            ua="Test UA",
            ip={"origin": "127.0.0.1"},
            resolution="1280x720",
            geo={"timezone": "UTC"},
            hardware={"memory": "4GB", "threads": "2", "canvas": "Blocked", "webgl": "Blocked"},
            storage={"save_tabs": False, "save_history": False, "local_storage": True},
            browser={"plugins": False, "extensions": False, "fonts": "Masked (50)"},
            fingerprint_score=0.90,
            risk="Low",
        )

        json_str = result.to_json()
        parsed = json.loads(json_str)

        assert parsed["ua"] == "Test UA"
        assert parsed["fingerprint_score"] == 0.9
        assert parsed["risk"] == "Low"

    def test_result_with_extended_fields(self):
        """Test FingerprintResult with all extended fields."""
        result = FingerprintResult(
            ua="Full Test",
            ip={"origin": "10.0.0.1"},
            resolution="2560x1440",
            geo={"timezone": "+00:00 Europe/London"},
            hardware={"memory": "16GB", "threads": "8", "canvas": "Real", "webgl": "Real"},
            storage={"save_tabs": True, "save_history": True, "local_storage": True},
            browser={"plugins": True, "extensions": True, "fonts": "Real (200)"},
            fingerprint_score=0.65,
            risk="Medium",
            platform="Win32",
            language="en-GB",
            languages=["en-GB", "en"],
            color_depth=32,
            pixel_ratio=2.0,
            do_not_track=True,
            webdriver_detected=False,
            headers={"Accept": "text/html"},
            recommendations=["Test recommendation"],
            captured_at="2024-01-01T00:00:00Z",
        )

        d = result.to_dict()

        assert d["platform"] == "Win32"
        assert d["language"] == "en-GB"
        assert d["color_depth"] == 32
        assert d["pixel_ratio"] == 2.0
        assert d["do_not_track"] is True
        assert len(d["recommendations"]) == 1


class TestGoLoginClient:
    """Tests for GoLoginClient."""

    def test_client_without_api_key(self):
        """Test client behavior without API key."""
        # Ensure env var is not set
        with patch.dict(os.environ, {}, clear=True):
            client = GoLoginClient()
            assert client.available is False
            assert client.get_profile("test") is None
            assert client.list_profiles() == []

    def test_client_with_api_key_env(self):
        """Test client picks up API key from environment."""
        with patch.dict(os.environ, {"GOLOGIN_API_KEY": "test_key_123"}):
            client = GoLoginClient()
            assert client.available is True
            assert client.api_key == "test_key_123"

    def test_client_with_explicit_api_key(self):
        """Test client with explicit API key."""
        client = GoLoginClient(api_key="explicit_key")
        assert client.available is True
        assert client.api_key == "explicit_key"

    @patch("requests.get")
    def test_get_profile_success(self, mock_get):
        """Test successful profile fetch."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "profiles": [
                {"name": "Test Profile", "id": "123"},
                {"name": "Proper English Lad", "id": "456"},
            ]
        }
        mock_get.return_value = mock_response

        client = GoLoginClient(api_key="test_key")
        profile = client.get_profile("Proper English Lad")

        assert profile is not None
        assert profile["name"] == "Proper English Lad"
        assert profile["id"] == "456"

    @patch("requests.get")
    def test_get_profile_not_found(self, mock_get):
        """Test profile not found."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"profiles": []}
        mock_get.return_value = mock_response

        client = GoLoginClient(api_key="test_key")
        profile = client.get_profile("Nonexistent")

        assert profile is None


class TestFingerprintViewer:
    """Tests for FingerprintViewer."""

    def test_viewer_initialization(self):
        """Test viewer initializes correctly."""
        viewer = FingerprintViewer()
        assert viewer.config is not None
        assert viewer.config.headless is True

    def test_viewer_with_custom_config(self):
        """Test viewer with custom configuration."""
        config = FingerprintConfig(
            browser_type="firefox",
            headless=False,
            viewport_width=1280,
            viewport_height=720,
        )
        viewer = FingerprintViewer(config)

        assert viewer.config.browser_type == "firefox"
        assert viewer.config.headless is False
        assert viewer.config.viewport_width == 1280

    @patch("requests.get")
    def test_get_public_ip(self, mock_get):
        """Test public IP fetching."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"origin": "203.0.113.42"}
        mock_get.return_value = mock_response

        viewer = FingerprintViewer()
        ip_data = viewer._get_public_ip()

        assert ip_data["origin"] == "203.0.113.42"

    @patch("requests.get")
    def test_get_public_ip_failure(self, mock_get):
        """Test public IP fetch failure handling."""
        mock_get.side_effect = Exception("Network error")

        viewer = FingerprintViewer()
        ip_data = viewer._get_public_ip()

        assert ip_data["origin"] == "unavailable"

    @patch("requests.get")
    def test_get_geo_info(self, mock_get):
        """Test geo info fetching."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "timezone": "America/New_York",
            "offset": -18000,
        }
        mock_get.return_value = mock_response

        viewer = FingerprintViewer()
        geo_data = viewer._get_geo_info("1.2.3.4")

        assert "America/New_York" in geo_data["timezone"]

    def test_compute_fingerprint_score(self):
        """Test fingerprint score computation."""
        viewer = FingerprintViewer()

        # Test with typical browser data
        data = {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "resolution": "1920x1080",
            "canvasHash": "abc123",
            "canvasStatus": "Real",
            "hardware": {"threads": 8, "memory": "8GB"},
            "fontsEstimate": 120,
            "platform": "Win32",
            "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
            "webgl": {"renderer": "ANGLE", "status": "Real"},
        }

        score = viewer._compute_fingerprint_score(data)

        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be fairly unique

    def test_compute_fingerprint_score_masked(self):
        """Test score with masked fingerprint."""
        viewer = FingerprintViewer()

        data = {
            "ua": "Mozilla/5.0 Generic",
            "resolution": "1920x1080",
            "canvasHash": "blocked",
            "canvasStatus": "Blocked",
            "hardware": {"threads": 4, "memory": "Unknown"},
            "fontsEstimate": 20,
            "platform": "Unknown",
            "plugins": [],
            "webgl": {"renderer": "blocked", "status": "Blocked"},
        }

        score = viewer._compute_fingerprint_score(data)

        # Masked fingerprint should have lower uniqueness
        assert 0.0 <= score <= 1.0

    def test_assess_risk_low(self):
        """Test risk assessment for low-risk fingerprint."""
        viewer = FingerprintViewer()

        data = {"canvasStatus": "Blocked", "webgl": {"status": "Blocked"}}
        risk = viewer._assess_risk(0.85, data)

        assert risk == "Low"

    def test_assess_risk_high(self):
        """Test risk assessment for high-risk fingerprint."""
        viewer = FingerprintViewer()

        data = {"canvasStatus": "Real", "webgl": {"status": "Real"}}
        risk = viewer._assess_risk(0.3, data)

        assert risk == "High"

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        viewer = FingerprintViewer()

        data = {
            "canvasStatus": "Real",
            "webgl": {"status": "Real"},
            "fontsEstimate": 150,
            "plugins": ["a", "b", "c", "d", "e", "f"],
            "doNotTrack": True,
            "features": {"webdriver": False},
            "storage": {"cookies": True},
        }

        recommendations = viewer._generate_recommendations(data, 0.4)

        assert len(recommendations) > 0
        assert any("canvas" in r.lower() for r in recommendations)
        assert any("webgl" in r.lower() for r in recommendations)
        assert any("font" in r.lower() for r in recommendations)

    def test_simulate_local(self):
        """Test local simulation without browser."""
        viewer = FingerprintViewer()

        with patch.object(viewer, "_get_public_ip", return_value={"origin": "127.0.0.1"}):
            with patch.object(viewer, "_get_geo_info", return_value={"timezone": "UTC"}):
                result = viewer.simulate_local()

        assert result is not None
        assert result.ua is not None
        assert result.ip["origin"] == "127.0.0.1"
        assert result.fingerprint_score > 0.5
        assert result.risk in ["Low", "Medium", "High"]
        assert len(result.recommendations) > 0


class TestFingerprintViewerIntegration:
    """Integration tests requiring Playwright (skipped if not available)."""

    @pytest.fixture
    def viewer(self):
        """Create viewer for tests."""
        return FingerprintViewer(FingerprintConfig(headless=True))

    def test_playwright_availability(self, viewer):
        """Test Playwright availability detection."""
        # This just tests that the check works
        assert isinstance(viewer._playwright_available, bool)

    @pytest.mark.skipif(
        not pytest.importorskip("playwright", reason="Playwright not installed"),
        reason="Playwright not available"
    )
    def test_capture_fingerprint_simulate(self, viewer):
        """Test fingerprint capture with simulation."""
        try:
            with patch.object(viewer, "_get_public_ip", return_value={"origin": "1.2.3.4"}):
                with patch.object(viewer, "_get_geo_info", return_value={"timezone": "UTC"}):
                    result = viewer.capture_fingerprint(simulate=True)

            assert result is not None
            assert result.ua is not None
            assert len(result.ua) > 0
            assert result.resolution is not None
            assert result.fingerprint_score > 0.5
            assert result.risk in ["Low", "Medium", "High"]

        except RuntimeError as e:
            if "Playwright" in str(e):
                pytest.skip("Playwright browsers not installed")
            raise


class TestFingerprintScoreValidation:
    """Additional tests for score validation."""

    def test_score_always_in_range(self):
        """Test that score is always between 0 and 1."""
        viewer = FingerprintViewer()

        test_cases = [
            {},  # Empty data
            {"ua": "x" * 10000},  # Very long UA
            {"fontsEstimate": 1000},  # Extreme font count
            {"plugins": ["p"] * 100},  # Many plugins
            {"features": {"webdriver": True}},  # Bot detected
        ]

        for data in test_cases:
            score = viewer._compute_fingerprint_score(data)
            assert 0.0 <= score <= 1.0, f"Score {score} out of range for data: {data}"

    def test_score_deterministic(self):
        """Test that same input produces same score."""
        viewer = FingerprintViewer()

        data = {
            "ua": "Test UA",
            "resolution": "1920x1080",
            "platform": "Win32",
        }

        score1 = viewer._compute_fingerprint_score(data)
        score2 = viewer._compute_fingerprint_score(data)

        assert score1 == score2


class TestCLIIntegration:
    """Test CLI integration."""

    def test_cli_fingerprint_help(self):
        """Test fingerprint command help."""
        from click.testing import CliRunner
        from bisontitan.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["fingerprint", "--help"])

        assert result.exit_code == 0
        assert "fingerprint" in result.output.lower()
        assert "--output" in result.output
        assert "--simulate" in result.output
        assert "--gologin-profile" in result.output

    def test_cli_fingerprint_no_browser(self):
        """Test fingerprint with --no-browser flag."""
        from click.testing import CliRunner
        from bisontitan.cli import cli

        runner = CliRunner()

        with patch("bisontitan.fingerprint_viewer.FingerprintViewer.simulate_local") as mock:
            mock.return_value = FingerprintResult(
                ua="Test",
                ip={"origin": "127.0.0.1"},
                resolution="1920x1080",
                geo={"timezone": "UTC"},
                hardware={"memory": "8GB", "threads": "4", "canvas": "Real", "webgl": "Real"},
                storage={"save_tabs": True, "save_history": True, "local_storage": True},
                browser={"plugins": True, "extensions": True, "fonts": "Real (100)"},
                fingerprint_score=0.75,
                risk="Medium",
            )

            result = runner.invoke(cli, ["fingerprint", "--no-browser", "--output", "json"])

            # Should not fail even without Playwright
            assert "ua" in result.output or result.exit_code == 0

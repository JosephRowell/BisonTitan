"""
BisonTitan Fingerprint Viewer Module
Browser and machine fingerprinting analysis.

Phase 3 implementation - Simulates what tracking services see about your machine.
Uses Playwright for headless browser automation with optional GoLogin integration.
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests

from bisontitan.config import FingerprintConfig


logger = logging.getLogger("bisontitan.fingerprint")


# JavaScript to extract browser fingerprint data
FINGERPRINT_JS = """
() => {
    const data = {};

    // User Agent
    data.ua = navigator.userAgent;

    // Platform
    data.platform = navigator.platform;

    // Language
    data.language = navigator.language;
    data.languages = navigator.languages ? Array.from(navigator.languages) : [navigator.language];

    // Screen/Resolution
    data.resolution = `${screen.width}x${screen.height}`;
    data.colorDepth = screen.colorDepth;
    data.pixelRatio = window.devicePixelRatio || 1;

    // Timezone
    const tzOffset = new Date().getTimezoneOffset();
    const tzHours = Math.abs(Math.floor(tzOffset / 60));
    const tzMinutes = Math.abs(tzOffset % 60);
    const tzSign = tzOffset <= 0 ? '+' : '-';
    data.timezoneOffset = `${tzSign}${String(tzHours).padStart(2, '0')}:${String(tzMinutes).padStart(2, '0')}`;
    try {
        data.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch (e) {
        data.timezone = 'Unknown';
    }

    // Hardware
    data.hardware = {
        memory: navigator.deviceMemory ? `${navigator.deviceMemory}GB` : 'Unknown',
        threads: navigator.hardwareConcurrency || 'Unknown',
        maxTouchPoints: navigator.maxTouchPoints || 0
    };

    // Canvas fingerprint
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 50;
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('BisonTitan FP', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('BisonTitan FP', 4, 17);
        data.canvasHash = canvas.toDataURL().slice(-50);
        data.canvasStatus = 'Real';
    } catch (e) {
        data.canvasHash = 'unavailable';
        data.canvasStatus = 'Blocked';
    }

    // WebGL fingerprint
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            data.webgl = {
                vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
                renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
                status: 'Real'
            };
        } else {
            data.webgl = { vendor: 'unavailable', renderer: 'unavailable', status: 'Blocked' };
        }
    } catch (e) {
        data.webgl = { vendor: 'error', renderer: 'error', status: 'Blocked' };
    }

    // Audio fingerprint (simplified)
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) {
            data.audioContext = 'available';
        } else {
            data.audioContext = 'unavailable';
        }
    } catch (e) {
        data.audioContext = 'blocked';
    }

    // Plugins
    data.plugins = [];
    if (navigator.plugins) {
        for (let i = 0; i < Math.min(navigator.plugins.length, 10); i++) {
            data.plugins.push(navigator.plugins[i].name);
        }
    }
    data.pluginsEnabled = navigator.plugins && navigator.plugins.length > 0;

    // Fonts (simplified detection)
    const testFonts = ['Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Georgia',
                       'Verdana', 'Comic Sans MS', 'Impact', 'Trebuchet MS', 'Palatino Linotype'];
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    const getWidth = (fontFamily) => {
        ctx.font = `${testSize} ${fontFamily}`;
        return ctx.measureText(testString).width;
    };

    const baseWidths = {};
    baseFonts.forEach(font => {
        baseWidths[font] = getWidth(font);
    });

    let fontCount = 0;
    testFonts.forEach(font => {
        const detected = baseFonts.some(baseFont => {
            return getWidth(`'${font}', ${baseFont}`) !== baseWidths[baseFont];
        });
        if (detected) fontCount++;
    });

    // Estimate total fonts based on detected common ones
    data.fontsDetected = fontCount;
    data.fontsEstimate = Math.round(fontCount * 12);  // Rough estimate

    // Media devices (count only for privacy)
    try {
        if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
            data.mediaDevicesAvailable = true;
        } else {
            data.mediaDevicesAvailable = false;
        }
    } catch (e) {
        data.mediaDevicesAvailable = false;
    }

    // Storage availability
    data.storage = {
        localStorage: !!window.localStorage,
        sessionStorage: !!window.sessionStorage,
        indexedDB: !!window.indexedDB,
        cookies: navigator.cookieEnabled
    };

    // Do Not Track
    data.doNotTrack = navigator.doNotTrack === '1' ||
                      window.doNotTrack === '1' ||
                      navigator.msDoNotTrack === '1';

    // Browser features
    data.features = {
        webdriver: navigator.webdriver || false,
        automation: !!window.document.__selenium_unwrapped ||
                    !!window.document.__webdriver_evaluate ||
                    !!window.document.__driver_evaluate,
        headless: /HeadlessChrome/.test(navigator.userAgent)
    };

    // Connection info
    if (navigator.connection) {
        data.connection = {
            type: navigator.connection.effectiveType || 'unknown',
            downlink: navigator.connection.downlink || 'unknown',
            rtt: navigator.connection.rtt || 'unknown'
        };
    } else {
        data.connection = { type: 'unknown', downlink: 'unknown', rtt: 'unknown' };
    }

    return data;
}
"""


@dataclass
class FingerprintResult:
    """Browser/machine fingerprint data matching the required JSON structure."""
    ua: str
    ip: dict[str, str]
    resolution: str
    geo: dict[str, str]
    hardware: dict[str, Any]
    storage: dict[str, bool]
    browser: dict[str, Any]
    fingerprint_score: float
    risk: str

    # Extended data
    platform: str = ""
    language: str = ""
    languages: list[str] = field(default_factory=list)
    color_depth: int = 24
    pixel_ratio: float = 1.0
    do_not_track: bool = False
    webdriver_detected: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    captured_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary matching required JSON structure."""
        return {
            "ua": self.ua,
            "ip": self.ip,
            "resolution": self.resolution,
            "geo": self.geo,
            "hardware": self.hardware,
            "storage": self.storage,
            "browser": self.browser,
            "fingerprint_score": round(self.fingerprint_score, 2),
            "risk": self.risk,
            "platform": self.platform,
            "language": self.language,
            "languages": self.languages,
            "color_depth": self.color_depth,
            "pixel_ratio": self.pixel_ratio,
            "do_not_track": self.do_not_track,
            "webdriver_detected": self.webdriver_detected,
            "headers": self.headers,
            "recommendations": self.recommendations,
            "captured_at": self.captured_at,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class GoLoginClient:
    """
    Client for GoLogin API integration.
    Optional debug feature for testing with different browser profiles.
    """

    BASE_URL = "https://api.gologin.com"

    def __init__(self, api_key: str | None = None):
        """
        Initialize GoLogin client.

        Args:
            api_key: GoLogin API key (or from GOLOGIN_API_KEY env var)
        """
        self.api_key = api_key or os.environ.get("GOLOGIN_API_KEY")
        self.available = bool(self.api_key)

    def get_profile(self, profile_name: str) -> dict[str, Any] | None:
        """
        Fetch a profile by name from GoLogin.

        Args:
            profile_name: Name of the profile to fetch

        Returns:
            Profile data dict or None if not found/available
        """
        if not self.available:
            logger.warning("GoLogin API key not configured")
            return None

        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.get(
                f"{self.BASE_URL}/browser/v2",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                profiles = response.json()
                for profile in profiles.get("profiles", []):
                    if profile.get("name", "").lower() == profile_name.lower():
                        return profile
                logger.warning(f"Profile '{profile_name}' not found")
            else:
                logger.error(f"GoLogin API error: {response.status_code}")

        except requests.RequestException as e:
            logger.error(f"GoLogin API request failed: {e}")

        return None

    def list_profiles(self) -> list[dict[str, Any]]:
        """
        List all available profiles.

        Returns:
            List of profile summaries
        """
        if not self.available:
            return []

        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.get(
                f"{self.BASE_URL}/browser/v2",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                return response.json().get("profiles", [])

        except requests.RequestException as e:
            logger.error(f"Failed to list profiles: {e}")

        return []


class FingerprintViewer:
    """
    Captures and analyzes browser/machine fingerprints.

    Uses Playwright to simulate browser behavior and capture
    what fingerprinting services see about your machine.
    Simulates companion website tool (bisontitan.com/privacy-check).
    """

    def __init__(self, config: FingerprintConfig | None = None):
        """
        Initialize fingerprint viewer.

        Args:
            config: Fingerprint configuration
        """
        self.config = config or FingerprintConfig()
        self._playwright = None
        self._browser = None
        self._gologin = GoLoginClient()

        # Check Playwright availability
        try:
            from playwright.sync_api import sync_playwright
            self._playwright_available = True
        except ImportError:
            self._playwright_available = False
            logger.warning("playwright not available. Install with: pip install playwright && playwright install")

    def _get_public_ip(self) -> dict[str, str]:
        """Fetch public IP using free httpbin.org endpoint."""
        try:
            response = requests.get("http://httpbin.org/ip", timeout=5)
            if response.status_code == 200:
                return response.json()
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch public IP: {e}")

        # Fallback
        return {"origin": "unavailable"}

    def _get_geo_info(self, ip: str) -> dict[str, str]:
        """Get timezone/geo info for IP using free endpoint."""
        try:
            # Use ip-api.com free tier (no API key needed)
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,timezone,offset",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    offset_sec = data.get("offset", 0)
                    offset_hours = offset_sec // 3600
                    offset_mins = abs(offset_sec % 3600) // 60
                    sign = "+" if offset_hours >= 0 else "-"
                    tz_str = f"{sign}{abs(offset_hours):02d}:{offset_mins:02d}"
                    return {
                        "timezone": f"{tz_str} {data.get('timezone', 'Unknown')}"
                    }
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch geo info: {e}")

        return {"timezone": "Unknown"}

    def _compute_fingerprint_score(self, data: dict[str, Any]) -> float:
        """
        Compute fingerprint uniqueness score (0-1).
        Higher score = more unique = more trackable.

        Uses hash of key fingerprinting vectors.
        """
        # Combine key fingerprinting vectors
        vectors = [
            data.get("ua", ""),
            data.get("resolution", ""),
            str(data.get("canvasHash", "")),
            str(data.get("hardware", {}).get("threads", "")),
            str(data.get("hardware", {}).get("memory", "")),
            str(data.get("fontsEstimate", "")),
            data.get("platform", ""),
            str(data.get("plugins", [])),
            str(data.get("webgl", {}).get("renderer", "")),
        ]

        combined = "|".join(str(v) for v in vectors)
        hash_val = hashlib.sha256(combined.encode()).hexdigest()

        # Convert first 8 hex chars to score
        score_raw = int(hash_val[:8], 16) / 0xFFFFFFFF

        # Adjust based on uniqueness factors
        adjustments = 0.0

        # Unique canvas = more trackable
        if data.get("canvasStatus") == "Real":
            adjustments += 0.1

        # Unique WebGL = more trackable
        if data.get("webgl", {}).get("status") == "Real":
            adjustments += 0.1

        # Many fonts = more unique
        fonts = data.get("fontsEstimate", 0)
        if fonts > 100:
            adjustments += 0.1
        elif fonts > 50:
            adjustments += 0.05

        # Plugins reveal info
        if len(data.get("plugins", [])) > 5:
            adjustments += 0.05

        # Do Not Track ironically makes you more trackable
        if data.get("doNotTrack"):
            adjustments += 0.02

        # WebDriver detection (automation)
        if data.get("features", {}).get("webdriver"):
            adjustments -= 0.2  # Less unique if detected as bot

        final_score = min(1.0, max(0.0, score_raw * 0.6 + adjustments + 0.3))
        return final_score

    def _assess_risk(self, score: float, data: dict[str, Any]) -> str:
        """
        Assess tracking risk based on fingerprint score.

        Args:
            score: Fingerprint uniqueness score
            data: Raw fingerprint data

        Returns:
            "Low", "Medium", or "High" risk level
        """
        # Check for masking/protection
        canvas_masked = data.get("canvasStatus") == "Blocked"
        webgl_masked = data.get("webgl", {}).get("status") == "Blocked"

        if score > 0.8 or (canvas_masked and webgl_masked):
            return "Low"
        elif score > 0.5:
            return "Medium"
        else:
            return "High"

    def _generate_recommendations(self, data: dict[str, Any], score: float) -> list[str]:
        """Generate privacy recommendations based on fingerprint analysis."""
        recommendations = []

        if data.get("canvasStatus") == "Real":
            recommendations.append("Consider using canvas fingerprint protection (e.g., CanvasBlocker extension)")

        if data.get("webgl", {}).get("status") == "Real":
            recommendations.append("WebGL fingerprinting enabled - consider WebGL blocker")

        fonts = data.get("fontsEstimate", 0)
        if fonts > 100:
            recommendations.append(f"High font count ({fonts}) increases uniqueness - consider font blocking")

        if len(data.get("plugins", [])) > 5:
            recommendations.append("Multiple browser plugins detected - reduce for less fingerprint surface")

        if data.get("doNotTrack"):
            recommendations.append("'Do Not Track' is enabled but ironically increases uniqueness")

        if data.get("features", {}).get("webdriver"):
            recommendations.append("WebDriver detected - browser automation signatures visible")

        if data.get("storage", {}).get("cookies"):
            recommendations.append("Cookies enabled - consider stricter cookie policies")

        if score < 0.5:
            recommendations.append("High tracking risk - consider using a privacy-focused browser profile")

        if not recommendations:
            recommendations.append("Good privacy posture - fingerprint is well-protected")

        return recommendations

    def capture_fingerprint(
        self,
        gologin_profile: str | None = None,
        simulate: bool = False
    ) -> FingerprintResult:
        """
        Capture browser fingerprint using Playwright.

        Args:
            gologin_profile: Optional GoLogin profile name for debug
            simulate: If True, use local dummy page instead of external

        Returns:
            FingerprintResult with captured data
        """
        if not self._playwright_available:
            raise RuntimeError(
                "Playwright not available. Install with: pip install playwright && playwright install chromium"
            )

        from playwright.sync_api import sync_playwright

        # Get GoLogin profile if specified
        profile_config = None
        if gologin_profile and self._gologin.available:
            profile_config = self._gologin.get_profile(gologin_profile)
            if profile_config:
                logger.info(f"Using GoLogin profile: {gologin_profile}")

        # Fetch public IP first (outside browser)
        ip_data = self._get_public_ip()
        ip_address = ip_data.get("origin", "").split(",")[0].strip()
        geo_data = self._get_geo_info(ip_address) if ip_address != "unavailable" else {"timezone": "Unknown"}

        with sync_playwright() as p:
            # Configure browser launch options
            launch_options = {
                "headless": self.config.headless,
            }

            # Context options
            context_options = {
                "viewport": {
                    "width": self.config.viewport_width,
                    "height": self.config.viewport_height,
                },
            }

            # Apply GoLogin profile settings if available
            if profile_config:
                if profile_config.get("navigator", {}).get("userAgent"):
                    context_options["user_agent"] = profile_config["navigator"]["userAgent"]
                if profile_config.get("proxy"):
                    proxy = profile_config["proxy"]
                    context_options["proxy"] = {
                        "server": f"{proxy.get('mode', 'http')}://{proxy.get('host')}:{proxy.get('port')}"
                    }
            elif self.config.user_agent:
                context_options["user_agent"] = self.config.user_agent

            if self.config.proxy:
                context_options["proxy"] = {"server": self.config.proxy}

            # Launch browser
            browser_type = getattr(p, self.config.browser_type, p.chromium)
            browser = browser_type.launch(**launch_options)
            context = browser.new_context(**context_options)
            page = context.new_page()

            try:
                # Navigate to a page to execute JS
                if simulate:
                    # Create a minimal data URL page
                    page.goto("data:text/html,<html><body><h1>BisonTitan Privacy Check</h1></body></html>")
                else:
                    # Use httpbin to also capture headers
                    page.goto("http://httpbin.org/headers", timeout=15000)

                # Execute fingerprint collection JS
                raw_data = page.evaluate(FINGERPRINT_JS)

                # Try to capture headers from httpbin response
                headers = {}
                if not simulate:
                    try:
                        content = page.content()
                        if '"headers"' in content:
                            import re
                            match = re.search(r'\{[^{}]*"headers"[^{}]*\{([^}]+)\}', content)
                            if match:
                                # Parse headers from httpbin response
                                pass  # Headers already in raw format
                    except Exception:
                        pass

            finally:
                browser.close()

        # Build result in required JSON structure
        hardware = {
            "memory": raw_data.get("hardware", {}).get("memory", "Unknown"),
            "threads": raw_data.get("hardware", {}).get("threads", "Unknown"),
            "canvas": raw_data.get("canvasStatus", "Unknown"),
            "webgl": raw_data.get("webgl", {}).get("status", "Unknown"),
        }

        fonts_count = raw_data.get("fontsEstimate", 0)
        fonts_status = "Masked" if fonts_count < 50 else "Real"

        storage = {
            "save_tabs": raw_data.get("storage", {}).get("sessionStorage", False),
            "save_history": raw_data.get("storage", {}).get("localStorage", False),
            "local_storage": raw_data.get("storage", {}).get("localStorage", True),
        }

        browser_info = {
            "plugins": raw_data.get("pluginsEnabled", False),
            "extensions": len(raw_data.get("plugins", [])) > 0,
            "fonts": f"{fonts_status} ({fonts_count})",
        }

        # Compute score and risk
        score = self._compute_fingerprint_score(raw_data)
        risk = self._assess_risk(score, raw_data)
        recommendations = self._generate_recommendations(raw_data, score)

        result = FingerprintResult(
            ua=raw_data.get("ua", "Unknown"),
            ip=ip_data,
            resolution=raw_data.get("resolution", f"{self.config.viewport_width}x{self.config.viewport_height}"),
            geo={
                "timezone": f"{raw_data.get('timezoneOffset', '')} {raw_data.get('timezone', 'Unknown')}"
            } if raw_data.get("timezone") else geo_data,
            hardware=hardware,
            storage=storage,
            browser=browser_info,
            fingerprint_score=score,
            risk=risk,
            platform=raw_data.get("platform", "Unknown"),
            language=raw_data.get("language", "Unknown"),
            languages=raw_data.get("languages", []),
            color_depth=raw_data.get("colorDepth", 24),
            pixel_ratio=raw_data.get("pixelRatio", 1.0),
            do_not_track=raw_data.get("doNotTrack", False),
            webdriver_detected=raw_data.get("features", {}).get("webdriver", False),
            headers=headers,
            recommendations=recommendations,
            captured_at=datetime.now(timezone.utc).isoformat(),
        )

        return result

    def capture_fingerprint_async(
        self,
        gologin_profile: str | None = None,
        simulate: bool = False
    ):
        """
        Async version of capture_fingerprint.
        """
        if not self._playwright_available:
            raise RuntimeError("Playwright not available")

        import asyncio
        from playwright.async_api import async_playwright

        async def _capture():
            ip_data = self._get_public_ip()
            ip_address = ip_data.get("origin", "").split(",")[0].strip()
            geo_data = self._get_geo_info(ip_address) if ip_address != "unavailable" else {"timezone": "Unknown"}

            async with async_playwright() as p:
                browser_type = getattr(p, self.config.browser_type, p.chromium)
                browser = await browser_type.launch(headless=self.config.headless)

                context_options = {
                    "viewport": {
                        "width": self.config.viewport_width,
                        "height": self.config.viewport_height,
                    },
                }
                if self.config.user_agent:
                    context_options["user_agent"] = self.config.user_agent

                context = await browser.new_context(**context_options)
                page = await context.new_page()

                try:
                    if simulate:
                        await page.goto("data:text/html,<html><body></body></html>")
                    else:
                        await page.goto("http://httpbin.org/headers", timeout=15000)

                    raw_data = await page.evaluate(FINGERPRINT_JS)
                finally:
                    await browser.close()

                return raw_data, ip_data, geo_data

        return asyncio.run(_capture())

    def simulate_local(self) -> FingerprintResult:
        """
        Simulate fingerprint capture with mock data for testing.
        Does not require Playwright.
        """
        import platform as plat
        import socket

        # Get basic system info without browser
        ip_data = self._get_public_ip()
        ip_address = ip_data.get("origin", "").split(",")[0].strip()
        geo_data = self._get_geo_info(ip_address) if ip_address != "unavailable" else {"timezone": "Unknown"}

        # Mock browser data
        mock_ua = f"Mozilla/5.0 ({plat.system()}; {plat.machine()}) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

        hardware = {
            "memory": "8GB",  # Stub
            "threads": str(os.cpu_count() or 4),
            "canvas": "Real",
            "webgl": "Real",
        }

        storage = {
            "save_tabs": True,
            "save_history": True,
            "local_storage": True,
        }

        browser_info = {
            "plugins": True,
            "extensions": True,
            "fonts": "Masked (119)",
        }

        # Compute mock score
        mock_data = {
            "ua": mock_ua,
            "resolution": f"{self.config.viewport_width}x{self.config.viewport_height}",
            "canvasHash": "simulated",
            "canvasStatus": "Real",
            "hardware": {"threads": os.cpu_count(), "memory": "8GB"},
            "fontsEstimate": 119,
            "platform": plat.system(),
            "plugins": [],
            "webgl": {"renderer": "simulated", "status": "Real"},
        }

        score = self._compute_fingerprint_score(mock_data)
        risk = self._assess_risk(score, mock_data)
        recommendations = self._generate_recommendations(mock_data, score)

        return FingerprintResult(
            ua=mock_ua,
            ip=ip_data,
            resolution=f"{self.config.viewport_width}x{self.config.viewport_height}",
            geo=geo_data,
            hardware=hardware,
            storage=storage,
            browser=browser_info,
            fingerprint_score=score,
            risk=risk,
            platform=plat.system(),
            language="en-US",
            languages=["en-US", "en"],
            recommendations=recommendations,
            captured_at=datetime.now(timezone.utc).isoformat(),
        )

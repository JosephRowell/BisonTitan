"""
BisonTitan Threat Intelligence Module
Real API integrations for threat detection and enrichment.

APIs Used:
    - NVD (NIST): CVE/vulnerability lookup (FREE, no key)
    - AbuseIPDB: IP reputation (FREE tier: 1000/day)
    - ip-api.com: GeoIP lookup (FREE: 45/min)
    - VirusTotal: Hash/URL checking (FREE tier: 4/min) - optional
    - Shodan: Internet intelligence (optional, requires key)

Environment Variables:
    ABUSEIPDB_API_KEY - For IP reputation checks
    VIRUSTOTAL_API_KEY - For hash/URL checks (optional)
    SHODAN_API_KEY - For Shodan lookups (optional)
"""

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

import requests

logger = logging.getLogger("bisontitan.threat_intel")


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class CVEInfo:
    """CVE vulnerability information from NVD."""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, NONE
    cvss_score: float | None
    cvss_vector: str | None
    published_date: datetime | None
    last_modified: datetime | None
    references: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    exploit_available: bool = False

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "references": self.references,
            "affected_products": self.affected_products,
            "exploit_available": self.exploit_available,
        }


@dataclass
class IPReputation:
    """IP reputation data from multiple sources."""
    ip: str
    is_malicious: bool = False
    risk_score: int = 0  # 0-100
    abuse_confidence: int = 0
    total_reports: int = 0
    categories: list[str] = field(default_factory=list)
    country: str | None = None
    isp: str | None = None
    is_tor: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    last_seen: datetime | None = None
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "is_malicious": self.is_malicious,
            "risk_score": self.risk_score,
            "abuse_confidence": self.abuse_confidence,
            "total_reports": self.total_reports,
            "categories": self.categories,
            "country": self.country,
            "isp": self.isp,
            "is_tor": self.is_tor,
            "is_proxy": self.is_proxy,
            "is_vpn": self.is_vpn,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "sources": self.sources,
        }


@dataclass
class HashReputation:
    """File hash reputation data."""
    hash_value: str
    hash_type: str  # md5, sha1, sha256
    is_malicious: bool = False
    detection_ratio: str | None = None  # e.g., "15/70"
    malware_names: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "hash_value": self.hash_value,
            "hash_type": self.hash_type,
            "is_malicious": self.is_malicious,
            "detection_ratio": self.detection_ratio,
            "malware_names": self.malware_names,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "source": self.source,
        }


# =============================================================================
# NVD (National Vulnerability Database) Client - FREE, NO KEY NEEDED
# =============================================================================

class NVDClient:
    """
    NIST National Vulnerability Database API client.

    FREE API - No key required (rate limited to ~5 req/30s)
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None):
        """
        Initialize NVD client.

        Args:
            api_key: Optional API key for higher rate limits
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self._last_request = 0
        self._min_interval = 6.0 if not self.api_key else 0.6  # Rate limiting

    def _rate_limit(self):
        """Ensure we don't exceed rate limits."""
        elapsed = time.time() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    def search_cve(self, cve_id: str) -> CVEInfo | None:
        """
        Look up a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            CVEInfo or None if not found
        """
        self._rate_limit()

        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(
                self.BASE_URL,
                params={"cveId": cve_id},
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            cve_data = vulnerabilities[0].get("cve", {})
            return self._parse_cve(cve_data)

        except requests.RequestException as e:
            logger.warning(f"NVD API error for {cve_id}: {e}")
            return None

    def search_by_keyword(self, keyword: str, limit: int = 10) -> list[CVEInfo]:
        """
        Search CVEs by keyword (product name, etc.).

        Args:
            keyword: Search term (e.g., "apache", "openssh 8.0")
            limit: Maximum results to return

        Returns:
            List of matching CVEInfo
        """
        self._rate_limit()

        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(
                self.BASE_URL,
                params={
                    "keywordSearch": keyword,
                    "resultsPerPage": min(limit, 100),
                },
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            results = []
            for vuln in data.get("vulnerabilities", [])[:limit]:
                cve_data = vuln.get("cve", {})
                cve_info = self._parse_cve(cve_data)
                if cve_info:
                    results.append(cve_info)

            return results

        except requests.RequestException as e:
            logger.warning(f"NVD search error for '{keyword}': {e}")
            return []

    def search_by_cpe(self, cpe: str, limit: int = 20) -> list[CVEInfo]:
        """
        Search CVEs by CPE (Common Platform Enumeration).

        Args:
            cpe: CPE string (e.g., "cpe:2.3:a:apache:http_server:2.4.49")
            limit: Maximum results

        Returns:
            List of CVEInfo affecting the CPE
        """
        self._rate_limit()

        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(
                self.BASE_URL,
                params={
                    "cpeName": cpe,
                    "resultsPerPage": min(limit, 100),
                },
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            results = []
            for vuln in data.get("vulnerabilities", [])[:limit]:
                cve_data = vuln.get("cve", {})
                cve_info = self._parse_cve(cve_data)
                if cve_info:
                    results.append(cve_info)

            return results

        except requests.RequestException as e:
            logger.warning(f"NVD CPE search error: {e}")
            return []

    def get_recent_critical(self, days: int = 7, limit: int = 20) -> list[CVEInfo]:
        """
        Get recent critical/high severity CVEs.

        Args:
            days: How many days back to search
            limit: Maximum results

        Returns:
            List of recent critical CVEs
        """
        self._rate_limit()

        try:
            start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
            end_date = datetime.now().strftime("%Y-%m-%dT23:59:59.999")

            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(
                self.BASE_URL,
                params={
                    "pubStartDate": start_date,
                    "pubEndDate": end_date,
                    "cvssV3Severity": "CRITICAL",
                    "resultsPerPage": min(limit, 100),
                },
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            results = []
            for vuln in data.get("vulnerabilities", [])[:limit]:
                cve_data = vuln.get("cve", {})
                cve_info = self._parse_cve(cve_data)
                if cve_info:
                    results.append(cve_info)

            return results

        except requests.RequestException as e:
            logger.warning(f"NVD recent CVE error: {e}")
            return []

    def _parse_cve(self, cve_data: dict) -> CVEInfo | None:
        """Parse NVD CVE response into CVEInfo."""
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # Get description (prefer English)
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Get CVSS scores
            metrics = cve_data.get("metrics", {})
            cvss_score = None
            cvss_vector = None
            severity = "NONE"

            # Try CVSS 3.1 first, then 3.0, then 2.0
            for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_key in metrics and metrics[cvss_key]:
                    cvss_data = metrics[cvss_key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    severity = cvss_data.get("baseSeverity", "NONE")
                    break

            # Get dates
            published = None
            modified = None
            if cve_data.get("published"):
                try:
                    published = datetime.fromisoformat(
                        cve_data["published"].replace("Z", "+00:00")
                    )
                except ValueError:
                    pass
            if cve_data.get("lastModified"):
                try:
                    modified = datetime.fromisoformat(
                        cve_data["lastModified"].replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            # Get references
            references = []
            for ref in cve_data.get("references", [])[:10]:
                url = ref.get("url", "")
                if url:
                    references.append(url)

            # Check for exploit indicators
            exploit_available = False
            for ref in cve_data.get("references", []):
                tags = ref.get("tags", [])
                if "Exploit" in tags or "exploit" in ref.get("url", "").lower():
                    exploit_available = True
                    break

            # Get affected products
            affected_products = []
            configurations = cve_data.get("configurations", [])
            for config in configurations[:5]:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", [])[:5]:
                        criteria = cpe_match.get("criteria", "")
                        if criteria:
                            # Extract product name from CPE
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                product = f"{parts[3]}:{parts[4]}"
                                if product not in affected_products:
                                    affected_products.append(product)

            return CVEInfo(
                cve_id=cve_id,
                description=description[:500],  # Truncate long descriptions
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=published,
                last_modified=modified,
                references=references,
                affected_products=affected_products[:10],
                exploit_available=exploit_available,
            )

        except Exception as e:
            logger.debug(f"CVE parse error: {e}")
            return None


# =============================================================================
# Service-to-CVE Mapper
# =============================================================================

class ServiceVulnMapper:
    """
    Maps detected services/versions to known CVEs.
    Uses NVD API for real vulnerability lookups.
    """

    # Common service name mappings to CPE vendor:product format
    SERVICE_CPE_MAP = {
        "ssh": "openssh:openssh",
        "openssh": "openssh:openssh",
        "apache": "apache:http_server",
        "httpd": "apache:http_server",
        "nginx": "nginx:nginx",
        "iis": "microsoft:iis",
        "mysql": "oracle:mysql",
        "mariadb": "mariadb:mariadb",
        "postgresql": "postgresql:postgresql",
        "postgres": "postgresql:postgresql",
        "mongodb": "mongodb:mongodb",
        "redis": "redis:redis",
        "ftp": "vsftpd:vsftpd",
        "vsftpd": "vsftpd:vsftpd",
        "proftpd": "proftpd:proftpd",
        "smb": "samba:samba",
        "samba": "samba:samba",
        "rdp": "microsoft:remote_desktop",
        "vnc": "realvnc:vnc",
        "telnet": "telnet:telnet",
        "tomcat": "apache:tomcat",
        "jenkins": "jenkins:jenkins",
        "docker": "docker:docker",
        "kubernetes": "kubernetes:kubernetes",
        "elasticsearch": "elastic:elasticsearch",
    }

    def __init__(self):
        """Initialize mapper with NVD client."""
        self.nvd = NVDClient()
        self._cache: dict[str, list[CVEInfo]] = {}

    def get_vulns_for_service(
        self,
        service: str,
        version: str | None = None,
        limit: int = 10
    ) -> list[CVEInfo]:
        """
        Get CVEs for a service/version combination.

        Args:
            service: Service name (e.g., "openssh", "apache")
            version: Optional version string
            limit: Maximum CVEs to return

        Returns:
            List of relevant CVEInfo
        """
        # Normalize service name
        service_lower = service.lower().strip()

        # Build cache key
        cache_key = f"{service_lower}:{version or 'any'}"
        if cache_key in self._cache:
            return self._cache[cache_key][:limit]

        # Build search query
        if service_lower in self.SERVICE_CPE_MAP:
            cpe_product = self.SERVICE_CPE_MAP[service_lower]
            if version:
                # Clean version string
                version_clean = re.sub(r'[^0-9.]', '', version.split()[0])
                search_term = f"{cpe_product} {version_clean}"
            else:
                search_term = cpe_product
        else:
            search_term = f"{service_lower} {version or ''}".strip()

        # Search NVD
        logger.info(f"Searching NVD for: {search_term}")
        results = self.nvd.search_by_keyword(search_term, limit=limit * 2)

        # Filter to most relevant (highest severity first)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
        results.sort(key=lambda c: severity_order.get(c.severity, 5))

        # Cache results
        self._cache[cache_key] = results
        return results[:limit]


# =============================================================================
# Enhanced IP Reputation (combines multiple sources)
# =============================================================================

class IPReputationChecker:
    """
    Comprehensive IP reputation checker using multiple sources.
    """

    def __init__(self):
        """Initialize with API keys from environment."""
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self._cache: dict[str, IPReputation] = {}

    def check_ip(self, ip: str) -> IPReputation:
        """
        Check IP reputation across multiple sources.

        Args:
            ip: IP address to check

        Returns:
            IPReputation with combined data
        """
        if ip in self._cache:
            return self._cache[ip]

        result = IPReputation(ip=ip)

        # Check AbuseIPDB
        if self.abuseipdb_key:
            abuse_data = self._check_abuseipdb(ip)
            if abuse_data:
                result.abuse_confidence = abuse_data.get("abuseConfidenceScore", 0)
                result.total_reports = abuse_data.get("totalReports", 0)
                result.country = abuse_data.get("countryCode")
                result.isp = abuse_data.get("isp")
                result.is_tor = abuse_data.get("isTor", False)
                result.sources.append("abuseipdb")

                # Determine if malicious
                if result.abuse_confidence >= 50:
                    result.is_malicious = True
                    result.risk_score = result.abuse_confidence

        # Check ip-api.com for geo/proxy info (free, no key)
        geo_data = self._check_ipapi(ip)
        if geo_data:
            if not result.country:
                result.country = geo_data.get("countryCode")
            if not result.isp:
                result.isp = geo_data.get("isp")
            result.is_proxy = geo_data.get("proxy", False)
            if result.is_proxy:
                result.risk_score = max(result.risk_score, 30)
            result.sources.append("ip-api")

        self._cache[ip] = result
        return result

    def _check_abuseipdb(self, ip: str) -> dict | None:
        """Check AbuseIPDB API."""
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                },
                timeout=10,
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except Exception as e:
            logger.debug(f"AbuseIPDB error for {ip}: {e}")
            return None

    def _check_ipapi(self, ip: str) -> dict | None:
        """Check ip-api.com (free)."""
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,countryCode,isp,proxy"},
                timeout=5,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data
        except Exception as e:
            logger.debug(f"ip-api error for {ip}: {e}")
        return None


# =============================================================================
# Unified Threat Intelligence Interface
# =============================================================================

class ThreatIntelligence:
    """
    Unified threat intelligence interface.
    Combines CVE lookup, IP reputation, and hash checking.
    """

    def __init__(self):
        """Initialize all threat intel components."""
        self.nvd = NVDClient()
        self.service_mapper = ServiceVulnMapper()
        self.ip_checker = IPReputationChecker()

    def lookup_cve(self, cve_id: str) -> CVEInfo | None:
        """Look up a specific CVE."""
        return self.nvd.search_cve(cve_id)

    def search_vulns(self, keyword: str, limit: int = 10) -> list[CVEInfo]:
        """Search for vulnerabilities by keyword."""
        return self.nvd.search_by_keyword(keyword, limit)

    def get_service_vulns(
        self,
        service: str,
        version: str | None = None,
        limit: int = 10
    ) -> list[CVEInfo]:
        """Get vulnerabilities for a service."""
        return self.service_mapper.get_vulns_for_service(service, version, limit)

    def check_ip(self, ip: str) -> IPReputation:
        """Check IP reputation."""
        return self.ip_checker.check_ip(ip)

    def get_recent_threats(self, days: int = 7) -> list[CVEInfo]:
        """Get recent critical CVEs."""
        return self.nvd.get_recent_critical(days)

    def calculate_file_hashes(self, filepath: str) -> dict[str, str]:
        """
        Calculate MD5, SHA1, SHA256 hashes of a file.

        Args:
            filepath: Path to file

        Returns:
            Dict with hash values
        """
        hashes = {"md5": "", "sha1": "", "sha256": ""}

        try:
            with open(filepath, "rb") as f:
                content = f.read()
                hashes["md5"] = hashlib.md5(content).hexdigest()
                hashes["sha1"] = hashlib.sha1(content).hexdigest()
                hashes["sha256"] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            logger.warning(f"Hash calculation failed for {filepath}: {e}")

        return hashes


# =============================================================================
# Quick Access Functions
# =============================================================================

def quick_cve_lookup(cve_id: str) -> dict | None:
    """
    Quick CVE lookup.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")

    Returns:
        CVE info dict or None
    """
    intel = ThreatIntelligence()
    result = intel.lookup_cve(cve_id)
    return result.to_dict() if result else None


def quick_ip_check(ip: str) -> dict:
    """
    Quick IP reputation check.

    Args:
        ip: IP address

    Returns:
        IP reputation dict
    """
    intel = ThreatIntelligence()
    return intel.check_ip(ip).to_dict()


def quick_service_vulns(service: str, version: str | None = None) -> list[dict]:
    """
    Quick service vulnerability lookup.

    Args:
        service: Service name
        version: Optional version

    Returns:
        List of CVE dicts
    """
    intel = ThreatIntelligence()
    results = intel.get_service_vulns(service, version)
    return [r.to_dict() for r in results]


# =============================================================================
# CLI for testing
# =============================================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python threat_intel.py cve CVE-2021-44228")
        print("  python threat_intel.py ip 8.8.8.8")
        print("  python threat_intel.py service openssh 8.0")
        print("  python threat_intel.py recent")
        sys.exit(1)

    cmd = sys.argv[1]
    intel = ThreatIntelligence()

    if cmd == "cve" and len(sys.argv) > 2:
        cve_id = sys.argv[2]
        print(f"Looking up {cve_id}...")
        result = intel.lookup_cve(cve_id)
        if result:
            print(f"\n{result.cve_id}")
            print(f"Severity: {result.severity} (CVSS: {result.cvss_score})")
            print(f"Description: {result.description[:200]}...")
            if result.exploit_available:
                print("⚠️  EXPLOIT AVAILABLE")
        else:
            print("CVE not found")

    elif cmd == "ip" and len(sys.argv) > 2:
        ip = sys.argv[2]
        print(f"Checking {ip}...")
        result = intel.check_ip(ip)
        print(f"\nIP: {result.ip}")
        print(f"Malicious: {result.is_malicious}")
        print(f"Risk Score: {result.risk_score}")
        print(f"Abuse Confidence: {result.abuse_confidence}%")
        print(f"Country: {result.country}")
        print(f"ISP: {result.isp}")

    elif cmd == "service" and len(sys.argv) > 2:
        service = sys.argv[2]
        version = sys.argv[3] if len(sys.argv) > 3 else None
        print(f"Searching vulnerabilities for {service} {version or ''}...")
        results = intel.get_service_vulns(service, version, limit=5)
        for cve in results:
            print(f"\n{cve.cve_id} [{cve.severity}]")
            print(f"  {cve.description[:100]}...")

    elif cmd == "recent":
        print("Fetching recent critical CVEs...")
        results = intel.get_recent_threats(days=7)
        for cve in results[:10]:
            print(f"\n{cve.cve_id} [{cve.severity}] - {cve.published_date}")
            print(f"  {cve.description[:100]}...")

    else:
        print("Unknown command")

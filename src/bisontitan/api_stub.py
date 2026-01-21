"""
BisonTitan API Stub Module
Sprint 4 - Lovable project embedding and Supabase sync.

Provides:
- /scan endpoint for Lovable project integration
- Supabase sync for SQLite data migration
- JSON API responses for embedding

Usage:
    # Start API server
    python -m bisontitan.api_stub serve --port 8000

    # Sync to Supabase
    python -m bisontitan.api_stub sync

    # Get scan result as JSON
    python -m bisontitan.api_stub scan --target 127.0.0.1
"""

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("bisontitan.api")


# =============================================================================
# Lovable Embed Response Structures
# =============================================================================

@dataclass
class LovableEmbedResponse:
    """Standard response format for Lovable embedding."""
    success: bool
    data: dict[str, Any]
    timestamp: str
    version: str = "1.0.0"

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "data": self.data,
            "timestamp": self.timestamp,
            "version": self.version,
            "source": "bisontitan",
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# =============================================================================
# API Endpoints (Stub Functions)
# =============================================================================

def scan_endpoint(target: str = "127.0.0.1", scan_type: str = "quick") -> LovableEmbedResponse:
    """
    /scan endpoint for Lovable project integration.

    Args:
        target: IP address or hostname to scan
        scan_type: "quick" or "full"

    Returns:
        LovableEmbedResponse with scan results
    """
    try:
        from bisontitan.vuln_checker import VulnChecker

        scanner = VulnChecker()

        if scan_type == "quick":
            result = scanner.quick_scan(target)
        else:
            result = scanner.full_scan(target)

        return LovableEmbedResponse(
            success=True,
            data={
                "scan_result": result.to_dict(),
                "target": target,
                "scan_type": scan_type,
            },
            timestamp=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        logger.error(f"Scan endpoint error: {e}")
        return LovableEmbedResponse(
            success=False,
            data={"error": str(e)},
            timestamp=datetime.utcnow().isoformat(),
        )


def status_endpoint() -> LovableEmbedResponse:
    """
    /status endpoint for health check.

    Returns:
        LovableEmbedResponse with system status
    """
    try:
        # Check dependencies
        status = {
            "api": "online",
            "modules": {},
        }

        try:
            from bisontitan.db import get_db
            db = get_db()
            status["modules"]["database"] = "connected"
            status["db_url"] = str(db.url)[:50]
        except Exception:
            status["modules"]["database"] = "unavailable"

        try:
            from bisontitan.vuln_checker import VulnChecker
            status["modules"]["scanner"] = "available"
        except ImportError:
            status["modules"]["scanner"] = "unavailable"

        try:
            from bisontitan.log_analyzer import LogAnalyzer
            status["modules"]["log_analyzer"] = "available"
        except ImportError:
            status["modules"]["log_analyzer"] = "unavailable"

        return LovableEmbedResponse(
            success=True,
            data=status,
            timestamp=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        return LovableEmbedResponse(
            success=False,
            data={"error": str(e)},
            timestamp=datetime.utcnow().isoformat(),
        )


def recent_scans_endpoint(limit: int = 10) -> LovableEmbedResponse:
    """
    /scans/recent endpoint for recent scan results.

    Args:
        limit: Maximum number of scans to return

    Returns:
        LovableEmbedResponse with recent scan data
    """
    try:
        from bisontitan.db import get_scan_repo

        repo = get_scan_repo()
        scans = repo.get_scans(limit=limit)

        return LovableEmbedResponse(
            success=True,
            data={
                "scans": scans,
                "count": len(scans),
            },
            timestamp=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        return LovableEmbedResponse(
            success=False,
            data={"error": str(e)},
            timestamp=datetime.utcnow().isoformat(),
        )


def anomalies_endpoint(limit: int = 10) -> LovableEmbedResponse:
    """
    /anomalies endpoint for security anomalies.

    Args:
        limit: Maximum number of anomalies to return

    Returns:
        LovableEmbedResponse with anomaly data
    """
    try:
        from bisontitan.db import get_anomaly_repo

        repo = get_anomaly_repo()
        anomalies = repo.get_recent_anomalies(limit=limit)

        return LovableEmbedResponse(
            success=True,
            data={
                "anomalies": anomalies,
                "count": len(anomalies),
            },
            timestamp=datetime.utcnow().isoformat(),
        )

    except Exception as e:
        return LovableEmbedResponse(
            success=False,
            data={"error": str(e)},
            timestamp=datetime.utcnow().isoformat(),
        )


# =============================================================================
# Supabase Sync Functions
# =============================================================================

def get_supabase_client():
    """
    Get Supabase client from environment variables.

    Environment Variables:
        SUPABASE_URL: Supabase project URL
        SUPABASE_KEY: Supabase API key

    Returns:
        Supabase client or None
    """
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")

    if not url or not key:
        logger.warning("Supabase not configured. Set SUPABASE_URL and SUPABASE_KEY")
        return None

    try:
        from supabase import create_client
        return create_client(url, key)
    except ImportError:
        logger.warning("supabase-py not installed. Run: pip install supabase")
        return None


def sync_scans_to_supabase(since_hours: int = 24) -> dict:
    """
    Sync recent scans from SQLite to Supabase.

    Args:
        since_hours: Sync scans from last N hours

    Returns:
        Sync result dict
    """
    client = get_supabase_client()
    if not client:
        return {"success": False, "error": "Supabase not configured"}

    try:
        from bisontitan.db import get_scan_repo
        from datetime import datetime, timedelta

        repo = get_scan_repo()
        scans = repo.get_scans(limit=1000)

        # Filter recent scans
        cutoff = datetime.utcnow() - timedelta(hours=since_hours)
        recent_scans = []
        for scan in scans:
            scan_time = scan.get("scan_time", "")
            if scan_time:
                try:
                    st = datetime.fromisoformat(scan_time.replace("Z", "+00:00"))
                    if st > cutoff:
                        recent_scans.append(scan)
                except ValueError:
                    pass

        if not recent_scans:
            return {"success": True, "synced": 0, "message": "No recent scans to sync"}

        # Upsert to Supabase
        result = client.table("scan_results").upsert(recent_scans).execute()

        return {
            "success": True,
            "synced": len(recent_scans),
            "message": f"Synced {len(recent_scans)} scans to Supabase",
        }

    except Exception as e:
        logger.error(f"Supabase sync error: {e}")
        return {"success": False, "error": str(e)}


def sync_anomalies_to_supabase(since_hours: int = 24) -> dict:
    """
    Sync recent anomalies from SQLite to Supabase.

    Args:
        since_hours: Sync anomalies from last N hours

    Returns:
        Sync result dict
    """
    client = get_supabase_client()
    if not client:
        return {"success": False, "error": "Supabase not configured"}

    try:
        from bisontitan.db import get_anomaly_repo
        from datetime import datetime, timedelta

        repo = get_anomaly_repo()
        anomalies = repo.get_recent_anomalies(limit=1000)

        # Filter recent anomalies
        cutoff = datetime.utcnow() - timedelta(hours=since_hours)
        recent = []
        for a in anomalies:
            detected_at = a.get("detected_at", "")
            if detected_at:
                try:
                    dt = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
                    if dt > cutoff:
                        recent.append(a)
                except ValueError:
                    pass

        if not recent:
            return {"success": True, "synced": 0, "message": "No recent anomalies to sync"}

        # Upsert to Supabase
        result = client.table("security_anomalies").upsert(recent).execute()

        return {
            "success": True,
            "synced": len(recent),
            "message": f"Synced {len(recent)} anomalies to Supabase",
        }

    except Exception as e:
        logger.error(f"Supabase sync error: {e}")
        return {"success": False, "error": str(e)}


def full_sync_to_supabase() -> dict:
    """
    Full sync of all data to Supabase.

    Returns:
        Combined sync results
    """
    results = {
        "scans": sync_scans_to_supabase(since_hours=720),  # Last 30 days
        "anomalies": sync_anomalies_to_supabase(since_hours=720),
        "timestamp": datetime.utcnow().isoformat(),
    }

    success = all(r.get("success", False) for r in [results["scans"], results["anomalies"]])
    results["overall_success"] = success

    return results


# =============================================================================
# Simple HTTP Server (for testing)
# =============================================================================

def start_api_server(host: str = "127.0.0.1", port: int = 8000):
    """
    Start a simple HTTP server for API testing.

    For production, use FastAPI or Flask.

    Args:
        host: Server host
        port: Server port
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from urllib.parse import urlparse, parse_qs

    class APIHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            # Route handling
            if path == "/scan":
                target = query.get("target", ["127.0.0.1"])[0]
                scan_type = query.get("type", ["quick"])[0]
                response = scan_endpoint(target, scan_type)
            elif path == "/status":
                response = status_endpoint()
            elif path == "/scans/recent":
                limit = int(query.get("limit", ["10"])[0])
                response = recent_scans_endpoint(limit)
            elif path == "/anomalies":
                limit = int(query.get("limit", ["10"])[0])
                response = anomalies_endpoint(limit)
            else:
                response = LovableEmbedResponse(
                    success=False,
                    data={"error": "Unknown endpoint", "available": ["/scan", "/status", "/scans/recent", "/anomalies"]},
                    timestamp=datetime.utcnow().isoformat(),
                )

            # Send response
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")  # CORS for Lovable
            self.end_headers()
            self.wfile.write(response.to_json().encode())

        def log_message(self, format, *args):
            logger.info(f"API: {args[0]}")

    server = HTTPServer((host, port), APIHandler)
    print(f"BisonTitan API Server running on http://{host}:{port}")
    print("Endpoints:")
    print("  GET /scan?target=127.0.0.1&type=quick")
    print("  GET /status")
    print("  GET /scans/recent?limit=10")
    print("  GET /anomalies?limit=10")
    print("\nPress Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


# =============================================================================
# CLI
# =============================================================================

def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="BisonTitan API Stub")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start API server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Server host")
    serve_parser.add_argument("--port", "-p", type=int, default=8000, help="Server port")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run scan and output JSON")
    scan_parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP")
    scan_parser.add_argument("--type", default="quick", choices=["quick", "full"])

    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Sync to Supabase")
    sync_parser.add_argument("--hours", type=int, default=24, help="Sync last N hours")

    # Status command
    subparsers.add_parser("status", help="Check API status")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.command == "serve":
        start_api_server(args.host, args.port)

    elif args.command == "scan":
        response = scan_endpoint(args.target, args.type)
        print(response.to_json())

    elif args.command == "sync":
        result = full_sync_to_supabase()
        print(json.dumps(result, indent=2))

    elif args.command == "status":
        response = status_endpoint()
        print(response.to_json())

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

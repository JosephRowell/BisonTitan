"""
BisonTitan Database Migration Stub
Sprint 1 - Supabase/PostgreSQL migration utilities.

This module provides migration tools for transitioning from local SQLite
to cloud PostgreSQL (Supabase) while maintaining data integrity.

Usage:
    # Export local data to JSON
    python migration.py export --output backup.json

    # Import to Supabase
    python migration.py import --input backup.json --target supabase

    # Verify migration
    python migration.py verify

Environment Variables:
    SUPABASE_URL - Supabase project URL
    SUPABASE_KEY - Supabase API key (anon or service role)
    DATABASE_URL - Direct PostgreSQL connection string
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("bisontitan.migration")


# =============================================================================
# Supabase Configuration (Stub)
# =============================================================================

def get_supabase_config() -> dict | None:
    """
    Get Supabase configuration from environment.

    Returns:
        Dict with url and key, or None if not configured
    """
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")

    if url and key:
        return {"url": url, "key": key}
    return None


def get_supabase_client():
    """
    Get Supabase client (requires supabase-py).

    Returns:
        Supabase client or None if not available
    """
    config = get_supabase_config()
    if not config:
        logger.warning("Supabase not configured. Set SUPABASE_URL and SUPABASE_KEY")
        return None

    try:
        from supabase import create_client
        return create_client(config["url"], config["key"])
    except ImportError:
        logger.warning("supabase-py not installed. Run: pip install supabase")
        return None


# =============================================================================
# SQL Schema for Supabase/PostgreSQL
# =============================================================================

SUPABASE_SCHEMA = """
-- BisonTitan Supabase Schema
-- Run this in your Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scan Results Table
CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    scan_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    duration_sec FLOAT DEFAULT 0.0,
    risk_score FLOAT DEFAULT 0.0,
    total_ports INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    raw_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Port Scans Table
CREATE TABLE IF NOT EXISTS port_scans (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scan_results(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    state VARCHAR(20) DEFAULT 'open',
    service VARCHAR(100),
    version VARCHAR(200),
    risk_level VARCHAR(20) DEFAULT 'low',
    reason TEXT,
    cve_data JSONB
);

-- Security Anomalies Table
CREATE TABLE IF NOT EXISTS security_anomalies (
    id SERIAL PRIMARY KEY,
    anomaly_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    recommended_action TEXT,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    source_ip VARCHAR(50),
    mitre_techniques JSONB,
    mitre_tactic VARCHAR(100),
    extra_data JSONB,
    resolved BOOLEAN DEFAULT FALSE
);

-- Dashboard Metrics Table
CREATE TABLE IF NOT EXISTS dashboard_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value FLOAT NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    tags JSONB
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS ix_scan_target_time ON scan_results(target, scan_time);
CREATE INDEX IF NOT EXISTS ix_port_scan_port ON port_scans(scan_id, port);
CREATE INDEX IF NOT EXISTS ix_anomaly_type ON security_anomalies(anomaly_type);
CREATE INDEX IF NOT EXISTS ix_anomaly_time ON security_anomalies(detected_at);
CREATE INDEX IF NOT EXISTS ix_metric_name_time ON dashboard_metrics(metric_name, recorded_at);

-- Row Level Security (RLS) - Optional
-- ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE port_scans ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE security_anomalies ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE dashboard_metrics ENABLE ROW LEVEL SECURITY;
"""


# =============================================================================
# Export Functions
# =============================================================================

def export_to_json(output_path: str = "bisontitan_backup.json") -> bool:
    """
    Export local SQLite data to JSON for migration.

    Args:
        output_path: Path to output JSON file

    Returns:
        True if successful
    """
    try:
        from bisontitan.db import get_db, get_scan_repo, get_anomaly_repo

        db = get_db()
        scan_repo = get_scan_repo()
        anomaly_repo = get_anomaly_repo()

        # Collect data
        data = {
            "export_time": datetime.utcnow().isoformat(),
            "source": db.url,
            "scans": scan_repo.get_scans(limit=10000),
            "anomalies": anomaly_repo.get_recent_anomalies(limit=10000),
        }

        # Write to file
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Exported {len(data['scans'])} scans, {len(data['anomalies'])} anomalies to {output_path}")
        return True

    except Exception as e:
        logger.error(f"Export failed: {e}")
        return False


def import_from_json(input_path: str, target: str = "supabase") -> bool:
    """
    Import data from JSON to target database.

    Args:
        input_path: Path to JSON file
        target: Target database ("supabase" or "postgresql")

    Returns:
        True if successful
    """
    try:
        with open(input_path, "r") as f:
            data = json.load(f)

        if target == "supabase":
            return _import_to_supabase(data)
        else:
            return _import_to_postgresql(data)

    except Exception as e:
        logger.error(f"Import failed: {e}")
        return False


def _import_to_supabase(data: dict) -> bool:
    """Import data to Supabase using REST API."""
    client = get_supabase_client()
    if not client:
        return False

    # Import scans
    scans = data.get("scans", [])
    if scans:
        result = client.table("scan_results").insert(scans).execute()
        logger.info(f"Imported {len(scans)} scans to Supabase")

    # Import anomalies
    anomalies = data.get("anomalies", [])
    if anomalies:
        result = client.table("security_anomalies").insert(anomalies).execute()
        logger.info(f"Imported {len(anomalies)} anomalies to Supabase")

    return True


def _import_to_postgresql(data: dict) -> bool:
    """Import data to PostgreSQL using SQLAlchemy."""
    from bisontitan.db import get_db, get_scan_repo

    db = get_db()
    if not db.is_postgresql():
        logger.error("Target database is not PostgreSQL")
        return False

    scan_repo = get_scan_repo()
    for scan in data.get("scans", []):
        scan_repo.save_scan(scan)

    return True


# =============================================================================
# Verification Functions
# =============================================================================

def verify_migration() -> dict:
    """
    Verify migration by comparing local and remote data counts.

    Returns:
        Dict with verification results
    """
    from bisontitan.db import get_db, get_scan_repo

    results = {
        "local": {},
        "remote": {},
        "match": False,
    }

    # Local counts
    try:
        scan_repo = get_scan_repo()
        local_scans = len(scan_repo.get_scans(limit=10000))
        results["local"]["scans"] = local_scans
    except Exception as e:
        results["local"]["error"] = str(e)

    # Remote counts (Supabase)
    try:
        client = get_supabase_client()
        if client:
            scans = client.table("scan_results").select("id", count="exact").execute()
            results["remote"]["scans"] = scans.count if hasattr(scans, 'count') else len(scans.data)
    except Exception as e:
        results["remote"]["error"] = str(e)

    # Check match
    if results.get("local", {}).get("scans") == results.get("remote", {}).get("scans"):
        results["match"] = True

    return results


def generate_supabase_schema() -> str:
    """
    Get the SQL schema for Supabase.

    Returns:
        SQL schema string
    """
    return SUPABASE_SCHEMA


# =============================================================================
# CLI
# =============================================================================

def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="BisonTitan Database Migration")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export local data to JSON")
    export_parser.add_argument("--output", "-o", default="bisontitan_backup.json", help="Output file")

    # Import command
    import_parser = subparsers.add_parser("import", help="Import data to target DB")
    import_parser.add_argument("--input", "-i", required=True, help="Input JSON file")
    import_parser.add_argument("--target", "-t", default="supabase", choices=["supabase", "postgresql"])

    # Schema command
    schema_parser = subparsers.add_parser("schema", help="Output Supabase SQL schema")
    schema_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify migration")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.command == "export":
        success = export_to_json(args.output)
        print(f"Export {'succeeded' if success else 'failed'}")

    elif args.command == "import":
        success = import_from_json(args.input, args.target)
        print(f"Import {'succeeded' if success else 'failed'}")

    elif args.command == "schema":
        schema = generate_supabase_schema()
        if args.output:
            with open(args.output, "w") as f:
                f.write(schema)
            print(f"Schema written to {args.output}")
        else:
            print(schema)

    elif args.command == "verify":
        results = verify_migration()
        print(json.dumps(results, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

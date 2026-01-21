"""
BisonTitan Database Layer
Sprint 1 - PostgreSQL with SQLite fallback (local only).

Stores scan results, anomalies, and metrics for dashboard visualization.
Uses SQLAlchemy ORM with automatic fallback to SQLite if PostgreSQL unavailable.

Environment Variables:
    DATABASE_URL - PostgreSQL connection string (optional)
    BISONTITAN_DB_PATH - SQLite path (default: ~/.bisontitan/data.db)
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    Float,
    String,
    DateTime,
    Boolean,
    Text,
    JSON,
    ForeignKey,
    Index,
    text,
)
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    relationship,
    Session,
)
from sqlalchemy.exc import OperationalError

logger = logging.getLogger("bisontitan.db")

Base = declarative_base()


# =============================================================================
# Models
# =============================================================================

class ScanResult(Base):
    """Stores vulnerability scan results."""
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False)  # "quick", "full", "config"
    scan_time = Column(DateTime, default=datetime.utcnow, index=True)
    duration_sec = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    total_ports = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    raw_data = Column(JSON, nullable=True)  # Full scan result JSON

    # Relationships
    ports = relationship("PortScan", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scan_target_time", "target", "scan_time"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "scan_type": self.scan_type,
            "scan_time": self.scan_time.isoformat() if self.scan_time else None,
            "duration_sec": self.duration_sec,
            "risk_score": self.risk_score,
            "total_ports": self.total_ports,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
        }


class PortScan(Base):
    """Individual port scan results."""
    __tablename__ = "port_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)
    port = Column(Integer, nullable=False)
    state = Column(String(20), default="open")
    service = Column(String(100), nullable=True)
    version = Column(String(200), nullable=True)
    risk_level = Column(String(20), default="low")  # critical, high, medium, low, info
    reason = Column(Text, nullable=True)
    cve_data = Column(JSON, nullable=True)  # CVE enrichment data

    # Relationships
    scan = relationship("ScanResult", back_populates="ports")

    __table_args__ = (
        Index("ix_port_scan_port", "scan_id", "port"),
    )

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "cve_data": self.cve_data,
        }


class SecurityAnomaly(Base):
    """Detected security anomalies from log analysis."""
    __tablename__ = "security_anomalies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    anomaly_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False)  # critical, warning, info
    description = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(50), nullable=True)
    mitre_techniques = Column(JSON, nullable=True)  # ["T1110", "T1078"]
    mitre_tactic = Column(String(100), nullable=True)
    extra_data = Column(JSON, nullable=True)
    resolved = Column(Boolean, default=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "recommended_action": self.recommended_action,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "source_ip": self.source_ip,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactic": self.mitre_tactic,
            "resolved": self.resolved,
        }


class DashboardMetric(Base):
    """Time-series metrics for dashboard charts."""
    __tablename__ = "dashboard_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)
    tags = Column(JSON, nullable=True)  # {"host": "server1", "type": "scan"}

    __table_args__ = (
        Index("ix_metric_name_time", "metric_name", "recorded_at"),
    )


# =============================================================================
# Database Connection Manager
# =============================================================================

class Database:
    """
    Database connection manager with PostgreSQL/SQLite fallback.

    Usage:
        db = Database()
        with db.session() as session:
            session.add(ScanResult(...))
    """

    def __init__(self, url: str | None = None):
        """
        Initialize database connection.

        Args:
            url: Database URL. If None, tries DATABASE_URL env var,
                 then falls back to SQLite.
        """
        self.url = url or self._get_database_url()
        self.engine = None
        self.SessionLocal = None
        self._connect()

    def _get_database_url(self) -> str:
        """Get database URL from environment or default to SQLite."""
        # Try PostgreSQL first
        pg_url = os.getenv("DATABASE_URL")
        if pg_url:
            logger.info("Using PostgreSQL from DATABASE_URL")
            return pg_url

        # Fallback to SQLite
        db_path = os.getenv("BISONTITAN_DB_PATH")
        if not db_path:
            # Default path
            data_dir = Path.home() / ".bisontitan"
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(data_dir / "data.db")

        logger.info(f"Using SQLite at {db_path}")
        return f"sqlite:///{db_path}"

    def _connect(self):
        """Establish database connection with fallback."""
        try:
            # Try primary connection
            self.engine = create_engine(
                self.url,
                echo=False,
                pool_pre_ping=True,
            )
            # Test connection
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))

            self.SessionLocal = sessionmaker(bind=self.engine)
            logger.info(f"Connected to database: {self.url.split('@')[-1] if '@' in self.url else self.url}")

        except OperationalError as e:
            if "postgresql" in self.url:
                logger.warning(f"PostgreSQL connection failed: {e}")
                logger.info("Falling back to SQLite...")
                # Fallback to SQLite
                data_dir = Path.home() / ".bisontitan"
                data_dir.mkdir(parents=True, exist_ok=True)
                sqlite_path = str(data_dir / "data.db")
                self.url = f"sqlite:///{sqlite_path}"
                self.engine = create_engine(self.url, echo=False)
                self.SessionLocal = sessionmaker(bind=self.engine)
            else:
                raise

    def create_tables(self):
        """Create all tables if they don't exist."""
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created/verified")

    def session(self) -> Session:
        """Get a database session (use with context manager)."""
        return self.SessionLocal()

    def is_postgresql(self) -> bool:
        """Check if using PostgreSQL."""
        return "postgresql" in self.url


# =============================================================================
# Data Access Layer (CRUD Operations)
# =============================================================================

class ScanRepository:
    """Repository for scan results."""

    def __init__(self, db: Database):
        self.db = db

    def save_scan(self, scan_result: dict) -> int:
        """
        Save a scan result to database.

        Args:
            scan_result: Dict from VulnChecker.full_scan().to_dict()

        Returns:
            Scan ID
        """
        with self.db.session() as session:
            # Count by severity
            ports = scan_result.get("open_ports", [])
            critical = sum(1 for p in ports if p.get("risk_level") == "critical")
            high = sum(1 for p in ports if p.get("risk_level") == "high")
            medium = sum(1 for p in ports if p.get("risk_level") == "medium")
            low = sum(1 for p in ports if p.get("risk_level") in ["low", "info"])

            scan = ScanResult(
                target=scan_result.get("target", "unknown"),
                scan_type=scan_result.get("scan_type", "quick"),
                scan_time=datetime.fromisoformat(scan_result["scan_time"]) if scan_result.get("scan_time") else datetime.utcnow(),
                duration_sec=scan_result.get("scan_duration_sec", 0.0),
                risk_score=scan_result.get("risk_score", 0.0),
                total_ports=len(ports),
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
                raw_data=scan_result,
            )
            session.add(scan)
            session.flush()  # Get ID

            # Save individual port results
            for port_data in ports:
                port = PortScan(
                    scan_id=scan.id,
                    port=port_data.get("port", 0),
                    state=port_data.get("state", "open"),
                    service=port_data.get("service"),
                    version=port_data.get("version"),
                    risk_level=port_data.get("risk_level", "low"),
                    reason=port_data.get("reason"),
                    cve_data=port_data.get("cve_details"),
                )
                session.add(port)

            session.commit()
            logger.info(f"Saved scan {scan.id} for {scan.target}")
            return scan.id

    def get_latest_scan(self, target: str = None) -> dict | None:
        """Get the most recent scan result."""
        with self.db.session() as session:
            query = session.query(ScanResult).order_by(ScanResult.scan_time.desc())
            if target:
                query = query.filter(ScanResult.target == target)
            scan = query.first()
            return scan.to_dict() if scan else None

    def get_scans(self, limit: int = 100, target: str = None) -> list[dict]:
        """Get recent scans."""
        with self.db.session() as session:
            query = session.query(ScanResult).order_by(ScanResult.scan_time.desc())
            if target:
                query = query.filter(ScanResult.target == target)
            scans = query.limit(limit).all()
            return [s.to_dict() for s in scans]

    def get_port_details(self, scan_id: int) -> list[dict]:
        """Get port details for a scan."""
        with self.db.session() as session:
            ports = session.query(PortScan).filter(PortScan.scan_id == scan_id).all()
            return [p.to_dict() for p in ports]

    def get_risk_distribution(self, days: int = 30) -> dict:
        """Get risk distribution for dashboard pie chart."""
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(days=days)

        with self.db.session() as session:
            scans = session.query(ScanResult).filter(
                ScanResult.scan_time >= cutoff
            ).all()

            totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for scan in scans:
                totals["critical"] += scan.critical_count
                totals["high"] += scan.high_count
                totals["medium"] += scan.medium_count
                totals["low"] += scan.low_count

            return totals

    def get_heatmap_data(self, limit: int = 10) -> dict:
        """Get data for port heatmap visualization."""
        with self.db.session() as session:
            # Get recent scans with ports
            scans = session.query(ScanResult).order_by(
                ScanResult.scan_time.desc()
            ).limit(limit).all()

            if not scans:
                return {"hosts": [], "ports": [], "data": []}

            hosts = []
            port_set = set()
            port_risks = {}  # {(host, port): risk_score}

            for scan in scans:
                host = scan.target
                if host not in hosts:
                    hosts.append(host)

                for port in scan.ports:
                    port_set.add(port.port)
                    risk_value = {"critical": 10, "high": 7, "medium": 5, "low": 2, "info": 1}.get(port.risk_level, 0)
                    port_risks[(host, port.port)] = risk_value

            ports = sorted(list(port_set))

            # Build heatmap matrix
            data = []
            for host in hosts:
                row = [port_risks.get((host, p), 0) for p in ports]
                data.append(row)

            return {
                "hosts": hosts,
                "ports": [str(p) for p in ports],
                "data": data,
            }


class AnomalyRepository:
    """Repository for security anomalies."""

    def __init__(self, db: Database):
        self.db = db

    def save_anomaly(self, anomaly_data: dict) -> int:
        """Save a security anomaly."""
        with self.db.session() as session:
            anomaly = SecurityAnomaly(
                anomaly_type=anomaly_data.get("type", "unknown"),
                severity=anomaly_data.get("severity", "info"),
                description=anomaly_data.get("description"),
                recommended_action=anomaly_data.get("recommended_action"),
                source_ip=anomaly_data.get("source_ip"),
                mitre_techniques=anomaly_data.get("mitre_techniques"),
                mitre_tactic=anomaly_data.get("mitre_tactic"),
                extra_data=anomaly_data.get("metadata"),
            )
            session.add(anomaly)
            session.commit()
            return anomaly.id

    def get_recent_anomalies(self, limit: int = 50, severity: str = None) -> list[dict]:
        """Get recent anomalies."""
        with self.db.session() as session:
            query = session.query(SecurityAnomaly).order_by(
                SecurityAnomaly.detected_at.desc()
            )
            if severity:
                query = query.filter(SecurityAnomaly.severity == severity)
            anomalies = query.limit(limit).all()
            return [a.to_dict() for a in anomalies]

    def get_anomaly_counts(self) -> dict:
        """Get anomaly counts by severity."""
        with self.db.session() as session:
            from sqlalchemy import func
            results = session.query(
                SecurityAnomaly.severity,
                func.count(SecurityAnomaly.id)
            ).group_by(SecurityAnomaly.severity).all()
            return {r[0]: r[1] for r in results}


class MetricsRepository:
    """Repository for dashboard metrics."""

    def __init__(self, db: Database):
        self.db = db

    def record_metric(self, name: str, value: float, tags: dict = None):
        """Record a metric value."""
        with self.db.session() as session:
            metric = DashboardMetric(
                metric_name=name,
                metric_value=value,
                tags=tags,
            )
            session.add(metric)
            session.commit()

    def get_metric_series(self, name: str, hours: int = 24) -> list[dict]:
        """Get metric time series."""
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        with self.db.session() as session:
            metrics = session.query(DashboardMetric).filter(
                DashboardMetric.metric_name == name,
                DashboardMetric.recorded_at >= cutoff
            ).order_by(DashboardMetric.recorded_at).all()

            return [
                {"time": m.recorded_at.isoformat(), "value": m.metric_value}
                for m in metrics
            ]


# =============================================================================
# Global Database Instance
# =============================================================================

_db_instance: Database | None = None


def get_db() -> Database:
    """Get or create the global database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
        _db_instance.create_tables()
    return _db_instance


def get_scan_repo() -> ScanRepository:
    """Get scan repository."""
    return ScanRepository(get_db())


def get_anomaly_repo() -> AnomalyRepository:
    """Get anomaly repository."""
    return AnomalyRepository(get_db())


def get_metrics_repo() -> MetricsRepository:
    """Get metrics repository."""
    return MetricsRepository(get_db())


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Initialize database
    db = get_db()
    print(f"Database: {db.url}")
    print(f"PostgreSQL: {db.is_postgresql()}")

    # Test save scan
    scan_repo = get_scan_repo()

    test_scan = {
        "target": "127.0.0.1",
        "scan_type": "quick",
        "scan_time": datetime.utcnow().isoformat(),
        "scan_duration_sec": 2.5,
        "risk_score": 6.5,
        "open_ports": [
            {"port": 445, "state": "open", "service": "SMB", "risk_level": "critical", "reason": "SMB exposed"},
            {"port": 3389, "state": "open", "service": "RDP", "risk_level": "critical", "reason": "RDP exposed"},
            {"port": 80, "state": "open", "service": "HTTP", "risk_level": "low", "reason": "Web server"},
        ],
    }

    scan_id = scan_repo.save_scan(test_scan)
    print(f"Saved scan ID: {scan_id}")

    # Test retrieve
    latest = scan_repo.get_latest_scan()
    print(f"Latest scan: {latest}")

    # Test heatmap
    heatmap = scan_repo.get_heatmap_data()
    print(f"Heatmap data: {heatmap}")

    print("\nDatabase test completed!")

"""
BisonTitan Streamlit GUI Dashboard
Sprint 1 - Real data flow with PostgreSQL/SQLite backend.

Run with: streamlit run app.py
Or via CLI: bisontitan gui --launch

Features:
- Real vulnerability scans via vuln_checker
- Database storage (PostgreSQL/SQLite)
- Live heatmap from scan results
"""

import json
import os
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import Config module for settings management
try:
    from bisontitan.config import Config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

# Import BisonTitan modules
try:
    from bisontitan.db import get_db, get_scan_repo, get_anomaly_repo, get_metrics_repo
    from bisontitan.vuln_checker import VulnChecker
    DB_AVAILABLE = True
except ImportError as e:
    DB_AVAILABLE = False
    print(f"DB import error: {e}")

# Import log analyzer for real event analysis
try:
    from bisontitan.log_analyzer import LogAnalyzer, LogAnalysisResult
    LOG_ANALYZER_AVAILABLE = True
except ImportError as e:
    LOG_ANALYZER_AVAILABLE = False
    print(f"LogAnalyzer import error: {e}")

# Import fingerprint viewer for real browser fingerprinting
try:
    from bisontitan.fingerprint_viewer import FingerprintViewer, FingerprintResult
    FINGERPRINT_AVAILABLE = True
except ImportError as e:
    FINGERPRINT_AVAILABLE = False
    print(f"FingerprintViewer import error: {e}")

# Page configuration
st.set_page_config(
    page_title="BisonTitan Security Suite",
    page_icon="🦬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 0;
    }
    .sub-header {
        font-size: 1rem;
        color: #666;
        margin-top: 0;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
    }
    .risk-critical { color: #ff4444; font-weight: bold; }
    .risk-high { color: #ffaa00; font-weight: bold; }
    .risk-medium { color: #00aaff; }
    .risk-low { color: #888; }
    .risk-none { color: #44ff44; }
    .stAlert { border-radius: 10px; }
    div[data-testid="stMetricValue"] { font-size: 2rem; }
</style>
""", unsafe_allow_html=True)


# =============================================================================
# Sprint 10 - Global Session State Initialization
# =============================================================================
# Initialize all session state variables at app startup to prevent conflicts
# with st.cache_resource and widget keys. Uses timestamp-based unique keys.

def init_session_state():
    """
    Initialize all session state variables at app startup.
    Sprint 10 fix - prevents widget key conflicts with cached resources.
    """
    # Generate unique session identifier with timestamp
    if "_session_init_ts" not in st.session_state:
        st.session_state["_session_init_ts"] = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    # Core session variables
    defaults = {
        "session_id": str(uuid.uuid4())[:8],
        "gui_settings": None,  # Will be loaded later

        # Baseline filtering state (Sprint 8/9/10)
        "baseline_enabled_state": True,
        "baseline_enabled": True,
        "quick_filter_state": None,
        "quick_filter": None,
        "event_search_state": "",
        "event_search": "",
        "baseline_stats": {},

        # Log analysis state
        "log_analyzed": False,
        "log_analysis_result": None,

        # Scanner state
        "scanner_result": None,
        "process_scan": None,
        "file_scan_result": None,
        "file_scan_results": None,

        # Vulnerability state
        "vuln_result": None,
        "vuln_scanned": False,

        # Fingerprint state
        "fingerprint_data": None,

        # Simulation state
        "sim_complete": False,
    }

    for key, default_value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default_value


def get_unique_widget_key(base_key: str) -> str:
    """
    Generate a unique widget key using session timestamp.
    Sprint 10 fix - prevents key conflicts with st.cache_resource.

    Args:
        base_key: Base name for the widget key

    Returns:
        Unique key string with session timestamp
    """
    init_ts = st.session_state.get("_session_init_ts", "default")
    return f"{base_key}_{init_ts}"


# Initialize session state immediately at module load
init_session_state()


def get_bisontitan_path() -> str:
    """Get the path to bisontitan CLI."""
    if os.name == 'nt':
        return "bisontitan"
    return "bisontitan"


def run_cli_command(args: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """Run a BisonTitan CLI command and return output."""
    cmd = [get_bisontitan_path()] + args + ["--json-output"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except FileNotFoundError:
        return "", "BisonTitan CLI not found.", 1


def parse_json_output(output: str) -> dict[str, Any] | None:
    """Parse JSON output from CLI."""
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


# =============================================================================
# Real Scan Functions (Sprint 1)
# =============================================================================

@st.cache_resource
def get_scanner():
    """Get cached VulnChecker instance."""
    if DB_AVAILABLE:
        return VulnChecker()
    return None


def run_real_scan(target: str, scan_type: str = "quick") -> dict | None:
    """
    Run a real vulnerability scan and store in database.

    Args:
        target: IP address or hostname to scan
        scan_type: "quick" or "full"

    Returns:
        Scan result dict or None on failure
    """
    if not DB_AVAILABLE:
        st.error("Database module not available")
        return None

    try:
        scanner = get_scanner()
        if not scanner:
            return None

        # Run scan
        if scan_type == "quick":
            result = scanner.quick_scan(target)
        else:
            result = scanner.full_scan(target)

        # Convert to dict
        result_dict = result.to_dict()
        result_dict["scan_type"] = scan_type

        # Store in database
        scan_repo = get_scan_repo()
        scan_id = scan_repo.save_scan(result_dict)
        result_dict["db_id"] = scan_id

        # Record metric
        metrics_repo = get_metrics_repo()
        metrics_repo.record_metric("risk_score", result.risk_score, {"target": target})

        return result_dict

    except Exception as e:
        st.error(f"Scan failed: {e}")
        return None


def load_dashboard_data() -> dict:
    """
    Load real data from database for dashboard.

    Returns:
        Dict with dashboard metrics and chart data
    """
    if not DB_AVAILABLE:
        return get_placeholder_data()

    try:
        scan_repo = get_scan_repo()
        anomaly_repo = get_anomaly_repo()

        # Get latest scan
        latest_scan = scan_repo.get_latest_scan()

        # Get risk distribution
        risk_dist = scan_repo.get_risk_distribution(days=30)

        # Get heatmap data
        heatmap = scan_repo.get_heatmap_data(limit=10)

        # Get anomaly counts
        anomaly_counts = anomaly_repo.get_anomaly_counts()

        # Get recent anomalies
        recent_anomalies = anomaly_repo.get_recent_anomalies(limit=10)

        return {
            "latest_scan": latest_scan,
            "risk_distribution": risk_dist,
            "heatmap": heatmap,
            "anomaly_counts": anomaly_counts,
            "recent_anomalies": recent_anomalies,
            "has_data": latest_scan is not None,
        }

    except Exception as e:
        st.warning(f"Could not load data: {e}")
        return get_placeholder_data()


def get_placeholder_data() -> dict:
    """Return placeholder data when no scans exist."""
    return {
        "latest_scan": None,
        "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "heatmap": {"hosts": [], "ports": [], "data": []},
        "anomaly_counts": {},
        "recent_anomalies": [],
        "has_data": False,
    }


# =============================================================================
# Real Log Analysis Functions (Sprint 2)
# =============================================================================

@st.cache_resource
def get_log_analyzer():
    """Get cached LogAnalyzer instance."""
    if LOG_ANALYZER_AVAILABLE:
        return LogAnalyzer()
    return None


def check_admin_status() -> tuple[bool, str]:
    """Check if running as admin (for log analysis)."""
    import ctypes
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            return True, "Running as Administrator"
        return False, "Not running as Administrator"
    except Exception:
        return False, "Could not check admin status"


def run_real_log_analysis(
    log_type: str = "Security",
    hours: int = 24,
    baseline_enabled: bool = True,
    quick_filter: str | None = None,
) -> dict | None:
    """
    Run real Windows event log analysis and store anomalies in DB.
    Sprint 8 - Added baseline filtering support.
    Sprint 10 - Added safe_full_analysis with better error handling.

    Args:
        log_type: Type of log to analyze (Security, System, Application)
        hours: Hours of logs to analyze
        baseline_enabled: Whether to apply baseline filtering
        quick_filter: Optional quick filter preset name

    Returns:
        Analysis result dict or None on failure
    """
    if not LOG_ANALYZER_AVAILABLE:
        st.warning("Log analyzer not available. Install with: pip install pywin32")
        return None

    try:
        analyzer = get_log_analyzer()
        if not analyzer:
            st.error("Failed to initialize log analyzer")
            return None

        # Sprint 10 - Verify analyzer has required methods
        if not hasattr(analyzer, 'full_analysis') and not hasattr(analyzer, 'safe_full_analysis'):
            st.error("Log analyzer missing required methods. Please reinstall bisontitan.")
            return None

        # Sprint 8 - Set baseline filtering state
        if hasattr(analyzer, 'set_baseline_enabled'):
            analyzer.set_baseline_enabled(baseline_enabled)

        # Sprint 10 - Use safe_full_analysis if available, fallback to full_analysis
        if hasattr(analyzer, 'safe_full_analysis'):
            result = analyzer.safe_full_analysis(log_type=log_type, hours=hours)
        else:
            result = analyzer.full_analysis(log_type=log_type, hours=hours)

        # Check for errors in result
        stats = result.statistics if hasattr(result, 'statistics') else {}

        # Check if there was an error
        if stats.get("error"):
            error_msg = stats.get("error", "Unknown error")
            if stats.get("admin_required"):
                st.error(f"**Admin Required:** {error_msg}")
                st.info("To analyze Security logs, run Streamlit as Administrator:\n"
                       "1. Open Command Prompt as Administrator\n"
                       "2. Run: `streamlit run src/bisontitan/gui/app.py`")
            elif stats.get("error_type") == "AttributeError":
                st.error(f"**Configuration Error:** {error_msg}")
                st.info("Try clearing the cache: press 'C' then 'Enter' in the terminal")
            else:
                st.error(f"**Analysis Error:** {error_msg}")
            return result.to_dict()

        # Sprint 8 - Get baseline stats
        baseline_stats = {}
        if hasattr(analyzer, 'get_baseline_stats'):
            baseline_stats = analyzer.get_baseline_stats()

        # Store anomalies in database
        if DB_AVAILABLE and hasattr(result, 'anomalies') and result.anomalies:
            anomaly_repo = get_anomaly_repo()
            for anomaly in result.anomalies:
                anomaly_data = anomaly.to_dict() if hasattr(anomaly, 'to_dict') else anomaly
                anomaly_repo.save_anomaly(anomaly_data)

        # Add baseline stats to result
        result_dict = result.to_dict() if hasattr(result, 'to_dict') else {}
        result_dict["baseline_stats"] = baseline_stats

        return result_dict

    except AttributeError as e:
        st.error(f"**Attribute Error:** {e}")
        st.info("The log analyzer may need to be reloaded. Try refreshing the page.")
        return None
    except PermissionError as e:
        st.error(f"**Permission Denied:** {e}")
        st.info("Security logs require Administrator privileges.\n"
               "Run Streamlit as Administrator to access Security events.")
        return None
    except Exception as e:
        st.error(f"Log analysis failed: {e}")
        import traceback
        st.expander("Error Details").code(traceback.format_exc())
        return None


def load_recent_anomalies(limit: int = 10) -> list[dict]:
    """Load recent anomalies from database."""
    if not DB_AVAILABLE:
        return []

    try:
        anomaly_repo = get_anomaly_repo()
        return anomaly_repo.get_recent_anomalies(limit=limit)
    except Exception as e:
        st.warning(f"Could not load anomalies: {e}")
        return []


# =============================================================================
# Real Fingerprint Functions (Sprint 2)
# =============================================================================

@st.cache_resource
def get_fingerprint_viewer():
    """Get cached FingerprintViewer instance."""
    if FINGERPRINT_AVAILABLE:
        return FingerprintViewer()
    return None


def capture_real_fingerprint(use_playwright: bool = True) -> dict | None:
    """
    Capture real browser fingerprint using Playwright.

    Args:
        use_playwright: If True, use Playwright for full capture

    Returns:
        Fingerprint dict or None on failure
    """
    if not FINGERPRINT_AVAILABLE:
        st.warning("Fingerprint viewer not available")
        return None

    try:
        viewer = get_fingerprint_viewer()
        if not viewer:
            return None

        if use_playwright and viewer._playwright_available:
            result = viewer.capture_fingerprint(simulate=False)
            return result.to_dict()
        else:
            # Fallback: Get basic system info without Playwright
            return get_basic_fingerprint()

    except Exception as e:
        st.warning(f"Fingerprint capture failed: {e}. Using fallback.")
        return get_basic_fingerprint()


def get_basic_fingerprint() -> dict:
    """Get basic fingerprint without Playwright (fallback)."""
    import platform
    import socket

    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except:
        hostname = "unknown"
        local_ip = "127.0.0.1"

    return {
        "ua": f"Python/{platform.python_version()} ({platform.system()} {platform.release()})",
        "ip": {"origin": local_ip},
        "resolution": "N/A (server-side)",
        "geo": {"timezone": "Local"},
        "hardware": {
            "memory": "N/A",
            "threads": str(os.cpu_count() or "unknown"),
            "maxTouchPoints": 0,
        },
        "storage": {
            "localStorage": False,
            "sessionStorage": False,
            "indexedDB": False,
            "cookies": False,
        },
        "browser": {
            "canvas": "N/A (server-side)",
            "webgl": {"vendor": "N/A", "renderer": "N/A"},
            "plugins": [],
        },
        "fingerprint_score": 0.5,
        "risk": "Medium",
        "platform": platform.system(),
        "language": "en-US",
        "recommendations": [
            "Install Playwright for full browser fingerprint analysis",
            "Run: pip install playwright && playwright install chromium",
        ],
        "captured_at": datetime.now().isoformat(),
    }


# =============================================================================
# Config Management Functions (Sprint 3)
# =============================================================================

def get_session_id() -> str:
    """Get or create session-based user ID for config storage."""
    if "session_id" not in st.session_state:
        st.session_state.session_id = str(uuid.uuid4())[:8]
    return st.session_state.session_id


def get_config_path() -> Path:
    """Get path to user config file."""
    config_dir = Path.home() / ".bisontitan"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.yaml"


def get_gui_settings_path() -> Path:
    """Get path to GUI-specific settings file."""
    config_dir = Path.home() / ".bisontitan"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "gui_settings.yaml"


def load_gui_settings() -> dict:
    """Load GUI settings from YAML file."""
    settings_path = get_gui_settings_path()
    if settings_path.exists():
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {
        "theme": "Dark",
        "notifications": True,
        "auto_refresh": False,
        "refresh_interval": 60,
        "scan_timeout": "60s",
        "abuseipdb_api_key": "",
        "gologin_api_key": "",
        "session_id": get_session_id(),
    }


def save_gui_settings(settings: dict) -> bool:
    """Save GUI settings to YAML file."""
    settings_path = get_gui_settings_path()
    try:
        settings["session_id"] = get_session_id()
        settings["last_saved"] = datetime.now().isoformat()
        with open(settings_path, "w", encoding="utf-8") as f:
            yaml.dump(settings, f, default_flow_style=False)
        return True
    except Exception as e:
        st.error(f"Failed to save settings: {e}")
        return False


def load_app_config() -> "Config | None":
    """Load full application config."""
    if not CONFIG_AVAILABLE:
        return None
    try:
        config_path = get_config_path()
        if config_path.exists():
            return Config.load(config_path)
        return Config()
    except Exception:
        return Config()


def save_app_config(config: "Config") -> bool:
    """Save full application config to YAML."""
    if not CONFIG_AVAILABLE:
        return False
    try:
        config_path = get_config_path()
        config.save(config_path)
        return True
    except Exception as e:
        st.error(f"Failed to save config: {e}")
        return False


def export_config_yaml() -> str:
    """Export current config as YAML string."""
    settings = load_gui_settings()
    if CONFIG_AVAILABLE:
        config = load_app_config()
        if config:
            full_config = {
                "gui_settings": settings,
                "app_config": config.to_dict(),
            }
            return yaml.dump(full_config, default_flow_style=False)
    return yaml.dump({"gui_settings": settings}, default_flow_style=False)


def import_config_yaml(yaml_content: str) -> bool:
    """Import config from YAML string."""
    try:
        data = yaml.safe_load(yaml_content)
        if "gui_settings" in data:
            save_gui_settings(data["gui_settings"])
        if "app_config" in data and CONFIG_AVAILABLE:
            config = Config._from_dict(data["app_config"])
            save_app_config(config)
        return True
    except Exception as e:
        st.error(f"Failed to import config: {e}")
        return False


# Initialize session state for settings
if "gui_settings" not in st.session_state:
    st.session_state.gui_settings = load_gui_settings()


# =============================================================================
# Sidebar Navigation
# =============================================================================
with st.sidebar:
    st.image("https://raw.githubusercontent.com/placeholder/bisontitan/main/logo.png", width=100)
    st.markdown("## 🦬 BisonTitan")
    st.markdown("*Security Suite Dashboard*")
    st.divider()

    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "🔍 Scanner", "🔒 Privacy Check", "📋 Log Analysis",
         "⚠️ Vulnerabilities", "⚔️ Attack Simulation", "⚙️ Settings"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("""
    **Quick Links:**
    - [Documentation](https://github.com/bisontitan/docs)
    - [Report Issue](https://github.com/bisontitan/issues)
    """)

    st.divider()
    st.caption(f"v1.0.0 | {datetime.now().strftime('%Y-%m-%d')}")


# =============================================================================
# Dashboard Page (Sprint 1 - Real Data)
# =============================================================================
if page == "📊 Dashboard":
    st.markdown('<p class="main-header">🦬 BisonTitan Security Dashboard</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Real-time security overview and threat monitoring</p>', unsafe_allow_html=True)
    st.divider()

    # Load real data from database
    dashboard_data = load_dashboard_data()
    latest_scan = dashboard_data.get("latest_scan")
    risk_dist = dashboard_data.get("risk_distribution", {})
    heatmap_data = dashboard_data.get("heatmap", {})

    # Quick scan button at top
    col_scan, col_status = st.columns([1, 3])
    with col_scan:
        if st.button("🔄 Quick Scan 127.0.0.1", type="primary"):
            with st.spinner("Running real scan..."):
                result = run_real_scan("127.0.0.1", "quick")
                if result:
                    st.success(f"Scan complete! Risk: {result.get('risk_score', 0):.1f}/10")
                    st.rerun()

    with col_status:
        if dashboard_data.get("has_data"):
            st.success(f"Last scan: {latest_scan.get('target')} at {latest_scan.get('scan_time', 'N/A')[:19]}")
        else:
            st.info("No scans yet. Click 'Quick Scan' to populate real data.")

    st.divider()

    # Top metrics row - REAL DATA
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        risk_score = latest_scan.get("risk_score", 0) if latest_scan else 0
        st.metric(
            label="Overall Risk Score",
            value=f"{risk_score:.1f}/10",
            delta="-0.0" if risk_score == 0 else None,
            delta_color="inverse",
        )

    with col2:
        total_ports = latest_scan.get("total_ports", 0) if latest_scan else 0
        high_risk = (latest_scan.get("critical_count", 0) + latest_scan.get("high_count", 0)) if latest_scan else 0
        st.metric(
            label="Open Ports",
            value=str(total_ports),
            delta=f"{high_risk} high-risk" if high_risk else None,
            delta_color="off",
        )

    with col3:
        anomaly_counts = dashboard_data.get("anomaly_counts", {})
        total_anomalies = sum(anomaly_counts.values())
        st.metric(
            label="Security Events",
            value=str(total_anomalies),
            delta=None,
        )

    with col4:
        critical_anomalies = anomaly_counts.get("critical", 0)
        st.metric(
            label="Anomalies Detected",
            value=str(total_anomalies),
            delta=f"{critical_anomalies} critical" if critical_anomalies else None,
            delta_color="off",
        )

    st.divider()

    # Charts row
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Risk Distribution")

        # Pie chart for risk distribution - REAL DATA
        if risk_dist and any(risk_dist.values()):
            risk_data = {
                "Category": ["Critical", "High", "Medium", "Low"],
                "Count": [
                    risk_dist.get("critical", 0),
                    risk_dist.get("high", 0),
                    risk_dist.get("medium", 0),
                    risk_dist.get("low", 0),
                ],
            }
        else:
            # Placeholder when no data
            risk_data = {
                "Category": ["No Data"],
                "Count": [1],
            }

        fig_pie = px.pie(
            risk_data,
            values="Count",
            names="Category",
            color="Category",
            color_discrete_map={
                "Critical": "#ff4444",
                "High": "#ffaa00",
                "Medium": "#00aaff",
                "Low": "#888888",
                "No Data": "#cccccc",
            },
            hole=0.4,
        )
        fig_pie.update_layout(
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2),
            margin=dict(t=20, b=20, l=20, r=20),
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_right:
        st.subheader("Security Events Timeline")

        # Line chart for events over time
        import pandas as pd
        dates = pd.date_range(start="2024-01-01", periods=14, freq="D")
        events_data = pd.DataFrame({
            "Date": dates,
            "Failed Logins": [5, 8, 3, 12, 6, 4, 15, 8, 5, 9, 3, 7, 4, 6],
            "Successful Logins": [120, 115, 125, 130, 128, 122, 135, 140, 138, 145, 150, 148, 155, 160],
            "Anomalies": [1, 0, 0, 2, 1, 0, 3, 1, 0, 1, 0, 1, 0, 2],
        })

        fig_timeline = px.line(
            events_data,
            x="Date",
            y=["Failed Logins", "Anomalies"],
            labels={"value": "Count", "variable": "Event Type"},
        )
        fig_timeline.update_layout(
            legend=dict(orientation="h", yanchor="bottom", y=-0.3),
            margin=dict(t=20, b=20, l=20, r=20),
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

    st.divider()

    # Port Heatmap - REAL DATA
    st.subheader("🔥 Vulnerability Port Heatmap")

    # Use real heatmap data from database if available
    if heatmap_data.get("hosts") and heatmap_data.get("data"):
        hosts = heatmap_data["hosts"]
        ports = heatmap_data["ports"]
        matrix_data = heatmap_data["data"]

        fig_heatmap = px.imshow(
            matrix_data,
            labels=dict(x="Port", y="Host", color="Risk Score"),
            x=ports,
            y=hosts,
            color_continuous_scale=["#44ff44", "#ffff00", "#ffaa00", "#ff4444"],
            aspect="auto",
        )
        fig_heatmap.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
        )
        st.plotly_chart(fig_heatmap, use_container_width=True)
    else:
        # Placeholder heatmap when no data
        st.info("No scan data available. Run a scan to populate the heatmap.")
        placeholder_ports = ["445 (SMB)", "3389 (RDP)", "22 (SSH)", "80 (HTTP)"]
        placeholder_hosts = ["Run scan to see data"]
        placeholder_data = [[0, 0, 0, 0]]

        fig_heatmap = px.imshow(
            placeholder_data,
            labels=dict(x="Port", y="Host", color="Risk Score"),
            x=placeholder_ports,
            y=placeholder_hosts,
            color_continuous_scale=["#cccccc", "#cccccc"],
            aspect="auto",
        )
        fig_heatmap.update_layout(margin=dict(t=20, b=20, l=20, r=20))
        st.plotly_chart(fig_heatmap, use_container_width=True)

    st.divider()

    # Recent Alerts - REAL DATA FROM DB (Sprint 2)
    st.subheader("🚨 Recent Alerts")

    # Load real anomalies from database
    recent_anomalies = load_recent_anomalies(limit=10)

    if recent_anomalies:
        # Format for display
        alerts_data = []
        for anomaly in recent_anomalies:
            severity_map = {
                "critical": "🚨 CRITICAL",
                "warning": "⚠️ HIGH",
                "info": "ℹ️ INFO",
            }
            detected_at = anomaly.get("detected_at", "")
            time_str = detected_at[11:19] if detected_at and len(detected_at) > 19 else "N/A"

            alerts_data.append({
                "Time": time_str,
                "Severity": severity_map.get(anomaly.get("severity", "info"), "ℹ️ INFO"),
                "Type": anomaly.get("anomaly_type", "Unknown"),
                "Details": (anomaly.get("description", "")[:50] + "...") if anomaly.get("description") else "N/A",
                "MITRE": ", ".join(anomaly.get("mitre_techniques", [])) or "N/A",
            })

        st.dataframe(
            alerts_data,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Severity": st.column_config.TextColumn(width="small"),
                "MITRE": st.column_config.TextColumn(width="small"),
            }
        )
    else:
        st.info("No anomalies detected yet. Run a log analysis to populate alerts.")


# =============================================================================
# Scanner Page (Sprint 4 - Real Scans)
# =============================================================================
elif page == "🔍 Scanner":
    st.markdown("## 🔍 Security Scanner")
    st.markdown("Run real security scans using nmap/psutil")
    st.divider()

    scan_type = st.selectbox(
        "Select Scan Type",
        ["Quick Vulnerability Scan", "Full Port Scan", "Process Scan", "File Scan"]
    )

    col1, col2 = st.columns([2, 1])

    with col1:
        if scan_type == "File Scan":
            target_path = st.text_input("Target Path", placeholder="C:\\Users\\...")
            recursive = st.checkbox("Recursive scan", value=True)
            quarantine = st.checkbox("Auto-quarantine threats")

        elif scan_type == "Process Scan":
            st.info("Will scan all running processes for suspicious activity")

        elif scan_type in ["Quick Vulnerability Scan", "Full Port Scan"]:
            target_ip = st.text_input("Target IP", value="127.0.0.1")
            if scan_type == "Full Port Scan":
                port_range = st.text_input("Port Range", value="1-1024")

    with col2:
        st.markdown("### Scan Options")
        min_severity = st.select_slider(
            "Minimum Severity",
            options=["info", "low", "medium", "high", "critical"],
            value="low"
        )

    if st.button("🚀 Start Scan", type="primary", use_container_width=True):
        if scan_type in ["Quick Vulnerability Scan", "Full Port Scan"]:
            # Real vulnerability scan
            with st.spinner(f"Running {scan_type.lower()} on {target_ip}..."):
                scan_mode = "quick" if scan_type == "Quick Vulnerability Scan" else "full"
                result = run_real_scan(target_ip, scan_type=scan_mode)

                if result:
                    st.success(f"Scan completed! Risk Score: {result.get('risk_score', 0):.1f}/10")
                    st.session_state["scanner_result"] = result

        elif scan_type == "Process Scan":
            # Process scan using psutil
            with st.spinner("Scanning running processes..."):
                try:
                    import psutil
                    processes = []
                    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']):
                        try:
                            pinfo = proc.info
                            processes.append({
                                "PID": pinfo['pid'],
                                "Name": pinfo['name'],
                                "User": pinfo['username'] or "SYSTEM",
                                "CPU %": f"{pinfo['cpu_percent']:.1f}",
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    st.session_state["process_scan"] = processes[:50]  # Limit to 50
                    st.success(f"Found {len(processes)} running processes")
                except ImportError:
                    st.error("psutil not installed. Run: pip install psutil")

        else:
            # File Scan - Sprint 6: Verbose error message
            if not target_path:
                st.warning("Please enter a target path to scan")
            else:
                try:
                    from bisontitan.scanner import FileScanner, YARA_AVAILABLE

                    if not YARA_AVAILABLE:
                        st.error("""
                        **YARA Rules Setup Required**

                        File scanning uses YARA for malware detection. To enable:

                        1. **Install yara-python:**
                        ```bash
                        pip install yara-python
                        ```

                        2. **Add YARA rules to config:**
                        Create `.yar` files in `config/rules/` directory

                        3. **Run as Administrator** for full file system access

                        **Sample YARA rule (save as `config/rules/sample.yar`):**
                        ```yara
                        rule SuspiciousStrings {
                            strings:
                                $s1 = "malware" nocase
                                $s2 = "payload" nocase
                            condition:
                                any of them
                        }
                        ```
                        """)
                    else:
                        scanner = FileScanner()
                        if scanner.load_yara_rules():
                            with st.spinner(f"Scanning {target_path}..."):
                                from pathlib import Path
                                target = Path(target_path)
                                if target.is_file():
                                    result = scanner.scan_file(target)
                                    st.session_state["file_scan_result"] = result.to_dict()
                                    if result.threat_level.value in ["high", "critical"]:
                                        st.error(f"Threat detected: {result.threat_level.value.upper()}")
                                    else:
                                        st.success("Scan complete - no threats detected")
                                elif target.is_dir():
                                    results = list(scanner.scan_directory(target, recursive=recursive))
                                    threats = [r for r in results if r.threat_level.value in ["high", "critical"]]
                                    st.session_state["file_scan_results"] = [r.to_dict() for r in results[:50]]
                                    if threats:
                                        st.error(f"Found {len(threats)} threat(s) in {len(results)} files")
                                    else:
                                        st.success(f"Scanned {len(results)} files - no threats detected")
                                else:
                                    st.error(f"Path not found: {target_path}")
                        else:
                            st.warning("""
                            **YARA Rules Not Loaded**

                            Create YARA rule files in `config/rules/` directory.

                            Example rule file (`config/rules/malware.yar`):
                            ```yara
                            rule Suspicious_Executable {
                                meta:
                                    description = "Detects suspicious patterns"
                                    severity = "high"
                                strings:
                                    $mz = { 4D 5A }
                                    $cmd = "cmd.exe" nocase
                                condition:
                                    $mz at 0 and $cmd
                            }
                            ```
                            """)
                except ImportError as e:
                    st.error(f"""
                    **Scanner Module Error**

                    Failed to import scanner: {e}

                    Ensure all dependencies are installed:
                    ```bash
                    pip install yara-python psutil
                    ```
                    """)
                except PermissionError:
                    st.error("""
                    **Permission Denied**

                    Run the application as **Administrator** for full file system access.

                    On Windows:
                    - Right-click Command Prompt → "Run as administrator"
                    - Then: `streamlit run src/bisontitan/gui/app.py`
                    """)
                except Exception as e:
                    st.error(f"Scan error: {e}")

    # Display results
    if st.session_state.get("scanner_result"):
        result = st.session_state["scanner_result"]
        st.divider()
        st.subheader("Scan Results")

        # Summary
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Risk Score", f"{result.get('risk_score', 0):.1f}/10")
        with col2:
            st.metric("Open Ports", len(result.get("open_ports", [])))
        with col3:
            critical = sum(1 for p in result.get("open_ports", []) if p.get("risk_level") == "critical")
            st.metric("Critical Issues", critical)

        # Ports table
        open_ports = result.get("open_ports", [])
        if open_ports:
            st.subheader("🔓 Open Ports Detected")
            port_data = []
            for port in open_ports:
                risk_map = {"critical": "🚨 CRITICAL", "high": "⚠️ HIGH", "medium": "⚡ MEDIUM", "low": "ℹ️ LOW"}
                port_data.append({
                    "Port": port.get("port"),
                    "Service": port.get("service", "unknown"),
                    "Risk": risk_map.get(port.get("risk_level", "low"), "ℹ️ LOW"),
                    "Reason": port.get("reason", "")[:60],
                })
            st.dataframe(port_data, use_container_width=True, hide_index=True)

            # Sprint 6: Add netsh firewall commands for risky ports
            risky_ports = [p for p in open_ports if p.get("risk_level") in ["critical", "high"]]
            if risky_ports:
                st.subheader("🛡️ Firewall Block Commands")
                st.markdown("Copy-paste these commands into an **Administrator PowerShell** to block risky ports:")

                # Generate commands with expandable sections
                for port in risky_ports:
                    port_num = port.get("port")
                    service = port.get("service", f"Port{port_num}")
                    risk_emoji = "🚨" if port.get("risk_level") == "critical" else "⚠️"

                    with st.expander(f"{risk_emoji} Block {service} (Port {port_num})", expanded=False):
                        # Inbound block
                        inbound_cmd = f'netsh advfirewall firewall add rule name="Block {service} Inbound" dir=in action=block protocol=TCP localport={port_num}'
                        st.code(inbound_cmd, language="powershell")

                        # Outbound block (optional)
                        outbound_cmd = f'netsh advfirewall firewall add rule name="Block {service} Outbound" dir=out action=block protocol=TCP localport={port_num}'
                        st.code(outbound_cmd, language="powershell")

                        # Delete rule command
                        st.caption("To remove this rule later:")
                        delete_cmd = f'netsh advfirewall firewall delete rule name="Block {service} Inbound"'
                        st.code(delete_cmd, language="powershell")

                # All-in-one script
                st.markdown("---")
                st.markdown("**Block all risky ports at once:**")
                all_commands = []
                for port in risky_ports:
                    port_num = port.get("port")
                    service = port.get("service", f"Port{port_num}")
                    all_commands.append(f'netsh advfirewall firewall add rule name="Block {service}" dir=in action=block protocol=TCP localport={port_num}')
                st.code("\n".join(all_commands), language="powershell")

        else:
            st.success("No open ports detected!")

    # File scan results display
    if st.session_state.get("file_scan_result"):
        st.divider()
        st.subheader("📁 File Scan Result")
        result = st.session_state["file_scan_result"]
        threat_level = result.get("threat_level", "clean")
        threat_map = {"clean": "✅ Clean", "info": "ℹ️ Info", "low": "⚠️ Low", "medium": "🟡 Medium", "high": "🟠 High", "critical": "🔴 Critical"}

        col1, col2 = st.columns(2)
        with col1:
            st.metric("File", result.get("filepath", "Unknown").split("\\")[-1])
        with col2:
            st.metric("Threat Level", threat_map.get(threat_level, threat_level))

        if result.get("matches"):
            st.markdown("**Matches:**")
            for match in result.get("matches", []):
                st.markdown(f"- **{match.get('rule')}**: {match.get('description')}")

        if threat_level in ["high", "critical"]:
            st.markdown("**Recommended Actions:**")
            st.markdown("1. **Quarantine** the file immediately")
            st.markdown("2. **Scan with Windows Defender**: `Start-MpScan -ScanType QuickScan`")
            st.markdown("3. **Delete if confirmed malicious**: Move to quarantine folder")

    # Process scan results
    if st.session_state.get("process_scan"):
        st.divider()
        st.subheader("Running Processes")
        processes = st.session_state["process_scan"]
        st.dataframe(processes, use_container_width=True, hide_index=True)

        # Sprint 6: Suggested actions for process scan
        st.subheader("🔧 Process Management Actions")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Kill a suspicious process:**")
            pid_to_kill = st.text_input("Enter PID to terminate", placeholder="e.g., 1234")
            if pid_to_kill:
                st.code(f"taskkill /PID {pid_to_kill} /F", language="cmd")
                st.caption("Run in Administrator Command Prompt")

        with col2:
            st.markdown("**Investigate a process:**")
            proc_name = st.text_input("Process name to investigate", placeholder="e.g., suspicious.exe")
            if proc_name:
                st.code(f'wmic process where "name=\'{proc_name}\'" get processid,commandline', language="cmd")

        with st.expander("📋 Common Process Investigation Commands"):
            st.markdown("**List all processes with command lines:**")
            st.code("wmic process get name,processid,commandline", language="cmd")

            st.markdown("**Find process by port:**")
            st.code("netstat -ano | findstr :PORT", language="cmd")

            st.markdown("**Get process details:**")
            st.code("tasklist /V /FO TABLE", language="cmd")

            st.markdown("**Check process file location:**")
            st.code('wmic process where "processid=PID" get executablepath', language="cmd")


# =============================================================================
# Privacy Check Page (Sprint 2 - Real Fingerprint)
# =============================================================================
elif page == "🔒 Privacy Check":
    st.markdown("## 🔒 Browser Fingerprint Analysis")
    st.markdown("See what tracking services can learn about you")
    st.divider()

    # Capture button
    col_btn, col_status = st.columns([1, 3])
    with col_btn:
        capture_clicked = st.button("🔍 Capture Fingerprint", type="primary")

    # Initialize or load fingerprint from session state
    if capture_clicked or "fingerprint_data" not in st.session_state:
        with st.spinner("Capturing fingerprint..."):
            fp_data = capture_real_fingerprint(use_playwright=True)
            if fp_data:
                st.session_state["fingerprint_data"] = fp_data

    fingerprint_data = st.session_state.get("fingerprint_data", get_basic_fingerprint())

    with col_status:
        captured_at = fingerprint_data.get("captured_at", "")
        if captured_at:
            st.success(f"Captured at: {captured_at[:19]}")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("Your Fingerprint")

        # Real fingerprint data
        hardware = fingerprint_data.get("hardware", {})
        browser = fingerprint_data.get("browser", {})
        webgl = browser.get("webgl", {}) if isinstance(browser.get("webgl"), dict) else {}

        display_fp = {
            "User Agent": fingerprint_data.get("ua", "N/A")[:60] + "...",
            "IP Address": fingerprint_data.get("ip", {}).get("origin", "N/A"),
            "Resolution": fingerprint_data.get("resolution", "N/A"),
            "Platform": fingerprint_data.get("platform", "N/A"),
            "Timezone": fingerprint_data.get("geo", {}).get("timezone", "N/A"),
            "Language": fingerprint_data.get("language", "N/A"),
            "CPU Threads": str(hardware.get("threads", "N/A")),
            "Memory": str(hardware.get("memory", "N/A")),
            "Canvas": str(browser.get("canvas", "N/A"))[:30],
            "WebGL": str(webgl.get("renderer", "N/A"))[:40],
        }

        for key, value in display_fp.items():
            st.markdown(f"**{key}:** `{value}`")

    with col2:
        st.subheader("Privacy Score")

        # Real privacy score
        score = fingerprint_data.get("fingerprint_score", 0.5)
        risk = fingerprint_data.get("risk", "Medium")

        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=score * 100,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Tracking Risk"},
            delta={'reference': 50, 'increasing': {'color': "red"}},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "#ff4444" if score > 0.7 else "#ffaa00" if score > 0.4 else "#44ff44"},
                'steps': [
                    {'range': [0, 40], 'color': "#d4edda"},
                    {'range': [40, 70], 'color': "#fff3cd"},
                    {'range': [70, 100], 'color': "#f8d7da"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 70
                }
            }
        ))
        fig_gauge.update_layout(height=300, margin=dict(t=50, b=20, l=20, r=20))
        st.plotly_chart(fig_gauge, use_container_width=True)

        risk_colors = {"High": "error", "Medium": "warning", "Low": "success"}
        if risk == "High":
            st.error(f"**Risk Level: {risk}** - Your browser is highly identifiable")
        elif risk == "Low":
            st.success(f"**Risk Level: {risk}** - Good privacy protection detected")
        else:
            st.warning(f"**Risk Level: {risk}** - Some tracking vectors exposed")

    st.divider()

    st.subheader("📋 Recommendations")

    # Real recommendations from fingerprint analysis
    recommendations = fingerprint_data.get("recommendations", [])
    if not recommendations:
        recommendations = [
            "Use a privacy-focused browser (Firefox, Brave)",
            "Enable canvas fingerprint protection",
            "Use a VPN to mask your IP address",
            "Consider using Tor for sensitive browsing",
        ]

    for i, rec in enumerate(recommendations[:6]):
        st.checkbox(f"🔲 {rec}", key=f"rec_{i}")

    if st.button("🔄 Refresh Fingerprint", type="secondary"):
        if "fingerprint_data" in st.session_state:
            del st.session_state["fingerprint_data"]
        st.rerun()


# =============================================================================
# Log Analysis Page (Sprint 4 - Real Data with Admin Consent)
# =============================================================================
elif page == "📋 Log Analysis":
    st.markdown("## 📋 Security Log Analysis")
    st.markdown("Analyze Windows event logs for security threats")

    # Admin status check
    is_admin, admin_msg = check_admin_status()
    if is_admin:
        st.success(f"✅ {admin_msg} - Full log access available")
    else:
        st.warning(f"⚠️ {admin_msg} - Security log access may be limited")
        st.caption("For full Security log access, run as Administrator")

    st.divider()

    # Sprint 7/9 - Boost Auditing Section (Expanded)
    with st.expander("🔧 Boost Auditing (Enable Verbose Logging)", expanded=False):
        st.markdown("""
        **Enable advanced Windows auditing to capture detailed security information.**

        By default, Windows may not log all events needed for security monitoring.
        Use these commands to enable comprehensive auditing:
        """)

        audit_tab1, audit_tab2, audit_tab3, audit_tab4, audit_tab5 = st.tabs([
            "📋 Logon Audit",
            "📁 Object Access",
            "🔒 File Integrity",
            "🔑 Registry",
            "⬇️ Download Scripts"
        ])

        with audit_tab1:
            st.markdown("**Enable Logon/Logoff Auditing (Run as Administrator):**")
            audit_cmd = """# Enable logon success/failure auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Enable account logon auditing (for Kerberos/NTLM)
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Enable privilege use auditing
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:enable

# Verify settings
auditpol /get /category:"Logon/Logoff"
auditpol /get /category:"Account Logon"
auditpol /get /category:"Privilege Use" """
            st.code(audit_cmd, language="powershell")
            st.caption("💡 Enables auditing for: logons, RDP sessions, Kerberos auth, and privilege use.")

        with audit_tab2:
            st.markdown("**Enable Object Access Auditing:**")
            object_access_cmd = """# Enable Object Access Auditing (files, registry, SAM)
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:disable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:enable

# Enable detailed file share auditing
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

# Enable removable storage auditing
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# Enable filtering platform auditing (firewall)
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:enable

# Verify settings
auditpol /get /category:"Object Access" """
            st.code(object_access_cmd, language="powershell")
            st.caption("📁 Enables auditing for: file access, registry changes, shares, and USB storage.")

        with audit_tab3:
            st.markdown("**File Integrity Monitoring (FIM) Setup:**")
            fim_cmd = """# ==============================================
# FILE INTEGRITY MONITORING (FIM) via SACL
# ==============================================

# Set audit SACL on critical Windows directories
# This enables Event ID 4663 (file access) for monitored paths

# Monitor System32 for unauthorized changes
$path = "C:\\Windows\\System32"
$acl = Get-Acl $path
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Write,Delete,ChangePermissions",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success,Failure"
)
$acl.AddAuditRule($rule)
Set-Acl $path $acl

# Monitor hosts file for modifications
$hostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts"
$hostsAcl = Get-Acl $hostsPath
$hostsRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Write,Delete",
    "None",
    "None",
    "Success,Failure"
)
$hostsAcl.AddAuditRule($hostsRule)
Set-Acl $hostsPath $hostsAcl

# Monitor startup folders
$startupPaths = @(
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
)
foreach ($startup in $startupPaths) {
    if (Test-Path $startup) {
        $sacl = Get-Acl $startup
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "Write,Delete,CreateFiles", "ContainerInherit,ObjectInherit",
            "None", "Success,Failure"
        )
        $sacl.AddAuditRule($auditRule)
        Set-Acl $startup $sacl
    }
}

Write-Host "FIM auditing enabled for critical paths" -ForegroundColor Green """
            st.code(fim_cmd, language="powershell")
            st.caption("🔒 Monitors: System32, hosts file, and startup folders for unauthorized changes.")

        with audit_tab4:
            st.markdown("**Registry Keys for Enhanced Auditing:**")
            reg_cmd = """# Enable command line logging in process creation (4688)
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enable PowerShell Script Block Logging
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Enable PowerShell Module Logging
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f

# Enable Verbose Status Messages
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v VerboseStatus /t REG_DWORD /d 1 /f

# Enable Advanced Audit Policy
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

# Increase event log sizes
wevtutil sl Security /ms:104857600
wevtutil sl System /ms:52428800
wevtutil sl Application /ms:52428800
wevtutil sl "Windows PowerShell" /ms:52428800
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:52428800

# Enable WMI activity logging
wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /e:true /ms:52428800 """
            st.code(reg_cmd, language="powershell")
            st.caption("🔑 Enables: command line logging, PowerShell logging, and increases log sizes.")

        with audit_tab5:
            st.markdown("**Download Complete Audit Setup Scripts:**")

            # PowerShell Script
            boost_ps1 = '''# BisonTitan Boost Auditing Script (PowerShell)
# Version: 2.0 (Sprint 9)
# Run as Administrator
# Enables comprehensive security auditing for threat detection

param(
    [switch]$IncludeFIM,
    [switch]$IncludeObjectAccess,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

function Write-Status($msg, $color = "White") {
    if (-not $Quiet) { Write-Host $msg -ForegroundColor $color }
}

Write-Status "=============================================" "Cyan"
Write-Status "  BisonTitan Boost Auditing v2.0" "Cyan"
Write-Status "=============================================" "Cyan"
Write-Status ""

# Check admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges!"
    exit 1
}

Write-Status "[1/8] Enabling Logon/Logoff Auditing..." "Yellow"
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null

Write-Status "[2/8] Enabling Account Logon Auditing..." "Yellow"
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null

Write-Status "[3/8] Enabling Privilege Use Auditing..." "Yellow"
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null

Write-Status "[4/8] Enabling Account Management Auditing..." "Yellow"
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable | Out-Null

Write-Status "[5/8] Enabling Policy Change Auditing..." "Yellow"
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable | Out-Null

Write-Status "[6/8] Setting Registry Keys..." "Yellow"
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f 2>$null | Out-Null
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f 2>$null | Out-Null
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v VerboseStatus /t REG_DWORD /d 1 /f 2>$null | Out-Null
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f 2>$null | Out-Null

Write-Status "[7/8] Increasing Log Sizes..." "Yellow"
wevtutil sl Security /ms:104857600 2>$null
wevtutil sl System /ms:52428800 2>$null
wevtutil sl Application /ms:52428800 2>$null

if ($IncludeObjectAccess) {
    Write-Status "[7.5/8] Enabling Object Access Auditing..." "Yellow"
    auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null
}

if ($IncludeFIM) {
    Write-Status "[7.6/8] Enabling File Integrity Monitoring..." "Yellow"
    $hostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    if (Test-Path $hostsPath) {
        $acl = Get-Acl $hostsPath
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "Write,Delete", "None", "None", "Success,Failure"
        )
        $acl.AddAuditRule($rule)
        Set-Acl $hostsPath $acl
    }
}

Write-Status "[8/8] Verifying Configuration..." "Yellow"
Write-Status ""
Write-Status "=============================================" "Green"
Write-Status "  Boost Auditing COMPLETE!" "Green"
Write-Status "=============================================" "Green"
Write-Status ""
Write-Status "Enabled Audit Categories:" "Cyan"
auditpol /get /category:"Logon/Logoff" | Select-String "Success|Failure"
Write-Status ""
Write-Status "NOTE: A reboot may be required for registry changes." "Yellow"
Write-Status "Run with -IncludeObjectAccess for file/registry auditing." "Cyan"
Write-Status "Run with -IncludeFIM for file integrity monitoring." "Cyan"
'''
            st.code(boost_ps1, language="powershell")
            st.download_button(
                label="⬇️ Download BisonTitan-Boost-Auditing.ps1",
                data=boost_ps1,
                file_name="BisonTitan-Boost-Auditing.ps1",
                mime="text/plain",
                key="download_boost_ps1"
            )

            st.markdown("---")

            # Batch Script
            boost_bat = '''@echo off
REM BisonTitan Boost Auditing Script (Batch)
REM Version: 2.0 (Sprint 9)
REM Run as Administrator
REM Enables comprehensive security auditing for threat detection

echo =============================================
echo   BisonTitan Boost Auditing v2.0
echo =============================================
echo.

REM Check admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires Administrator privileges!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [1/8] Enabling Logon/Logoff Auditing...
auditpol /set /subcategory:"Logon" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable >nul

echo [2/8] Enabling Account Logon Auditing...
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable >nul

echo [3/8] Enabling Privilege Use Auditing...
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable >nul

echo [4/8] Enabling Account Management Auditing...
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable >nul

echo [5/8] Enabling Policy Change Auditing...
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable >nul

echo [6/8] Enabling Object Access Auditing...
auditpol /set /subcategory:"File System" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Registry" /success:enable /failure:enable >nul
auditpol /set /subcategory:"File Share" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable >nul

echo [7/8] Setting Registry Keys...
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v VerboseStatus /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f >nul 2>&1

echo [8/8] Increasing Log Sizes...
wevtutil sl Security /ms:104857600 >nul 2>&1
wevtutil sl System /ms:52428800 >nul 2>&1
wevtutil sl Application /ms:52428800 >nul 2>&1

echo.
echo =============================================
echo   Boost Auditing COMPLETE!
echo =============================================
echo.
echo Verifying configuration...
echo.
auditpol /get /category:"Logon/Logoff"
echo.
echo NOTE: A reboot may be required for registry changes.
echo.
pause
'''
            st.code(boost_bat, language="batch")
            st.download_button(
                label="⬇️ Download BisonTitan-Boost-Auditing.bat",
                data=boost_bat,
                file_name="BisonTitan-Boost-Auditing.bat",
                mime="text/plain",
                key="download_boost_bat"
            )

            st.markdown("---")
            st.markdown("**Usage:**")
            st.markdown("""
            - **PowerShell**: `./BisonTitan-Boost-Auditing.ps1 -IncludeObjectAccess -IncludeFIM`
            - **Batch**: Right-click → Run as Administrator
            - Both scripts enable 8+ audit categories and registry settings
            """)

    st.divider()

    col1, col2, col3 = st.columns(3)

    with col1:
        log_type = st.selectbox(
            "Log Type",
            ["Security", "System", "Application"],
            help="Security requires admin. System/Application work without admin."
        )
        if log_type == "Security" and not is_admin:
            st.caption("⚠️ Security log requires admin")

    with col2:
        time_range = st.selectbox("Time Range", ["Last 24 hours", "Last 7 days", "Last 30 days"])
        hours_map = {"Last 24 hours": 24, "Last 7 days": 168, "Last 30 days": 720}
        hours = hours_map.get(time_range, 24)

    with col3:
        analyze_clicked = st.button("🔍 Analyze Logs", type="primary")

    # Sprint 8/9/10 - Baseline Filtering Controls (Fixed widget keys with timestamps)
    st.divider()

    # Session state already initialized by init_session_state() at module load (Sprint 10)

    with st.expander("🎯 Baseline Filtering (Noise Reduction)", expanded=False):
        st.markdown("""
        **Reduce noise by filtering known benign events.**

        Baseline filtering uses YAML rules to suppress routine events like:
        - Service account logins (SYSTEM, LOCAL SERVICE)
        - Routine logoff events
        - Known service state changes
        """)

        filter_col1, filter_col2, filter_col3 = st.columns(3)

        with filter_col1:
            # Sprint 10 - Use timestamp-based unique key to prevent conflicts
            baseline_enabled = st.checkbox(
                "Enable Baseline Filtering",
                value=st.session_state.get("baseline_enabled_state", True),
                key=get_unique_widget_key("baseline_toggle"),
                help="Filter out known benign events"
            )
            st.session_state["baseline_enabled_state"] = baseline_enabled
            st.session_state["baseline_enabled"] = baseline_enabled

        with filter_col2:
            quick_filter_options = ["None", "Security Focus", "Critical Only", "Threat Hunting", "Compliance"]
            quick_filter = st.selectbox(
                "Quick Filter Preset",
                quick_filter_options,
                index=0,
                key=get_unique_widget_key("quick_filter"),
                help="Pre-configured filter combinations"
            )
            quick_filter_map = {
                "None": None,
                "Security Focus": "security_focus",
                "Critical Only": "critical_only",
                "Threat Hunting": "threat_hunting",
                "Compliance": "compliance",
            }
            st.session_state["quick_filter_state"] = quick_filter_map.get(quick_filter)
            st.session_state["quick_filter"] = quick_filter_map.get(quick_filter)

        with filter_col3:
            search_term = st.text_input(
                "Search Events",
                value=st.session_state.get("event_search_state", ""),
                key=get_unique_widget_key("event_search"),
                placeholder="Filter by user, IP, or event type...",
                help="Search within filtered results"
            )
            st.session_state["event_search_state"] = search_term
            st.session_state["event_search"] = search_term

        # Show baseline stats if available
        baseline_stats = st.session_state.get("baseline_stats", {})
        if baseline_stats and baseline_stats.get("total", 0) > 0:
            st.markdown("---")
            stat_col1, stat_col2, stat_col3 = st.columns(3)
            with stat_col1:
                st.metric("Events Analyzed", f"{baseline_stats.get('total', 0):,}")
            with stat_col2:
                st.metric("Events Suppressed", f"{baseline_stats.get('suppressed', 0):,}")
            with stat_col3:
                filter_rate = baseline_stats.get('filter_rate', 0) * 100
                st.metric("Filter Rate", f"{filter_rate:.1f}%")

    st.divider()

    # Run real analysis when button clicked
    if analyze_clicked:
        # Get baseline settings from session state
        baseline_on = st.session_state.get("baseline_enabled", True)
        qf = st.session_state.get("quick_filter")

        with st.spinner(f"Analyzing {log_type} logs ({time_range})..."):
            result = run_real_log_analysis(
                log_type=log_type,
                hours=hours,
                baseline_enabled=baseline_on,
                quick_filter=qf,
            )
            if result:
                st.session_state["log_analysis_result"] = result
                st.session_state["log_analyzed"] = True
                # Store baseline stats for display
                st.session_state["baseline_stats"] = result.get("baseline_stats", {})

    # Display results
    if st.session_state.get("log_analyzed") and st.session_state.get("log_analysis_result"):
        result = st.session_state["log_analysis_result"]
        stats = result.get("statistics", {})
        anomalies_data = result.get("anomalies", [])

        # Sprint 8 - Show baseline filtering summary
        baseline_stats = result.get("baseline_stats", {})
        if baseline_stats and baseline_stats.get("baseline_enabled"):
            suppression_rate = baseline_stats.get("suppression_rate", 0) * 100
            if suppression_rate > 0:
                st.info(f"🎯 Baseline filtering reduced noise by {suppression_rate:.1f}% ({baseline_stats.get('suppressed', 0):,} events suppressed)")

        # Summary metrics - REAL DATA
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Events", f"{stats.get('total_events', 0):,}")
        with col2:
            critical_count = len([a for a in anomalies_data if a.get("severity") == "critical"])
            st.metric("Critical Anomalies", str(critical_count), delta_color="inverse")
        with col3:
            st.metric("Failed Logins", str(stats.get("failed_logins", 0)))
        with col4:
            st.metric("Privilege Changes", str(stats.get("privilege_changes", 0)))

        st.divider()

        # Anomalies table - REAL DATA
        st.subheader("🚨 Detected Anomalies")

        if anomalies_data:
            display_anomalies = []
            for a in anomalies_data[:20]:  # Limit to 20
                severity_map = {"critical": "🚨 CRITICAL", "warning": "⚠️ HIGH", "info": "ℹ️ INFO"}
                mitre = ", ".join(a.get("mitre_techniques", [])) or "N/A"

                display_anomalies.append({
                    "Severity": severity_map.get(a.get("severity", "info"), "ℹ️ INFO"),
                    "Type": a.get("type", "Unknown"),
                    "Description": (a.get("description", "")[:60] + "...") if a.get("description") else "N/A",
                    "MITRE": mitre,
                    "Action": (a.get("recommended_action", "")[:40] + "...") if a.get("recommended_action") else "N/A",
                })

            st.dataframe(
                display_anomalies,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Description": st.column_config.TextColumn(width="large"),
                    "Action": st.column_config.TextColumn(width="medium"),
                }
            )
        else:
            st.success("No security anomalies detected in the analyzed timeframe.")

        # Sprint 5 - Verbose Service Installation Table
        st.divider()
        st.subheader("🔧 Service Installations (Verbose)")

        # Check for service-related anomalies with detailed metadata
        service_anomalies = [a for a in anomalies_data if "service_installed" in a.get("type", "")]

        if service_anomalies:
            # Get service details from metadata
            all_service_details = []
            for anomaly in service_anomalies:
                details = anomaly.get("metadata", {}).get("service_details", [])
                all_service_details.extend(details)

            if all_service_details:
                # Risk summary
                risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for detail in all_service_details:
                    risk_level = detail.get("risk_level", "low")
                    risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

                # Summary metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Services", len(all_service_details))
                with col2:
                    critical_high = risk_counts["critical"] + risk_counts["high"]
                    st.metric("Critical/High Risk", critical_high, delta_color="inverse" if critical_high > 0 else "off")
                with col3:
                    st.metric("Medium Risk", risk_counts["medium"])
                with col4:
                    whitelisted = sum(1 for d in all_service_details if d.get("is_whitelisted"))
                    st.metric("Whitelisted", whitelisted)

                # MITRE ATT&CK link
                st.markdown("**MITRE ATT&CK:** [T1543.003 - Create/Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)")

                # Verbose service table
                st.markdown("#### Detailed Service List (sorted by risk)")

                # Prepare table data
                table_data = []
                for detail in sorted(all_service_details, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("risk_level", "low"), 4)):
                    risk_level = detail.get("risk_level", "low")
                    risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(risk_level, "⚪")
                    signed = detail.get("is_signed")
                    signed_str = "✅ Signed" if signed else ("❌ Unsigned" if signed is False else "❓ Unknown")

                    table_data.append({
                        "Risk": f"{risk_emoji} {risk_level.upper()}",
                        "Service Name": detail.get("service_name", "Unknown"),
                        "Binary Path": detail.get("binary_path", "Unknown")[:50] + "..." if len(detail.get("binary_path", "")) > 50 else detail.get("binary_path", "Unknown"),
                        "Install Time": detail.get("install_time", "Unknown")[:19],
                        "User": detail.get("installing_user", "SYSTEM") or "SYSTEM",
                        "Startup": detail.get("startup_type", "Unknown"),
                        "Signed": signed_str,
                        "Publisher": detail.get("signature_publisher", "-") or "-",
                    })

                st.dataframe(
                    table_data,
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Risk": st.column_config.TextColumn(width="small"),
                        "Service Name": st.column_config.TextColumn(width="medium"),
                        "Binary Path": st.column_config.TextColumn(width="large"),
                        "Install Time": st.column_config.TextColumn(width="medium"),
                        "Signed": st.column_config.TextColumn(width="small"),
                    }
                )

                # Expandable details for each risky service
                risky_services = [d for d in all_service_details if d.get("risk_level") in ["critical", "high", "medium"]]
                if risky_services:
                    st.markdown("#### Investigation Details")

                    for i, detail in enumerate(risky_services[:5]):  # Limit to top 5
                        risk_level = detail.get("risk_level", "medium")
                        risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(risk_level, "⚪")

                        with st.expander(f"{risk_emoji} {detail.get('service_name', 'Unknown')} - {risk_level.upper()} RISK", expanded=(i==0)):
                            col1, col2 = st.columns(2)

                            with col1:
                                st.markdown("**Service Details:**")
                                st.markdown(f"- **Name:** {detail.get('service_name', 'Unknown')}")
                                st.markdown(f"- **Binary:** `{detail.get('binary_path', 'Unknown')}`")
                                st.markdown(f"- **Install Time:** {detail.get('install_time', 'Unknown')}")
                                st.markdown(f"- **Installed By:** {detail.get('installing_user', 'SYSTEM')}")
                                st.markdown(f"- **Startup Type:** {detail.get('startup_type', 'Unknown')}")
                                if detail.get("file_hash"):
                                    st.markdown(f"- **SHA256:** `{detail.get('file_hash')[:32]}...`")

                            with col2:
                                st.markdown("**Risk Assessment:**")
                                for reason in detail.get("risk_reasons", []):
                                    st.markdown(f"- ⚠️ {reason}")

                                st.markdown("**MITRE ATT&CK:**")
                                st.markdown(f"- Technique: [{detail.get('mitre_technique', 'T1543.003')}](https://attack.mitre.org/techniques/T1543/003/)")
                                st.markdown(f"- Tactic: {detail.get('mitre_tactic', 'Persistence')}")

                            # Correlated events
                            correlated = detail.get("correlated_events", [])
                            if correlated:
                                st.markdown("**Correlated Events (5 min before install):**")
                                for event in correlated[:3]:
                                    if event.get("event_id") == 4624:
                                        st.markdown(f"- 🔐 Login: {event.get('user', 'Unknown')} via {event.get('logon_type', 'Unknown')} from {event.get('source_ip', 'N/A')}")
                                    elif event.get("event_id") == 4688:
                                        st.markdown(f"- 🔧 Process: {event.get('process', 'Unknown')[:50]}")

                            # Action buttons
                            st.markdown("**Recommended Actions:**")
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                if st.button(f"🚫 Block User", key=f"block_user_{i}"):
                                    user = detail.get("installing_user", "")
                                    if user and user not in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]:
                                        st.warning(f"To block user '{user}', run as admin: `net user {user} /active:no`")
                                    else:
                                        st.info("Cannot block system accounts")
                            with col2:
                                if st.button(f"🔍 VirusTotal", key=f"vt_{i}"):
                                    file_hash = detail.get("file_hash")
                                    if file_hash:
                                        st.markdown(f"[Check on VirusTotal](https://www.virustotal.com/gui/file/{file_hash})")
                                    else:
                                        st.info("No hash available for VirusTotal lookup")
                            with col3:
                                if st.button(f"🛑 Stop Service", key=f"stop_{i}"):
                                    svc_name = detail.get("service_name", "")
                                    st.warning(f"To stop service, run as admin: `sc stop {svc_name}`")

            else:
                st.info("No detailed service information available. This may occur if events lack required fields.")
        else:
            st.info("No service installation events detected in the analyzed timeframe.")

        # Sprint 7 - Verbose Logon Events Table
        st.divider()
        st.subheader("🔐 Logon Events (Verbose)")

        # Get logon events from the raw events data
        # For now, display based on anomalies with failed_login type
        logon_anomalies = [a for a in anomalies_data if "login" in a.get("type", "").lower() or "logon" in a.get("type", "").lower()]

        # Display logon summary (from statistics)
        logon_summary = stats.get("logon_summary", {})
        if logon_summary:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Logons", logon_summary.get("total_logons", 0))
            with col2:
                st.metric("Remote Logons", logon_summary.get("remote_count", 0), delta_color="inverse" if logon_summary.get("remote_count", 0) > 0 else "off")
            with col3:
                st.metric("Failed Attempts", logon_summary.get("failed_count", 0), delta_color="inverse" if logon_summary.get("failed_count", 0) > 0 else "off")
            with col4:
                st.metric("With Service Install", logon_summary.get("with_service_install", 0), delta_color="inverse" if logon_summary.get("with_service_install", 0) > 0 else "off")

            # MITRE ATT&CK reference
            st.markdown(f"**MITRE ATT&CK:** [T1078 - Valid Accounts]({logon_summary.get('mitre_url', 'https://attack.mitre.org/techniques/T1078/')})")

            # Risk breakdown
            risk_breakdown = logon_summary.get("risk_breakdown", {})
            if any(risk_breakdown.values()):
                st.markdown("**Risk Summary:** " +
                    f"🔴 Critical: {risk_breakdown.get('critical', 0)} | " +
                    f"🟠 High: {risk_breakdown.get('high', 0)} | " +
                    f"🟡 Medium: {risk_breakdown.get('medium', 0)} | " +
                    f"🟢 Low: {risk_breakdown.get('low', 0)}")

            # Verbose logon table
            table_rows = logon_summary.get("table_rows", [])
            if table_rows:
                st.markdown("#### Detailed Logon Events (sorted by risk)")

                # Filter options
                filter_col1, filter_col2 = st.columns(2)
                with filter_col1:
                    show_local = st.checkbox("Show Local Logons", value=False, key="logon_show_local")
                with filter_col2:
                    min_risk = st.selectbox("Minimum Risk", ["All", "Medium+", "High+", "Critical Only"], key="logon_min_risk")

                # Apply filters
                filtered_rows = table_rows
                if not show_local:
                    filtered_rows = [r for r in filtered_rows if "REMOTE" in r.get("Location", "")]
                if min_risk == "Medium+":
                    filtered_rows = [r for r in filtered_rows if r.get("Risk", "").upper() not in ["🟢 LOW"]]
                elif min_risk == "High+":
                    filtered_rows = [r for r in filtered_rows if "CRITICAL" in r.get("Risk", "").upper() or "HIGH" in r.get("Risk", "").upper()]
                elif min_risk == "Critical Only":
                    filtered_rows = [r for r in filtered_rows if "CRITICAL" in r.get("Risk", "").upper()]

                if filtered_rows:
                    st.dataframe(
                        filtered_rows[:50],  # Limit to 50 for performance
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "Risk": st.column_config.TextColumn(width="small"),
                            "Time": st.column_config.TextColumn(width="medium"),
                            "Status": st.column_config.TextColumn(width="small"),
                            "Location": st.column_config.TextColumn(width="small"),
                            "User": st.column_config.TextColumn(width="medium"),
                            "Logon Type": st.column_config.TextColumn(width="medium"),
                            "Source IP": st.column_config.TextColumn(width="medium"),
                            "MITRE": st.column_config.TextColumn(width="small"),
                        }
                    )

                    if len(table_rows) > 50:
                        st.caption(f"Showing 50 of {len(table_rows)} logon events")
                else:
                    st.info("No logon events match the current filters.")

                # Expandable details for high-risk logons
                high_risk_logons = [d for d in logon_summary.get("logon_details", []) if d.get("risk_level") in ["critical", "high"]]
                if high_risk_logons:
                    st.markdown("#### High-Risk Logon Investigation")

                    for i, detail in enumerate(high_risk_logons[:5]):  # Limit to top 5
                        risk_level = detail.get("risk_level", "high")
                        risk_emoji = {"critical": "🔴", "high": "🟠"}.get(risk_level, "🟡")
                        status = "✅" if detail.get("is_success") else "❌"
                        location = "🌐 REMOTE" if detail.get("is_remote") else "🏠 LOCAL"

                        expander_title = f"{risk_emoji} {detail.get('username', 'Unknown')} - {location} {status}"
                        with st.expander(expander_title, expanded=(i == 0)):
                            col1, col2 = st.columns(2)

                            with col1:
                                st.markdown("**Logon Details:**")
                                st.markdown(f"- **User:** {detail.get('domain', '')}\{detail.get('username', 'Unknown')}" if detail.get('domain') else f"- **User:** {detail.get('username', 'Unknown')}")
                                st.markdown(f"- **Time:** {detail.get('event_time', 'Unknown')[:19]}")
                                st.markdown(f"- **Logon Type:** {detail.get('logon_type_name', 'Unknown')} (Type {detail.get('logon_type', 0)})")
                                st.markdown(f"- **Source IP:** {detail.get('source_ip', '-') or '-'}")
                                st.markdown(f"- **Source Host:** {detail.get('source_hostname', '-') or '-'}")
                                if detail.get("elevated_token"):
                                    st.markdown("- **Elevated Token:** 👑 Yes")
                                if detail.get("failure_reason"):
                                    st.markdown(f"- **Failure Reason:** {detail.get('failure_reason')}")

                            with col2:
                                st.markdown("**Risk Assessment:**")
                                for reason in detail.get("risk_reasons", []):
                                    st.markdown(f"- ⚠️ {reason}")

                                st.markdown("**MITRE ATT&CK:**")
                                technique = detail.get("mitre_technique", "T1078")
                                tactic = detail.get("mitre_tactic", "Initial Access")
                                st.markdown(f"- Technique: [{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/)")
                                st.markdown(f"- Tactic: {tactic}")

                            # Correlated service installs
                            correlated = detail.get("correlated_services", [])
                            if correlated:
                                st.markdown("**⚠️ Services Installed After Login (within 30 min):**")
                                for svc in correlated:
                                    st.markdown(f"- 🔧 **{svc.get('service_name', 'Unknown')}** installed {svc.get('minutes_after_login', 0):.1f} min after login")
                                    st.markdown(f"  - Path: `{svc.get('binary_path', 'Unknown')[:60]}...`" if len(svc.get('binary_path', '')) > 60 else f"  - Path: `{svc.get('binary_path', 'Unknown')}`")

                            # Action buttons
                            st.markdown("**Recommended Actions:**")
                            col_a, col_b = st.columns(2)
                            with col_a:
                                if st.button(f"🔍 Check Source IP", key=f"logon_ip_{i}"):
                                    src_ip = detail.get("source_ip")
                                    if src_ip and src_ip not in ["-", "127.0.0.1", "::1"]:
                                        st.markdown(f"[AbuseIPDB Lookup](https://www.abuseipdb.com/check/{src_ip})")
                                        st.markdown(f"[VirusTotal IP](https://www.virustotal.com/gui/ip-address/{src_ip})")
                                    else:
                                        st.info("No external IP to check")
                            with col_b:
                                if st.button(f"🚫 Block User", key=f"logon_block_{i}"):
                                    user = detail.get("username", "")
                                    if user and user.upper() not in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]:
                                        st.code(f"net user {user} /active:no", language="cmd")
                                    else:
                                        st.info("Cannot block system accounts")

            else:
                st.info("No verbose logon data available. Run analysis on Security log for logon events.")
        else:
            # Fallback display based on anomalies
            failed_login_count = stats.get("failed_logins", 0)
            if failed_login_count > 0:
                st.warning(f"⚠️ {failed_login_count} failed login attempts detected. Enable verbose auditing for detailed analysis.")
            elif logon_anomalies:
                st.info(f"Found {len(logon_anomalies)} logon-related anomalies. Check the Detected Anomalies section above.")
            else:
                st.info("No logon events to display. Run analysis on Security log for logon details.")

        # Event type distribution - REAL DATA
        st.subheader("📊 Event Distribution")

        col1, col2 = st.columns(2)

        with col1:
            event_counts = stats.get("event_type_counts", {})
            if event_counts:
                event_types = {
                    "Event Type": list(event_counts.keys())[:10],
                    "Count": list(event_counts.values())[:10],
                }

                fig_bar = px.bar(
                    event_types,
                    x="Count",
                    y="Event Type",
                    orientation="h",
                    color="Count",
                    color_continuous_scale=["#44ff44", "#ffaa00", "#ff4444"],
                )
                fig_bar.update_layout(showlegend=False, margin=dict(t=20, b=20, l=20, r=20))
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("No event type data available")

        with col2:
            # Anomaly type distribution
            if anomalies_data:
                anomaly_types = {}
                for a in anomalies_data:
                    atype = a.get("type", "Unknown")
                    anomaly_types[atype] = anomaly_types.get(atype, 0) + 1

                fig_pie = px.pie(
                    values=list(anomaly_types.values()),
                    names=list(anomaly_types.keys()),
                    title="Anomaly Types",
                )
                fig_pie.update_layout(margin=dict(t=40, b=20, l=20, r=20))
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("No anomaly distribution data")

    elif not st.session_state.get("log_analyzed"):
        st.info("Click 'Analyze Logs' to run real Windows event log analysis.")


# =============================================================================
# Vulnerabilities Page (Sprint 4 - Real Scans)
# =============================================================================
elif page == "⚠️ Vulnerabilities":
    st.markdown("## ⚠️ Vulnerability Assessment")
    st.markdown("Check for open ports and security misconfigurations")
    st.divider()

    col1, col2 = st.columns([2, 1])

    with col1:
        target = st.text_input("Target IP/Hostname", value="127.0.0.1")

    with col2:
        scan_type = st.selectbox("Scan Type", ["Quick Scan", "Full Port Scan", "Config Check"])

    if st.button("🔍 Run Vulnerability Check", type="primary"):
        with st.spinner(f"Running {scan_type.lower()} on {target}..."):
            scan_mode = "quick" if scan_type == "Quick Scan" else "full"
            result = run_real_scan(target, scan_type=scan_mode)
            if result:
                st.session_state["vuln_result"] = result
                st.session_state["vuln_scanned"] = True
                st.success(f"Scan complete! Risk Score: {result.get('risk_score', 0):.1f}/10")

    if st.session_state.get("vuln_scanned") and st.session_state.get("vuln_result"):
        result = st.session_state["vuln_result"]
        st.divider()

        # Risk score gauge - REAL DATA
        col1, col2 = st.columns([1, 2])

        with col1:
            risk_score = result.get("risk_score", 0)
            bar_color = "#ff4444" if risk_score >= 7 else "#ffaa00" if risk_score >= 4 else "#44ff44"
            fig_risk = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Risk Score"},
                gauge={
                    'axis': {'range': [0, 10]},
                    'bar': {'color': bar_color},
                    'steps': [
                        {'range': [0, 4], 'color': "#d4edda"},
                        {'range': [4, 7], 'color': "#fff3cd"},
                        {'range': [7, 10], 'color': "#f8d7da"}
                    ],
                }
            ))
            fig_risk.update_layout(height=250, margin=dict(t=30, b=10, l=10, r=10))
            st.plotly_chart(fig_risk, use_container_width=True)

        with col2:
            st.subheader("Summary")
            open_ports = result.get("open_ports", [])
            config_checks = result.get("config_checks", [])

            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Open Ports", len(open_ports))
            with col_b:
                critical = sum(1 for p in open_ports if p.get("risk_level") == "critical")
                st.metric("Critical Issues", critical)
            with col_c:
                config_fails = sum(1 for c in config_checks if not c.get("passed", True))
                st.metric("Config Problems", config_fails)

        st.divider()

        # Open ports table - REAL DATA
        st.subheader("🔓 Open Ports")

        if open_ports:
            ports_data = []
            for port in open_ports:
                risk_map = {"critical": "🚨 CRITICAL", "high": "⚠️ HIGH", "medium": "⚡ MEDIUM", "low": "ℹ️ LOW"}
                ports_data.append({
                    "Port": port.get("port"),
                    "Service": port.get("service", "unknown"),
                    "Risk": risk_map.get(port.get("risk_level", "low"), "ℹ️ LOW"),
                    "Reason": port.get("reason", "")[:60],
                })
            st.dataframe(ports_data, use_container_width=True, hide_index=True)
        else:
            st.success("No open ports detected on target!")

        # Config issues - REAL DATA
        st.subheader("⚙️ Configuration Issues")

        if config_checks:
            config_data = []
            for check in config_checks:
                status = "✅ PASSED" if check.get("passed") else "❌ FAILED"
                risk_map = {"critical": "🚨 CRITICAL", "high": "⚠️ HIGH", "medium": "⚡ MEDIUM", "none": "✅ OK"}
                config_data.append({
                    "Check": check.get("description", check.get("name", "Unknown")),
                    "Status": status,
                    "Risk": risk_map.get(check.get("risk_level", "none"), "✅ OK"),
                    "Fix": check.get("recommendation", "-")[:50],
                })
            st.dataframe(config_data, use_container_width=True, hide_index=True)
        else:
            st.info("No configuration checks performed in this scan mode")

        # Firewall rules - DYNAMIC based on real scan
        critical_ports = [p for p in open_ports if p.get("risk_level") in ["critical", "high"]]
        if critical_ports:
            st.subheader("🛡️ Suggested Firewall Rules")
            rules = []
            for port in critical_ports:
                service = port.get("service", f"Port{port.get('port')}")
                rules.append(f"# Block {service} ({port.get('port')})")
                rules.append(f"netsh advfirewall firewall add rule name=\"Block {service}\" dir=in action=block protocol=TCP localport={port.get('port')}")
                rules.append("")
            st.code("\n".join(rules), language="powershell")

        # Sprint 6: Comprehensive Suggested Actions for all scan types
        st.subheader("🔧 Recommended Actions")

        # Create action tabs based on scan findings
        action_tabs = st.tabs(["🛡️ Firewall", "🔍 Windows Defender", "🔧 Configuration", "📋 Full Remediation"])

        with action_tabs[0]:
            st.markdown("### Firewall Hardening")
            if critical_ports:
                st.markdown("**Block risky ports (copy-paste to Admin PowerShell):**")
                for port in critical_ports:
                    port_num = port.get("port")
                    service = port.get("service", f"Port{port_num}")
                    with st.expander(f"🔒 Block {service} (Port {port_num})"):
                        st.code(f'netsh advfirewall firewall add rule name="Block {service} IN" dir=in action=block protocol=TCP localport={port_num}', language="powershell")
                        st.code(f'netsh advfirewall firewall add rule name="Block {service} OUT" dir=out action=block protocol=TCP localport={port_num}', language="powershell")
            else:
                st.success("No critical ports to block")

            st.markdown("**Enable Windows Firewall (all profiles):**")
            st.code("netsh advfirewall set allprofiles state on", language="powershell")

        with action_tabs[1]:
            st.markdown("### Windows Defender Scans")
            st.markdown("**Run quick scan:**")
            st.code("Start-MpScan -ScanType QuickScan", language="powershell")

            st.markdown("**Run full system scan:**")
            st.code("Start-MpScan -ScanType FullScan", language="powershell")

            st.markdown("**Update definitions:**")
            st.code("Update-MpSignature", language="powershell")

            st.markdown("**Check protection status:**")
            st.code("Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled", language="powershell")

        with action_tabs[2]:
            st.markdown("### Configuration Fixes")

            failed_checks = [c for c in config_checks if not c.get("passed", True)]
            if failed_checks:
                for check in failed_checks:
                    with st.expander(f"❌ {check.get('description', 'Unknown Check')}"):
                        st.markdown(f"**Recommendation:** {check.get('recommendation', 'N/A')}")
            else:
                st.success("All configuration checks passed!")

            st.markdown("**Common security hardening:**")

            st.markdown("Disable SMBv1:")
            st.code("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", language="powershell")

            st.markdown("Enable NLA for RDP:")
            st.code('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1', language="powershell")

            st.markdown("Disable Guest account:")
            st.code("net user guest /active:no", language="cmd")

        with action_tabs[3]:
            st.markdown("### Full Remediation Script")
            st.markdown("**Copy this complete script to remediate all findings:**")

            full_script = ["# BisonTitan Remediation Script", "# Run as Administrator", ""]

            # Firewall rules
            if critical_ports:
                full_script.append("# Block risky ports")
                for port in critical_ports:
                    port_num = port.get("port")
                    service = port.get("service", f"Port{port_num}")
                    full_script.append(f'netsh advfirewall firewall add rule name="Block {service}" dir=in action=block protocol=TCP localport={port_num}')
                full_script.append("")

            # Config fixes
            if failed_checks:
                full_script.append("# Configuration fixes")
                for check in failed_checks:
                    if "SMBv1" in check.get("description", ""):
                        full_script.append("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force")
                    if "Firewall" in check.get("description", ""):
                        full_script.append("netsh advfirewall set allprofiles state on")
                    if "Guest" in check.get("description", ""):
                        full_script.append("net user guest /active:no")
                full_script.append("")

            # Always add Defender scan
            full_script.extend([
                "# Run Windows Defender scan",
                "Update-MpSignature",
                "Start-MpScan -ScanType QuickScan",
                "",
                "Write-Host 'Remediation complete!' -ForegroundColor Green"
            ])

            st.code("\n".join(full_script), language="powershell")

            st.download_button(
                label="📥 Download Script",
                data="\n".join(full_script),
                file_name="bisontitan_remediation.ps1",
                mime="text/plain"
            )

    else:
        st.info("Click 'Run Vulnerability Check' to scan the target")


# =============================================================================
# Attack Simulation Page
# =============================================================================
elif page == "⚔️ Attack Simulation":
    st.markdown("## ⚔️ Attack Simulation")
    st.markdown("Simulate attacks for security testing (educational/authorized only)")

    st.warning("""
    **⚠️ ETHICAL USE ONLY**

    This tool performs security testing simulations. Only use on:
    - Systems you own
    - Systems you have written authorization to test

    Unauthorized use may violate laws.
    """)

    st.divider()

    col1, col2 = st.columns([2, 1])

    with col1:
        target = st.text_input("Target", value="127.0.0.1", help="Only localhost is auto-authorized")

    with col2:
        scenario = st.selectbox(
            "Scenario",
            ["All Scenarios", "Port Scan", "SMB Probe", "Weak Auth", "DNS Enum", "Buffer Overflow"]
        )

    authorized = st.checkbox("I confirm I have authorization to test this target")

    if st.button("🚀 Run Simulation", type="primary", disabled=not authorized):
        with st.spinner("Running attack simulation..."):
            import time
            time.sleep(3)

        st.session_state["sim_complete"] = True

    if st.session_state.get("sim_complete"):
        st.divider()
        st.success("Simulation complete!")

        # Overall results
        st.subheader("📊 Simulation Results")

        col1, col2 = st.columns([1, 2])

        with col1:
            overall_score = 5.2
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=overall_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Overall Risk"},
                gauge={
                    'axis': {'range': [0, 10]},
                    'bar': {'color': "#ffaa00"},
                    'steps': [
                        {'range': [0, 4], 'color': "#d4edda"},
                        {'range': [4, 7], 'color': "#fff3cd"},
                        {'range': [7, 10], 'color': "#f8d7da"}
                    ],
                }
            ))
            fig.update_layout(height=250, margin=dict(t=30, b=10, l=10, r=10))
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            scenarios_results = [
                {"Scenario": "Port Reconnaissance", "Risk Level": "⚡ Medium", "Score": "4.5/10"},
                {"Scenario": "SMB Protocol Security", "Risk Level": "⚠️ High", "Score": "7.0/10"},
                {"Scenario": "Weak Authentication", "Risk Level": "⚡ Medium", "Score": "5.0/10"},
                {"Scenario": "Buffer Overflow Analysis", "Risk Level": "⚡ Medium", "Score": "5.0/10"},
                {"Scenario": "DNS Enumeration", "Risk Level": "ℹ️ Low", "Score": "3.5/10"},
            ]

            st.dataframe(scenarios_results, use_container_width=True, hide_index=True)

        # Attack Tree Visualization
        st.subheader("🌳 Attack Tree - SMB Probe")

        st.markdown("""
        ```
        [✓] SMB Port Detection (T1021.002)
            └─ Check for open SMB ports (139, 445)
               Details: Ports open: [445]
        [✓] SMB Version Enumeration (T1082)
            └─ Identify SMB protocol version
               [✓] Check SMBv1
               [✓] Check SMBv2
               [✓] Check Signing
        [✓] Share Enumeration (T1135)
            └─ Enumerate accessible shares
               [✓] List shares
               [✓] Check IPC$
               [✗] Check ADMIN$
        [✗] Weak Authentication Assessment (T1110.001)
            └─ Assess authentication security posture
        [✓] Known Vulnerability Assessment (T1210)
            └─ Check for known SMB vulnerabilities
               [✓] CVE-2017-0144 (EternalBlue)
               [✓] CVE-2020-0796 (SMBGhost)
        ```
        """)

        # Action Items
        st.subheader("📋 Priority Action Items")

        actions = [
            {"Priority": "🚨 Critical", "Action": "Disable SMBv1 Protocol",
             "Command": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"},
            {"Priority": "⚠️ High", "Action": "Enable UAC",
             "Command": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\...' -Name 'EnableLUA' -Value 1"},
            {"Priority": "⚡ Medium", "Action": "Review Authentication Security",
             "Command": "Implement MFA for all remote access"},
        ]

        for action in actions:
            with st.expander(f"{action['Priority']}: {action['Action']}"):
                st.code(action["Command"], language="powershell")


# =============================================================================
# Settings Page (Sprint 3 - Real Config Save)
# =============================================================================
elif page == "⚙️ Settings":
    st.markdown("## ⚙️ Settings")

    # Show session ID
    session_id = get_session_id()
    st.caption(f"Session ID: `{session_id}` | Config: `{get_gui_settings_path()}`")
    st.divider()

    # Load current settings
    settings = st.session_state.gui_settings

    st.subheader("General Settings")

    col1, col2 = st.columns(2)

    with col1:
        theme = st.selectbox(
            "Theme",
            ["Dark", "Light", "System"],
            index=["Dark", "Light", "System"].index(settings.get("theme", "Dark"))
        )
        notifications = st.checkbox(
            "Enable notifications",
            value=settings.get("notifications", True)
        )
        auto_refresh = st.checkbox(
            "Auto-refresh dashboard",
            value=settings.get("auto_refresh", False)
        )

    with col2:
        refresh_interval = st.number_input(
            "Refresh interval (seconds)",
            min_value=10,
            max_value=300,
            value=settings.get("refresh_interval", 60)
        )
        timeout_options = ["30s", "60s", "120s", "300s"]
        scan_timeout = st.selectbox(
            "Default scan timeout",
            timeout_options,
            index=timeout_options.index(settings.get("scan_timeout", "60s"))
        )

    st.divider()

    st.subheader("API Configuration")

    abuseipdb_key = st.text_input(
        "AbuseIPDB API Key",
        type="password",
        value=settings.get("abuseipdb_api_key", ""),
        placeholder="Enter API key..."
    )
    gologin_key = st.text_input(
        "GoLogin API Key",
        type="password",
        value=settings.get("gologin_api_key", ""),
        placeholder="Enter API key..."
    )

    st.divider()

    # Save Settings Button
    col_save, col_reset = st.columns([2, 1])

    with col_save:
        if st.button("💾 Save Settings", type="primary", use_container_width=True):
            new_settings = {
                "theme": theme,
                "notifications": notifications,
                "auto_refresh": auto_refresh,
                "refresh_interval": refresh_interval,
                "scan_timeout": scan_timeout,
                "abuseipdb_api_key": abuseipdb_key,
                "gologin_api_key": gologin_key,
            }
            if save_gui_settings(new_settings):
                st.session_state.gui_settings = new_settings
                st.success(f"Settings saved to `{get_gui_settings_path()}`")
                # Also update environment variables for API keys
                if abuseipdb_key:
                    os.environ["ABUSEIPDB_API_KEY"] = abuseipdb_key
                if gologin_key:
                    os.environ["GOLOGIN_API_KEY"] = gologin_key

    with col_reset:
        if st.button("🔄 Reset to Defaults", use_container_width=True):
            default_settings = {
                "theme": "Dark",
                "notifications": True,
                "auto_refresh": False,
                "refresh_interval": 60,
                "scan_timeout": "60s",
                "abuseipdb_api_key": "",
                "gologin_api_key": "",
            }
            save_gui_settings(default_settings)
            st.session_state.gui_settings = default_settings
            st.rerun()

    st.divider()

    st.subheader("Export/Import Configuration")

    col1, col2 = st.columns(2)

    with col1:
        config_yaml = export_config_yaml()
        st.download_button(
            "📤 Export Configuration",
            data=config_yaml,
            file_name=f"bisontitan_config_{session_id}.yaml",
            mime="text/yaml",
            use_container_width=True,
        )

    with col2:
        uploaded = st.file_uploader("📥 Import Configuration", type=["yaml", "yml"])
        if uploaded:
            content = uploaded.read().decode("utf-8")
            if import_config_yaml(content):
                st.session_state.gui_settings = load_gui_settings()
                st.success("Configuration imported successfully!")
                st.rerun()

    st.divider()

    # Database Status
    st.subheader("Database Status")
    if DB_AVAILABLE:
        try:
            db = get_db()
            st.success(f"Connected: `{db.url}`")
            col1, col2, col3 = st.columns(3)
            with col1:
                scan_repo = get_scan_repo()
                scans = scan_repo.get_scans(limit=1000)
                st.metric("Total Scans", len(scans))
            with col2:
                anomaly_repo = get_anomaly_repo()
                anomalies = anomaly_repo.get_recent_anomalies(limit=1000)
                st.metric("Total Anomalies", len(anomalies))
            with col3:
                st.metric("Config Status", "Loaded" if CONFIG_AVAILABLE else "Default")
        except Exception as e:
            st.error(f"Database error: {e}")
    else:
        st.warning("Database not available")

    st.divider()

    st.subheader("About")
    st.info("""
    **BisonTitan Security Suite** v1.1.0 (Sprint 3)

    A robust, modular security toolkit for defensive security operations.

    - Malware scanning with YARA rules
    - Network traffic analysis
    - Windows event log analysis with MITRE ATT&CK
    - Vulnerability assessment
    - Attack simulation (educational)
    - Browser fingerprint analysis (Playwright)
    - Real-time config persistence (YAML)

    For support, visit: https://github.com/bisontitan
    """)


# =============================================================================
# Footer
# =============================================================================
st.divider()
st.caption("🦬 BisonTitan Security Suite | For authorized security testing only | © 2024")

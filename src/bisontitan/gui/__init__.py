"""
BisonTitan GUI Module
Streamlit-based web dashboard for security monitoring.
"""

from pathlib import Path

GUI_APP_PATH = Path(__file__).parent / "app.py"

__all__ = ["GUI_APP_PATH"]

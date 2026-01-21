"""
Mobile-responsive CSS styles for BisonTitan Streamlit Dashboard.

Usage in app.py:
    from .mobile_styles import inject_mobile_styles
    inject_mobile_styles()
"""

import streamlit as st


MOBILE_CSS = """
<style>
/* =============================================================================
   BisonTitan Mobile-Responsive Styles
   ============================================================================= */

/* --- Base Mobile Adjustments --- */
@media (max-width: 768px) {
    /* Reduce main padding */
    .main .block-container {
        padding: 1rem 0.5rem !important;
        max-width: 100% !important;
    }

    /* Smaller headers */
    .main-header {
        font-size: 1.5rem !important;
    }

    .sub-header {
        font-size: 0.85rem !important;
    }

    /* Stack columns vertically */
    [data-testid="column"] {
        width: 100% !important;
        flex: 1 1 100% !important;
    }

    /* Adjust metric cards */
    div[data-testid="stMetricValue"] {
        font-size: 1.5rem !important;
    }

    div[data-testid="stMetricLabel"] {
        font-size: 0.8rem !important;
    }

    /* Smaller buttons */
    .stButton > button {
        width: 100% !important;
        padding: 0.5rem 1rem !important;
        font-size: 0.9rem !important;
    }

    /* Adjust sidebar */
    [data-testid="stSidebar"] {
        min-width: 200px !important;
        max-width: 250px !important;
    }

    [data-testid="stSidebar"] .block-container {
        padding: 1rem 0.5rem !important;
    }

    /* Smaller tab labels */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.25rem !important;
    }

    .stTabs [data-baseweb="tab"] {
        padding: 0.5rem 0.75rem !important;
        font-size: 0.8rem !important;
    }

    /* Tables scroll horizontally */
    .stDataFrame {
        overflow-x: auto !important;
    }

    /* Adjust plotly charts */
    .js-plotly-plot {
        width: 100% !important;
    }

    /* Input fields */
    .stTextInput input, .stSelectbox select {
        font-size: 16px !important; /* Prevents iOS zoom */
    }

    /* Expander headers */
    .streamlit-expanderHeader {
        font-size: 0.9rem !important;
    }
}

/* --- Small Mobile (< 480px) --- */
@media (max-width: 480px) {
    .main .block-container {
        padding: 0.5rem 0.25rem !important;
    }

    .main-header {
        font-size: 1.25rem !important;
    }

    div[data-testid="stMetricValue"] {
        font-size: 1.25rem !important;
    }

    /* Hide sidebar by default on very small screens */
    [data-testid="stSidebar"][aria-expanded="true"] {
        min-width: 100% !important;
        max-width: 100% !important;
    }

    /* Vertical tabs on small screens */
    .stTabs [data-baseweb="tab-list"] {
        flex-wrap: wrap !important;
    }

    .stTabs [data-baseweb="tab"] {
        flex: 1 1 45% !important;
        text-align: center !important;
        margin: 0.1rem !important;
    }
}

/* --- Touch-Friendly Adjustments --- */
@media (pointer: coarse) {
    /* Larger touch targets */
    .stButton > button {
        min-height: 44px !important;
        min-width: 44px !important;
    }

    .stCheckbox label {
        padding: 0.5rem 0 !important;
    }

    .stRadio label {
        padding: 0.5rem 0 !important;
    }

    /* Larger clickable areas */
    .streamlit-expanderHeader {
        padding: 0.75rem !important;
    }

    /* Scroll indicators */
    .stDataFrame::-webkit-scrollbar {
        height: 8px !important;
    }
}

/* --- Dark Mode Mobile Adjustments --- */
@media (prefers-color-scheme: dark) and (max-width: 768px) {
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%) !important;
    }
}

/* --- Landscape Mobile --- */
@media (max-width: 896px) and (orientation: landscape) {
    [data-testid="stSidebar"] {
        max-width: 200px !important;
    }

    .main .block-container {
        padding: 0.5rem 1rem !important;
    }
}

/* --- Print Styles (for reports) --- */
@media print {
    [data-testid="stSidebar"] {
        display: none !important;
    }

    .stButton {
        display: none !important;
    }

    .main .block-container {
        max-width: 100% !important;
        padding: 0 !important;
    }
}

/* =============================================================================
   Component-Specific Mobile Fixes
   ============================================================================= */

/* Fix for metric cards on mobile */
@media (max-width: 768px) {
    [data-testid="metric-container"] {
        padding: 0.5rem !important;
    }

    /* Stack metrics 2x2 instead of 4x1 */
    .row-widget.stHorizontalBlock {
        flex-wrap: wrap !important;
    }

    .row-widget.stHorizontalBlock > div {
        flex: 1 1 45% !important;
        min-width: 140px !important;
    }
}

/* Fix chart legends on mobile */
@media (max-width: 768px) {
    .js-plotly-plot .legend {
        font-size: 10px !important;
    }
}

/* Fix for scrollable code blocks */
@media (max-width: 768px) {
    .stCodeBlock {
        max-height: 300px !important;
        overflow-y: auto !important;
    }

    pre {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
    }
}

/* Collapsible sections on mobile */
@media (max-width: 768px) {
    .streamlit-expander {
        margin-bottom: 0.5rem !important;
    }
}

</style>
"""


def inject_mobile_styles():
    """Inject mobile-responsive CSS into the Streamlit app."""
    st.markdown(MOBILE_CSS, unsafe_allow_html=True)


# Viewport meta tag for proper mobile scaling
VIEWPORT_META = """
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
"""


def inject_viewport_meta():
    """Inject viewport meta tag for mobile scaling."""
    st.markdown(VIEWPORT_META, unsafe_allow_html=True)


def setup_mobile_friendly_layout():
    """
    Setup mobile-friendly configuration.
    Call this at the start of your app.
    """
    inject_mobile_styles()
    inject_viewport_meta()

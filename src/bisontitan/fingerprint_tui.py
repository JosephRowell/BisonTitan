"""
BisonTitan Fingerprint TUI Dashboard
Textual-based terminal UI for fingerprint visualization.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    Pretty,
    ProgressBar,
    Static,
    TabbedContent,
    TabPane,
)

if TYPE_CHECKING:
    from bisontitan.fingerprint_viewer import FingerprintResult


class RiskIndicator(Static):
    """Visual risk indicator widget."""

    def __init__(self, risk: str, score: float, **kwargs):
        super().__init__(**kwargs)
        self.risk = risk
        self.score = score

    def compose(self) -> ComposeResult:
        risk_colors = {"Low": "green", "Medium": "yellow", "High": "red"}
        color = risk_colors.get(self.risk, "white")
        score_pct = int(self.score * 100)

        yield Static(f"[bold]Tracking Risk: [{color}]{self.risk}[/{color}][/bold]")
        yield Static(f"Fingerprint Score: {self.score:.2f} ({score_pct}%)")
        yield ProgressBar(total=100, show_eta=False)

    def on_mount(self) -> None:
        progress = self.query_one(ProgressBar)
        progress.update(progress=int(self.score * 100))


class IdentityPanel(Static):
    """Panel showing browser identity information."""

    def __init__(self, result: "FingerprintResult", **kwargs):
        super().__init__(**kwargs)
        self.result = result

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Browser Identity[/bold cyan]", classes="panel-title")
        yield Static(f"[bold]User Agent:[/bold]\n  {self.result.ua}")
        yield Static(f"[bold]IP Address:[/bold] {self.result.ip.get('origin', 'Unknown')}")
        yield Static(f"[bold]Resolution:[/bold] {self.result.resolution}")
        yield Static(f"[bold]Platform:[/bold] {self.result.platform}")
        yield Static(f"[bold]Language:[/bold] {self.result.language}")
        yield Static(f"[bold]Timezone:[/bold] {self.result.geo.get('timezone', 'Unknown')}")


class HardwarePanel(Static):
    """Panel showing hardware fingerprint information."""

    def __init__(self, result: "FingerprintResult", **kwargs):
        super().__init__(**kwargs)
        self.result = result

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Hardware Fingerprint[/bold cyan]", classes="panel-title")

        table = DataTable()
        table.add_columns("Property", "Value", "Status")

        hw = self.result.hardware
        canvas = hw.get("canvas", "Unknown")
        webgl = hw.get("webgl", "Unknown")

        table.add_row("Memory", str(hw.get("memory", "Unknown")), "Detected")
        table.add_row("CPU Threads", str(hw.get("threads", "Unknown")), "Detected")
        table.add_row(
            "Canvas",
            canvas,
            "[green]Protected[/green]" if canvas == "Blocked" else "[yellow]Exposed[/yellow]"
        )
        table.add_row(
            "WebGL",
            webgl,
            "[green]Protected[/green]" if webgl == "Blocked" else "[yellow]Exposed[/yellow]"
        )

        yield table


class BrowserPanel(Static):
    """Panel showing browser settings information."""

    def __init__(self, result: "FingerprintResult", **kwargs):
        super().__init__(**kwargs)
        self.result = result

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Browser Settings[/bold cyan]", classes="panel-title")

        table = DataTable()
        table.add_columns("Setting", "Value")

        br = self.result.browser
        table.add_row("Plugins", str(br.get("plugins", False)))
        table.add_row("Extensions", str(br.get("extensions", False)))
        table.add_row("Fonts", str(br.get("fonts", "Unknown")))

        yield table


class StoragePanel(Static):
    """Panel showing storage settings information."""

    def __init__(self, result: "FingerprintResult", **kwargs):
        super().__init__(**kwargs)
        self.result = result

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Storage Settings[/bold cyan]", classes="panel-title")

        table = DataTable()
        table.add_columns("Setting", "Enabled")

        st = self.result.storage
        table.add_row(
            "Save Tabs",
            "[green]Yes[/green]" if st.get("save_tabs") else "[red]No[/red]"
        )
        table.add_row(
            "Save History",
            "[green]Yes[/green]" if st.get("save_history") else "[red]No[/red]"
        )
        table.add_row(
            "Local Storage",
            "[green]Yes[/green]" if st.get("local_storage") else "[red]No[/red]"
        )

        yield table


class RecommendationsPanel(Static):
    """Panel showing privacy recommendations."""

    def __init__(self, result: "FingerprintResult", **kwargs):
        super().__init__(**kwargs)
        self.result = result

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Privacy Recommendations[/bold cyan]", classes="panel-title")

        if self.result.recommendations:
            for i, rec in enumerate(self.result.recommendations, 1):
                yield Static(f"  {i}. {rec}")
        else:
            yield Static("  [green]No recommendations - good privacy posture![/green]")


class JsonPanel(Static):
    """Panel showing raw JSON output."""

    def __init__(self, result: "FingerprintResult", **kwargs):
        super().__init__(**kwargs)
        self.result = result

    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Raw JSON Output[/bold cyan]", classes="panel-title")
        yield Pretty(self.result.to_dict())


class FingerprintTUI(App):
    """
    Textual TUI application for fingerprint visualization.
    Provides an interactive dashboard view of browser fingerprint data.
    """

    CSS = """
    Screen {
        background: $surface;
    }

    .panel-title {
        text-style: bold;
        color: cyan;
        padding: 1 0;
        border-bottom: solid $primary;
        margin-bottom: 1;
    }

    IdentityPanel, HardwarePanel, BrowserPanel, StoragePanel {
        border: solid $primary;
        padding: 1 2;
        margin: 1;
    }

    RecommendationsPanel {
        border: solid $warning;
        padding: 1 2;
        margin: 1;
    }

    JsonPanel {
        border: solid $secondary;
        padding: 1 2;
        margin: 1;
    }

    RiskIndicator {
        border: solid $accent;
        padding: 1 2;
        margin: 1;
        height: auto;
    }

    DataTable {
        height: auto;
        margin: 1 0;
    }

    #main-container {
        layout: grid;
        grid-size: 2;
        grid-columns: 1fr 1fr;
    }

    #left-column {
        column-span: 1;
    }

    #right-column {
        column-span: 1;
    }

    #bottom-panel {
        column-span: 2;
    }

    TabPane {
        padding: 1;
    }

    Button {
        margin: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("j", "copy_json", "Copy JSON"),
        Binding("r", "refresh", "Refresh"),
        Binding("tab", "next_tab", "Next Tab"),
    ]

    def __init__(self, result: "FingerprintResult", **kwargs):
        super().__init__(**kwargs)
        self.result = result
        self.title = "BisonTitan Fingerprint Viewer"
        self.sub_title = f"Risk: {result.risk} | Score: {result.fingerprint_score:.2f}"

    def compose(self) -> ComposeResult:
        yield Header()

        with TabbedContent():
            with TabPane("Dashboard", id="dashboard"):
                yield RiskIndicator(self.result.risk, self.result.fingerprint_score)

                with Horizontal(id="main-container"):
                    with Vertical(id="left-column"):
                        yield IdentityPanel(self.result)
                        yield HardwarePanel(self.result)

                    with Vertical(id="right-column"):
                        yield BrowserPanel(self.result)
                        yield StoragePanel(self.result)

                yield RecommendationsPanel(self.result, id="bottom-panel")

            with TabPane("JSON", id="json-tab"):
                with ScrollableContainer():
                    yield JsonPanel(self.result)

            with TabPane("Details", id="details-tab"):
                yield Static("[bold]Extended Details[/bold]\n")
                yield Static(f"[bold]Color Depth:[/bold] {self.result.color_depth}")
                yield Static(f"[bold]Pixel Ratio:[/bold] {self.result.pixel_ratio}")
                yield Static(f"[bold]Do Not Track:[/bold] {self.result.do_not_track}")
                yield Static(f"[bold]WebDriver Detected:[/bold] {self.result.webdriver_detected}")
                yield Static(f"[bold]Languages:[/bold] {', '.join(self.result.languages)}")
                yield Static(f"[bold]Captured At:[/bold] {self.result.captured_at}")

        with Horizontal():
            yield Button("Copy JSON", id="copy-btn", variant="primary")
            yield Button("Export", id="export-btn", variant="default")
            yield Button("Quit", id="quit-btn", variant="error")

        yield Footer()

    def action_quit(self) -> None:
        """Quit the application."""
        self.exit()

    def action_copy_json(self) -> None:
        """Copy JSON to clipboard (if pyperclip available)."""
        try:
            import pyperclip
            pyperclip.copy(self.result.to_json())
            self.notify("JSON copied to clipboard!")
        except ImportError:
            self.notify("Install pyperclip for clipboard support", severity="warning")

    def action_refresh(self) -> None:
        """Refresh fingerprint data."""
        self.notify("Refresh requires re-running the command", severity="information")

    def action_next_tab(self) -> None:
        """Switch to next tab."""
        tabs = self.query_one(TabbedContent)
        tabs.action_next_tab()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "quit-btn":
            self.exit()
        elif event.button.id == "copy-btn":
            self.action_copy_json()
        elif event.button.id == "export-btn":
            # Export to file
            try:
                with open("fingerprint_export.json", "w") as f:
                    f.write(self.result.to_json(indent=2))
                self.notify("Exported to fingerprint_export.json")
            except Exception as e:
                self.notify(f"Export failed: {e}", severity="error")


def main():
    """Entry point for standalone TUI testing."""
    from bisontitan.fingerprint_viewer import FingerprintResult

    # Create mock result for testing
    mock_result = FingerprintResult(
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        ip={"origin": "203.0.113.42"},
        resolution="1920x1080",
        geo={"timezone": "-05:00 America/New_York"},
        hardware={
            "memory": "8GB",
            "threads": "8",
            "canvas": "Real",
            "webgl": "Real",
        },
        storage={
            "save_tabs": True,
            "save_history": True,
            "local_storage": True,
        },
        browser={
            "plugins": True,
            "extensions": True,
            "fonts": "Masked (119)",
        },
        fingerprint_score=0.85,
        risk="Low",
        platform="Win32",
        language="en-US",
        languages=["en-US", "en"],
        recommendations=[
            "Consider using canvas fingerprint protection",
            "WebGL fingerprinting enabled - consider WebGL blocker",
        ],
        captured_at="2024-01-15T10:30:00Z",
    )

    app = FingerprintTUI(mock_result)
    app.run()


if __name__ == "__main__":
    main()

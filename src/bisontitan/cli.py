"""
BisonTitan CLI Module
Main command-line interface using Click.
"""

import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from bisontitan import __version__
from bisontitan.config import Config
from bisontitan.scanner import FileScanner, ProcessScanner, ThreatLevel
from bisontitan.utils import setup_logging, is_admin, print_banner, get_platform


console = Console()


def get_version_info() -> str:
    """Get detailed version information."""
    import platform
    lines = [
        f"BisonTitan {__version__}",
        f"Python {platform.python_version()}",
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()})",
    ]
    return "\n".join(lines)


def get_threat_color(level: ThreatLevel) -> str:
    """Get color for threat level display."""
    colors = {
        ThreatLevel.CLEAN: "green",
        ThreatLevel.INFO: "blue",
        ThreatLevel.LOW: "yellow",
        ThreatLevel.MEDIUM: "orange1",
        ThreatLevel.HIGH: "red",
        ThreatLevel.CRITICAL: "bold red",
    }
    return colors.get(level, "white")


@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Suppress non-essential output",
)
@click.option(
    "--json-output", "-j",
    is_flag=True,
    help="Output results as JSON",
)
@click.version_option(
    version=__version__,
    prog_name="BisonTitan",
    message=get_version_info(),
)
@click.pass_context
def cli(ctx, config, verbose, quiet, json_output):
    """
    BisonTitan Security Suite

    A robust, modular security toolkit for defensive security operations.

    Examples:

        bisontitan scan --files ./suspicious_dir

        bisontitan scan --processes

        bisontitan traffic --label

        bisontitan fingerprint

        bisontitan sim-attack --scenario port_scan
    """
    ctx.ensure_object(dict)

    # Load configuration
    try:
        ctx.obj["config"] = Config.load_or_default(config)
    except Exception as e:
        if not quiet:
            console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")
        ctx.obj["config"] = Config()

    # Set up logging
    log_level = logging.DEBUG if verbose else logging.INFO
    if quiet:
        log_level = logging.WARNING

    logger = setup_logging(
        log_file=ctx.obj["config"].log_file if not quiet else None,
        level=log_level,
        console=not quiet and not json_output,
    )
    ctx.obj["logger"] = logger
    ctx.obj["json_output"] = json_output
    ctx.obj["quiet"] = quiet

    # Print banner unless quiet
    if not quiet and not json_output:
        print_banner()
        console.print(f"[dim]Platform: {get_platform()} | Admin: {is_admin()}[/dim]\n")


@cli.command("scan")
@click.option(
    "--files", "-f",
    type=click.Path(exists=True, path_type=Path),
    help="Directory or file to scan",
)
@click.option(
    "--processes", "-p",
    is_flag=True,
    help="Scan running processes",
)
@click.option(
    "--recursive", "-r",
    is_flag=True,
    default=True,
    help="Scan directories recursively (default: True)",
)
@click.option(
    "--quarantine", "-Q",
    is_flag=True,
    help="Automatically quarantine detected threats",
)
@click.option(
    "--min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity to report (default: low)",
)
@click.pass_context
def scan(ctx, files, processes, recursive, quarantine, min_severity):
    """
    Scan files or processes for malware and suspicious activity.

    Examples:

        bisontitan scan --files ./downloads

        bisontitan scan --processes

        bisontitan scan --files ./temp --quarantine
    """
    config = ctx.obj["config"]
    json_output = ctx.obj["json_output"]
    results = []
    min_level = ThreatLevel[min_severity.upper()]

    if not files and not processes:
        console.print("[red]Error: Specify --files or --processes[/red]")
        raise SystemExit(1)

    # File scanning
    if files:
        if not json_output:
            console.print(f"\n[bold]Scanning: {files}[/bold]\n")

        scanner = FileScanner(config.scanner)
        scanner.load_yara_rules()

        scanned = 0
        threats_found = 0

        if files.is_file():
            result = scanner.scan_file(files)
            scanned = 1
            if result.threat_level.value != ThreatLevel.CLEAN.value:
                if result.threat_level.value >= min_level.value:
                    threats_found += 1
                    results.append(result.to_dict())

                    if quarantine and result.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                        scanner.quarantine_file(files, result)
        else:
            for result in scanner.scan_directory(files, recursive):
                scanned += 1

                if result.threat_level != ThreatLevel.CLEAN:
                    # Compare threat levels
                    level_order = [ThreatLevel.CLEAN, ThreatLevel.INFO, ThreatLevel.LOW,
                                   ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
                    if level_order.index(result.threat_level) >= level_order.index(min_level):
                        threats_found += 1
                        results.append(result.to_dict())

                        if not json_output:
                            color = get_threat_color(result.threat_level)
                            console.print(
                                f"[{color}][{result.threat_level.value.upper()}][/{color}] "
                                f"{result.filepath}"
                            )
                            for match in result.matches:
                                console.print(f"  └─ {match.rule_name}: {match.description}")

                        if quarantine and result.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                            scanner.quarantine_file(result.filepath, result)

                if not json_output and scanned % 100 == 0:
                    console.print(f"[dim]Scanned {scanned} files...[/dim]", end="\r")

        if not json_output:
            console.print(f"\n[bold]Scan Complete[/bold]")
            console.print(f"Files scanned: {scanned}")
            console.print(f"Threats found: {threats_found}")

    # Process scanning
    if processes:
        if not json_output:
            console.print(f"\n[bold]Scanning Processes[/bold]\n")

        scanner = ProcessScanner(config.scanner)
        scanner.load_yara_rules()

        scanned = 0
        threats_found = 0

        # Create table for process results
        if not json_output:
            table = Table(title="Suspicious Processes", box=box.ROUNDED)
            table.add_column("PID", style="cyan", width=8)
            table.add_column("Name", style="white", width=20)
            table.add_column("Threat", style="white", width=10)
            table.add_column("Details", style="dim", width=40)

        for result in scanner.scan_all_processes():
            scanned += 1

            if result.threat_level != ThreatLevel.CLEAN:
                level_order = [ThreatLevel.CLEAN, ThreatLevel.INFO, ThreatLevel.LOW,
                               ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
                if level_order.index(result.threat_level) >= level_order.index(min_level):
                    threats_found += 1
                    results.append(result.to_dict())

                    if not json_output:
                        color = get_threat_color(result.threat_level)
                        details = ", ".join(m.rule_name for m in result.matches[:3])
                        table.add_row(
                            str(result.pid),
                            result.name,
                            f"[{color}]{result.threat_level.value.upper()}[/{color}]",
                            details,
                        )

        if not json_output:
            if threats_found > 0:
                console.print(table)
            console.print(f"\nProcesses scanned: {scanned}")
            console.print(f"Suspicious processes: {threats_found}")

    # JSON output
    if json_output:
        output = {
            "scan_type": "files" if files else "processes",
            "target": str(files) if files else "all_processes",
            "results": results,
            "summary": {
                "total_scanned": scanned,
                "threats_found": threats_found,
            }
        }
        click.echo(json.dumps(output, indent=2))


@cli.command("traffic")
@click.option(
    "--label", "-l",
    is_flag=True,
    help="Label captured traffic as legitimate/suspicious",
)
@click.option(
    "--duration", "-d",
    type=int,
    default=5,
    help="Capture duration in seconds (default: 5)",
)
@click.option(
    "--interface", "-i",
    type=str,
    help="Network interface to capture on",
)
@click.option(
    "--threat-intel", "-t",
    is_flag=True,
    help="Enable AbuseIPDB threat intelligence lookups",
)
@click.option(
    "--list-interfaces",
    is_flag=True,
    help="List available network interfaces and exit",
)
@click.pass_context
def traffic(ctx, label, duration, interface, threat_intel, list_interfaces):
    """
    Analyze network traffic for suspicious activity.

    Examples:

        bisontitan traffic --label

        bisontitan traffic --label --duration 10

        bisontitan traffic --label --threat-intel

        bisontitan traffic --list-interfaces

    Note: Requires administrator/root privileges and scapy.
    On Windows, also requires Npcap: https://npcap.com/
    """
    from bisontitan.traffic_analyzer import TrafficAnalyzer, TrafficCategory

    config = ctx.obj["config"]
    json_output = ctx.obj["json_output"]
    quiet = ctx.obj["quiet"]

    # Override threat intel setting if flag provided
    if threat_intel:
        config.traffic.enable_threat_feeds = True

    try:
        analyzer = TrafficAnalyzer(config.traffic)
    except Exception as e:
        console.print(f"[red]Error initializing traffic analyzer: {e}[/red]")
        raise SystemExit(1)

    # List interfaces mode
    if list_interfaces:
        interfaces = analyzer.get_interfaces()
        if not interfaces:
            console.print("[yellow]No interfaces found (is scapy installed?)[/yellow]")
        else:
            console.print("\n[bold]Available Network Interfaces:[/bold]")
            for iface in interfaces:
                console.print(f"  - {iface}")
        return

    # Check admin for capture
    if not is_admin():
        console.print("[red]Error: Traffic capture requires administrator privileges[/red]")
        console.print("[dim]Run as Administrator (Windows) or with sudo (Linux/Mac)[/dim]")
        raise SystemExit(1)

    if not json_output:
        console.print(f"\n[bold]Traffic Analysis[/bold]")
        console.print(f"Duration: {duration}s | Interface: {interface or 'auto'}")
        console.print(f"Threat Intel: {'enabled' if config.traffic.enable_threat_feeds else 'disabled'}\n")

        if config.traffic.proxy_whitelist:
            console.print(f"[dim]Whitelisted IPs: {', '.join(config.traffic.proxy_whitelist)}[/dim]")

        console.print("[yellow]Capturing packets...[/yellow]")

    try:
        packets, stats = analyzer.analyze_capture(duration=duration, interface=interface)
    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("[dim]Install scapy: pip install scapy[/dim]")
        raise SystemExit(1)
    except PermissionError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Capture error: {e}[/red]")
        raise SystemExit(1)

    # Prepare results
    suspicious_packets = [
        (p, l) for p, l in packets
        if l.category in [TrafficCategory.SUSPICIOUS, TrafficCategory.MALICIOUS]
    ]

    if json_output:
        output = {
            "stats": stats.to_dict(),
            "packets": [
                {
                    "packet": p.to_dict(),
                    "label": l.to_dict(),
                }
                for p, l in packets
            ],
            "suspicious_count": len(suspicious_packets),
        }
        click.echo(json.dumps(output, indent=2))
        return

    # Display results
    console.print(f"\n[bold]Capture Complete[/bold]")
    console.print(f"Duration: {stats.duration_sec:.1f}s")
    console.print(f"Packets captured: {stats.total_packets}")
    console.print(f"Unique IPs: {len(stats.unique_ips)}")
    console.print(f"Bytes: {stats.bytes_captured:,}")

    # Protocol breakdown
    if stats.protocols:
        proto_str = ", ".join(f"{k}: {v}" for k, v in stats.protocols.items())
        console.print(f"Protocols: {proto_str}")

    # Summary
    console.print(f"\n[bold]Classification Summary:[/bold]")
    console.print(f"  Suspicious: [yellow]{stats.suspicious_count}[/yellow]")
    console.print(f"  Malicious:  [red]{stats.malicious_count}[/red]")
    console.print(f"  Whitelisted: [green]{stats.whitelisted_count}[/green]")

    # Show suspicious traffic details
    if suspicious_packets and label:
        console.print(f"\n[bold]Suspicious Traffic Details:[/bold]")

        table = Table(box=box.ROUNDED)
        table.add_column("Direction", style="cyan", width=30)
        table.add_column("Port", style="white", width=8)
        table.add_column("Category", width=12)
        table.add_column("Risk", width=6)
        table.add_column("Reasons", style="dim", width=40)

        for packet, label_info in suspicious_packets[:20]:  # Limit to 20
            direction = f"{packet.src_ip} -> {packet.dst_ip}"
            port = str(packet.dst_port or "-")

            if label_info.category == TrafficCategory.MALICIOUS:
                cat_display = "[red]MALICIOUS[/red]"
            else:
                cat_display = "[yellow]SUSPICIOUS[/yellow]"

            risk = f"{label_info.risk_score}%"
            reasons = "; ".join(label_info.reasons[:2])

            table.add_row(direction, port, cat_display, risk, reasons)

        console.print(table)

        if len(suspicious_packets) > 20:
            console.print(f"[dim]... and {len(suspicious_packets) - 20} more[/dim]")

    elif not suspicious_packets:
        console.print("\n[green]No suspicious traffic detected.[/green]")


@cli.command("fingerprint")
@click.option(
    "--output", "-o",
    type=click.Choice(["json", "table", "tui"]),
    default="table",
    help="Output format: json, table, or tui (default: table)",
)
@click.option(
    "--gologin-profile",
    type=str,
    help="GoLogin profile name for debug (requires GOLOGIN_API_KEY env var)",
)
@click.option(
    "--simulate",
    is_flag=True,
    help="Use local simulation instead of external endpoints",
)
@click.option(
    "--save", "-s",
    type=click.Path(path_type=Path),
    help="Save fingerprint JSON to file",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help="Skip browser capture, use system info only (faster)",
)
@click.pass_context
def fingerprint(ctx, output, gologin_profile, simulate, save, no_browser):
    """
    View browser/machine fingerprint as seen by external services.

    Simulates what tracking tools like GoLogin see about your machine.
    Shows what websites can infer: UA, IP, resolution, hardware, canvas, WebGL, fonts.

    Examples:

        bisontitan fingerprint

        bisontitan fingerprint --output json

        bisontitan fingerprint --simulate --output tui

        bisontitan fingerprint --gologin-profile "Proper English Lad"

        bisontitan fingerprint --save fingerprint.json
    """
    from bisontitan.fingerprint_viewer import FingerprintViewer

    config = ctx.obj["config"]
    json_cli_output = ctx.obj["json_output"]
    quiet = ctx.obj["quiet"]

    # Override output format if --json-output flag was used globally
    if json_cli_output:
        output = "json"

    if not quiet and output != "json":
        console.print(f"\n[bold]Fingerprint Viewer[/bold]")
        console.print("[dim]Simulating what tracking services see about your machine...[/dim]\n")

    viewer = FingerprintViewer(config.fingerprint)

    try:
        if no_browser:
            # Fast mode: use system info only
            if not quiet and output != "json":
                console.print("[yellow]Using system info only (no browser)[/yellow]")
            result = viewer.simulate_local()
        elif simulate:
            # Simulate with local dummy page
            if not quiet and output != "json":
                console.print("[yellow]Simulating with local dummy page...[/yellow]")
            result = viewer.capture_fingerprint(gologin_profile=gologin_profile, simulate=True)
        else:
            # Full browser capture
            if not quiet and output != "json":
                console.print("[yellow]Launching headless browser...[/yellow]")
            result = viewer.capture_fingerprint(gologin_profile=gologin_profile, simulate=False)

    except RuntimeError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("[dim]Install Playwright: pip install playwright && playwright install chromium[/dim]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Fingerprint capture failed: {e}[/red]")
        raise SystemExit(1)

    # Save to file if requested
    if save:
        save_path = Path(save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(result.to_json(indent=2))
        if not quiet:
            console.print(f"[green]Saved to: {save_path}[/green]")

    # Output based on format
    if output == "json":
        click.echo(result.to_json(indent=2))

    elif output == "tui":
        # Launch Textual TUI
        try:
            from bisontitan.fingerprint_tui import FingerprintTUI
            app = FingerprintTUI(result)
            app.run()
        except ImportError:
            console.print("[yellow]TUI requires textual. Falling back to table.[/yellow]")
            _display_fingerprint_table(result)
        except Exception as e:
            console.print(f"[yellow]TUI failed: {e}. Falling back to table.[/yellow]")
            _display_fingerprint_table(result)

    else:  # table
        _display_fingerprint_table(result)


def _display_fingerprint_table(result):
    """Display fingerprint result as rich table."""
    from rich.panel import Panel

    # Risk color
    risk_colors = {"Low": "green", "Medium": "yellow", "High": "red"}
    risk_color = risk_colors.get(result.risk, "white")

    # Main info panel
    console.print(Panel(
        f"[bold]User Agent:[/bold] {result.ua}\n"
        f"[bold]IP:[/bold] {result.ip.get('origin', 'Unknown')}\n"
        f"[bold]Resolution:[/bold] {result.resolution}\n"
        f"[bold]Platform:[/bold] {result.platform}\n"
        f"[bold]Timezone:[/bold] {result.geo.get('timezone', 'Unknown')}",
        title="Browser Identity",
        border_style="cyan",
    ))

    # Hardware table
    hw_table = Table(title="Hardware Fingerprint", box=box.ROUNDED)
    hw_table.add_column("Property", style="cyan", width=15)
    hw_table.add_column("Value", style="white", width=30)
    hw_table.add_column("Status", width=10)

    hw = result.hardware
    hw_table.add_row("Memory", str(hw.get("memory", "Unknown")), "[dim]Detected[/dim]")
    hw_table.add_row("CPU Threads", str(hw.get("threads", "Unknown")), "[dim]Detected[/dim]")
    canvas_status = hw.get("canvas", "Unknown")
    canvas_color = "green" if canvas_status == "Blocked" else "yellow"
    hw_table.add_row("Canvas", canvas_status, f"[{canvas_color}]{canvas_status}[/{canvas_color}]")
    webgl_status = hw.get("webgl", "Unknown")
    webgl_color = "green" if webgl_status == "Blocked" else "yellow"
    hw_table.add_row("WebGL", webgl_status, f"[{webgl_color}]{webgl_status}[/{webgl_color}]")
    console.print(hw_table)

    # Browser settings table
    br_table = Table(title="Browser Settings", box=box.ROUNDED)
    br_table.add_column("Setting", style="cyan", width=15)
    br_table.add_column("Value", style="white", width=30)

    br = result.browser
    br_table.add_row("Plugins", str(br.get("plugins", False)))
    br_table.add_row("Extensions", str(br.get("extensions", False)))
    br_table.add_row("Fonts", str(br.get("fonts", "Unknown")))
    console.print(br_table)

    # Storage table
    st_table = Table(title="Storage Settings", box=box.ROUNDED)
    st_table.add_column("Setting", style="cyan", width=20)
    st_table.add_column("Enabled", style="white", width=10)

    st = result.storage
    st_table.add_row("Save Tabs", "[green]Yes[/green]" if st.get("save_tabs") else "[red]No[/red]")
    st_table.add_row("Save History", "[green]Yes[/green]" if st.get("save_history") else "[red]No[/red]")
    st_table.add_row("Local Storage", "[green]Yes[/green]" if st.get("local_storage") else "[red]No[/red]")
    console.print(st_table)

    # Score and risk
    score_pct = int(result.fingerprint_score * 100)
    score_bar = "█" * (score_pct // 10) + "░" * (10 - score_pct // 10)

    console.print(Panel(
        f"[bold]Fingerprint Score:[/bold] {result.fingerprint_score:.2f} ({score_pct}%)\n"
        f"[{risk_color}]{score_bar}[/{risk_color}]\n\n"
        f"[bold]Tracking Risk:[/bold] [{risk_color}]{result.risk}[/{risk_color}]\n\n"
        f"[dim]Higher score = more unique = easier to track[/dim]",
        title="Privacy Analysis",
        border_style=risk_color,
    ))

    # Recommendations
    if result.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in result.recommendations:
            console.print(f"  • {rec}")


@cli.command("logs")
@click.option(
    "--analyze", "-a",
    is_flag=True,
    default=True,
    help="Analyze logs for security anomalies (default: True)",
)
@click.option(
    "--log-type",
    type=click.Choice(["Security", "System", "Application", "all"]),
    default="Security",
    help="Windows event log to analyze (default: Security)",
)
@click.option(
    "--days", "-d",
    type=int,
    default=1,
    help="Days of logs to analyze (default: 1)",
)
@click.option(
    "--hours",
    type=int,
    help="Hours of logs to analyze (overrides --days)",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json", "md"]),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--save", "-s",
    type=click.Path(path_type=Path),
    help="Save report to file",
)
@click.option(
    "--csv",
    type=click.Path(exists=True, path_type=Path),
    help="Analyze events from CSV file (cross-platform testing)",
)
@click.pass_context
def logs(ctx, analyze, log_type, days, hours, output, save, csv):
    """
    Analyze Windows event logs for security threats.

    Detects brute-force attacks, privilege escalation, account manipulation,
    and other security anomalies using pywin32 and pandas.

    Examples:

        bisontitan logs --analyze

        bisontitan logs --log-type Security --days 7

        bisontitan logs --output md --save report.md

        bisontitan logs --csv test_events.csv

    Note: Windows only (unless using --csv). Requires administrator privileges.
    """
    from bisontitan.log_analyzer import LogAnalyzer, LogAnalysisResult

    config = ctx.obj["config"]
    json_cli_output = ctx.obj["json_output"]
    quiet = ctx.obj["quiet"]

    # Override output if global --json flag used
    if json_cli_output:
        output = "json"

    # Calculate hours
    analysis_hours = hours if hours else days * 24

    # CSV mode works cross-platform
    if csv:
        if not quiet and output != "json":
            console.print(f"\n[bold]Log Analysis (from CSV)[/bold]")
            console.print(f"File: {csv}\n")

        analyzer = LogAnalyzer(config.log_analyzer)
        try:
            events = analyzer.read_events_from_csv(str(csv))
            result = analyzer.analyze_events(events)
        except Exception as e:
            console.print(f"[red]Error reading CSV: {e}[/red]")
            raise SystemExit(1)
    else:
        # Windows-only mode
        if get_platform() != "windows":
            console.print("[red]Error: Log analysis is Windows-only[/red]")
            console.print("[dim]Use --csv to analyze exported logs on other platforms[/dim]")
            raise SystemExit(1)

        if not is_admin():
            console.print("[red]Error: Log analysis requires administrator privileges[/red]")
            console.print("[dim]Run as Administrator to access Windows Event Logs[/dim]")
            raise SystemExit(1)

        if not quiet and output != "json":
            console.print(f"\n[bold]Log Analysis[/bold]")
            console.print(f"Log type: {log_type} | Period: {analysis_hours} hours\n")

        analyzer = LogAnalyzer(config.log_analyzer)

        try:
            if log_type == "all":
                log_types = ["Security", "System", "Application"]
            else:
                log_types = [log_type]

            result = analyzer.analyze_all(log_types=log_types, hours=analysis_hours)
        except RuntimeError as e:
            console.print(f"[red]Error: {e}[/red]")
            console.print("[dim]Install pywin32: pip install pywin32[/dim]")
            raise SystemExit(1)
        except Exception as e:
            console.print(f"[red]Analysis failed: {e}[/red]")
            raise SystemExit(1)

    # Save to file if requested
    if save:
        save_path = Path(save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        if output == "md" or str(save).endswith(".md"):
            content = result.to_markdown()
        else:
            content = json.dumps(result.to_dict(), indent=2)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(content)
        if not quiet:
            console.print(f"[green]Saved to: {save_path}[/green]")

    # Output based on format
    if output == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))

    elif output == "md":
        console.print(result.to_markdown())

    else:  # table
        _display_log_analysis_table(result)


def _display_log_analysis_table(result):
    """Display log analysis result as rich tables."""
    # Summary panel
    critical_count = sum(1 for a in result.anomalies if a.severity == "critical")
    warning_count = sum(1 for a in result.anomalies if a.severity == "warning")
    info_count = sum(1 for a in result.anomalies if a.severity == "info")

    summary_color = "red" if critical_count > 0 else "yellow" if warning_count > 0 else "green"

    console.print(Panel(
        f"[bold]Events Analyzed:[/bold] {result.total_events:,}\n"
        f"[bold]Time Range:[/bold] Last {result.time_range_hours} hours\n"
        f"[bold]Logs:[/bold] {', '.join(result.analyzed_logs)}\n\n"
        f"[red]Critical: {critical_count}[/red]  |  "
        f"[yellow]Warning: {warning_count}[/yellow]  |  "
        f"[blue]Info: {info_count}[/blue]",
        title="Log Analysis Summary",
        border_style=summary_color,
    ))

    # Anomalies table
    if result.anomalies:
        table = Table(title="Detected Anomalies", box=box.ROUNDED)
        table.add_column("Severity", width=10)
        table.add_column("Type", style="cyan", width=25)
        table.add_column("Description", width=40)
        table.add_column("Action", style="dim", width=35)

        severity_order = {"critical": 0, "warning": 1, "info": 2}
        for anomaly in sorted(result.anomalies, key=lambda a: severity_order.get(a.severity, 3)):
            sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(anomaly.severity, "white")
            sev_emoji = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}.get(anomaly.severity, "")

            table.add_row(
                f"[{sev_color}]{sev_emoji} {anomaly.severity.upper()}[/{sev_color}]",
                anomaly.anomaly_type.replace("_", " ").title(),
                anomaly.description[:40],
                anomaly.recommended_action[:35] + "..." if len(anomaly.recommended_action) > 35 else anomaly.recommended_action,
            )

        console.print(table)
    else:
        console.print("\n[green]No security anomalies detected.[/green]")

    # Statistics
    if result.statistics:
        stats = result.statistics
        if "top_event_ids" in stats:
            console.print("\n[bold]Top Event Types:[/bold]")
            for event_type, count in list(stats["top_event_ids"].items())[:5]:
                console.print(f"  • {event_type}: {count}")


@cli.command("vulns")
@click.option(
    "--scan",
    type=click.Choice(["ports", "quick", "full", "config"]),
    default="quick",
    help="Scan type: ports, quick (common ports), full, or config (default: quick)",
)
@click.option(
    "--target", "-t",
    type=str,
    default="127.0.0.1",
    help="Target to scan (default: localhost)",
)
@click.option(
    "--ports", "-p",
    type=str,
    default="1-1024",
    help="Port range for 'ports' scan type (default: 1-1024)",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json", "md"]),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--save", "-s",
    type=click.Path(path_type=Path),
    help="Save report to file",
)
@click.option(
    "--no-confirm",
    is_flag=True,
    help="Skip authorization confirmation prompt",
)
@click.pass_context
def vulns(ctx, scan, target, ports, output, save, no_confirm):
    """
    Check for vulnerabilities and misconfigurations.

    Scans for open ports (NetBIOS 137-139/445, RDP 3389) and
    checks Windows security configurations (UAC, SMBv1, firewall).

    Examples:

        bisontitan vulns --scan quick

        bisontitan vulns --scan ports --ports 1-1024

        bisontitan vulns --scan full --target 192.168.1.1

        bisontitan vulns --output md --save report.md

    Note: Only scan systems you own or have authorization to test.
    """
    from bisontitan.vuln_checker import VulnChecker

    config = ctx.obj["config"]
    json_cli_output = ctx.obj["json_output"]
    quiet = ctx.obj["quiet"]

    if json_cli_output:
        output = "json"

    # Authorization warning
    if not no_confirm and not quiet and output != "json" and target not in ["127.0.0.1", "localhost"]:
        console.print(Panel(
            "[yellow]WARNING: Only scan systems you own or have explicit authorization to test.[/yellow]\n"
            "Unauthorized scanning may violate laws.",
            title="Legal Notice",
            border_style="yellow",
        ))
        if not click.confirm(f"Do you have authorization to scan {target}?"):
            console.print("[yellow]Scan cancelled.[/yellow]")
            raise SystemExit(0)

    if not quiet and output != "json":
        console.print(f"\n[bold]Vulnerability Check[/bold]")
        console.print(f"Target: {target} | Scan type: {scan}\n")

    checker = VulnChecker(config.vuln_checker)

    try:
        if scan == "quick":
            if not quiet and output != "json":
                console.print("[yellow]Running quick scan (common vulnerable ports)...[/yellow]")
            result = checker.quick_scan(target)
        elif scan == "ports":
            if not quiet and output != "json":
                console.print(f"[yellow]Scanning ports {ports}...[/yellow]")
            result = checker.full_scan(target, ports)
        elif scan == "config":
            if not quiet and output != "json":
                console.print("[yellow]Checking system configuration...[/yellow]")
            # Config-only scan
            from bisontitan.vuln_checker import VulnCheckResult, ConfigCheckResult
            from datetime import datetime
            config_checks = checker.check_windows_config() if is_admin() else checker.check_config_simple()
            result = VulnCheckResult(
                target=target,
                scan_time=datetime.now(),
                open_ports=[],
                config_checks=config_checks,
                vulnerabilities=[],
                recommendations=[c.recommendation for c in config_checks if not c.passed],
                risk_score=checker.calculate_risk_score([], config_checks),
            )
        else:  # full
            if not quiet and output != "json":
                console.print("[yellow]Running full vulnerability scan...[/yellow]")
            result = checker.full_scan(target, ports)

    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise SystemExit(1)

    # Save to file if requested
    if save:
        save_path = Path(save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        if output == "md" or str(save).endswith(".md"):
            content = result.to_markdown()
        else:
            content = json.dumps(result.to_dict(), indent=2)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(content)
        if not quiet:
            console.print(f"[green]Saved to: {save_path}[/green]")

    # Output based on format
    if output == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))

    elif output == "md":
        console.print(result.to_markdown())

    else:  # table
        _display_vuln_check_table(result)


def _display_vuln_check_table(result):
    """Display vulnerability check result as rich tables."""
    # Risk score panel
    risk_color = "red" if result.risk_score >= 7 else "yellow" if result.risk_score >= 4 else "green"
    risk_bar = "█" * int(result.risk_score) + "░" * (10 - int(result.risk_score))

    console.print(Panel(
        f"[bold]Risk Score:[/bold] {result.risk_score:.1f}/10\n"
        f"[{risk_color}]{risk_bar}[/{risk_color}]\n\n"
        f"[bold]Open Ports:[/bold] {len(result.open_ports)}\n"
        f"[bold]Duration:[/bold] {result.scan_duration_sec:.1f}s",
        title=f"Vulnerability Assessment - {result.target}",
        border_style=risk_color,
    ))

    # Open ports table
    if result.open_ports:
        table = Table(title="Open Ports", box=box.ROUNDED)
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Service", width=15)
        table.add_column("Risk", width=12)
        table.add_column("Reason", style="dim", width=45)

        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for port in sorted(result.open_ports, key=lambda p: risk_order.get(p.risk_level, 4)):
            risk_emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(port.risk_level, "")
            risk_color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}.get(port.risk_level, "white")

            table.add_row(
                str(port.port),
                port.service or "unknown",
                f"[{risk_color}]{risk_emoji} {port.risk_level.upper()}[/{risk_color}]",
                port.reason[:45],
            )

        console.print(table)
    else:
        console.print("\n[green]No open ports detected.[/green]")

    # Config checks table
    failed_configs = [c for c in result.config_checks if not c.passed]
    if failed_configs:
        table = Table(title="Configuration Issues", box=box.ROUNDED)
        table.add_column("Check", width=35)
        table.add_column("Risk", width=12)
        table.add_column("Recommendation", style="dim", width=40)

        for check in failed_configs:
            risk_emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡"}.get(check.risk_level, "")
            risk_color = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(check.risk_level, "white")

            table.add_row(
                check.description,
                f"[{risk_color}]{risk_emoji} {check.risk_level.upper()}[/{risk_color}]",
                check.recommendation[:40] + "..." if len(check.recommendation) > 40 else check.recommendation,
            )

        console.print(table)

    # Recommendations
    if result.recommendations:
        console.print("\n[bold]Recommended Actions:[/bold]")
        for i, rec in enumerate(result.recommendations[:5], 1):
            console.print(f"  {i}. {rec}")
        if len(result.recommendations) > 5:
            console.print(f"  [dim]... and {len(result.recommendations) - 5} more[/dim]")


# Keep the old vuln-check command as an alias
@cli.command("vuln-check")
@click.option("--target", "-t", type=str, default="127.0.0.1", help="Target to scan")
@click.option("--ports", "-p", type=str, default="1-1024", help="Port range")
@click.option("--check-all", is_flag=True, help="Run all checks")
@click.pass_context
def vuln_check(ctx, target, ports, check_all):
    """Alias for 'vulns' command. Use 'bisontitan vulns' instead."""
    ctx.invoke(vulns, scan="full" if check_all else "quick", target=target, ports=ports)


@cli.command("sim-attack")
@click.option(
    "--scenario", "-s",
    type=click.Choice(["port_scan", "smb_probe", "weak_auth", "dns_enum", "buffer_overflow", "all"]),
    required=True,
    help="Attack scenario to simulate",
)
@click.option(
    "--target", "-t",
    type=str,
    default="127.0.0.1",
    help="Target for simulation (default: localhost)",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file for report",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["table", "json", "md"]),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--no-confirm",
    is_flag=True,
    help="Skip confirmation prompts",
)
@click.option(
    "--verbose", "-v",
    "sim_verbose",
    is_flag=True,
    help="Enable verbose simulation output",
)
@click.pass_context
def sim_attack(ctx, scenario, target, output, output_format, no_confirm, sim_verbose):
    """
    Simulate attacks for security testing (ethical/authorized only).

    Generates reports with remediation recommendations.

    Examples:

        bisontitan sim-attack --scenario port_scan

        bisontitan sim-attack --scenario smb_probe --target 127.0.0.1

        bisontitan sim-attack --scenario all --output report.md

        bisontitan sim-attack --scenario all --format json

    Note: Only use on systems you own or have authorization to test.
    """
    from bisontitan.attack_sim import AttackSimulator, SimulationReport

    config = ctx.obj["config"]
    json_cli_output = ctx.obj["json_output"]
    quiet = ctx.obj["quiet"]

    # Override format if global --json flag used
    if json_cli_output:
        output_format = "json"

    if not quiet and output_format != "json":
        console.print(f"\n[bold]Attack Simulation[/bold]")
        console.print(f"Scenario: {scenario} | Target: {target}\n")
        console.print(Panel(
            "[bold red]ETHICAL USE ONLY[/bold red]\n\n"
            "This tool performs security testing. Only use on:\n"
            "  - Systems you own\n"
            "  - Systems you have written authorization to test\n\n"
            "Unauthorized use may violate laws.",
            title="Legal Warning",
            border_style="red",
        ))

    # Confirm for non-localhost targets
    if not no_confirm and output_format != "json" and target not in ["127.0.0.1", "localhost"]:
        if not click.confirm("\nDo you have authorization to test this target?"):
            console.print("[yellow]Simulation cancelled.[/yellow]")
            raise SystemExit(0)

    try:
        simulator = AttackSimulator(config.attack_sim, verbose=sim_verbose)

        if not quiet and output_format != "json":
            console.print("[yellow]Running attack simulation...[/yellow]\n")

        # Run scenarios
        if scenario == "all":
            scenarios_to_run = ["port_scan", "smb_probe", "weak_auth", "dns_enum", "buffer_overflow"]
        else:
            scenarios_to_run = [scenario]

        results = []
        for sc in scenarios_to_run:
            try:
                result = simulator.simulate_scenario(sc, target)
                results.append(result)
                if not quiet and output_format != "json":
                    level_color = {
                        "Critical": "red", "High": "yellow",
                        "Medium": "cyan", "Low": "dim", "None": "green"
                    }.get(result.success_level.value, "white")
                    console.print(f"  [{level_color}]✓[/{level_color}] {result.scenario}: {result.success_level.value}")
            except Exception as e:
                if not quiet:
                    console.print(f"  [red]✗[/red] {sc}: {e}")

        # Generate report
        report = simulator.generate_report(results, target)

        # Save to file if requested
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if output_format == "md" or str(output).endswith(".md"):
                content = report.to_markdown()
            else:
                content = json.dumps(report.to_dict(), indent=2)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            if not quiet:
                console.print(f"\n[green]Report saved to: {output_path}[/green]")

        # Output based on format
        if output_format == "json":
            click.echo(json.dumps(report.to_dict(), indent=2))
        elif output_format == "md":
            console.print(report.to_markdown())
        else:
            _display_sim_attack_table(report)

    except Exception as e:
        console.print(f"[red]Simulation failed: {e}[/red]")
        raise SystemExit(1)


def _display_sim_attack_table(report):
    """Display simulation report as rich tables."""
    from bisontitan.attack_sim import SimulationReport

    # Risk color and bar
    risk_colors = {"Critical": "red", "High": "yellow", "Medium": "cyan", "Low": "dim", "None": "green"}
    risk_color = risk_colors.get(report.overall_risk, "white")
    risk_bar = "█" * int(report.overall_score) + "░" * (10 - int(report.overall_score))

    # Summary panel
    console.print(Panel(
        f"[bold]Target:[/bold] {report.target}\n"
        f"[bold]Scenarios Run:[/bold] {len(report.scenarios_run)}\n"
        f"[bold]Overall Risk:[/bold] [{risk_color}]{report.overall_risk}[/{risk_color}] ({report.overall_score:.1f}/10)\n"
        f"[{risk_color}]{risk_bar}[/{risk_color}]\n\n"
        f"[dim]SIMULATION MODE - No actual attacks performed[/dim]",
        title="Attack Simulation Results",
        border_style=risk_color,
    ))

    # Results table
    if report.results:
        table = Table(title="Scenario Results", box=box.ROUNDED)
        table.add_column("Scenario", style="cyan", width=35)
        table.add_column("Risk Level", width=15)
        table.add_column("Score", width=8)
        table.add_column("Key Finding", style="dim", width=35)

        for result in sorted(report.results, key=lambda r: r.success_score, reverse=True):
            level_emoji = {"Critical": "🚨", "High": "⚠️", "Medium": "⚡", "Low": "ℹ️", "None": "✅"}.get(result.success_level.value, "")
            level_color = risk_colors.get(result.success_level.value, "white")
            finding = result.findings[0][:35] if result.findings else "No findings"

            table.add_row(
                result.scenario,
                f"[{level_color}]{level_emoji} {result.success_level.value}[/{level_color}]",
                f"{result.success_score:.1f}",
                finding,
            )

        console.print(table)

    # Action Items
    if report.action_items:
        console.print("\n[bold]Priority Action Items:[/bold]")
        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        for action in sorted(report.action_items, key=lambda a: priority_order.get(a.priority, 4))[:5]:
            priority_emoji = {"Critical": "🚨", "High": "⚠️", "Medium": "⚡", "Low": "ℹ️"}.get(action.priority, "")
            priority_color = {"Critical": "red", "High": "yellow", "Medium": "cyan", "Low": "dim"}.get(action.priority, "white")
            console.print(f"  [{priority_color}]{priority_emoji}[/{priority_color}] [{priority_color}]{action.priority}[/{priority_color}]: {action.title}")
            if action.command:
                console.print(f"      [dim]Command: {action.command[:60]}...[/dim]" if len(action.command) > 60 else f"      [dim]Command: {action.command}[/dim]")

    # Best Practices
    if report.best_practices:
        console.print("\n[bold]Top Security Best Practices:[/bold]")
        for practice in report.best_practices[:5]:
            console.print(f"  • {practice}")

    console.print("\n[dim]Run with --format md for full report or --output report.md to save[/dim]")


@cli.command("quarantine")
@click.option(
    "--list", "-l",
    "list_quarantine",
    is_flag=True,
    help="List quarantined files",
)
@click.option(
    "--restore", "-r",
    type=click.Path(exists=True, path_type=Path),
    help="Restore a quarantined file",
)
@click.option(
    "--delete", "-d",
    type=click.Path(exists=True, path_type=Path),
    help="Permanently delete quarantined file",
)
@click.pass_context
def quarantine_cmd(ctx, list_quarantine, restore, delete):
    """
    Manage quarantined files.

    Examples:

        bisontitan quarantine --list

        bisontitan quarantine --restore quarantine/file.quarantine
    """
    config = ctx.obj["config"]
    quarantine_dir = Path(config.scanner.quarantine_dir)

    if list_quarantine:
        if not quarantine_dir.exists():
            console.print("[yellow]Quarantine directory is empty[/yellow]")
            return

        files = list(quarantine_dir.glob("*.quarantine"))
        if not files:
            console.print("[yellow]No quarantined files[/yellow]")
            return

        table = Table(title="Quarantined Files", box=box.ROUNDED)
        table.add_column("File", style="cyan")
        table.add_column("Original Path", style="dim")
        table.add_column("Quarantine Date", style="yellow")

        for f in files:
            meta_path = f.with_suffix(".json")
            if meta_path.exists():
                with open(meta_path) as mf:
                    meta = json.load(mf)
                table.add_row(
                    f.name,
                    meta.get("original_path", "Unknown"),
                    meta.get("quarantine_time", "Unknown")[:19],
                )

        console.print(table)

    elif restore:
        scanner = FileScanner(config.scanner)
        success, path = scanner.restore_from_quarantine(restore)
        if success:
            console.print(f"[green]Restored to: {path}[/green]")
        else:
            console.print("[red]Failed to restore file[/red]")

    elif delete:
        if click.confirm(f"Permanently delete {delete}?"):
            Path(delete).unlink()
            meta = Path(delete).with_suffix(".json")
            if meta.exists():
                meta.unlink()
            console.print("[green]File deleted[/green]")


@cli.command("gui")
@click.option(
    "--launch", "-l",
    is_flag=True,
    default=True,
    help="Launch the Streamlit GUI dashboard (default: True)",
)
@click.option(
    "--port", "-p",
    type=int,
    default=8501,
    help="Port to run the dashboard on (default: 8501)",
)
@click.option(
    "--host",
    type=str,
    default="localhost",
    help="Host to bind to (default: localhost)",
)
@click.option(
    "--browser/--no-browser",
    default=True,
    help="Open browser automatically (default: True)",
)
@click.pass_context
def gui_cmd(ctx, launch, port, host, browser):
    """
    Launch the BisonTitan web dashboard.

    Starts a Streamlit server with an interactive security dashboard
    featuring visualizations, scanners, and analysis tools.

    Examples:

        bisontitan gui

        bisontitan gui --port 8080

        bisontitan gui --no-browser

    Requirements: streamlit, plotly (pip install streamlit plotly)
    """
    import subprocess
    import webbrowser
    from pathlib import Path

    quiet = ctx.obj.get("quiet", False)

    # Find the app.py file
    try:
        from bisontitan.gui import GUI_APP_PATH
        app_path = GUI_APP_PATH
    except ImportError:
        # Fallback to relative path
        app_path = Path(__file__).parent / "gui" / "app.py"

    if not app_path.exists():
        console.print(f"[red]Error: GUI app not found at {app_path}[/red]")
        raise SystemExit(1)

    if not quiet:
        console.print(f"\n[bold]BisonTitan Web Dashboard[/bold]")
        console.print(f"Starting server on http://{host}:{port}")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    # Build streamlit command
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(app_path),
        "--server.port", str(port),
        "--server.address", host,
        "--theme.base", "dark",
    ]

    if not browser:
        cmd.extend(["--server.headless", "true"])

    try:
        # Check if streamlit is installed
        import streamlit
    except ImportError:
        console.print("[red]Error: Streamlit not installed[/red]")
        console.print("[dim]Install with: pip install streamlit plotly[/dim]")
        raise SystemExit(1)

    try:
        # Run streamlit
        process = subprocess.run(cmd)
        sys.exit(process.returncode)
    except KeyboardInterrupt:
        if not quiet:
            console.print("\n[yellow]Dashboard stopped[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Failed to start dashboard: {e}[/red]")
        raise SystemExit(1)


def main():
    """Main entry point."""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()

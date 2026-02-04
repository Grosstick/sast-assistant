"""CLI entry point for SAST Assistant."""

import argparse
import logging
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import Config
from .scanner.semgrep import SemgrepScanner, SemgrepScanError
from .extractor.context import ContextExtractor
from .ai_engine.client import GeminiClient
from .reporter.markdown import MarkdownReporter
from .models.semgrep import SemgrepResult
from .models.finding import EnrichedFinding, VulnerabilityType
from .models.report import ScanReport

console = Console()
logger = logging.getLogger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sast-assistant",
        description="AI-powered Static Application Security Testing assistant",
        epilog="Example: sast-assistant scan ./src --output report.md",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a codebase for vulnerabilities",
    )
    scan_parser.add_argument(
        "target",
        type=str,
        help="Path to file or directory to scan",
    )
    scan_parser.add_argument(
        "--output", "-o",
        type=str,
        default="sast_report.md",
        help="Output file path for the report (default: sast_report.md)",
    )
    scan_parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis (scan only mode)",
    )
    scan_parser.add_argument(
        "--sqli-xss-only",
        action="store_true",
        help="Filter results to SQL injection and XSS only",
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of Markdown report",
    )
    
    # Verify command (check dependencies)
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify installation and dependencies",
    )
    
    return parser


def run_scan(args: argparse.Namespace, config: Config) -> int:
    """
    Run the vulnerability scan.
    
    Args:
        args: Parsed command line arguments
        config: Application configuration
        
    Returns:
        Exit code (0 for success)
    """
    target_path = Path(args.target)
    output_path = Path(args.output)
    
    # Validate target
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Target path does not exist: {target_path}")
        return 1
    
    console.print(Panel(
        f"[bold]SAST Assistant v{__version__}[/bold]\n\n"
        f"Target: {target_path}\n"
        f"Output: {output_path}\n"
        f"AI Analysis: {'Disabled' if args.no_ai else 'Enabled'}",
        title="🔍 Security Scan",
    ))
    
    start_time = time.time()
    
    try:
        # Stage 1: Semgrep Scan
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running Semgrep scan...", total=None)
            
            scanner = SemgrepScanner(config.semgrep)
            
            if args.sqli_xss_only:
                scan_result = scanner.scan_for_sqli_and_xss(target_path)
            else:
                scan_result = scanner.scan(target_path)
            
            progress.update(task, completed=True)
        
        console.print(f"[green]✓[/green] Semgrep scan complete: {scan_result.finding_count} findings")
        
        if scan_result.finding_count == 0:
            console.print("[green]No vulnerabilities detected![/green]")
            # Create empty report
            report = ScanReport.from_enriched_findings(
                findings=[],
                target_path=str(target_path),
                scan_duration=time.time() - start_time,
                ai_enabled=not args.no_ai,
            )
            reporter = MarkdownReporter(config.reporter)
            reporter.save_report(report, output_path)
            console.print(f"[blue]Report saved to:[/blue] {output_path}")
            return 0
        
        # Stage 2: Extract Context
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Extracting code context...", total=scan_result.finding_count)
            
            extractor = ContextExtractor(config.context)
            contexts = extractor.extract_context_batch(scan_result.results)
            
            progress.update(task, completed=scan_result.finding_count)
        
        console.print(f"[green]✓[/green] Context extracted for {len(contexts)} findings")
        
        # Stage 3: AI Analysis (optional)
        enriched_findings: list[EnrichedFinding] = []
        
        if args.no_ai:
            # Create enriched findings without AI analysis
            for finding in scan_result.results:
                finding_id = f"{finding.path}:{finding.line_number}:{finding.check_id}"
                context = contexts.get(finding_id)
                enriched = EnrichedFinding(original=finding, context=context)
                enriched_findings.append(enriched)
        else:
            try:
                ai_client = GeminiClient(config.gemini)
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("Running AI analysis...", total=scan_result.finding_count)
                    
                    for finding in scan_result.results:
                        finding_id = f"{finding.path}:{finding.line_number}:{finding.check_id}"
                        context = contexts.get(finding_id)
                        
                        if context:
                            enriched = ai_client.enrich_finding(finding, context)
                        else:
                            enriched = EnrichedFinding(original=finding)
                        
                        enriched_findings.append(enriched)
                        progress.advance(task)
                
                console.print(f"[green]✓[/green] AI analysis complete for {len(enriched_findings)} findings")
                
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] AI analysis failed: {e}")
                console.print("[yellow]Continuing without AI analysis...[/yellow]")
                # Fall back to non-AI enriched findings
                for finding in scan_result.results:
                    finding_id = f"{finding.path}:{finding.line_number}:{finding.check_id}"
                    context = contexts.get(finding_id)
                    enriched = EnrichedFinding(original=finding, context=context)
                    enriched_findings.append(enriched)
        
        # Stage 4: Generate Report
        scan_duration = time.time() - start_time
        
        if args.json:
            # Output raw JSON
            import json
            output_data = {
                "findings": [f.model_dump() for f in enriched_findings],
                "scan_duration": scan_duration,
            }
            output_path = output_path.with_suffix(".json")
            output_path.write_text(json.dumps(output_data, indent=2, default=str))
        else:
            # Generate Markdown report
            report = ScanReport.from_enriched_findings(
                findings=enriched_findings,
                target_path=str(target_path),
                scan_duration=scan_duration,
                ai_enabled=not args.no_ai,
            )
            report.semgrep_version = scan_result.version
            report.sast_assistant_version = __version__
            
            reporter = MarkdownReporter(config.reporter)
            reporter.save_report(report, output_path)
        
        console.print(f"[blue]Report saved to:[/blue] {output_path}")
        
        # Print summary table
        _print_summary_table(enriched_findings)
        
        console.print(f"\n[dim]Scan completed in {scan_duration:.2f} seconds[/dim]")
        
        return 0
        
    except SemgrepScanError as e:
        console.print(f"[red]Semgrep error:[/red] {e}")
        if e.stderr:
            console.print(f"[dim]{e.stderr}[/dim]")
        return 1
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        return 1


def _print_summary_table(findings: list[EnrichedFinding]) -> None:
    """Print a summary table of findings."""
    if not findings:
        return
    
    table = Table(title="Findings Summary")
    table.add_column("#", style="dim")
    table.add_column("Severity", justify="center")
    table.add_column("Type")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Verdict", justify="center")
    
    severity_colors = {"ERROR": "red", "WARNING": "yellow", "INFO": "blue"}
    
    for i, f in enumerate(findings[:10], start=1):  # Show first 10
        severity = f.severity.upper()
        color = severity_colors.get(severity, "white")
        
        vuln_type = f.vulnerability_type.value.replace("_", " ").title()
        
        verdict = "?"
        if f.ai_analysis:
            verdict_map = {
                "true_positive": "⚠️",
                "false_positive": "✅",
                "needs_review": "🔍",
            }
            verdict = verdict_map.get(f.ai_analysis.verdict.value, "?")
        
        # Truncate path
        file_path = f.file_path
        if len(file_path) > 30:
            file_path = "..." + file_path[-27:]
        
        table.add_row(
            str(i),
            f"[{color}]{severity}[/{color}]",
            vuln_type,
            file_path,
            str(f.line_number),
            verdict,
        )
    
    if len(findings) > 10:
        table.add_row("...", "...", "...", f"({len(findings) - 10} more)", "...", "...")
    
    console.print(table)


def run_verify(config: Config) -> int:
    """
    Verify installation and dependencies.
    
    Returns:
        Exit code (0 for all checks passed)
    """
    console.print(Panel("[bold]Verifying SAST Assistant Installation[/bold]", title="🔧 Verify"))
    
    all_ok = True
    
    # Check Semgrep
    console.print("\n[bold]1. Semgrep[/bold]")
    try:
        scanner = SemgrepScanner(config.semgrep)
        ok, msg = scanner.verify_installation()
        if ok:
            console.print(f"  [green]✓[/green] {msg}")
        else:
            console.print(f"  [red]✗[/red] {msg}")
            all_ok = False
    except Exception as e:
        console.print(f"  [red]✗[/red] Error: {e}")
        all_ok = False
    
    # Check Gemini API
    console.print("\n[bold]2. Gemini API[/bold]")
    try:
        api_key = config.gemini.get_api_key()
        # Mask the key for display
        masked = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
        console.print(f"  [green]✓[/green] API key found: {masked}")
        
        # Test connection
        client = GeminiClient(config.gemini)
        ok, msg = client.test_connection()
        if ok:
            console.print(f"  [green]✓[/green] {msg}")
        else:
            console.print(f"  [yellow]![/yellow] {msg}")
            
    except ValueError as e:
        console.print(f"  [yellow]![/yellow] {e}")
        console.print("  [dim]AI analysis will be unavailable[/dim]")
    
    # Check Python version
    console.print("\n[bold]3. Python[/bold]")
    py_version = sys.version_info
    if py_version >= (3, 10):
        console.print(f"  [green]✓[/green] Python {py_version.major}.{py_version.minor}.{py_version.micro}")
    else:
        console.print(f"  [red]✗[/red] Python {py_version.major}.{py_version.minor} (requires 3.10+)")
        all_ok = False
    
    if all_ok:
        console.print("\n[green]All checks passed![/green]")
        return 0
    else:
        console.print("\n[yellow]Some checks failed. See details above.[/yellow]")
        return 1


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    # Load configuration
    config = Config.from_env()
    
    # Set up logging
    if hasattr(args, 'verbose') and args.verbose:
        config.log_level = "DEBUG"
    config.setup_logging()
    
    if args.command == "scan":
        return run_scan(args, config)
    elif args.command == "verify":
        return run_verify(config)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())

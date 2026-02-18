"""Report generation (console and JSON)."""

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from .models import ScanResult, Severity


def print_console(result: ScanResult) -> None:
    """Print scan result to console with Rich formatting."""
    console = Console()
    console.print(Panel(f"[bold]Bug Bounty Scanner - Results for {result.target}[/bold]", box=box.DOUBLE))

    # Summary
    summary = (
        f"[red]Critical: {result.critical_count}[/red]  "
        f"[orange3]High: {result.high_count}[/orange3]  "
        f"[yellow]Medium: {result.medium_count}[/yellow]  "
        f"[blue]Low: {result.low_count}[/blue]  "
        f"[dim]Info: {result.info_count}[/dim]"
    )
    console.print(Panel(summary, title="Summary", border_style="blue"))
    console.print(f"\nURLs tested: [cyan]{len(result.urls_tested)}[/cyan]\n")

    if result.errors:
        console.print("[red]Errors:[/red]")
        for e in result.errors[:10]:
            console.print(f"  • {e}")
        if len(result.errors) > 10:
            console.print(f"  ... and {len(result.errors) - 10} more")
        console.print()

    # Findings table
    if not result.findings:
        console.print("[green]No findings above threshold.[/green]")
        return

    table = Table(title="Findings", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=18)
    table.add_column("Title", width=40)
    table.add_column("URL", width=50)

    severity_style = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "orange3",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    for f in sorted(result.findings, key=lambda x: (-_severity_rank(x.severity), x.title)):
        style = severity_style.get(f.severity, "white")
        table.add_row(
            f"[{style}]{f.severity.value.upper()}[/]",
            f.finding_type.value,
            f.title[:38] + ".." if len(f.title) > 40 else f.title,
            f.url[:48] + ".." if len(f.url) > 50 else f.url,
        )
    console.print(table)

    # Detail for each finding (use a safe border color: gray not valid in some Rich versions)
    console.print("\n[bold]Details[/bold]\n")
    for i, f in enumerate(sorted(result.findings, key=lambda x: (-_severity_rank(x.severity), x.title)), 1):
        style = severity_style.get(f.severity, "white")
        body = f"[bold]Description:[/bold] {f.description}\n"
        body += f"[bold]URL:[/bold] {f.url}\n"
        if f.evidence:
            body += f"[bold]Evidence:[/bold] {f.evidence}\n"
        if f.recommendation:
            body += f"[bold]Recommendation:[/bold] {f.recommendation}\n"
        if f.cwe_id:
            body += f"[bold]CWE:[/bold] {f.cwe_id}\n"
        try:
            console.print(Panel(body, title=f"#{i} [{style}]{f.severity.value.upper()}[/] - {f.title}", border_style="bright_black"))
        except Exception:
            console.print(Panel(body, title=f"#{i} [{style}]{f.severity.value.upper()}[/] - {f.title}"))


def _severity_rank(s: Severity) -> int:
    order = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    try:
        return order.index(s)
    except ValueError:
        return 0


def to_dict(result: ScanResult) -> dict:
    """Serialize ScanResult to a JSON-serializable dict."""
    return {
        "target": result.target,
        "urls_tested": result.urls_tested,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }


def write_json(result: ScanResult, path: str | Path) -> None:
    """Write scan result to JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(to_dict(result), f, indent=2)

"""Command-line entry point."""

from pathlib import Path

import typer
from rich.console import Console

from appsec import __version__
from appsec.models import ScanResult
from appsec.scanners import PythonSecurityScanner

app = typer.Typer(help="AI-assisted application security scanner.")
console = Console()


@app.command()
def version() -> None:
    """Show the platform version."""
    console.print(f"ai-appsec-platform {__version__}")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, readable=True),
) -> None:
    """Run deterministic security scanners against PATH."""
    scanner = PythonSecurityScanner()
    findings = scanner.scan(path)
    files_scanned = sum(
        1
        for candidate in path.rglob("*.py")
        if not any(part in {".git", ".venv", "venv", "__pycache__", "node_modules"} for part in candidate.parts)
    )
    result = ScanResult(findings=findings, files_scanned=files_scanned, rules_run=2)

    console.print(f"Scanned [bold]{path.resolve()}[/bold]")
    console.print(f"Files: {result.files_scanned} | Findings: {len(result.findings)}")
    for finding in result.findings:
        console.print(
            f"[{finding.severity.value}] {finding.rule_id} "
            f"{finding.path}:{finding.line} — {finding.title}"
        )

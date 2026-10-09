"""Command-line entry point."""

import json
from pathlib import Path

import typer
from rich.console import Console

from appsec import __version__
from appsec.findings import normalize_findings
from appsec.models import ScanResult
from appsec.scanners import JavaScriptSecurityScanner, PythonSecurityScanner, SecretScanner

app = typer.Typer(help="AI-assisted application security scanner.")
console = Console()


@app.command()
def version() -> None:
    """Show the platform version."""
    console.print(f"ai-appsec-platform {__version__}")


@app.command()
def scan(
    path: Path = typer.Argument(  # noqa: B008
        Path("."), exists=True, file_okay=False, readable=True
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON instead of human-readable output."
    ),
) -> None:
    """Run deterministic security scanners against PATH."""
    scanners = (
        PythonSecurityScanner(),
        JavaScriptSecurityScanner(),
        SecretScanner(),
    )
    raw_findings = [finding for scanner in scanners for finding in scanner.scan(path)]
    findings = normalize_findings(raw_findings, path)

    extensions = SecretScanner._EXTENSIONS | JavaScriptSecurityScanner._EXTENSIONS
    extensions.add(".py")
    files_scanned = sum(
        1
        for candidate in path.rglob("*")
        if candidate.is_file()
        and candidate.suffix.lower() in extensions
        and not any(
            part in {".git", ".venv", "venv", "__pycache__", "node_modules"}
            for part in candidate.parts
        )
    )
    result = ScanResult(findings=findings, files_scanned=files_scanned, rules_run=11)

    if json_output:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
        return

    console.print(f"Scanned [bold]{path.resolve()}[/bold]")
    console.print(
        f"Files: {result.files_scanned} | Findings: {len(result.findings)} | Rules: {result.rules_run}"
    )
    for finding in result.findings:
        console.print(
            f"[{finding.severity.value}] {finding.rule_id} "
            f"{finding.path}:{finding.line} — {finding.title}"
        )

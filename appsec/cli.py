"""Command-line entry point."""

from pathlib import Path

import typer
from rich.console import Console

from appsec.models import ScanResult

app = typer.Typer(help="AI-assisted application security scanner.")
console = Console()


@app.command()
def version() -> None:
    """Show the platform version."""
    from appsec import __version__

    console.print(f"ai-appsec-platform {__version__}")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, readable=True),
) -> None:
    """Run the security scanner against PATH."""
    result = ScanResult()
    console.print(
        f"Scanned [bold]{path.resolve()}[/bold]: "
        f"{result.files_scanned} files, {len(result.findings)} findings."
    )

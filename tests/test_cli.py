from typer.testing import CliRunner

from appsec.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "ai-appsec-platform" in result.stdout

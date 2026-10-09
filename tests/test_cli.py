from pathlib import Path

from typer.testing import CliRunner

from appsec.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "ai-appsec-platform" in result.stdout


def test_scan_json_output(tmp_path: Path) -> None:
    (tmp_path / "sample.js").write_text("element.innerHTML = userInput;\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])

    assert result.exit_code == 0
    payload = __import__("json").loads(result.stdout)
    assert payload["files_scanned"] == 1
    assert payload["findings"][0]["rule_id"] == "JSSEC-004"
    assert payload["findings"][0]["path"] == "sample.js"

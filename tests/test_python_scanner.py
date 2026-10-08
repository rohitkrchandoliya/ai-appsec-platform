from pathlib import Path

from appsec.models import Severity
from appsec.scanners.python import PythonSecurityScanner


def write_source(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")
    return path


def test_detects_eval(tmp_path: Path) -> None:
    write_source(tmp_path, "value = eval(user_input)\n")
    findings = PythonSecurityScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "PYSEC-001"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].cwe == "CWE-95"


def test_detects_shell_true(tmp_path: Path) -> None:
    write_source(tmp_path, "subprocess.run(command, shell=True)\n")
    findings = PythonSecurityScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "PYSEC-002"
    assert findings[0].cwe == "CWE-78"


def test_ignores_safe_subprocess_call(tmp_path: Path) -> None:
    write_source(tmp_path, "subprocess.run([\"git\", \"status\"], check=True)\n")
    findings = PythonSecurityScanner().scan(tmp_path)
    assert findings == []


def test_skips_invalid_python(tmp_path: Path) -> None:
    write_source(tmp_path, "def broken(:\n")
    findings = PythonSecurityScanner().scan(tmp_path)
    assert findings == []

from pathlib import Path

from appsec.models import Severity
from appsec.scanners.secrets import SecretScanner


def write_source(tmp_path: Path, name: str, source: str) -> None:
    (tmp_path / name).write_text(source, encoding="utf-8")


def test_detects_aws_access_key_and_redacts_evidence(tmp_path: Path) -> None:
    write_source(tmp_path, "config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = SecretScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-002"
    assert findings[0].severity is Severity.HIGH
    assert "AKIAIOSFODNN7EXAMPLE" not in (findings[0].evidence or "")


def test_detects_private_key_header(tmp_path: Path) -> None:
    write_source(tmp_path, "key.pem", "-----BEGIN RSA PRIVATE KEY-----\n")
    findings = SecretScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-001"
    assert findings[0].severity is Severity.CRITICAL


def test_detects_github_token_without_exposing_it(tmp_path: Path) -> None:
    token = "ghp_" + "A" * 36
    write_source(tmp_path, "settings.py", f'TOKEN = "{token}"\n')
    findings = SecretScanner().scan(tmp_path)
    assert any(f.rule_id == "SEC-003" for f in findings)
    assert all(token not in (f.evidence or "") for f in findings)


def test_detects_generic_hardcoded_password(tmp_path: Path) -> None:
    write_source(tmp_path, "settings.py", 'password = "production-secret-123"\n')
    findings = SecretScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-005"
    assert "production-secret-123" not in (findings[0].evidence or "")


def test_ignores_common_placeholder(tmp_path: Path) -> None:
    write_source(tmp_path, "config.py", 'API_KEY = "your-api-key"\n')
    findings = SecretScanner().scan(tmp_path)
    assert findings == []

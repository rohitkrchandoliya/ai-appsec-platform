from pathlib import Path

import pytest
from pydantic import ValidationError

from appsec.models import Finding, Severity


def test_finding_accepts_valid_security_finding() -> None:
    finding = Finding(
        rule_id="TEST-001",
        title="Example finding",
        severity=Severity.HIGH,
        message="Unsafe operation detected.",
        path=Path("example.py"),
        line=12,
        cwe="CWE-89",
        confidence=0.95,
    )

    assert finding.severity is Severity.HIGH
    assert finding.line == 12
    assert finding.confidence == 0.95


def test_finding_rejects_invalid_line() -> None:
    with pytest.raises(ValidationError):
        Finding(
            rule_id="TEST-001",
            title="Example",
            severity=Severity.LOW,
            message="Invalid location.",
            path=Path("example.py"),
            line=0,
        )


def test_finding_rejects_invalid_confidence() -> None:
    with pytest.raises(ValidationError):
        Finding(
            rule_id="TEST-001",
            title="Example",
            severity=Severity.LOW,
            message="Invalid confidence.",
            path=Path("example.py"),
            line=1,
            confidence=1.5,
        )

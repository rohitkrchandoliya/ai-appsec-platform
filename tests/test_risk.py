from pathlib import Path

from appsec.models import Dependency, Finding, Severity
from appsec.risk import dependency_risk_score


def test_unpinned_dependency_gets_low_risk_without_advisory(tmp_path: Path) -> None:
    dependency = Dependency(name="flask", specifier=">=3.0", source=str(tmp_path / "pyproject.toml"))
    score, severity, rationale = dependency_risk_score(dependency, [])

    assert score == 10
    assert severity == Severity.LOW
    assert "not exact-pinned" in rationale


def test_high_advisory_drives_high_risk(tmp_path: Path) -> None:
    dependency = Dependency(
        name="requests", specifier="==2.32.0", source=str(tmp_path / "uv.lock")
    )
    finding = Finding(
        rule_id="DEP-PYSEC-TEST",
        title="Known issue",
        severity=Severity.HIGH,
        message="requests==2.32.0 is affected by DEP-PYSEC-TEST.",
        path=Path("uv.lock"),
        line=1,
    )

    score, severity, rationale = dependency_risk_score(dependency, [finding])

    assert score == 60
    assert severity == Severity.HIGH
    assert "1 known advisory finding" in rationale


def test_critical_multiple_advisories_are_capped() -> None:
    dependency = Dependency(name="demo", specifier="==1.0.0", source="uv.lock")
    findings = [
        Finding(
            rule_id=f"DEP-TEST-{index}",
            title="Known issue",
            severity=Severity.CRITICAL,
            message=f"demo==1.0.0 is affected by TEST-{index}.",
            path=Path("uv.lock"),
            line=1,
        )
        for index in range(1, 4)
    ]

    score, severity, _ = dependency_risk_score(dependency, findings)

    assert score == 100
    assert severity == Severity.CRITICAL

from pathlib import Path

from appsec.findings import normalize_findings
from appsec.models import Finding, Severity


def make_finding(path: Path, line: int = 1, column: int = 1) -> Finding:
    return Finding(
        rule_id="TEST-001",
        title="Test finding",
        severity=Severity.MEDIUM,
        message="Test message",
        path=path,
        line=line,
        column=column,
    )


def test_normalizes_paths_and_deduplicates() -> None:
    root = Path("/repo")
    first = make_finding(root / "src" / "app.js")
    duplicate = make_finding(root / "src" / "app.js")
    other = make_finding(root / "src" / "other.js", line=4)

    result = normalize_findings([duplicate, first, other], root)

    assert len(result) == 2
    assert result[0].path == Path("src/app.js")
    assert result[1].path == Path("src/other.js")

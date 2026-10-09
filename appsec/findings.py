"""Finding normalization and deterministic deduplication."""

from pathlib import Path

from appsec.models import Finding


def normalize_findings(findings: list[Finding], root: Path) -> list[Finding]:
    """Return stable, root-relative, duplicate-free findings."""
    normalized: list[Finding] = []
    seen: set[tuple[str, str, int, int | None]] = set()
    root = root.resolve()

    for finding in findings:
        path = finding.path.resolve()
        try:
            relative = path.relative_to(root)
        except ValueError:
            relative = path

        normalized_finding = finding.model_copy(update={"path": relative})
        key = (
            normalized_finding.rule_id,
            normalized_finding.path.as_posix(),
            normalized_finding.line,
            normalized_finding.column,
        )
        if key not in seen:
            seen.add(key)
            normalized.append(normalized_finding)

    return sorted(
        normalized,
        key=lambda finding: (
            finding.path.as_posix(),
            finding.line,
            finding.column or 0,
            finding.rule_id,
        ),
    )

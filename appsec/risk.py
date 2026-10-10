"""Deterministic dependency risk scoring."""

from appsec.models import Dependency, Finding, Severity


_SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 15,
    Severity.MEDIUM: 35,
    Severity.HIGH: 60,
    Severity.CRITICAL: 85,
}


def dependency_risk_score(
    dependency: Dependency,
    findings: list[Finding],
) -> tuple[int, Severity, str]:
    """Score one dependency from 0-100 using deterministic local evidence."""
    related = [
        finding
        for finding in findings
        if finding.rule_id.startswith("DEP-")
        and dependency.name.casefold() in finding.message.casefold()
    ]
    score = 0
    reasons: list[str] = []

    if dependency.specifier.strip().startswith("=="):
        reasons.append("exact version pinned")
    else:
        score += 10
        reasons.append("version is not exact-pinned")

    if related:
        highest = max((_SEVERITY_WEIGHT[f.severity] for f in related), default=0)
        score += highest
        if len(related) > 1:
            score += min(15, (len(related) - 1) * 5)
        reasons.append(f"{len(related)} known advisory finding(s)")
    else:
        reasons.append("no known advisory findings")

    score = min(score, 100)
    if score >= 85:
        severity = Severity.CRITICAL
    elif score >= 60:
        severity = Severity.HIGH
    elif score >= 35:
        severity = Severity.MEDIUM
    elif score >= 15:
        severity = Severity.LOW
    else:
        severity = Severity.INFO

    return score, severity, "; ".join(reasons)

"""SARIF 2.1.0 serialization for normalized scanner findings."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from appsec.models import Finding, ScanResult, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _fingerprint(finding: Finding) -> str:
    """Build a deterministic fingerprint from stable finding identity fields."""
    identity = "|".join(
        (
            finding.rule_id,
            finding.path.as_posix(),
            str(finding.line),
            str(finding.column or 1),
            finding.title,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _rule_descriptor(finding: Finding) -> dict[str, Any]:
    properties: dict[str, str] = {}
    if finding.cwe:
        properties["cwe"] = finding.cwe
    if finding.owasp:
        properties["owasp"] = finding.owasp
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "defaultConfiguration": {"level": _SEVERITY_LEVELS[finding.severity]},
        "properties": properties,
    }


def finding_to_sarif_result(finding: Finding) -> dict[str, Any]:
    """Convert one finding to a SARIF result without exporting source evidence."""
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": Path(finding.path).as_posix()},
            "region": {
                "startLine": finding.line,
                "startColumn": finding.column or 1,
            },
        }
    }
    properties: dict[str, str | float] = {"confidence": finding.confidence}
    if finding.cwe:
        properties["cwe"] = finding.cwe
    if finding.owasp:
        properties["owasp"] = finding.owasp

    return {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_LEVELS[finding.severity],
        "message": {"text": f"{finding.title}: {finding.message}"},
        "locations": [location],
        "partialFingerprints": {"primaryLocationLineHash": _fingerprint(finding)},
        "properties": properties,
    }


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a scan result into a deterministic SARIF 2.1.0 document."""
    findings = sorted(
        result.findings,
        key=lambda item: (
            item.path.as_posix(),
            item.line,
            item.column or 0,
            item.rule_id,
        ),
    )
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rules_by_id.setdefault(finding.rule_id, _rule_descriptor(finding))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "AI AppSec Platform",
                "informationUri": "https://github.com/rohitkrchandoliya/ai-appsec-platform",
                "rules": [rules_by_id[key] for key in sorted(rules_by_id)],
            }
        },
        "results": [finding_to_sarif_result(finding) for finding in findings],
        "properties": {
            "filesScanned": result.files_scanned,
            "rulesRun": result.rules_run,
        },
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def sarif_json(result: ScanResult) -> str:
    """Serialize scan results to stable, pretty-printed SARIF JSON."""
    import json

    return json.dumps(to_sarif(result), indent=2, sort_keys=True)

"""Known-vulnerability lookups for exact Python dependency versions."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from appsec.models import Dependency, Finding, Severity

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def query_osv(name: str, version: str, timeout: float = 10.0) -> list[dict[str, Any]]:
    """Query OSV for vulnerabilities affecting one exact PyPI package version."""
    payload = json.dumps(
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    ).encode("utf-8")
    request = Request(
        OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"OSV query failed for {name}=={version}: {exc}") from exc

    if not isinstance(data, dict):
        return []
    vulnerabilities = data.get("vulns", [])
    if not isinstance(vulnerabilities, list):
        return []
    return [item for item in vulnerabilities if isinstance(item, dict)]


def _severity(vulnerability: dict[str, Any]) -> Severity:
    candidates: list[Any] = [vulnerability.get("database_specific", {}).get("severity")]
    affected = vulnerability.get("affected", [])
    if isinstance(affected, list):
        for entry in affected:
            if isinstance(entry, dict):
                for key in ("database_specific", "ecosystem_specific"):
                    specific = entry.get(key, {})
                    if isinstance(specific, dict):
                        candidates.append(specific.get("severity"))
    for candidate in candidates:
        if isinstance(candidate, str):
            normalized = candidate.upper()
            if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                return Severity(normalized.lower())
    # OSV does not guarantee a severity score for every advisory.
    return Severity.MEDIUM


def audit_dependencies(
    dependencies: list[Dependency],
    root: Path,
    query: Callable[[str, str], list[dict[str, Any]]] = query_osv,
) -> list[Finding]:
    """Return OSV findings for exact-pinned Python dependencies only."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for dependency in dependencies:
        specifier = dependency.specifier.strip()
        if not specifier.startswith("=="):
            continue
        version = specifier[2:].strip()
        if not version or "," in version or " " in version:
            continue
        key = (dependency.name.casefold(), version)
        if key in seen:
            continue
        seen.add(key)
        for vulnerability in query(dependency.name, version):
            advisory_id = vulnerability.get("id")
            if not isinstance(advisory_id, str) or not advisory_id:
                continue
            summary = vulnerability.get("summary")
            if not isinstance(summary, str) or not summary.strip():
                summary = f"Known vulnerability in {dependency.name} {version}"
            source = Path(dependency.source)
            try:
                source = source.resolve().relative_to(root.resolve())
            except (OSError, ValueError):
                source = Path(dependency.source)
            findings.append(
                Finding(
                    rule_id=f"DEP-{advisory_id}",
                    title=summary.strip(),
                    severity=_severity(vulnerability),
                    message=f"{dependency.name}=={version} is affected by {advisory_id}.",
                    path=source,
                    line=1,
                    evidence=f"{dependency.name}=={version}",
                    confidence=1.0,
                )
            )
    return findings

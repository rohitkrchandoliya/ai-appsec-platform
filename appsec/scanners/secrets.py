"""High-confidence secret detection for source repositories."""

import re
from pathlib import Path
from typing import ClassVar

from appsec.models import Finding, Severity
from appsec.scanners.base import Scanner


class SecretScanner(Scanner):
    """Detect common credential formats while redacting secret material."""

    name = "secrets"

    _PATTERNS: ClassVar = (
        ("SEC-001", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", Severity.CRITICAL, "Private key material detected", "CWE-321"),
        ("SEC-002", r"\bAKIA[0-9A-Z]{16}\b", Severity.HIGH, "AWS access key ID detected", "CWE-798"),
        ("SEC-003", r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b", Severity.HIGH, "GitHub personal access token detected", "CWE-798"),
        ("SEC-004", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", Severity.HIGH, "Slack token detected", "CWE-798"),
    )
    _ASSIGNMENT: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?ix)\b(?P<name>api[_-]?key|secret|password|passwd|token|access[_-]?token)\s*[:=]\s*(?P<quote>["'])(?P<value>[^"']{8,})(?P=quote)"""
    )
    _PLACEHOLDERS: ClassVar = {
        "changeme", "change-me", "example", "example-key", "your-api-key",
        "your_api_key", "your-password", "your_password", "placeholder",
        "test-token", "test_token",
    }
    _EXTENSIONS: ClassVar = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".rb",
        ".php", ".cs", ".cpp", ".c", ".h", ".yaml", ".yml", ".json", ".toml",
        ".ini", ".cfg", ".conf", ".env", ".txt", ".md",
    }

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in self._EXTENSIONS:
                continue
            if any(part in {".git", ".venv", "venv", "__pycache__", "node_modules"} for part in path.parts):
                continue
            findings.extend(self._scan_file(path))
        return findings

    def _scan_file(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            return []

        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for rule_id, pattern, severity, title, cwe in self._PATTERNS:
                match = re.search(pattern, line)
                if match:
                    findings.append(self._finding(rule_id, title, severity, cwe, path, line_number, line, match))
            assignment = self._ASSIGNMENT.search(line)
            if assignment and assignment.group("value").strip().lower() not in self._PLACEHOLDERS:
                findings.append(self._finding("SEC-005", "Hardcoded credential assignment detected", Severity.HIGH, "CWE-798", path, line_number, line, assignment))
        return findings

    @staticmethod
    def _finding(
        rule_id: str,
        title: str,
        severity: Severity,
        cwe: str,
        path: Path,
        line_number: int,
        line: str,
        match: re.Match[str],
    ) -> Finding:
        start, end = match.span()
        if rule_id == "SEC-005":
            evidence = f"{line[:start].rstrip()}=***REDACTED***"
        else:
            evidence = f"{line[:start]}***REDACTED***{line[end:]}"
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            message="Credential material should not be committed to source control. Rotate exposed credentials and move them to a secure secret store.",
            path=path,
            line=line_number,
            cwe=cwe,
            owasp="A07:2021-Identification and Authentication Failures",
            evidence=evidence[:500],
            confidence=0.99,
        )

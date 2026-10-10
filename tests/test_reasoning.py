"""Tests for evidence-grounded reasoning contracts."""

from pathlib import Path

import pytest

from appsec.models import Finding, Severity
from appsec.reasoning import (
    GuardedReasoningProvider,
    ReasoningRequest,
    ReasoningResponse,
    build_reasoning_request,
)


def _finding() -> Finding:
    return Finding(
        rule_id="PY-001",
        title="Dynamic execution",
        severity=Severity.HIGH,
        message="eval() executes dynamically supplied code.",
        path=Path("app.py"),
        line=10,
        cwe="CWE-95",
        evidence="eval(user_input)",
    )


class FakeProvider:
    def __init__(self, response: ReasoningResponse) -> None:
        self.response = response

    def explain(self, request: ReasoningRequest) -> ReasoningResponse:
        return self.response


def test_build_request_is_bounded_to_explicit_context() -> None:
    request = build_reasoning_request(
        _finding(),
        source_context=["eval(user_input)"],
        references=["CWE-95"],
    )

    assert request.finding.rule_id == "PY-001"
    assert request.source_context == ["eval(user_input)"]
    assert request.references == ["CWE-95"]


def test_guard_rejects_different_finding() -> None:
    response = ReasoningResponse(
        finding_rule_id="SEC-999",
        explanation="Explanation.",
        exploitability="High.",
        remediation="Remove the unsafe call.",
        confidence=0.9,
    )

    with pytest.raises(ValueError, match="different finding"):
        GuardedReasoningProvider(FakeProvider(response)).explain(
            build_reasoning_request(_finding())
        )


def test_guard_rejects_unsupplied_reference() -> None:
    response = ReasoningResponse(
        finding_rule_id="PY-001",
        explanation="Explanation.",
        exploitability="High.",
        remediation="Remove the unsafe call.",
        references=["CWE-999"],
        confidence=0.9,
    )

    with pytest.raises(ValueError, match="not supplied"):
        GuardedReasoningProvider(FakeProvider(response)).explain(
            build_reasoning_request(_finding(), references=["CWE-95"])
        )


def test_guard_rejects_hallucinated_cve() -> None:
    response = ReasoningResponse(
        finding_rule_id="PY-001",
        explanation="This maps to CVE-2026-12345.",
        exploitability="High.",
        remediation="Remove the unsafe call.",
        confidence=0.9,
    )

    with pytest.raises(ValueError, match="unsupported security identifier"):
        GuardedReasoningProvider(FakeProvider(response)).explain(
            build_reasoning_request(_finding())
        )


def test_guard_accepts_supplied_security_context() -> None:
    response = ReasoningResponse(
        finding_rule_id="PY-001",
        explanation="The finding is consistent with CWE-95.",
        exploitability="An attacker may influence the executed expression.",
        remediation="Avoid dynamic evaluation of untrusted input.",
        references=["CWE-95"],
        confidence=0.9,
        limitations=["Exploitability depends on whether input is attacker-controlled."],
    )

    result = GuardedReasoningProvider(FakeProvider(response)).explain(
        build_reasoning_request(_finding(), references=["CWE-95"])
    )

    assert result.finding_rule_id == "PY-001"

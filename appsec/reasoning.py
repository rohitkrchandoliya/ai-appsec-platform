"""Provider-neutral, evidence-grounded AI security reasoning contracts."""

from __future__ import annotations

import re
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from appsec.models import Finding


_SECURITY_IDENTIFIER = re.compile(r"\\b(?:CVE-\\d{4}-\\d{4,}|CWE-\\d+)\\b", re.IGNORECASE)


class ReasoningRequest(BaseModel):
    """Bounded evidence supplied to a reasoning provider."""

    model_config = ConfigDict(extra="forbid")

    finding: Finding
    source_context: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class ReasoningResponse(BaseModel):
    """Structured reasoning that can be safely attached to a finding."""

    model_config = ConfigDict(extra="forbid")

    finding_rule_id: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    exploitability: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)


class ReasoningProvider(Protocol):
    """Provider interface implemented by an AI reasoning backend."""

    def explain(self, request: ReasoningRequest) -> ReasoningResponse:
        """Explain one finding using only the supplied request evidence."""
        ...


def build_reasoning_request(
    finding: Finding,
    *,
    source_context: list[str] | None = None,
    references: list[str] | None = None,
) -> ReasoningRequest:
    """Create a bounded reasoning request without adding repository data implicitly."""
    return ReasoningRequest(
        finding=finding,
        source_context=list(source_context or []),
        references=list(references or []),
    )


def validate_reasoning_response(
    request: ReasoningRequest,
    response: ReasoningResponse,
) -> ReasoningResponse:
    """Reject responses that cross the evidence boundary or change finding identity."""
    if response.finding_rule_id != request.finding.rule_id:
        raise ValueError("Reasoning response targets a different finding.")

    allowed_references = set(request.references)
    unknown_references = set(response.references) - allowed_references
    if unknown_references:
        raise ValueError("Reasoning response contains references not supplied as evidence.")

    allowed_identifiers = {request.finding.rule_id}
    if request.finding.cwe:
        allowed_identifiers.add(request.finding.cwe.upper())
    if request.finding.owasp:
        allowed_identifiers.add(request.finding.owasp.upper())

    generated_text = " ".join(
        [
            response.explanation,
            response.exploitability,
            response.remediation,
            *response.limitations,
        ]
    )
    for identifier in _SECURITY_IDENTIFIER.findall(generated_text):
        if identifier.upper() not in allowed_identifiers:
            raise ValueError(
                f"Reasoning response contains unsupported security identifier: {identifier}"
            )

    return response


class GuardedReasoningProvider:
    """Adapter that enforces the evidence boundary around an AI provider."""

    def __init__(self, provider: ReasoningProvider) -> None:
        self._provider = provider

    def explain(self, request: ReasoningRequest) -> ReasoningResponse:
        """Call the provider and validate its structured response."""
        response = self._provider.explain(request)
        return validate_reasoning_response(request, response)

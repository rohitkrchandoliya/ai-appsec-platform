"""Core security finding domain models."""

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Normalized severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A scanner-produced security finding."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    message: str = Field(min_length=1)
    path: Path
    line: int = Field(ge=1)
    column: int | None = Field(default=None, ge=1)
    cwe: str | None = None
    owasp: str | None = None
    evidence: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class ScanResult(BaseModel):
    """Result of scanning a source tree."""

    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = Field(default=0, ge=0)
    rules_run: int = Field(default=0, ge=0)

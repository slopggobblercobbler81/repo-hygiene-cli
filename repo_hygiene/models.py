"""Data models and enums for git repository security hygiene auditing."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    """Risk severity level of an audit finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Categorization of audit checks."""
    SENSITIVE_FILE_HISTORY = "sensitive_file_history"
    GITIGNORE_MISSING = "gitignore_missing"
    GIT_CONFIG_RISK = "git_config_risk"
    SECRET_IN_DIFF = "secret_in_diff"
    REPO_STRUCTURE = "repo_structure"


class Finding(BaseModel):
    """A specific security hygiene finding or violation."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str
    title: str
    category: Category
    severity: Severity
    description: str
    remediation: str
    commit_hash: Optional[str] = None
    file_path: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None


class AuditScore(BaseModel):
    """Aggregated numerical score and letter grade."""
    score: int = 100
    grade: str = "A+"
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    @classmethod
    def calculate(cls, findings: List[Finding]) -> AuditScore:
        """Calculate score out of 100 with deduction penalties."""
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        info = sum(1 for f in findings if f.severity == Severity.INFO)

        # Deductions
        deductions = (crit * 30) + (high * 15) + (med * 5) + (low * 2)
        score = max(0, 100 - deductions)

        # Assign letter grade
        if score >= 95:
            grade = "A+"
        elif score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return cls(
            score=score,
            grade=grade,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
        )


class HygieneReport(BaseModel):
    """Full repository audit report."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    repo_path: Path
    branch: str = "main"
    commit_count: int = 0
    findings: List[Finding] = Field(default_factory=list)
    detected_stacks: List[str] = Field(default_factory=list)
    score: AuditScore = Field(default_factory=AuditScore)
    elapsed_seconds: float = 0.0

    @property
    def has_critical_or_high(self) -> bool:
        """True if any critical or high severity findings exist."""
        return self.score.critical_count > 0 or self.score.high_count > 0

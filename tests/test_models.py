"""Tests for data models and scoring algorithms."""

from pathlib import Path
from repo_hygiene.models import (
    AuditScore,
    Category,
    Finding,
    HygieneReport,
    Severity,
)


def test_audit_score_perfect():
    findings = []
    score = AuditScore.calculate(findings)
    assert score.score == 100
    assert score.grade == "A+"
    assert score.critical_count == 0


def test_audit_score_deductions():
    f1 = Finding(
        id="F1",
        title="Critical issue",
        category=Category.SENSITIVE_FILE_HISTORY,
        severity=Severity.CRITICAL,
        description="desc",
        remediation="fix",
    )
    f2 = Finding(
        id="F2",
        title="High issue",
        category=Category.GITIGNORE_MISSING,
        severity=Severity.HIGH,
        description="desc",
        remediation="fix",
    )
    f3 = Finding(
        id="F3",
        title="Medium issue",
        category=Category.GIT_CONFIG_RISK,
        severity=Severity.MEDIUM,
        description="desc",
        remediation="fix",
    )

    # 100 - (30 + 15 + 5) = 50 -> Grade F
    score = AuditScore.calculate([f1, f2, f3])
    assert score.score == 50
    assert score.grade == "F"
    assert score.critical_count == 1
    assert score.high_count == 1
    assert score.medium_count == 1


def test_audit_score_grades():
    # 100 - 2 (low) = 98 -> A+
    f_low = Finding(id="L", title="t", category=Category.REPO_STRUCTURE, severity=Severity.LOW, description="d", remediation="r")
    assert AuditScore.calculate([f_low]).grade == "A+"

    # 100 - 15 (high) = 85 -> B
    f_high = Finding(id="H", title="t", category=Category.REPO_STRUCTURE, severity=Severity.HIGH, description="d", remediation="r")
    assert AuditScore.calculate([f_high]).grade == "B"


def test_hygiene_report_properties(tmp_path: Path):
    f_crit = Finding(id="C", title="t", category=Category.REPO_STRUCTURE, severity=Severity.CRITICAL, description="d", remediation="r")
    score = AuditScore.calculate([f_crit])

    report = HygieneReport(
        repo_path=tmp_path,
        branch="main",
        commit_count=42,
        findings=[f_crit],
        score=score,
    )

    assert report.has_critical_or_high is True
    assert report.score.critical_count == 1

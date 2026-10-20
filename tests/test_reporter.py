"""Tests for reporter module (Console, JSON, Markdown, and GitHub annotations)."""

import json
from pathlib import Path
from rich.console import Console

from repo_hygiene.models import (
    AuditScore,
    Category,
    Finding,
    HygieneReport,
    Severity,
)
from repo_hygiene.reporter import Reporter


def make_dummy_report(tmp_path: Path) -> HygieneReport:
    f1 = Finding(
        id="HISTORY_SENSITIVE_FILE_CRITICAL",
        title="Sensitive file committed: id_rsa",
        category=Category.SENSITIVE_FILE_HISTORY,
        severity=Severity.CRITICAL,
        description="SSH private key found in history",
        remediation="Rotate SSH key immediately",
        commit_hash="abc1234567890",
        file_path="id_rsa",
    )
    f2 = Finding(
        id="GITIGNORE_MISSING",
        title="Missing .gitignore",
        category=Category.GITIGNORE_MISSING,
        severity=Severity.HIGH,
        description="No .gitignore",
        remediation="Create .gitignore",
    )

    score = AuditScore.calculate([f1, f2])
    return HygieneReport(
        repo_path=tmp_path,
        branch="main",
        commit_count=10,
        findings=[f1, f2],
        detected_stacks=["python"],
        score=score,
        elapsed_seconds=0.045,
    )


def test_reporter_json(tmp_path: Path):
    report = make_dummy_report(tmp_path)
    reporter = Reporter()
    json_str = reporter.to_json(report)
    data = json.loads(json_str)

    assert data["branch"] == "main"
    assert data["commit_count"] == 10
    assert data["score"]["critical"] == 1
    assert data["score"]["high"] == 1
    assert len(data["findings"]) == 2


def test_reporter_markdown(tmp_path: Path):
    report = make_dummy_report(tmp_path)
    reporter = Reporter()
    md = reporter.to_markdown(report)

    assert "# 🛡️ Git Repository Hygiene Audit Report" in md
    assert "**Critical**: 1" in md
    assert "**High**: 1" in md
    assert "Sensitive file committed: id_rsa" in md


def test_reporter_console(tmp_path: Path):
    report = make_dummy_report(tmp_path)
    con = Console(record=True, width=120)
    reporter = Reporter(console=con)
    reporter.print_console(report)
    out = con.export_text()

    assert "Git Repository Security & Hygiene Audit" in out
    assert "CRITICAL" in out
    assert "id_rsa" in out


def test_reporter_github_annotations(tmp_path: Path, capsys):
    report = make_dummy_report(tmp_path)
    reporter = Reporter()
    reporter.print_github_annotations(report)
    captured = capsys.readouterr()

    assert "::error file=id_rsa::" in captured.out
    assert "Sensitive file committed: id_rsa" in captured.out

"""Tests for RepoAuditor functionality."""

import subprocess
from pathlib import Path
from repo_hygiene.auditor import RepoAuditor
from repo_hygiene.models import Category, Severity


def test_detect_tech_stacks(tmp_path: Path):
    # Setup files indicating python and node
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")

    auditor = RepoAuditor(tmp_path)
    stacks = auditor.detect_tech_stacks()

    assert "python" in stacks
    assert "node" in stacks
    assert "rust" not in stacks


def test_audit_repo_structure_missing_readme_and_license(tmp_path: Path):
    auditor = RepoAuditor(tmp_path)
    findings = auditor.audit_repo_structure()

    ids = [f.id for f in findings]
    assert "STRUCTURE_MISSING_README" in ids
    assert "STRUCTURE_MISSING_LICENSE" in ids


def test_audit_repo_structure_present(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Test", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT", encoding="utf-8")

    auditor = RepoAuditor(tmp_path)
    findings = auditor.audit_repo_structure()
    assert len(findings) == 0


def test_audit_gitignore_missing(tmp_path: Path):
    auditor = RepoAuditor(tmp_path)
    findings = auditor.audit_gitignore(["python"])

    assert len(findings) == 1
    assert findings[0].id == "GITIGNORE_MISSING"
    assert findings[0].severity == Severity.HIGH


def test_audit_gitignore_incomplete_and_fix(tmp_path: Path):
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("# My Ignore\n*.log\n", encoding="utf-8")

    auditor = RepoAuditor(tmp_path)
    findings = auditor.audit_gitignore(["python"])
    assert len(findings) == 1
    assert findings[0].id == "GITIGNORE_INCOMPLETE"

    # Fix gitignore
    added_count = auditor.fix_gitignore(["python"])
    assert added_count > 0

    # Re-audit should now have no missing python or general rules
    findings_after = auditor.audit_gitignore(["python"])
    assert len(findings_after) == 0

    # Idempotent second fix should add 0
    assert auditor.fix_gitignore(["python"]) == 0


def test_audit_in_actual_git_repo(tmp_path: Path):
    # Initialize a test git repository
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), capture_output=True, check=True)

    # Commit a clean file
    (tmp_path / "README.md").write_text("# Clean Readme", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT License", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".env\n*.pem\n*.key\n.DS_Store\nThumbs.db\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(tmp_path), capture_output=True, check=True)

    # Now commit a sensitive file: .env
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://...", encoding="utf-8")
    subprocess.run(["git", "add", "-f", ".env"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "Oops committed env"], cwd=str(tmp_path), capture_output=True, check=True)

    auditor = RepoAuditor(tmp_path)
    report = auditor.audit_all()

    # Verify sensitive file in history was detected
    history_findings = [f for f in report.findings if f.category == Category.SENSITIVE_FILE_HISTORY]
    assert len(history_findings) >= 1
    assert any(".env" in f.file_path for f in history_findings)
    assert report.score.critical_count > 0 or report.score.high_count > 0

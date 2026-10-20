"""Tests for repo-hygiene CLI commands."""

import json
from pathlib import Path
from click.testing import CliRunner
from repo_hygiene.cli import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "repo-hygiene" in result.output
    assert "0.1.0" in result.output


def test_cli_list_rules():
    runner = CliRunner()
    result = runner.invoke(cli, ["list-rules"])
    assert result.exit_code == 0
    assert "Sensitive File Patterns Audited" in result.output
    assert "Secret Patterns Audited" in result.output
    assert "Recommended .gitignore Rule Sets" in result.output


def test_cli_audit_json_output(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Hello", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["audit", str(tmp_path), "--format", "json", "--fail-on", "never"])
    assert result.exit_code == 0

    data = json.loads(result.output)
    assert "score" in data
    assert "findings" in data
    assert "repository" in data


def test_cli_audit_file_output(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Hello", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT", encoding="utf-8")
    out_file = tmp_path / "audit.json"

    runner = CliRunner()
    result = runner.invoke(cli, ["audit", str(tmp_path), "--format", "json", "--output", str(out_file), "--fail-on", "never"])
    assert result.exit_code == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert "score" in content


def test_cli_fix_gitignore(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]", encoding="utf-8")
    runner = CliRunner()

    # Dry-run
    res_dry = runner.invoke(cli, ["fix-gitignore", str(tmp_path), "--dry-run"])
    assert res_dry.exit_code == 0

    # Apply fix
    res_apply = runner.invoke(cli, ["fix-gitignore", str(tmp_path)])
    assert res_apply.exit_code == 0
    assert "Successfully added" in res_apply.output
    assert (tmp_path / ".gitignore").exists()


def test_cli_audit_fail_under(tmp_path: Path):
    # Repo with missing README, LICENSE, gitignore -> low score
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", str(tmp_path), "--fail-under", "99"])
    assert result.exit_code == 1

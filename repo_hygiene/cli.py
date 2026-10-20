"""Command Line Interface for Repo Hygiene CLI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from . import __version__
from .auditor import RepoAuditor
from .models import Severity
from .reporter import Reporter
from .rules import (
    RECOMMENDED_GITIGNORE_RULES,
    SECRET_CONTENT_PATTERNS,
    SENSITIVE_FILE_PATTERNS,
)


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="repo-hygiene")
def cli():
    """Repo Hygiene: Fast git repository security and hygiene auditor."""
    pass


@cli.command("audit")
@click.argument("repo_path", required=False, type=click.Path(exists=True, file_okay=False))
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["console", "json", "markdown", "github"], case_sensitive=False),
    default="console",
    help="Output report format.",
)
@click.option("--output", "-o", type=click.Path(dir_okay=False), help="Save report output to file.")
@click.option("--fail-under", type=int, default=0, help="Fail if security score is below threshold (0-100).")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "any", "never"], case_sensitive=False),
    default="high",
    help="Exit code failure threshold based on finding severity (default: high).",
)
def audit_command(
    repo_path: Optional[str],
    output_format: str,
    output: Optional[str],
    fail_under: int,
    fail_on: str,
):
    """Audit a repository for security hygiene, sensitive history, and configuration safety."""
    target_dir = Path(repo_path).resolve() if repo_path else Path.cwd()

    auditor = RepoAuditor(target_dir)
    report = auditor.audit_all()
    reporter = Reporter(console=console)

    fmt = output_format.lower()
    report_content = ""

    if fmt == "console":
        reporter.print_console(report)
    elif fmt == "json":
        report_content = reporter.to_json(report)
    elif fmt == "markdown":
        report_content = reporter.to_markdown(report)
    elif fmt == "github":
        reporter.print_github_annotations(report)
        reporter.print_console(report)

    if report_content:
        if output:
            Path(output).write_text(report_content, encoding="utf-8")
            console.print(f"[dim]Report saved to {output}[/]")
        elif fmt != "console" and fmt != "github":
            print(report_content)

    # Exit code determination
    exit_code = 0
    if fail_under > 0 and report.score.score < fail_under:
        exit_code = 1

    fail_threshold = fail_on.lower()
    if fail_threshold == "never":
        exit_code = 0
    elif fail_threshold == "critical":
        if report.score.critical_count > 0:
            exit_code = 1
    elif fail_threshold == "high":
        if report.score.critical_count > 0 or report.score.high_count > 0:
            exit_code = 1
    elif fail_threshold == "medium":
        if report.score.critical_count > 0 or report.score.high_count > 0 or report.score.medium_count > 0:
            exit_code = 1
    elif fail_threshold == "any":
        if report.findings:
            exit_code = 1

    sys.exit(exit_code)


@cli.command("fix-gitignore")
@click.argument("repo_path", required=False, type=click.Path(exists=True, file_okay=False))
@click.option("--dry-run", is_flag=True, help="List missing rules without modifying .gitignore.")
def fix_gitignore_command(repo_path: Optional[str], dry_run: bool):
    """Automatically append recommended missing patterns to .gitignore."""
    target_dir = Path(repo_path).resolve() if repo_path else Path.cwd()
    auditor = RepoAuditor(target_dir)
    stacks = auditor.detect_tech_stacks()

    if dry_run:
        findings = auditor.audit_gitignore(stacks)
        if not findings:
            console.print("[green]No missing .gitignore rules detected.[/]")
        else:
            console.print(f"[yellow]{findings[0].description}[/]")
        return

    added = auditor.fix_gitignore(stacks)
    if added > 0:
        console.print(f"[bold green]Successfully added {added} recommended rules to .gitignore![/]")
    else:
        console.print("[green].gitignore is already up to date with recommended rules.[/]")


@cli.command("list-rules")
def list_rules_command():
    """Display all built-in security hygiene audit rules and patterns."""
    console.print("\n[bold cyan]=== Sensitive File Patterns Audited in Git History ===[/]")
    for pattern, sev, desc, _ in SENSITIVE_FILE_PATTERNS:
        console.print(f"  • [{sev.value.upper()}] {desc} [dim](Pattern: {pattern.pattern})[/]")

    console.print("\n[bold cyan]=== Secret Patterns Audited in Commit Diffs ===[/]")
    for pattern, sev, desc in SECRET_CONTENT_PATTERNS:
        console.print(f"  • [{sev.value.upper()}] {desc}")

    console.print("\n[bold cyan]=== Recommended .gitignore Rule Sets ===[/]")
    for stack, rules in RECOMMENDED_GITIGNORE_RULES.items():
        console.print(f"  • [bold]{stack.capitalize()}[/]: {', '.join(rules[:5])}...")
    console.print()


if __name__ == "__main__":
    cli()

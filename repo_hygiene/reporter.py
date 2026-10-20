"""Reporters for console, JSON, Markdown, and GitHub Actions output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import HygieneReport, Severity


class Reporter:
    """Formatter and exporter for hygiene audit reports."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_console(self, report: HygieneReport) -> None:
        """Print rich console report with score card and findings table."""
        score = report.score

        # Grade color styling
        grade_colors = {
            "A+": "bold green",
            "A": "bold green",
            "B": "bold cyan",
            "C": "bold yellow",
            "D": "bold magenta",
            "F": "bold red",
        }
        color = grade_colors.get(score.grade, "white")

        # Top summary card
        card_content = (
            f"[bold]Target Repository:[/] {report.repo_path.name}  |  "
            f"[bold]Branch:[/] {report.branch}  |  "
            f"[bold]Commits:[/] {report.commit_count}\n"
            f"[bold]Detected Tech Stacks:[/] {', '.join(report.detected_stacks) if report.detected_stacks else 'None detected'}\n"
            f"[bold]Security Score:[/] [{color}]{score.score}/100 (Grade: {score.grade})[/]  |  "
            f"[bold red]Critical:[/] {score.critical_count}  |  "
            f"[bold dark_orange]High:[/] {score.high_count}  |  "
            f"[bold yellow]Medium:[/] {score.medium_count}  |  "
            f"[bold blue]Low:[/] {score.low_count}"
        )

        panel = Panel(
            card_content,
            title="Git Repository Security & Hygiene Audit",
            border_style=color,
            expand=False,
        )
        self.console.print()
        self.console.print(panel)

        if not report.findings:
            self.console.print("\n[bold green]Excellent! No security hygiene violations found.[/]\n")
            return

        table = Table(
            title=f"Audit Findings ({len(report.findings)} items)",
            header_style="bold magenta",
            show_header=True,
            expand=True,
        )
        table.add_column("Sev", width=9, justify="center")
        table.add_column("Category", style="cyan", width=18)
        table.add_column("Title & Details", overflow="fold")
        table.add_column("Location", style="dim", width=16)
        table.add_column("Recommended Remediation", style="green", overflow="fold")

        sev_styles = {
            Severity.CRITICAL: "bold white on red",
            Severity.HIGH: "bold red",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold blue",
            Severity.INFO: "dim",
        }

        for f in report.findings:
            sev_badge = Text(f.severity.value.upper(), style=sev_styles.get(f.severity, "white"))
            loc = ""
            if f.commit_hash and f.file_path:
                loc = f"{f.commit_hash[:7]}:{f.file_path}"
            elif f.commit_hash:
                loc = f"Commit {f.commit_hash[:7]}"
            elif f.file_path:
                loc = f.file_path

            title_and_desc = f"[bold]{f.title}[/]\n[dim]{f.description}[/]"
            table.add_row(sev_badge, f.category.value, title_and_desc, loc, f.remediation)

        self.console.print()
        self.console.print(table)
        self.console.print()

    def to_json(self, report: HygieneReport, indent: int = 2) -> str:
        """Export audit report to JSON string."""
        data = {
            "repository": str(report.repo_path),
            "branch": report.branch,
            "commit_count": report.commit_count,
            "detected_stacks": report.detected_stacks,
            "score": {
                "score": report.score.score,
                "grade": report.score.grade,
                "critical": report.score.critical_count,
                "high": report.score.high_count,
                "medium": report.score.medium_count,
                "low": report.score.low_count,
                "info": report.score.info_count,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "description": f.description,
                    "remediation": f.remediation,
                    "commit_hash": f.commit_hash,
                    "file_path": f.file_path,
                    "author": f.author,
                    "date": f.date,
                }
                for f in report.findings
            ],
            "elapsed_seconds": round(report.elapsed_seconds, 3),
        }
        return json.dumps(data, indent=indent)

    def to_markdown(self, report: HygieneReport) -> str:
        """Export report in GitHub-flavored Markdown."""
        score = report.score
        lines = [
            "# 🛡️ Git Repository Hygiene Audit Report",
            "",
            "## Summary",
            "",
            f"- **Repository**: `{report.repo_path.name}`",
            f"- **Branch**: `{report.branch}`",
            f"- **Total Commits Audited**: `{report.commit_count}`",
            f"- **Security Hygiene Score**: **{score.score}/100** (Grade: **{score.grade}**)",
            f"- **Detected Stacks**: {', '.join(f'`{s}`' for s in report.detected_stacks) if report.detected_stacks else 'None'}",
            "",
            "### Finding Breakdown",
            "",
            f"- :rotating_light: **Critical**: {score.critical_count}",
            f"- :warning: **High**: {score.high_count}",
            f"- :zap: **Medium**: {score.medium_count}",
            f"- :information_source: **Low**: {score.low_count}",
            "",
        ]

        if not report.findings:
            lines.append("No security hygiene violations were detected. :tada:")
            return "\n".join(lines)

        lines.extend([
            "## Detailed Findings",
            "",
            "| Severity | Category | Title | Location | Remediation |",
            "| :---: | --- | --- | --- | --- |",
        ])

        for f in report.findings:
            loc = f"`{f.commit_hash[:7]}`" if f.commit_hash else (f"`{f.file_path}`" if f.file_path else "-")
            lines.append(
                f"| `{f.severity.value.upper()}` | `{f.category.value}` | **{f.title}**<br>{f.description} | {loc} | {f.remediation} |"
            )

        return "\n".join(lines)

    def print_github_annotations(self, report: HygieneReport) -> None:
        """Emit GitHub Actions workflow annotations."""
        for f in report.findings:
            file_arg = f" file={f.file_path}" if f.file_path else ""
            msg = f"{f.title}: {f.description} Remediation: {f.remediation}"
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                print(f"::error{file_arg}::{msg}")
            elif f.severity == Severity.MEDIUM:
                print(f"::warning{file_arg}::{msg}")
            else:
                print(f"::notice{file_arg}::{msg}")

"""Repository Auditor coordinating security and hygiene inspections."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List, Set

from .git_utils import (
    get_commit_count,
    get_current_branch,
    get_git_config,
    get_git_remotes,
    get_historical_added_files,
    get_recent_diff_patches,
    is_git_repo,
)
from .models import AuditScore, Category, Finding, HygieneReport, Severity
from .rules import (
    RECOMMENDED_GITIGNORE_RULES,
    SECRET_CONTENT_PATTERNS,
    SENSITIVE_FILE_PATTERNS,
    TECH_STACK_MARKERS,
)


class RepoAuditor:
    """Core auditor for scanning git repository hygiene."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path.resolve()

    def detect_tech_stacks(self) -> List[str]:
        """Detect tech stacks active in the repository based on project files."""
        stacks: List[str] = []
        for stack, markers in TECH_STACK_MARKERS.items():
            for marker in markers:
                if (self.repo_path / marker).exists():
                    stacks.append(stack)
                    break
        return sorted(stacks)

    def audit_gitignore(self, detected_stacks: List[str]) -> List[Finding]:
        """Audit presence and completeness of .gitignore."""
        findings: List[Finding] = []
        gitignore_path = self.repo_path / ".gitignore"

        if not gitignore_path.exists():
            findings.append(
                Finding(
                    id="GITIGNORE_MISSING",
                    title="Missing .gitignore file",
                    category=Category.GITIGNORE_MISSING,
                    severity=Severity.HIGH,
                    description="No .gitignore file found at the root of the repository.",
                    remediation="Create a .gitignore file with rules for your project stacks.",
                )
            )
            return findings

        # Read existing patterns
        try:
            content = gitignore_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = ""

        existing_lines = set()
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                existing_lines.add(line.rstrip("/"))

        # Determine rules to check
        rules_to_check: Set[str] = set(RECOMMENDED_GITIGNORE_RULES.get("general", []))
        for stack in detected_stacks:
            rules_to_check.update(RECOMMENDED_GITIGNORE_RULES.get(stack, []))

        missing_rules = []
        for rule in sorted(rules_to_check):
            clean_rule = rule.rstrip("/")
            # Check if direct match or wildcard match
            matched = False
            for ex in existing_lines:
                if ex == clean_rule or ex == rule or ex == f"*{clean_rule}*":
                    matched = True
                    break
                if clean_rule.startswith(".env") and ex in (".env*", ".env"):
                    matched = True
                    break
            if not matched:
                missing_rules.append(rule)

        if missing_rules:
            findings.append(
                Finding(
                    id="GITIGNORE_INCOMPLETE",
                    title=f"Missing {len(missing_rules)} recommended .gitignore patterns",
                    category=Category.GITIGNORE_MISSING,
                    severity=Severity.MEDIUM,
                    description=f"Recommended patterns not covered in .gitignore: {', '.join(missing_rules[:6])}{'...' if len(missing_rules) > 6 else ''}",
                    remediation=f"Append recommended rules using `repo-hygiene fix-gitignore`.",
                )
            )

        return findings

    def audit_history_sensitive_files(self) -> List[Finding]:
        """Scan all historical git commits for committed sensitive files."""
        findings: List[Finding] = []
        historical_files = get_historical_added_files(self.repo_path)

        seen_keys: Set[str] = set()

        for commit_hash, author, date, file_path in historical_files:
            for pattern, severity, desc, remediation in SENSITIVE_FILE_PATTERNS:
                if pattern.search(file_path):
                    dedup_key = f"{commit_hash}:{file_path}"
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    findings.append(
                        Finding(
                            id=f"HISTORY_SENSITIVE_FILE_{severity.value.upper()}",
                            title=f"Sensitive file committed: {Path(file_path).name}",
                            category=Category.SENSITIVE_FILE_HISTORY,
                            severity=severity,
                            description=f"{desc} (File: '{file_path}')",
                            remediation=remediation,
                            commit_hash=commit_hash,
                            file_path=file_path,
                            author=author,
                            date=date,
                        )
                    )

        return findings

    def audit_commit_diff_secrets(self) -> List[Finding]:
        """Scan recent commit diffs for exposed secret patterns."""
        findings: List[Finding] = []
        diffs = get_recent_diff_patches(self.repo_path, max_commits=30)

        seen_secrets: Set[str] = set()

        for commit_hash, author, diff_text in diffs:
            for line in diff_text.splitlines():
                if not line.startswith("+"):
                    continue
                # Skip diff metadata
                if line.startswith("+++"):
                    continue

                for pattern, severity, desc in SECRET_CONTENT_PATTERNS:
                    if pattern.search(line):
                        dedup = f"{commit_hash}:{desc}"
                        if dedup in seen_secrets:
                            continue
                        seen_secrets.add(dedup)

                        findings.append(
                            Finding(
                                id=f"SECRET_IN_DIFF_{severity.value.upper()}",
                                title=f"Potential secret in commit diff: {desc}",
                                category=Category.SECRET_IN_DIFF,
                                severity=severity,
                                description=f"Pattern matching {desc} added in commit {commit_hash} by {author}.",
                                remediation="Revoke and rotate the exposed token, then rewrite git history.",
                                commit_hash=commit_hash,
                                author=author,
                            )
                        )

        return findings

    def audit_git_config(self) -> List[Finding]:
        """Audit git remotes and configuration settings."""
        findings: List[Finding] = []
        remotes = get_git_remotes(self.repo_path)

        for rname, url in remotes:
            # Check for embedded password/token in remote URL
            if re.search(r'https?://[^:@\s]+:[^@\s]+@', url):
                findings.append(
                    Finding(
                        id="REMOTE_PLAINTEXT_CREDENTIALS",
                        title=f"Plaintext credentials embedded in remote URL '{rname}'",
                        category=Category.GIT_CONFIG_RISK,
                        severity=Severity.CRITICAL,
                        description=f"Remote '{rname}' has username/password or token embedded in URL: {url}",
                        remediation=f"Remove embedded credentials: `git remote set-url {rname} <sanitized-url>` and use git credential manager or SSH keys.",
                    )
                )

            # Insecure plain HTTP remote
            if url.startswith("http://"):
                findings.append(
                    Finding(
                        id="REMOTE_INSECURE_HTTP",
                        title=f"Unencrypted HTTP remote URL in '{rname}'",
                        category=Category.GIT_CONFIG_RISK,
                        severity=Severity.MEDIUM,
                        description=f"Remote '{rname}' uses insecure HTTP protocol without TLS: {url}",
                        remediation=f"Change remote protocol to HTTPS or SSH.",
                    )
                )

        configs = get_git_config(self.repo_path)
        # Check commit signing
        signing = configs.get("commit.gpgsign", "").lower()
        if signing != "true":
            findings.append(
                Finding(
                    id="CONFIG_GPG_SIGNING_DISABLED",
                    title="Git commit GPG/SSH signing is not enabled",
                    category=Category.GIT_CONFIG_RISK,
                    severity=Severity.INFO,
                    description="Commit signing verifies author identity and prevents commit spoofing.",
                    remediation="Configure commit signing: `git config commit.gpgsign true`.",
                )
            )

        return findings

    def audit_repo_structure(self) -> List[Finding]:
        """Check for core open source hygiene files (README, LICENSE)."""
        findings: List[Finding] = []

        readme_candidates = ["README.md", "README", "README.rst", "readme.md"]
        has_readme = any((self.repo_path / r).is_file() for r in readme_candidates)
        if not has_readme:
            findings.append(
                Finding(
                    id="STRUCTURE_MISSING_README",
                    title="Missing README document",
                    category=Category.REPO_STRUCTURE,
                    severity=Severity.LOW,
                    description="No README file found at the root of the repository.",
                    remediation="Add a README.md documenting project purpose, usage, and installation.",
                )
            )

        license_candidates = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"]
        has_license = any((self.repo_path / l).is_file() for l in license_candidates)
        if not has_license:
            findings.append(
                Finding(
                    id="STRUCTURE_MISSING_LICENSE",
                    title="Missing open-source LICENSE file",
                    category=Category.REPO_STRUCTURE,
                    severity=Severity.LOW,
                    description="No LICENSE file detected at repository root.",
                    remediation="Add an open-source license (such as MIT, Apache-2.0, or BSD).",
                )
            )

        return findings

    def audit_all(self) -> HygieneReport:
        """Run all audits and compile report with scoring."""
        start_time = time.perf_counter()
        is_git = is_git_repo(self.repo_path)

        branch = get_current_branch(self.repo_path) if is_git else "non-git"
        commit_count = get_commit_count(self.repo_path) if is_git else 0
        detected_stacks = self.detect_tech_stacks()

        findings: List[Finding] = []

        # 1. Structure audit
        findings.extend(self.audit_repo_structure())

        # 2. .gitignore audit
        findings.extend(self.audit_gitignore(detected_stacks))

        # 3. Git-specific audits if inside a git repository
        if is_git:
            findings.extend(self.audit_history_sensitive_files())
            findings.extend(self.audit_commit_diff_secrets())
            findings.extend(self.audit_git_config())
        else:
            findings.append(
                Finding(
                    id="NOT_A_GIT_REPO",
                    title="Directory is not a git repository",
                    category=Category.REPO_STRUCTURE,
                    severity=Severity.INFO,
                    description="Git history and config audits were skipped because the target is not a git repository.",
                    remediation="Initialize git repository with `git init`.",
                )
            )

        score = AuditScore.calculate(findings)

        report = HygieneReport(
            repo_path=self.repo_path,
            branch=branch,
            commit_count=commit_count,
            findings=findings,
            detected_stacks=detected_stacks,
            score=score,
            elapsed_seconds=time.perf_counter() - start_time,
        )
        return report

    def fix_gitignore(self, detected_stacks: List[str]) -> int:
        """Append missing recommended ignore rules to .gitignore."""
        gitignore_path = self.repo_path / ".gitignore"
        existing_lines = set()

        if gitignore_path.exists():
            try:
                content = gitignore_path.read_text(encoding="utf-8")
                for line in content.splitlines():
                    existing_lines.add(line.strip().rstrip("/"))
            except Exception:
                content = ""
        else:
            content = ""

        rules_to_add: List[str] = []
        all_rules = list(RECOMMENDED_GITIGNORE_RULES.get("general", []))
        for stack in detected_stacks:
            all_rules.extend(RECOMMENDED_GITIGNORE_RULES.get(stack, []))

        for rule in all_rules:
            clean = rule.rstrip("/")
            if clean not in existing_lines and rule not in existing_lines:
                rules_to_add.append(rule)

        if not rules_to_add:
            return 0

        # Append to file
        new_content = content
        if new_content and not new_content.endswith("\n"):
            new_content += "\n"

        new_content += "\n# Added by repo-hygiene\n"
        for r in rules_to_add:
            new_content += f"{r}\n"

        gitignore_path.write_text(new_content, encoding="utf-8")
        return len(rules_to_add)

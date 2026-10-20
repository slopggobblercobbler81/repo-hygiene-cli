"""Git utility functions for interacting with repository history and configuration."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def run_git(args: List[str], cwd: Path) -> Tuple[int, str, str]:
    """Execute a git command within the specified repository directory."""
    try:
        proc = subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def is_git_repo(path: Path) -> bool:
    """Return True if path is within a valid git work tree."""
    code, out, _ = run_git(["rev-parse", "--is-inside-work-tree"], path)
    return code == 0 and out.lower() == "true"


def get_current_branch(path: Path) -> str:
    """Get active git branch name, falling back to 'main' or 'HEAD'."""
    code, out, _ = run_git(["branch", "--show-current"], path)
    if code == 0 and out:
        return out
    code, out, _ = run_git(["rev-parse", "--abbrev-ref", "HEAD"], path)
    if code == 0 and out:
        return out
    return "main"


def get_commit_count(path: Path) -> int:
    """Count total commits in the repository history."""
    code, out, _ = run_git(["rev-list", "--count", "HEAD"], path)
    if code == 0 and out.isdigit():
        return int(out)
    return 0


def get_historical_added_files(path: Path, max_commits: int = 500) -> List[Tuple[str, str, str, str]]:
    """Retrieve all files added in git history with (commit_hash, author, date, file_path)."""
    # Format: COMMIT:hash|author|date
    args = [
        "log",
        f"-n{max_commits}",
        "--diff-filter=A",
        "--name-only",
        "--pretty=format:COMMIT:%h|%an|%ad",
        "--date=short",
    ]
    code, out, _ = run_git(args, path)
    if code != 0 or not out:
        return []

    records: List[Tuple[str, str, str, str]] = []
    current_commit = ""
    current_author = ""
    current_date = ""

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COMMIT:"):
            parts = line[7:].split("|")
            current_commit = parts[0] if len(parts) > 0 else ""
            current_author = parts[1] if len(parts) > 1 else ""
            current_date = parts[2] if len(parts) > 2 else ""
        else:
            records.append((current_commit, current_author, current_date, line))

    return records


def get_git_config(path: Path) -> Dict[str, str]:
    """Retrieve all git config key-value pairs for the repository."""
    code, out, _ = run_git(["config", "--list"], path)
    if code != 0 or not out:
        return {}

    configs: Dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            key, val = line.split("=", 1)
            configs[key.strip()] = val.strip()
    return configs


def get_git_remotes(path: Path) -> List[Tuple[str, str]]:
    """Retrieve list of (remote_name, url)."""
    code, out, _ = run_git(["remote", "-v"], path)
    if code != 0 or not out:
        return []

    remotes: List[Tuple[str, str]] = []
    seen = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            rname, url = parts[0], parts[1]
            if (rname, url) not in seen:
                seen.add((rname, url))
                remotes.append((rname, url))
    return remotes


def get_recent_diff_patches(path: Path, max_commits: int = 50) -> List[Tuple[str, str, str]]:
    """Retrieve recent commit diffs as (commit_hash, author, diff_text)."""
    code, out, _ = run_git(["log", f"-n{max_commits}", "-p", "--pretty=format:COMMIT:%h|%an"], path)
    if code != 0 or not out:
        return []

    commits: List[Tuple[str, str, str]] = []
    current_hash = ""
    current_author = ""
    current_lines: List[str] = []

    for line in out.splitlines():
        if line.startswith("COMMIT:"):
            if current_hash and current_lines:
                commits.append((current_hash, current_author, "\n".join(current_lines)))
                current_lines = []
            parts = line[7:].split("|")
            current_hash = parts[0] if len(parts) > 0 else ""
            current_author = parts[1] if len(parts) > 1 else ""
        else:
            current_lines.append(line)

    if current_hash and current_lines:
        commits.append((current_hash, current_author, "\n".join(current_lines)))

    return commits

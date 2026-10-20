# Repo Hygiene CLI 🛡️

[![CI](https://github.com/slopggobblercobbler81/repo-hygiene-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/slopggobblercobbler81/repo-hygiene-cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

> **A fast developer CLI to audit git repositories for security hygiene: detecting sensitive files in git commit history, scanning for missing .gitignore patterns, verifying git config safety, and generating a security audit score.**

Prevent credential leaks, messy git histories, and repository misconfigurations before they reach production.

---

## 🚀 Key Features

- 🕵️ **Git History Forensic Audit**: Scans all commits in repository history for accidentally committed private keys (`id_rsa`, `*.pem`), environment files (`.env`), credentials, service account tokens, keystores, and database dumps.
- 🔍 **Secret Content Pattern Scanner**: Inspects commit diff additions for raw private keys, AWS access keys, GitHub tokens, Slack tokens, and OpenAI API keys.
- 📋 **Intelligent `.gitignore` Verification**: Auto-detects project tech stacks (Python, Node/TypeScript, Rust, Go, Java) and flags missing recommended ignore rules.
- 🔧 **One-Command `.gitignore` Repair**: Run `repo-hygiene fix-gitignore` to automatically append recommended missing rules to `.gitignore`.
- 🔐 **Git Configuration & Remote URL Safety**: Detects dangerous plaintext credentials in remote URLs (e.g. `https://user:password@github.com/...`), unencrypted plain HTTP remotes, and unsigned commit configs.
- 💯 **Security Hygiene Score**: Computes an audit score (0–100) and letter grade (A+ through F) with actionable remediation guidance.
- 📊 **Multi-Format Export**:
  - Beautiful Rich terminal cards and tables.
  - Machine-readable JSON output (`--format json`).
  - GitHub-flavored Markdown (`--format markdown`) for PR summaries.
  - Native GitHub Actions annotations (`--format github`).

---

## 📦 Installation

```bash
pip install repo-hygiene-cli
```

Or install in editable mode:

```bash
git clone https://github.com/slopggobblercobbler81/repo-hygiene-cli.git
cd repo-hygiene-cli
pip install -e ".[dev]"
```

---

## 🏃 Quick Start

### 1. Audit Current Repository

```bash
repo-hygiene audit
```

### 2. Audit a Specific Directory or Submodule

```bash
repo-hygiene audit /path/to/my-repo
```

### 3. Automatically Repair Missing `.gitignore` Patterns

```bash
repo-hygiene fix-gitignore
```

Or preview missing rules without modifying files:

```bash
repo-hygiene fix-gitignore --dry-run
```

### 4. Enforce CI Quality Gates

Fail the build if the security score drops below 85:

```bash
repo-hygiene audit --fail-under 85
```

Fail the build on any critical or high findings:

```bash
repo-hygiene audit --fail-on high --format github
```

### 5. Export Audit Report

```bash
repo-hygiene audit --format json --output audit-report.json
repo-hygiene audit --format markdown --output audit-report.md
```

### 6. List Built-in Audit Rules

```bash
repo-hygiene list-rules
```

---

## 🛠️ CLI Reference

### `repo-hygiene audit [PATH]`

| Option | Description | Default |
| --- | --- | --- |
| `--format, -f` | Output format: `console`, `json`, `markdown`, `github` | `console` |
| `--output, -o FILE` | Write report output to file | `stdout` |
| `--fail-under INT` | Return exit code 1 if score is lower than threshold | `0` (disabled) |
| `--fail-on` | Failure threshold: `critical`, `high`, `medium`, `any`, `never` | `high` |

### `repo-hygiene fix-gitignore [PATH]`

| Option | Description | Default |
| --- | --- | --- |
| `--dry-run` | List missing rules without modifying `.gitignore` | `False` |

---

## 🤖 GitHub Actions Workflow

Integrate `repo-hygiene` into your CI pipeline:

```yaml
name: Security & Hygiene Audit

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  hygiene:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Fetch complete history for accurate auditing

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - run: pip install repo-hygiene-cli

      - name: Run Repo Hygiene Audit
        run: repo-hygiene audit --fail-under 80 --fail-on high --format github
```

---

## 🧪 Running Tests

```bash
pytest -v --cov=repo_hygiene
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

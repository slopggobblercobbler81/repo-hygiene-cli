"""Rules and patterns for detecting sensitive files, secrets, and missing gitignore entries."""

import re
from typing import Dict, List, Pattern, Tuple
from .models import Severity


# (Regex pattern, Severity, Description, Remediation)
SENSITIVE_FILE_PATTERNS: List[Tuple[Pattern, Severity, str, str]] = [
    (
        re.compile(r'(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$', re.IGNORECASE),
        Severity.CRITICAL,
        "SSH private or public key file committed",
        "Remove from git history using git-filter-repo and rotate the SSH key immediately."
    ),
    (
        re.compile(r'\.(pem|key|p12|pfx|pkcs12)$', re.IGNORECASE),
        Severity.CRITICAL,
        "Cryptographic private key or PKCS certificate bundle",
        "Purge from git history and issue a replacement certificate."
    ),
    (
        re.compile(r'(^|/)\.env(\.[a-zA-Z0-9_-]+)?$', re.IGNORECASE),
        Severity.HIGH,
        "Environment file possibly containing active secrets",
        "Add .env to .gitignore, delete the file from history, and rotate exposed credentials."
    ),
    (
        re.compile(r'(^|/)(secrets|credentials|service-account.*)\.(json|yaml|yml|toml)$', re.IGNORECASE),
        Severity.CRITICAL,
        "Service credentials or secrets configuration file",
        "Revoke service account credentials and purge the file from repository history."
    ),
    (
        re.compile(r'(^|/)\.(netrc|npmrc|pypirc)$', re.IGNORECASE),
        Severity.HIGH,
        "Authentication credential configuration file (.netrc/.npmrc/.pypirc)",
        "Rotate registry/package tokens and remove the file from git history."
    ),
    (
        re.compile(r'(^|/)kube/config$', re.IGNORECASE),
        Severity.CRITICAL,
        "Kubernetes cluster configuration with authentication tokens",
        "Rotate cluster credentials and purge from git history."
    ),
    (
        re.compile(r'\.(keystore|jks)$', re.IGNORECASE),
        Severity.HIGH,
        "Java keystore containing private keys/certificates",
        "Ensure keystore is excluded via .gitignore and purged from history."
    ),
    (
        re.compile(r'\.(sql|dump|sqlite3?|db)$', re.IGNORECASE),
        Severity.MEDIUM,
        "Database dump or SQLite database file",
        "Remove database files from repository to avoid leaking customer or sensitive data."
    ),
]


SECRET_CONTENT_PATTERNS: List[Tuple[Pattern, Severity, str]] = [
    (
        re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        Severity.CRITICAL,
        "Raw Private Key Block"
    ),
    (
        re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
        Severity.CRITICAL,
        "AWS Access Key ID"
    ),
    (
        re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'),
        Severity.CRITICAL,
        "GitHub Personal Access Token"
    ),
    (
        re.compile(r'sk-[a-zA-Z0-9]{20,}'),
        Severity.HIGH,
        "OpenAI API Key"
    ),
    (
        re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
        Severity.HIGH,
        "Slack Bot/User Token"
    ),
]


RECOMMENDED_GITIGNORE_RULES: Dict[str, List[str]] = {
    "general": [
        ".env",
        ".env.*",
        "*.pem",
        "*.key",
        ".DS_Store",
        "Thumbs.db",
    ],
    "python": [
        "__pycache__/",
        "*.py[cod]",
        "*$py.class",
        ".venv/",
        "venv/",
        "*.egg-info/",
        ".pytest_cache/",
        ".coverage",
        "dist/",
        "build/",
    ],
    "node": [
        "node_modules/",
        ".npm/",
        "dist/",
        ".env.local",
        "npm-debug.log*",
    ],
    "rust": [
        "target/",
    ],
    "go": [
        "bin/",
        "pkg/",
    ],
    "java": [
        "*.class",
        "*.jar",
        "*.war",
        "target/",
        ".gradle/",
        "build/",
    ],
}


TECH_STACK_MARKERS: Dict[str, List[str]] = {
    "python": ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "Pipfile.lock"],
    "node": ["package.json", "yarn.lock", "package-lock.json", "pnpm-lock.yaml"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "go": ["go.mod", "go.sum"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
}

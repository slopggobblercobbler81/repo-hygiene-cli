"""Tests for regex rules detecting sensitive files and secret patterns."""

from repo_hygiene.rules import (
    SECRET_CONTENT_PATTERNS,
    SENSITIVE_FILE_PATTERNS,
)


def test_sensitive_file_patterns():
    matches = {
        "id_rsa": False,
        "id_ed25519": False,
        "cert.pem": False,
        "server.key": False,
        ".env": False,
        ".env.production": False,
        "secrets.json": False,
        "service-account-key.json": False,
        ".netrc": False,
        "kube/config": False,
        "app.keystore": False,
        "database.sqlite": False,
        "backup.sql": False,
    }

    for path in matches:
        for pattern, _, _, _ in SENSITIVE_FILE_PATTERNS:
            if pattern.search(path):
                matches[path] = True
                break

    for path, matched in matches.items():
        assert matched is True, f"Expected {path} to match a sensitive file pattern"

    # Clean files should NOT match
    clean_files = [
        "README.md",
        "main.py",
        "index.ts",
        "package.json",
        "Cargo.toml",
    ]
    for clean in clean_files:
        for pattern, _, _, _ in SENSITIVE_FILE_PATTERNS:
            assert not pattern.search(clean), f"{clean} should not match sensitive file patterns"


def test_secret_content_patterns():
    test_secrets = [
        ("-----BEGIN RSA PRIVATE KEY-----", "Raw Private Key Block"),
        ("AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID"),
        ("ghp_1234567890abcdefghijklmnopqrstuvwxyzAB", "GitHub Personal Access Token"),
        ("sk-abcdef1234567890abcdef123456", "OpenAI API Key"),
        ("xoxb-123456789012-1234567890123-456789abcdef", "Slack Bot/User Token"),
    ]

    for secret_str, expected_desc in test_secrets:
        found = False
        for pattern, _, desc in SECRET_CONTENT_PATTERNS:
            if pattern.search(secret_str):
                found = True
                assert desc == expected_desc
                break
        assert found is True, f"Failed to match secret pattern for: {secret_str}"

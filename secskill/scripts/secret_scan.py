#!/usr/bin/env python3
"""
secskill/scripts/secret_scan.py
Regex + Shannon entropy + context scanning for exposed secrets and credentials.
Automatically redacts detected values to preserve privacy.
"""
import math
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "min_entropy": 2.5
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)(?:aws_secret_access_key|aws_secret_key|aws_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "min_entropy": 4.0
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "min_entropy": 3.0
    },
    {
        "name": "JSON Web Token (JWT)",
        "pattern": r"ey[A-Za-z0-9-_=]{10,}\.ey[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,}",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "min_entropy": 3.5
    },
    {
        "name": "Generic Private Key",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "cwe": "CWE-321",
        "severity": "CRITICAL",
        "min_entropy": 0.0
    },
    {
        "name": "Slack API Token / Webhook",
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "min_entropy": 2.5
    },
    {
        "name": "Database Connection String with Password",
        "pattern": r"(?i)(?:postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9._%+-]+:([^@\s'\"]{4,})@[a-zA-Z0-9.-]+",
        "cwe": "CWE-259",
        "severity": "HIGH",
        "min_entropy": 2.5
    },
    {
        "name": "Hardcoded Secret / Password Assignment",
        "pattern": r"(?i)(?:api_key|apikey|secret_key|client_secret|auth_token|jwt_secret|private_key|db_password)\s*[:=]\s*['\"]([^'\"]{12,})['\"]",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "min_entropy": 3.0
    }
]

ALLOWLIST_KEYWORDS = [
    "example", "sample", "test", "dummy", "placeholder", "your_", "<", ">",
    "insert_", "fake", "todo", "replace_with", "xxxx", "000000", "123456",
    "abcdef", "my_secret", "changeme", "change_me", "none"
]

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".pytest_cache", ".ruff_cache", "target",
    "secskill", ".secskill", ".secskill_cache", "graphify-out", ".idea", ".vscode"
}

def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def redact_secret(val: str) -> str:
    """Always redact secret showing prefix and suffix at most."""
    s = val.strip()
    if len(s) <= 8:
        return "[REDACTED]"
    prefix = s[:4]
    suffix = s[-3:]
    return f"{prefix}...{suffix}"

def is_allowlisted(val: str, line_content: str, file_path: str) -> bool:
    """Check if value is a mock, test fixture, or placeholder."""
    val_lower = val.lower()
    line_lower = line_content.lower()
    path_lower = file_path.lower()

    if any(keyword in val_lower for keyword in ALLOWLIST_KEYWORDS):
        return True
    if any(k in line_lower for k in ["mock", "fixture", "dummy", "placeholder", "unit_test"]):
        return True
    if "test" in path_lower and any(kw in val_lower for kw in ["secret", "pass", "key"]):
        # allow obvious mock test keys in test files
        if "mock" in val_lower or "test" in val_lower or "dummy" in val_lower:
            return True
    return False

def scan_file(file_path: Path, root: Path) -> List[Dict[str, Any]]:
    findings = []
    rel_path = str(file_path.relative_to(root)).replace("\\", "/")

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                    # Check comments too if they hold real tokens, but skip trivial docs
                    pass

                for rule in SECRET_PATTERNS:
                    matches = re.finditer(rule["pattern"], line)
                    for m in matches:
                        # Extract the captured group if available, else full match
                        matched_val = m.group(1) if m.groups() else m.group(0)
                        
                        # Entropy check
                        if rule["min_entropy"] > 0:
                            ent = shannon_entropy(matched_val)
                            if ent < rule["min_entropy"]:
                                continue

                        # Allowlist check
                        if is_allowlisted(matched_val, line, rel_path):
                            continue

                        redacted = redact_secret(matched_val)
                        finding = {
                            "finding_id": f"SEC-F-{abs(hash(rel_path + str(idx) + rule['name'])) % 10000:04d}",
                            "title": f"Exposed Credential: {rule['name']}",
                            "cwe": rule["cwe"],
                            "owasp": "A02:2021-Cryptographic Failures" if rule["cwe"] == "CWE-798" else "A05:2021-Security Misconfiguration",
                            "severity": rule["severity"].lower(),
                            "confidence": 0.95,
                            "file": rel_path,
                            "line": idx,
                            "source": "secret_scanner",
                            "tool": "secskill_secret_scanner",
                            "evidence": f"Pattern matched '{rule['name']}' with value {redacted}. Shannon entropy: {shannon_entropy(matched_val):.2f}",
                            "status": "needs_validation",
                            "metadata": {
                                "redacted_value": redacted,
                                "rule_name": rule["name"]
                            }
                        }
                        findings.append(finding)
    except Exception:
        pass
    return findings

def scan_target(target_path: str) -> List[Dict[str, Any]]:
    root = Path(target_path).resolve()
    all_findings = []
    if root.is_file():
        return scan_file(root, root.parent)
    
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            rel = p.relative_to(root)
            parts = {part.lower() for part in rel.parts[:-1]}
        except ValueError:
            parts = {part.lower() for part in p.parts[:-1]}
        if any(ignored.lower() in parts for ignored in IGNORE_DIRS):
            continue
        fname = p.name.lower()
        if fname.startswith("secskill.") or fname.startswith(".secskill"):
            continue
        # Skip binary / media extensions
        if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".exe", ".bin", ".pyc"}:
            continue
        all_findings.extend(scan_file(p, root))

    return all_findings

def main():
    parser = argparse.ArgumentParser(description="SecSkill Secret & Credential Scanner")
    parser.add_argument("target", nargs="?", default=".", help="Target file or directory path")
    parser.add_argument("-o", "--output", help="Optional output JSON file path")
    args = parser.parse_args()

    findings = scan_target(args.target)
    out_json = json.dumps(findings, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"Secret scan results written to {args.output}")
    else:
        print(out_json)

if __name__ == "__main__":
    main()


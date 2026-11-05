#!/usr/bin/env python3
"""
secskill/scripts/normalize_findings.py
Merges raw findings from external tools, static rules, secret scanning,
and dependency scanning into the SecSkill Unified Finding Schema.
Deduplicates overlapping findings and harmonizes CWE/OWASP categorizations.
"""
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

CWE_OWASP_MAP = {
    "CWE-89": "A03:2021-Injection",
    "CWE-78": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",
    "CWE-94": "A03:2021-Injection",
    "CWE-1336": "A03:2021-Injection",
    "CWE-862": "A01:2021-Broken Access Control",
    "CWE-863": "A01:2021-Broken Access Control",
    "CWE-639": "A01:2021-Broken Access Control",
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-328": "A02:2021-Cryptographic Failures",
    "CWE-330": "A02:2021-Cryptographic Failures",
    "CWE-798": "A02:2021-Cryptographic Failures",
    "CWE-259": "A02:2021-Cryptographic Failures",
    "CWE-321": "A02:2021-Cryptographic Failures",
    "CWE-16": "A05:2021-Security Misconfiguration",
    "CWE-489": "A05:2021-Security Misconfiguration",
    "CWE-1004": "A05:2021-Security Misconfiguration",
    "CWE-611": "A05:2021-Security Misconfiguration",
    "CWE-918": "A10:2021-Server-Side Request Forgery",
    "CWE-1395": "A06:2021-Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021-Vulnerable and Outdated Components",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-287": "A07:2021-Identification and Authentication Failures",
    "CWE-384": "A07:2021-Identification and Authentication Failures",
    "CWE-613": "A07:2021-Identification and Authentication Failures",
    "CWE-74": "A04:2021-Insecure Design"
}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}

def normalize_single_finding(raw: Dict[str, Any], count: int) -> Dict[str, Any]:
    # Extract CWE
    cwe = raw.get("cwe") or raw.get("cwe_id") or "CWE-Generic"
    if isinstance(cwe, int):
        cwe = f"CWE-{cwe}"
    elif isinstance(cwe, str) and not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"

    # Harmonize OWASP
    owasp = raw.get("owasp") or raw.get("owasp_category")
    if not owasp or owasp == "unknown":
        owasp = CWE_OWASP_MAP.get(cwe, "A03:2021-Injection")

    # Severity
    sev = str(raw.get("severity", "medium")).lower()
    if sev not in VALID_SEVERITIES:
        sev = "medium"

    # Confidence
    conf = raw.get("confidence", 0.80)
    if isinstance(conf, str):
        mapping = {"high": 0.90, "medium": 0.70, "low": 0.40}
        conf = mapping.get(conf.lower(), 0.75)
    else:
        conf = float(conf)

    # Line number
    line = raw.get("line") or raw.get("line_number") or 1
    try:
        line = int(line)
    except (ValueError, TypeError):
        line = 1

    file_path = str(raw.get("file") or raw.get("file_path") or "").replace("\\", "/")

    finding_id = raw.get("finding_id") or raw.get("id") or f"F-{1000 + count}"

    return {
        "finding_id": str(finding_id),
        "title": str(raw.get("title", "Security Finding")),
        "cwe": cwe,
        "owasp": owasp,
        "severity": sev,
        "confidence": round(conf, 2),
        "file": file_path,
        "line": line,
        "source": str(raw.get("source", "static_analysis")),
        "tool": str(raw.get("tool", "secskill")),
        "evidence": str(raw.get("evidence", raw.get("description", ""))),
        "status": str(raw.get("status", "needs_validation")),
        "metadata": raw.get("metadata", {})
    }

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {}
    deduped = []
    for f in findings:
        key = (f["file"], f["line"], f["cwe"])
        if key not in seen:
            seen[key] = f
            deduped.append(f)
        else:
            # Keep higher severity or higher confidence
            existing = seen[key]
            if f["confidence"] > existing["confidence"]:
                deduped.remove(existing)
                seen[key] = f
                deduped.append(f)
    return deduped

def normalize_all(findings_lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    flat = []
    idx = 1
    for group in findings_lists:
        for item in group:
            flat.append(normalize_single_finding(item, idx))
            idx += 1
    return deduplicate_findings(flat)

def main():
    parser = argparse.ArgumentParser(description="SecSkill Findings Normalizer")
    parser.add_argument("inputs", nargs="+", help="One or more JSON files containing raw findings")
    parser.add_argument("-o", "--output", help="Optional output JSON file path")
    args = parser.parse_args()

    groups = []
    for inp in args.inputs:
        p = Path(inp)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    groups.append(data)
                elif isinstance(data, dict):
                    if "findings" in data and isinstance(data["findings"], list):
                        groups.append(data["findings"])
                    else:
                        groups.append([data])

    normalized = normalize_all(groups)
    out_json = json.dumps(normalized, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"Normalized {len(normalized)} findings written to {args.output}")
    else:
        print(out_json)

if __name__ == "__main__":
    main()


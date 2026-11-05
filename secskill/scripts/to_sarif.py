#!/usr/bin/env python3
"""
secskill/scripts/to_sarif.py
Converts SecSkill unified findings JSON into standard OASIS SARIF 2.1.0 format
compatible with GitHub Advanced Security / Code Scanning.
"""
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note"
}

def convert_findings_to_sarif(findings: List[Dict[str, Any]], repo_root: str = "") -> Dict[str, Any]:
    rules_dict: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        cwe = f.get("cwe", "CWE-Generic")
        rule_id = f"SEC-{cwe.replace('CWE-', '')}"
        title = f.get("title", "Security Finding")
        severity = f.get("severity", "medium").lower()
        level = SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")
        file_path = f.get("file", "unknown").replace("\\", "/")
        line = f.get("line", 1)
        evidence = f.get("evidence", "Security vulnerability detected.")

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": title.replace(" ", ""),
                "shortDescription": {"text": title},
                "fullDescription": {"text": f"{title} ({cwe}) - {evidence}"},
                "defaultConfiguration": {"level": level},
                "help": {
                    "text": f"Remediate {cwe} by avoiding unsafe sinks and parameterizing inputs.",
                    "markdown": f"### Remediation Guidance for {cwe}\n\n**Issue:** {title}\n\n**Evidence:** {evidence}\n"
                },
                "properties": {
                    "tags": ["security", cwe, f.get("owasp", "A03:2021-Injection")],
                    "precision": "high" if f.get("confidence", 0.8) > 0.85 else "medium"
                }
            }

        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"{title}: {evidence}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": 1
                        }
                    }
                }
            ],
            "properties": {
                "finding_id": f.get("finding_id"),
                "confidence": f.get("confidence", 0.8),
                "owasp": f.get("owasp", "")
            }
        }
        results.append(result)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecSkill",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/secskill/secskill",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": results
            }
        ]
    }
    return sarif_doc

def main():
    parser = argparse.ArgumentParser(description="SecSkill Findings to SARIF 2.1.0 Converter")
    parser.add_argument("input", help="Input unified findings JSON file")
    parser.add_argument("-o", "--output", help="Output SARIF file path (defaults to stdout)")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"Error: input file {args.input} does not exist.", file=sys.stderr)
        sys.exit(1)

    with open(in_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        findings = data if isinstance(data, list) else data.get("findings", [])

    sarif = convert_findings_to_sarif(findings)
    out_json = json.dumps(sarif, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"SARIF written to {args.output}")
    else:
        print(out_json)

if __name__ == "__main__":
    main()


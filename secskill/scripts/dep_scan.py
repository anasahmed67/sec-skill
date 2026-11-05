#!/usr/bin/env python3
"""
secskill/scripts/dep_scan.py
Parse dependency manifests, audit packages against vulnerability databases (OSV API or offline DB).
Maps vulnerable packages to OWASP A06:2021 with CVE, affected version, and fixed version.
"""
import os
import sys
import re
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Any, Optional

# Offline fallback database of high-severity CVEs for popular packages
OFFLINE_VULN_DB = {
    "pypi": {
        "requests": [
            {"max_affected": "2.31.0", "cve": "CVE-2023-32681", "fixed": "2.31.0", "title": "Proxy-Authorization Header Leaked on Redirect", "severity": "medium"}
        ],
        "urllib3": [
            {"max_affected": "1.26.17", "cve": "CVE-2023-43804", "fixed": "1.26.18", "title": "Cookie Leaked on Cross-Origin Redirect", "severity": "high"},
            {"max_affected": "2.0.6", "cve": "CVE-2023-45803", "fixed": "2.0.7", "title": "Request Body Leaked on Cross-Origin Redirect", "severity": "high"}
        ],
        "flask": [
            {"max_affected": "2.2.4", "cve": "CVE-2023-30861", "fixed": "2.2.5", "title": "Session Cookie Disclosure via Cache", "severity": "high"}
        ],
        "django": [
            {"max_affected": "4.2.15", "cve": "CVE-2024-45231", "fixed": "4.2.16", "title": "Denial of Service via Email Header Parsing", "severity": "high"},
            {"max_affected": "3.2.20", "cve": "CVE-2023-36053", "fixed": "3.2.21", "title": "ReDoS in EmailValidator", "severity": "high"}
        ],
        "pyyaml": [
            {"max_affected": "5.3.1", "cve": "CVE-2020-14343", "fixed": "5.4.0", "title": "Arbitrary Code Execution in FullLoader", "severity": "critical"}
        ],
        "pillow": [
            {"max_affected": "10.0.0", "cve": "CVE-2023-44271", "fixed": "10.0.1", "title": "Denial of Service via Uncontrolled Resource Consumption", "severity": "medium"}
        ],
        "jinja2": [
            {"max_affected": "3.1.2", "cve": "CVE-2024-22195", "fixed": "3.1.3", "title": "XSS via xmlattr filter with keys containing spaces", "severity": "medium"}
        ],
        "cryptography": [
            {"max_affected": "41.0.5", "cve": "CVE-2023-49083", "fixed": "41.0.6", "title": "NULL Pointer Dereference in PKCS7 Loading", "severity": "medium"}
        ]
    },
    "npm": {
        "lodash": [
            {"max_affected": "4.17.20", "cve": "CVE-2021-23337", "fixed": "4.17.21", "title": "Command Injection in template", "severity": "high"}
        ],
        "jsonwebtoken": [
            {"max_affected": "8.5.1", "cve": "CVE-2022-23529", "fixed": "9.0.0", "title": "Remote Code Execution via key parameter", "severity": "critical"}
        ],
        "express": [
            {"max_affected": "4.19.1", "cve": "CVE-2024-29041", "fixed": "4.19.2", "title": "Open Redirect via malformed URLs", "severity": "medium"}
        ],
        "axios": [
            {"max_affected": "1.5.1", "cve": "CVE-2023-45857", "fixed": "1.6.0", "title": "Cross-Site Request Forgery via credential leakage", "severity": "high"}
        ],
        "minimist": [
            {"max_affected": "1.2.5", "cve": "CVE-2021-44906", "fixed": "1.2.6", "title": "Prototype Pollution via setKey", "severity": "critical"}
        ]
    },
    "maven": {
        "org.apache.logging.log4j:log4j-core": [
            {"max_affected": "2.17.0", "cve": "CVE-2021-44228", "fixed": "2.17.1", "title": "Log4Shell JNDI Remote Code Execution", "severity": "critical"}
        ],
        "org.springframework:spring-core": [
            {"max_affected": "5.3.17", "cve": "CVE-2022-22965", "fixed": "5.3.18", "title": "Spring4Shell Remote Code Execution", "severity": "critical"}
        ]
    }
}

def parse_semver(v: str) -> List[int]:
    """Basic semver normalization for comparison."""
    parts = re.split(r"[-+.]", v.strip().lstrip("v^~>=<"))
    nums = []
    for p in parts:
        try:
            nums.append(int(p))
        except ValueError:
            break
    while len(nums) < 3:
        nums.append(0)
    return nums[:3]

def is_version_vulnerable(installed: str, max_affected: str) -> bool:
    try:
        inst_parts = parse_semver(installed)
        aff_parts = parse_semver(max_affected)
        return inst_parts <= aff_parts
    except Exception:
        return False

def parse_requirements_txt(path: Path) -> List[Dict[str, str]]:
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip().split("#")[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9a-zA-Z_\-\.]+)", line)
                if m:
                    packages.append({"name": m.group(1).lower(), "version": m.group(2), "ecosystem": "pypi", "file": str(path)})
    except Exception:
        pass
    return packages

def parse_package_json(path: Path) -> List[Dict[str, str]]:
    packages = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name, ver in deps.items():
                clean_ver = ver.lstrip("^~>=<")
                packages.append({"name": name.lower(), "version": clean_ver, "ecosystem": "npm", "file": str(path)})
    except Exception:
        pass
    return packages

def query_osv_api(package: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
    """Query Google OSV API for real-time CVE advisories."""
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {"name": package, "ecosystem": "PyPI" if ecosystem == "pypi" else "npm"},
        "version": version
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                res_data = json.loads(response.read().decode("utf-8"))
                return res_data.get("vulns", [])
    except Exception:
        pass
    return []

def audit_packages(packages: List[Dict[str, str]], allow_network: bool = False) -> List[Dict[str, Any]]:
    findings = []
    idx = 1000

    for pkg in packages:
        name = pkg["name"]
        ver = pkg["version"]
        eco = pkg["ecosystem"]
        file_path = pkg["file"]

        # Check offline database first
        if eco in OFFLINE_VULN_DB and name in OFFLINE_VULN_DB[eco]:
            for vuln in OFFLINE_VULN_DB[eco][name]:
                if is_version_vulnerable(ver, vuln["max_affected"]):
                    idx += 1
                    findings.append({
                        "finding_id": f"DEP-F-{idx}",
                        "title": f"Vulnerable Package: {name} ({vuln['cve']})",
                        "cwe": "CWE-1395",
                        "owasp": "A06:2021-Vulnerable and Outdated Components",
                        "ssdf": "RV.1.1",
                        "severity": vuln["severity"],
                        "confidence": 0.95,
                        "file": file_path,
                        "line": 1,
                        "source": "dependency_audit",
                        "tool": "secskill_dep_scan",
                        "evidence": f"Installed {name}=={ver} is vulnerable to {vuln['cve']} ({vuln['title']}). Fixed in {vuln['fixed']}.",
                        "status": "confirmed",
                        "metadata": {
                            "package": name,
                            "installed_version": ver,
                            "fixed_version": vuln["fixed"],
                            "cve": vuln["cve"]
                        }
                    })

        # Query OSV if consent and network allow
        if allow_network:
            osv_vulns = query_osv_api(name, ver, eco)
            for v in osv_vulns:
                cve_id = v.get("id", "OSV-ADVISORY")
                summary = v.get("summary", "Known vulnerability in third-party dependency")
                idx += 1
                findings.append({
                    "finding_id": f"DEP-F-{idx}",
                    "title": f"Vulnerable Dependency: {name} ({cve_id})",
                    "cwe": "CWE-1395",
                    "owasp": "A06:2021-Vulnerable and Outdated Components",
                    "ssdf": "RV.1.1",
                    "severity": "high",
                    "confidence": 0.90,
                    "file": file_path,
                    "line": 1,
                    "source": "dependency_audit",
                    "tool": "osv_api",
                    "evidence": f"OSV advisory {cve_id} detected for {name}=={ver}: {summary}",
                    "status": "confirmed",
                    "metadata": {
                        "package": name,
                        "installed_version": ver,
                        "advisory": cve_id
                    }
                })

    return findings

def scan_dependencies(target_dir: str, allow_network: bool = False) -> List[Dict[str, Any]]:
    root = Path(target_dir).resolve()
    packages: List[Dict[str, str]] = []

    if root.is_file():
        if root.name == "requirements.txt":
            packages.extend(parse_requirements_txt(root))
        elif root.name == "package.json":
            packages.extend(parse_package_json(root))
    else:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.name == "requirements.txt":
                packages.extend(parse_requirements_txt(p))
            elif p.name == "package.json":
                packages.extend(parse_package_json(p))

    return audit_packages(packages, allow_network=allow_network)

def main():
    parser = argparse.ArgumentParser(description="SecSkill Dependency Vulnerability Auditor")
    parser.add_argument("target", nargs="?", default=".", help="Target repository or manifest file")
    parser.add_argument("--consent", action="store_true", help="Allow external network requests to query OSV API")
    parser.add_argument("-o", "--output", help="Optional output JSON file")
    args = parser.parse_args()

    findings = scan_dependencies(args.target, allow_network=args.consent)
    out_json = json.dumps(findings, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"Dependency audit written to {args.output}")
    else:
        print(out_json)

if __name__ == "__main__":
    main()


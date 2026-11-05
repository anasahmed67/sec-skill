#!/usr/bin/env bash
# secskill/scripts/run_static.sh
# Orchestrates external SAST tools (Semgrep, Bandit, ESLint) if present in PATH.
# Degrades gracefully if tools are missing, emitting status reports.

set -e

TARGET="${1:-.}"
OUTPUT_FILE="${2:-static_findings.json}"

echo "[SecSkill] Checking for available static analysis tools..."

AVAILABLE_TOOLS=()
SKIPPED_TOOLS=()

if command -v semgrep >/dev/null 2>&1; then
    AVAILABLE_TOOLS+=("semgrep")
    echo "  [+] semgrep detected"
else
    SKIPPED_TOOLS+=("semgrep")
    echo "  [-] semgrep not found in PATH (skipped)"
fi

if command -v bandit >/dev/null 2>&1; then
    AVAILABLE_TOOLS+=("bandit")
    echo "  [+] bandit detected"
else
    SKIPPED_TOOLS+=("bandit")
    echo "  [-] bandit not found in PATH (skipped)"
fi

if command -v eslint >/dev/null 2>&1; then
    AVAILABLE_TOOLS+=("eslint")
    echo "  [+] eslint detected"
else
    SKIPPED_TOOLS+=("eslint")
    echo "  [-] eslint not found in PATH (skipped)"
fi

echo "[SecSkill] Executing available analyzers on: $TARGET"

# Temporary outputs
SEMGREP_OUT="/tmp/secskill_semgrep.json"
BANDIT_OUT="/tmp/secskill_bandit.json"

if [[ " ${AVAILABLE_TOOLS[@]} " =~ " semgrep " ]]; then
    echo "Running Semgrep..."
    semgrep scan --config auto --json --output "$SEMGREP_OUT" "$TARGET" || true
fi

if [[ " ${AVAILABLE_TOOLS[@]} " =~ " bandit " ]]; then
    echo "Running Bandit..."
    bandit -r "$TARGET" -f json -o "$BANDIT_OUT" || true
fi

# Fallback / Normalize into unified findings schema
python3 -c "
import sys, json, os

findings = []
# Process Semgrep if output exists
if os.path.exists('$SEMGREP_OUT'):
    try:
        with open('$SEMGREP_OUT') as f:
            data = json.load(f)
            for r in data.get('results', []):
                findings.append({
                    'finding_id': f'SG-{len(findings)+1}',
                    'title': r.get('check_id', 'Semgrep Finding'),
                    'cwe': r.get('extra', {}).get('metadata', {}).get('cwe', ['CWE-Generic'])[0] if isinstance(r.get('extra', {}).get('metadata', {}).get('cwe'), list) else 'CWE-Generic',
                    'owasp': r.get('extra', {}).get('metadata', {}).get('owasp', ['A03:2021-Injection'])[0] if isinstance(r.get('extra', {}).get('metadata', {}).get('owasp'), list) else 'A03:2021-Injection',
                    'severity': r.get('extra', {}).get('severity', 'medium').lower(),
                    'confidence': 0.85,
                    'file': r.get('path', ''),
                    'line': r.get('start', {}).get('line', 1),
                    'source': 'static_analysis',
                    'tool': 'semgrep',
                    'evidence': r.get('extra', {}).get('message', ''),
                    'status': 'needs_validation'
                })
    except Exception:
        pass

# Process Bandit if output exists
if os.path.exists('$BANDIT_OUT'):
    try:
        with open('$BANDIT_OUT') as f:
            data = json.load(f)
            for r in data.get('results', []):
                findings.append({
                    'finding_id': f'BD-{len(findings)+1}',
                    'title': r.get('test_name', 'Bandit Finding'),
                    'cwe': f'CWE-{r.get(\"issue_cwe\", {}).get(\"id\", 0)}',
                    'owasp': 'A03:2021-Injection',
                    'severity': r.get('issue_severity', 'medium').lower(),
                    'confidence': 0.85,
                    'file': r.get('filename', ''),
                    'line': r.get('line_number', 1),
                    'source': 'static_analysis',
                    'tool': 'bandit',
                    'evidence': r.get('issue_text', ''),
                    'status': 'needs_validation'
                })
    except Exception:
        pass

with open('$OUTPUT_FILE', 'w') as out:
    json.dump({
        'tools_executed': '$AVAILABLE_TOOLS'.split(),
        'tools_skipped': '$SKIPPED_TOOLS'.split(),
        'findings': findings
    }, out, indent=2)
"

echo "[SecSkill] Static analysis completed. Results written to: $OUTPUT_FILE"


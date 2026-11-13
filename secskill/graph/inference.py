"""Threat modeling and attack path domain inference logic."""
from typing import Dict, Any
from secskill.models import Finding

def infer_attack_path(finding: Finding) -> Dict[str, Any]:
    """Infer structured source-to-sink steps from a finding."""
    cwe = (finding.cwe_id or "").upper()
    title = finding.title
    file_path = finding.file_path
    line = finding.line_number

    if "89" in cwe or "SQL" in title.upper():
        return {
            "source": "HTTP Request (query/body parameter)",
            "source_type": "Untrusted User Input",
            "route": f"Endpoint Handler ({file_path})",
            "flaw": "String Interpolation / Missing Parameter Binding",
            "sink": f"cursor.execute() ({file_path}:{line})",
            "impact": "Database Records Exfiltrated / Auth Bypass",
            "target_asset": "Production Database (SQL)",
            "target_type": "Database",
            "eli5": "The application takes raw text entered by a user and directly concatenates it into a database query. An attacker can supply SQL syntax to dump entire tables or bypass authentication.",
            "quick_fix": '# Use parameterized queries instead of string concatenation:\ncursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        }
    elif "78" in cwe or "COMMAND" in title.upper():
        return {
            "source": "User CLI / API Argument",
            "source_type": "Untrusted Parameter",
            "route": f"System Call Wrapper ({file_path})",
            "flaw": "shell=True with Unescaped Metacharacters",
            "sink": f"OS Command Execution ({file_path}:{line})",
            "impact": "Arbitrary Remote Command Execution (RCE)",
            "target_asset": "Host Operating System Shell",
            "target_type": "Operating System",
            "eli5": "The application runs a shell command using text supplied by the user. An attacker can append metacharacters to execute arbitrary shell commands with server privileges.",
            "quick_fix": "# Pass arguments as a discrete list with shell=False:\nimport subprocess\nsubprocess.run(['ping', '-c', '1', host], shell=False, check=True)",
        }
    elif "79" in cwe or "XSS" in title.upper():
        return {
            "source": "URL Query / Form Input",
            "source_type": "Unsanitized String",
            "route": f"View Template / Handler ({file_path})",
            "flaw": "Missing HTML Entity Escaping (DOMPurify/escapeHtml)",
            "sink": f"Direct HTML Response ({file_path}:{line})",
            "impact": "Client Browser Session Token Theft (XSS)",
            "target_asset": "Victim Browser & Session Tokens",
            "target_type": "Client Session",
            "eli5": "User input is returned in a web page without proper encoding. An attacker can inject malicious JavaScript that executes in the browser of any user viewing the page.",
            "quick_fix": "# Escape output contextually or use safe template bindings:\nimport html\nsafe_output = html.escape(user_input)",
        }
    elif "22" in cwe or "TRAVERSAL" in title.upper() or "PATH" in title.upper():
        return {
            "source": "File Download Request Parameter",
            "source_type": "Relative Path with '../'",
            "route": f"File Loader ({file_path})",
            "flaw": "Missing Canonical Path Validation (resolve())",
            "sink": f"open() File System Sink ({file_path}:{line})",
            "impact": "Arbitrary File Disclosure (/etc/passwd, secrets)",
            "target_asset": "Host File System & Local Files",
            "target_type": "Filesystem",
            "eli5": "A filename parameter allows traversal sequences, enabling an attacker to escape the designated folder to read sensitive configuration and system files.",
            "quick_fix": "# Canonicalize path and ensure it stays inside base folder:\nfrom pathlib import Path\nsafe_path = (BASE_DIR / filename).resolve()\nif not str(safe_path).startswith(str(BASE_DIR)):\n    raise PermissionError('Path traversal blocked')",
        }
    elif "798" in cwe or "321" in cwe or "SECRET" in title.upper() or "KEY" in title.upper():
        return {
            "source": f"Hardcoded Credential in Code ({file_path}:{line})",
            "source_type": "Static Secret in Git History",
            "route": "Module Initialization",
            "flaw": "Token Hardcoded Instead of Vault / Environment Variable",
            "sink": "Cloud / Third-Party Provider API",
            "impact": "Full Unauthorized Cloud Account Takeover",
            "target_asset": "Cloud Infrastructure & Third-Party APIs",
            "target_type": "Secrets Vault",
            "eli5": "An API key or private secret is hardcoded in source files. Anyone who gains access to the repository can impersonate your system and access cloud assets.",
            "quick_fix": "# Load secrets dynamically from environment variables:\nimport os\napi_key = os.environ.get('API_SECRET_KEY')",
        }
    elif "74" in cwe or "PROMPT" in title.upper() or "LLM" in title.upper():
        return {
            "source": "User Chat / Feedback String",
            "source_type": "Untrusted Prompt Injection",
            "route": f"Agent Prompt Builder ({file_path})",
            "flaw": "Prompt Concatenation without Role / XML Tagging",
            "sink": f"llm.generate() / Tool Sink ({file_path}:{line})",
            "impact": "Agent Instruction Hijack & Unauthorized Tool Calling",
            "target_asset": "AI Agent Execution Engine & Tools",
            "target_type": "AI Runtime",
            "eli5": "Untrusted user text is merged directly into system instructions. An attacker can override instructions to trigger unauthorized tool actions.",
            "quick_fix": "# Isolate user input with clear demarcation:\nsystem_prompt = 'You are a helpful assistant.'\nuser_content = f'<user_input>\\n{raw_user_input}\\n</user_input>'",
        }
    else:
        return {
            "source": "External Untrusted Input",
            "source_type": "User-Controlled Data",
            "route": f"Application Logic ({file_path})",
            "flaw": finding.title,
            "sink": f"Sensitive Execution Sink ({file_path}:{line})",
            "impact": "Potential Confidentiality or Integrity Breach",
            "target_asset": "Application State & Resources",
            "target_type": "Application",
            "eli5": f"Unvalidated data reaches a sensitive execution sink without verification. {finding.description}",
            "quick_fix": "# Validate input and enforce strict authorization:\nassert is_valid(user_input), 'Invalid input format'",
        }


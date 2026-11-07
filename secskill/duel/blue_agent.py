"""Blue Team Defender Agent for SecSkill Duel Arena."""
import json
import difflib
from typing import Optional, Dict, Any
from secskill.duel.models import DefensePatch, AttackPayload
from secskill.llm.ollama_provider import OllamaProvider
from secskill.llm.openai_provider import OpenAIProvider
from secskill.llm.anthropic_provider import AnthropicProvider

BLUE_SYSTEM_PROMPT = """You are an Elite Defensive Blue Team Security Architect in the SecSkill Duel Arena.
Your mission is to take vulnerable code and write an impenetrable defensive patch that completely hardens the AST and neutralizes all taint dataflows.
Analyze the incoming attack payload and SecSkill AST referee feedback.
Never use naive blacklist string replacement.
Ensure:
1. SQL: Use parameterized queries with bound placeholders (%s or ?) passed as driver arguments.
2. OS Command: Use subprocess argument lists with shell=False.
3. Path Traversal: Canonicalize with Path.resolve() and verify boundaries with is_relative_to().
4. XSS: Encode using html.escape() or DOMPurify.sanitize().

Output ONLY a valid JSON object matching this schema:
{
  "strategy": "<concise name of defensive strategy>",
  "code": "<complete hardened python code>",
  "explanation": "<why this patch neutralizes the attack and hardens the AST>"
}
"""

HARDENED_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "naive": (
            "# Naive defense attempt: blacklist strip (vulnerable to WAF bypass)\n"
            "def query_user(user_input):\n"
            "    sanitized = user_input.replace(\"'\", \"\").replace(\"--\", \"\")\n"
            "    query = f\"SELECT * FROM users WHERE username = '{sanitized}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()\n"
        ),
        "hardened": (
            "# Hardened defense: DB-API parameterization with bound placeholder tuple\n"
            "def query_user(user_input):\n"
            "    query = \"SELECT * FROM users WHERE username = %s\"\n"
            "    cursor.execute(query, (user_input,))\n"
            "    return cursor.fetchall()\n"
        ),
        "naive_strategy": "Blacklist Character Stripping (.replace)",
        "hardened_strategy": "DB-API Parameterized Query with Driver Placeholders",
        "hardened_explanation": (
            "Separates SQL code from user data in the AST grammar. The database driver treats the payload "
            "as a literal string scalar, preventing SQL token re-lexing and rendering all injection vectors inert."
        ),
    },
    "cmdi": {
        "naive": (
            "# Naive defense attempt: strip semicolons\n"
            "def ping_host(hostname):\n"
            "    clean_host = hostname.replace(';', '').replace('&', '')\n"
            "    os.system(f\"ping -c 1 {clean_host}\")\n"
        ),
        "hardened": (
            "# Hardened defense: Subprocess argument list with shell=False\n"
            "import subprocess\n"
            "def ping_host(hostname):\n"
            "    result = subprocess.run([\"ping\", \"-c\", \"1\", hostname], shell=False, capture_output=True, check=True)\n"
            "    return result.stdout\n"
        ),
        "naive_strategy": "Character Blacklist Sanitization",
        "hardened_strategy": "Subprocess Argument List Isolation (shell=False)",
        "hardened_explanation": (
            "Bypasses the system shell interpreter completely. Arguments are passed directly to execve syscall, "
            "neutralizing command chaining, backticks, $IFS, and subshell injection."
        ),
    },
    "path-traversal": {
        "naive": (
            "# Naive defense attempt: replace ../\n"
            "def read_file(filename):\n"
            "    safe_name = filename.replace('../', '')\n"
            "    with open(f\"/var/www/uploads/{safe_name}\", 'r') as f:\n"
            "        return f.read()\n"
        ),
        "hardened": (
            "# Hardened defense: Canonical path resolution and boundary verification\n"
            "from pathlib import Path\n"
            "def read_file(filename):\n"
            "    base_dir = Path(\"/var/www/uploads\").resolve()\n"
            "    target = (base_dir / filename).resolve()\n"
            "    if not target.is_relative_to(base_dir):\n"
            "        raise PermissionError(\"Path traversal detected: Access Denied\")\n"
            "    with open(target, 'r') as f:\n"
            "        return f.read()\n"
        ),
        "naive_strategy": "Single-Pass Relative Path Removal",
        "hardened_strategy": "Canonical Path Boundary Assertion (Path.resolve + is_relative_to)",
        "hardened_explanation": (
            "Resolves symlinks and relative segments canonically before checking that the target path "
            "strictly resides within the trusted base directory boundary."
        ),
    },
    "xss": {
        "naive": (
            "# Naive defense: strip <script>\n"
            "def render_greeting(user_name):\n"
            "    cleaned = user_name.replace('<script>', '')\n"
            "    return f\"<h1>Welcome, {cleaned}</h1>\"\n"
        ),
        "hardened": (
            "# Hardened defense: Context-aware HTML entity escaping\n"
            "import html\n"
            "def render_greeting(user_name):\n"
            "    escaped = html.escape(user_name, quote=True)\n"
            "    return f\"<h1>Welcome, {escaped}</h1>\"\n"
        ),
        "naive_strategy": "Regex/Tag Blacklist Removal",
        "hardened_strategy": "Context-Aware HTML Entity Escaping (html.escape)",
        "hardened_explanation": (
            "Encodes special HTML characters (<, >, &, \", ') into harmless HTML entities (&lt;, &gt;, &quot;), "
            "preventing browser DOM mutation and script execution."
        ),
    },
}


class BlueTeamAgent:
    """Defender Agent that writes defensive patches to harden code against Red Team exploits."""

    def __init__(
        self,
        model_name: str = "codellama",
        provider_name: str = "ollama",
    ):
        self.model_name = model_name
        self.provider_name = provider_name
        self.llm_provider = self._init_provider()

    def _init_provider(self):
        if self.provider_name == "openai":
            return OpenAIProvider(model=self.model_name)
        elif self.provider_name == "anthropic":
            return AnthropicProvider(model=self.model_name)
        elif self.provider_name == "ollama":
            return OllamaProvider(model=self.model_name)
        return None

    def create_patch(
        self,
        original_code: str,
        vuln_type: str,
        round_number: int,
        total_rounds: int,
        red_payload: AttackPayload,
        referee_feedback: str = "",
    ) -> DefensePatch:
        """Generate a defensive patch using Local LLM or adaptive defense playbook."""
        # Try local LLM generation first if available
        if self.llm_provider and self.provider_name in ["ollama", "openai", "anthropic"]:
            try:
                user_prompt = (
                    f"Round: {round_number}/{total_rounds}\n"
                    f"Target Vulnerability: {vuln_type}\n"
                    f"Red Team Payload Used:\n"
                    f"Name: {red_payload.name}\n"
                    f"Payload: {red_payload.payload}\n"
                    f"Bypass Technique: {red_payload.bypass_technique}\n"
                    f"SecSkill Referee Feedback:\n{referee_feedback}\n\n"
                    f"Vulnerable Code:\n```\n{original_code}\n```\n\n"
                    f"Write a hardened, impenetrable patch. Return valid JSON."
                )
                raw_response = self.llm_provider.generate(user_prompt, system_prompt=BLUE_SYSTEM_PROMPT)
                parsed = self._extract_json(raw_response)
                if parsed and "code" in parsed:
                    code = parsed["code"]
                    diff = self._generate_diff(original_code, code)
                    return DefensePatch(
                        strategy=parsed.get("strategy", f"LLM Hardened Patch R{round_number}"),
                        code=code,
                        diff=diff,
                        explanation=parsed.get("explanation", "AST hardened against injection sinks."),
                    )
            except Exception:
                pass

        # Adaptive Defense Playbook
        return self._playbook_patch(original_code, vuln_type, round_number, total_rounds)

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        try:
            if "{" in text and "}" in text:
                start = text.index("{")
                end = text.rindex("}") + 1
                return json.loads(text[start:end])
        except Exception:
            pass
        return None

    def _playbook_patch(
        self,
        original_code: str,
        vuln_type: str,
        round_number: int,
        total_rounds: int,
    ) -> DefensePatch:
        vuln_key = "sqli"
        vuln_lower = vuln_type.lower()
        if "cmd" in vuln_lower or "78" in vuln_lower:
            vuln_key = "cmdi"
        elif "path" in vuln_lower or "22" in vuln_lower:
            vuln_key = "path-traversal"
        elif "xss" in vuln_lower or "79" in vuln_lower:
            vuln_key = "xss"

        template = HARDENED_TEMPLATES.get(vuln_key, HARDENED_TEMPLATES["sqli"])

        # In a multi-round duel (3+ rounds), Round 1 demonstrates an adaptive intermediate attempt
        # so Red can demonstrate a WAF bypass and Blue learns and hardens AST on Round 2!
        if round_number == 1 and total_rounds >= 3:
            code = template["naive"]
            strategy = template["naive_strategy"]
            explanation = "Initial filter attempt using blacklist string replacement."
        else:
            # Bulletproof hardened defense
            code = template["hardened"]
            strategy = template["hardened_strategy"]
            explanation = template["hardened_explanation"]

        diff = self._generate_diff(original_code, code)
        return DefensePatch(
            strategy=strategy,
            code=code,
            diff=diff,
            explanation=explanation,
        )

    def _generate_diff(self, old_code: str, new_code: str) -> str:
        old_lines = old_code.splitlines(keepends=True)
        new_lines = new_code.splitlines(keepends=True)
        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile="vulnerable_code.py",
            tofile="hardened_code.py",
            lineterm="",
        )
        return "".join(diff)


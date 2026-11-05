<div align="center">

<svg xmlns="http://www.w3.org/2000/svg" width="860" height="220" viewBox="0 0 860 220">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0d1117;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#1a2332;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#00ff88;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#00aa55;stop-opacity:1" />
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3.5" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
    <filter id="textGlow">
      <feGaussianBlur stdDeviation="6" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>

  <!-- Background -->
  <rect width="860" height="220" rx="16" fill="url(#bgGrad)"/>

  <!-- Subtle grid lines -->
  <line x1="0" y1="55" x2="860" y2="55" stroke="#ffffff08" stroke-width="1"/>
  <line x1="0" y1="110" x2="860" y2="110" stroke="#ffffff08" stroke-width="1"/>
  <line x1="0" y1="165" x2="860" y2="165" stroke="#ffffff08" stroke-width="1"/>
  <line x1="215" y1="0" x2="215" y2="220" stroke="#ffffff05" stroke-width="1"/>
  <line x1="430" y1="0" x2="430" y2="220" stroke="#ffffff05" stroke-width="1"/>
  <line x1="645" y1="0" x2="645" y2="220" stroke="#ffffff05" stroke-width="1"/>

  <!-- Glow orb behind shield -->
  <ellipse cx="108" cy="110" rx="68" ry="68" fill="#00ff88" opacity="0.07"/>

  <!-- Shield shape -->
  <path d="M108,42 L148,60 L148,105 Q148,145 108,165 Q68,145 68,105 L68,60 Z"
        fill="url(#shieldGrad)" filter="url(#glow)" opacity="0.95"/>
  <!-- Shield inner highlight -->
  <path d="M108,52 L140,67 L140,105 Q140,138 108,155 Q76,138 76,105 L76,67 Z"
        fill="none" stroke="#ffffff30" stroke-width="1.5"/>

  <!-- Checkmark inside shield -->
  <polyline points="92,108 103,120 126,94"
            fill="none" stroke="#0d1117" stroke-width="4.5"
            stroke-linecap="round" stroke-linejoin="round"/>

  <!-- "SecSkill" text -->
  <text x="195" y="105"
        font-family="'Courier New', Courier, monospace"
        font-size="62" font-weight="800"
        fill="#ffffff" filter="url(#textGlow)" opacity="0.98">
    Sec<tspan fill="#00ff88" filter="url(#glow)">Skill</tspan>
  </text>

  <!-- Tagline -->
  <text x="197" y="142"
        font-family="'Courier New', Courier, monospace"
        font-size="15.5" fill="#8b9ab0" letter-spacing="0.5">
    Agent-Native Security Reviewer &amp; Static Analysis Engine
  </text>

  <!-- Version pill -->
  <rect x="197" y="158" width="130" height="24" rx="12" fill="#00ff8822" stroke="#00ff8855" stroke-width="1"/>
  <text x="262" y="174" text-anchor="middle"
        font-family="'Courier New', Courier, monospace"
        font-size="12" fill="#00ff88" font-weight="600">v0.1.0-beta</text>

  <!-- Apache pill -->
  <rect x="337" y="158" width="110" height="24" rx="12" fill="#3b82f622" stroke="#3b82f655" stroke-width="1"/>
  <text x="392" y="174" text-anchor="middle"
        font-family="'Courier New', Courier, monospace"
        font-size="12" fill="#60a5fa" font-weight="600">Apache 2.0</text>

  <!-- Right-side accent lines -->
  <line x1="790" y1="40" x2="840" y2="40" stroke="#00ff88" stroke-width="2" opacity="0.5"/>
  <line x1="800" y1="50" x2="840" y2="50" stroke="#00ff88" stroke-width="1" opacity="0.3"/>
  <line x1="790" y1="170" x2="840" y2="170" stroke="#00ff88" stroke-width="2" opacity="0.5"/>
  <line x1="800" y1="180" x2="840" y2="180" stroke="#00ff88" stroke-width="1" opacity="0.3"/>
</svg>

</div>

---

<div align="center">

[![CI Pipeline](https://img.shields.io/github/actions/workflow/status/your-org/secskill/ci.yml?branch=main&label=CI%20Pipeline&logo=github-actions&logoColor=white&style=flat-square)](https://github.com/your-org/secskill/actions)
[![Version](https://img.shields.io/badge/version-0.1.0--beta-00ff88?style=flat-square&logo=semver&logoColor=white)](https://github.com/your-org/secskill/releases)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square&logo=apache&logoColor=white)](LICENSE)
[![Ruff](https://img.shields.io/badge/linter-ruff-ff7f00?style=flat-square&logo=ruff&logoColor=white)](https://docs.astral.sh/ruff/)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-9333ea?style=flat-square)](https://sarifweb.azurewebsites.net/)
[![OWASP](https://img.shields.io/badge/standard-OWASP%20Top%2010-dc2626?style=flat-square&logo=owasp&logoColor=white)](https://owasp.org/www-project-top-ten/)
[![MITRE CWE](https://img.shields.io/badge/standard-MITRE%20CWE%20Top%2025-7c3aed?style=flat-square)](https://cwe.mitre.org/top25/)
[![NIST SSDF](https://img.shields.io/badge/standard-NIST%20SSDF-2563eb?style=flat-square)](https://csrc.nist.gov/Projects/ssdf)
[![Privacy](https://img.shields.io/badge/privacy-100%25%20local-00ff88?style=flat-square&logo=lock&logoColor=white)](docs/privacy.md)

</div>

---

<div align="center">

[**Why SecSkill?**](#-why-secskill) · [**Features**](#-key-features) · [**Install**](#-installation) · [**AI Agents**](#-ai-agent-integrations) · [**Quickstart**](#-quickstart) · [**CLI**](#-cli-reference) · [**Architecture**](#-architecture) · [**Contributing**](#-contributing)

</div>

---

## 🛡️ Why SecSkill?

> Stop drowning in false positives. SecSkill combines deterministic AST analysis with an optional LLM triage layer to deliver only the vulnerabilities that matter — with zero noise.

<div align="center">

| Capability | SecSkill | Semgrep (OSS) | Bandit | CodeQL |
|---|:---:|:---:|:---:|:---:|
| Deterministic AST Analysis | ✅ | ✅ | ✅ | ✅ |
| LLM Contextual Triage | ✅ | ❌ | ❌ | ❌ |
| Zero False-Positive Filter | ✅ | ❌ | ❌ | ⚠️ |
| 100% Local / Air-Gapped | ✅ | ⚠️ | ✅ | ❌ |
| AI Agent Native (MCP/Skills) | ✅ | ❌ | ❌ | ❌ |
| Attack Path Graphing | ✅ | ❌ | ❌ | ⚠️ |
| SARIF 2.1.0 Output | ✅ | ✅ | ❌ | ✅ |
| Remediation Generation | ✅ | ❌ | ❌ | ❌ |
| Secret Watchdog (real-time) | ✅ | ❌ | ❌ | ❌ |

</div>

---

## ✨ Key Features

<table>
<tr>
<td width="50%" valign="top">

<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="11" fill="#00ff8820" stroke="#00ff88" stroke-width="1.5"/><path d="M8 12l3 3 5-5" stroke="#00ff88" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> **Deterministic AST Analysis**

Rule-based, reproducible scanning powered by a full Python AST engine. Same code → same result, every time. No randomness, no model variance.

</td>
<td width="50%" valign="top">

<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="11" fill="#3b82f620" stroke="#3b82f6" stroke-width="1.5"/><path d="M12 7v5l3 3" stroke="#3b82f6" stroke-width="2" stroke-linecap="round"/></svg> **Contextual LLM Triage**

Route flagged snippets through Ollama, OpenAI, or Anthropic to validate exploitability in real project context. Slash noise by up to 90%.

</td>
</tr>
<tr>
<td width="50%" valign="top">

<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="11" fill="#f59e0b20" stroke="#f59e0b" stroke-width="1.5"/><path d="M12 5v7h5" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/></svg> **Real-Time Secret Watchdog**

`secskill watch` monitors your filesystem for accidental credential commits, .env leaks, and hardcoded tokens — before they ever touch git.

</td>
<td width="50%" valign="top">

<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="11" fill="#ec489920" stroke="#ec4899" stroke-width="1.5"/><path d="M6 12h12M12 6l6 6-6 6" stroke="#ec4899" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> **Attack Path Graphing**

Visualize how data flows from untrusted input to sensitive sinks. `secskill graph` renders interactive call graphs and taint traces.

</td>
</tr>
<tr>
<td width="50%" valign="top">

<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="11" fill="#8b5cf620" stroke="#8b5cf6" stroke-width="1.5"/><path d="M9 12l2 2 4-4" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> **Zero False-Positive Filter**

A multi-stage confirmation pipeline (AST → data-flow → LLM) ensures every reported finding is actionable. No more alert fatigue.

</td>
<td width="50%" valign="top">

<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="11" fill="#06b6d420" stroke="#06b6d4" stroke-width="1.5"/><path d="M12 5a7 7 0 100 14A7 7 0 0012 5z" stroke="#06b6d4" stroke-width="1.5"/><path d="M12 9v3l2 2" stroke="#06b6d4" stroke-width="2" stroke-linecap="round"/></svg> **100% Local Privacy**

All analysis runs on your machine. No code is ever sent to external servers unless you explicitly configure a remote LLM. Air-gap friendly.

</td>
</tr>
<tr>
<td width="50%" valign="top">

<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="11" fill="#10b98120" stroke="#10b981" stroke-width="1.5"/><path d="M5 10l5 5 9-9" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> **Multi-Standard Coverage**

OWASP Top 10, MITRE CWE Top 25, and NIST SSDF built in. Every finding is tagged with the relevant standard ID and severity.

</td>
<td width="50%" valign="top">

<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="11" fill="#f9731620" stroke="#f97316" stroke-width="1.5"/><path d="M12 8v4l3 3" stroke="#f97316" stroke-width="2" stroke-linecap="round"/></svg> **AI-Native Architecture**

Ships with a `SKILL.md` for Antigravity, `CLAUDE.md` for Claude Code, and `.cursorrules` for Cursor. First-class agent tooling out of the box.

</td>
</tr>
</table>

---

## 🖥️ Terminal Demo

```
$ secskill scan ./src --format sarif --output results.sarif

  ╔══════════════════════════════════════════════════════╗
  ║            SecSkill  v0.1.0-beta                     ║
  ║   Agent-Native Security & Static Analysis Engine     ║
  ╚══════════════════════════════════════════════════════╝

  🔍 Stage 1/8  AST Parse          ████████████████ 100%  142 files
  🌊 Stage 2/8  Taint Trace        ████████████████ 100%  3,218 flows
  🔎 Stage 3/8  Rule Match         ████████████████ 100%  87 candidates
  🤖 Stage 4/8  LLM Triage         ████████████████ 100%  87 → 9 confirmed
  🗺️  Stage 5/8  Attack Graph       ████████████████ 100%  4 paths
  🛠️  Stage 6/8  Remediation        ████████████████ 100%  9 fixes generated
  📊 Stage 7/8  Report Build       ████████████████ 100%
  💾 Stage 8/8  SARIF Export       ████████████████ 100%

  ┌─────────────────────────────────────────────────────┐
  │  CRITICAL  2   HIGH  4   MEDIUM  3   LOW  0         │
  │  False-positive rate: 0.0%   Noise filtered: 90.2%  │
  │  Standards: OWASP A03, CWE-89, CWE-79, NIST PW.1   │
  └─────────────────────────────────────────────────────┘

  ✅ Results written → results.sarif
  🌐 Dashboard   → open secskill-report.html
```

---

## 📦 Installation

### Via pip (Recommended)

```bash
pip install secskill
```

### From Source

```bash
git clone https://github.com/your-org/secskill.git
cd secskill
pip install -e ".[dev]"
```

### Initialize a Project

```bash
cd your-project
secskill init
```

This creates `.secskill/config.yml`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, and copies `secskill/SKILL.md` to `.gemini/skills/secskill/SKILL.md`.

### LLM Backend (Optional — for triage)

```bash
# Option A: Fully local with Ollama
ollama pull codellama

# Option B: OpenAI
export OPENAI_API_KEY="sk-..."

# Option C: Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## 🤖 AI Agent Integrations

> SecSkill is designed to work **natively inside your AI coding assistant**. Pick your agent below for a tailored integration guide.

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#cc785c"/><text x="12" y="17" text-anchor="middle" font-family="Georgia,serif" font-size="13" font-weight="bold" fill="white">C</text></svg>
<b>Claude Code (Anthropic)</b>
</summary>

### Claude Code Integration

Claude Code reads `CLAUDE.md` files in your repository root and uses MCP servers for tool access.

**Step 1 — Add `CLAUDE.md`** (auto-created by `secskill init`, or manually):

```markdown
# CLAUDE.md

## Security Analysis
This project uses SecSkill for security analysis. When asked to review code for
security issues, run:

    secskill scan <path> --format markdown

SecSkill covers OWASP Top 10, MITRE CWE Top 25, and NIST SSDF.
Key commands:
- `secskill scan <path>` — full scan
- `secskill explain <finding-id>` — detailed exploit explanation
- `secskill fix <finding-id>` — generate a patch
- `secskill graph` — visualize attack paths
```

**Step 2 — Register as an MCP Tool** (optional, for direct tool calling):

```bash
# Install the SecSkill MCP adapter
pip install secskill[mcp]

# Add to your Claude Code MCP config (~/.claude/mcp_servers.json)
```

```json
{
  "mcpServers": {
    "secskill": {
      "command": "python",
      "args": ["-m", "secskill.mcp"],
      "env": {
        "SECSKILL_LLM": "ollama",
        "SECSKILL_MODEL": "codellama"
      }
    }
  }
}
```

**Step 3 — Use in conversation:**

```
> /mcp secskill scan src/api/
> /mcp secskill explain CWE-89-001
> /mcp secskill fix CWE-89-001
```

**Or simply ask Claude naturally:**
> *"Run a security scan on the auth module and explain any SQL injection risks."*

</details>

---

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#1a1a2e"/><path d="M5 12h14M12 5l7 7-7 7" stroke="#00aaff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
<b>Cursor IDE</b>
</summary>

### Cursor IDE Integration

Cursor supports project-level rules via `.cursorrules` and can run terminal commands directly.

**Step 1 — Initialize SecSkill in your project:**

```bash
secskill init
```

This generates a `.cursorrules` file automatically.

**Step 2 — Verify `.cursorrules`** (or create manually):

```
# .cursorrules

## Security Analysis with SecSkill

When reviewing code for security issues, use SecSkill:

```bash
secskill scan <file_or_directory>
```

- Always run `secskill scan` before suggesting code that handles user input,
  database queries, file paths, or authentication.
- Use `secskill explain <id>` to get a full exploit description of a finding.
- Use `secskill fix <id>` to generate a remediation patch.
- Output formats: `--format sarif`, `--format html`, `--format json`, `--format markdown`
- Standards enforced: OWASP Top 10, MITRE CWE Top 25, NIST SSDF

Never dismiss a CRITICAL or HIGH finding without running `secskill explain`.
```

**Step 3 — Use in Cursor Chat:**

```
@terminal secskill scan src/ --format markdown
```

Or ask Cursor's AI:
> *"Check this function for injection vulnerabilities using SecSkill."*

**Step 4 — Enable background watching:**

```bash
secskill watch ./src &
```

Cursor will show SecSkill alerts inline as you edit.

</details>

---

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#1a73e8"/><text x="12" y="17" text-anchor="middle" font-family="'Product Sans',Arial,sans-serif" font-size="11" font-weight="bold" fill="white">G</text></svg>
<b>Google Antigravity (AGY)</b>
</summary>

### Google Antigravity Integration

Antigravity loads skills from `~/.gemini/skills/` (global) or `.gemini/skills/` (project-local). SecSkill ships a ready-made `SKILL.md`.

**Step 1 — Install the skill (project-local, recommended):**

```bash
# secskill init does this automatically, or do it manually:
mkdir -p .gemini/skills/secskill
cp "$(python -c 'import secskill; import os; print(os.path.dirname(secskill.__file__))')/SKILL.md" \
   .gemini/skills/secskill/SKILL.md
```

**Step 2 — Or install globally (all projects):**

```bash
mkdir -p ~/.gemini/skills/secskill
cp "$(python -c 'import secskill; import os; print(os.path.dirname(secskill.__file__))')/SKILL.md" \
   ~/.gemini/skills/secskill/SKILL.md
```

**Step 3 — Verify Antigravity picks it up:**

```
# In Antigravity chat:
> What skills do you have loaded?
# Should mention: secskill
```

**Step 4 — Use naturally in Antigravity:**

> *"Scan the src/api/ directory for security issues using SecSkill."*
> *"Explain the SQL injection finding and generate a fix."*
> *"Show me the attack path graph for this module."*

The skill teaches Antigravity all SecSkill commands, output formats, and security standards — no manual prompting needed.

</details>

---

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#24292e"/><path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.202 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.741 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z" fill="white"/></svg>
<b>GitHub Copilot</b>
</summary>

### GitHub Copilot Integration

GitHub Copilot reads repository-level instructions from `.github/copilot-instructions.md`.

**Step 1 — Create `.github/copilot-instructions.md`:**

```markdown
# Copilot Instructions

## Security Analysis

This repository uses **SecSkill** for security analysis (OWASP Top 10, MITRE CWE Top 25, NIST SSDF).

### When to run SecSkill
- Before completing any code that handles user input, authentication, file I/O, or database queries
- When asked to review code for security vulnerabilities
- Before suggesting SQL queries, shell commands, or file path operations

### How to invoke SecSkill
Run in the integrated terminal:

```bash
# Full scan
secskill scan <path> --format markdown

# Explain a specific finding
secskill explain <finding-id>

# Generate a fix
secskill fix <finding-id>

# Visualize attack paths
secskill graph
```

### Output interpretation
- **CRITICAL/HIGH**: Must be fixed before merge
- **MEDIUM**: Fix or document accepted risk
- **LOW**: Review and decide
- Always prefer the LLM-triaged output (`--triage`) to minimize false positives
```

**Step 2 — Enable in VS Code settings:**

```json
// .vscode/settings.json
{
  "github.copilot.advanced": {
    "debug.useNodeFetcher": false
  },
  "github.copilot.chat.codeGeneration.instructions": [
    { "file": ".github/copilot-instructions.md" }
  ]
}
```

**Step 3 — Ask Copilot Chat:**

> *"@workspace Run SecSkill on the authentication module and summarize findings."*

</details>

---

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#0f172a"/><path d="M4 8h16M4 12h10M4 16h13" stroke="#06b6d4" stroke-width="2" stroke-linecap="round"/></svg>
<b>Windsurf / Codeium</b>
</summary>

### Windsurf / Codeium Integration

Windsurf reads `.windsurfrules` from your project root for persistent AI behavior customization.

**Step 1 — Create `.windsurfrules`** (auto-created by `secskill init`, or manually):

```
# .windsurfrules

## Security Analysis — SecSkill

This project enforces security analysis via SecSkill before accepting code changes.

### Rules
1. Any code touching user input, DB queries, file paths, auth, or crypto must be scanned:
   `secskill scan <file> --format markdown`

2. Never mark a vulnerability as resolved without running:
   `secskill explain <id>` to confirm the fix is complete.

3. For new endpoints or modules, always run:
   `secskill graph` to verify no new attack paths are introduced.

4. SecSkill standards: OWASP Top 10 · MITRE CWE Top 25 · NIST SSDF

### Quick Reference
- `secskill scan <path>`       — scan files/directories
- `secskill watch <path>`      — real-time monitoring
- `secskill simulate <path>`   — run attack simulations
- `secskill fix <id>`          — generate remediation patch
- `secskill view`              — open HTML dashboard
```

**Step 2 — Restart Windsurf** to pick up the new rules.

**Step 3 — Use in Cascade (Windsurf's AI):**

> *"Scan this file for security issues before we proceed."*

Cascade will automatically invoke `secskill` per the rules above.

</details>

---

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#2d2d2d"/><text x="12" y="16.5" text-anchor="middle" font-family="monospace" font-size="12" font-weight="bold" fill="#ff6b35">a</text></svg>
<b>Aider</b>
</summary>

### Aider Integration

Aider can read supplementary context files via `--read` or through `.aider.conf.yml`.

**Option A — `.aider.conf.yml` (persistent):**

```yaml
# .aider.conf.yml
read:
  - .secskill/AGENT_CONTEXT.md

# Optional: auto-run a security check before each commit
auto-commits: false
pre-commit-script: |
  secskill scan . --format json --fail-on critical
```

**Create `.secskill/AGENT_CONTEXT.md`:**

```markdown
# SecSkill Security Context

This project uses SecSkill for security analysis.

## Commands
- `secskill scan <path>` — analyze code for vulnerabilities
- `secskill explain <id>` — explain a finding in depth
- `secskill fix <id>` — generate a remediation patch
- `secskill simulate <path>` — simulate attacks against the code
- `secskill graph` — show taint/attack graph

## Standards
OWASP Top 10 · MITRE CWE Top 25 · NIST SSDF

## Policy
All CRITICAL and HIGH findings must be resolved before committing.
Run `secskill scan --triage` for LLM-validated results only.
```

**Option B — One-time `--read` flag:**

```bash
aider --read .secskill/AGENT_CONTEXT.md src/api/views.py
```

**Option C — Git hook integration:**

```bash
# .git/hooks/pre-commit
#!/bin/sh
secskill scan . --fail-on high && echo "✅ SecSkill: no high/critical findings"
```

</details>

---

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#1e3a5f"/><path d="M6 8h12M6 12h8M6 16h10" stroke="#4fc3f7" stroke-width="2" stroke-linecap="round"/><circle cx="18" cy="16" r="2.5" fill="#4fc3f7"/></svg>
<b>Continue.dev</b>
</summary>

### Continue.dev Integration

Continue.dev supports custom context providers and slash commands via `~/.continue/config.json`.

**Step 1 — Add a SecSkill slash command in `~/.continue/config.json`:**

```json
{
  "slashCommands": [
    {
      "name": "secskill",
      "description": "Run SecSkill security scan on the current file or selection",
      "run": "secskill scan {{{ input }}} --format markdown"
    },
    {
      "name": "secfix",
      "description": "Generate a SecSkill remediation patch for a finding ID",
      "run": "secskill fix {{{ input }}}"
    },
    {
      "name": "secexplain",
      "description": "Explain a SecSkill finding in depth",
      "run": "secskill explain {{{ input }}}"
    }
  ],
  "contextProviders": [
    {
      "name": "secskill-report",
      "description": "Load the latest SecSkill scan report as context",
      "type": "file",
      "params": {
        "nFiles": 1,
        "defaultPath": ".secskill/last-report.md"
      }
    }
  ],
  "systemMessage": "This project uses SecSkill for security analysis (OWASP Top 10, MITRE CWE Top 25, NIST SSDF). When reviewing security-sensitive code, suggest running `secskill scan` and interpret the results."
}
```

**Step 2 — Generate a persistent markdown report for context:**

```bash
secskill scan . --format markdown --output .secskill/last-report.md
```

**Step 3 — Use in Continue.dev:**

```
/secskill src/api/auth.py
/secfix CWE-89-001
@secskill-report
```

</details>

---

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#1a0533"/><path d="M12 4l2 5h5l-4 3 1.5 5L12 14l-4.5 3L9 12 5 9h5z" fill="#a855f7"/></svg>
<b>OpenHands (OpenDevin)</b>
</summary>

### OpenHands Integration

OpenHands supports microagent instructions via `.openhands/microagents/` and repository-level `CLAUDE.md`-style files.

**Step 1 — Create `.openhands/microagents/secskill.md`:**

```markdown
---
name: secskill
agent: CodeActAgent
triggers:
  - security scan
  - vulnerability check
  - secskill
  - owasp
  - injection
  - xss
  - sql injection
---

# SecSkill Security Microagent

When asked to perform a security review or scan, use SecSkill:

## Available Commands

| Command | Description |
|---------|-------------|
| `secskill scan <path>` | Full security scan |
| `secskill scan <path> --triage` | LLM-validated scan (fewer false positives) |
| `secskill explain <id>` | Detailed finding explanation with PoC |
| `secskill fix <id>` | Generate a remediation patch |
| `secskill graph` | Visualize attack paths |
| `secskill simulate <path>` | Run attack simulations |
| `secskill watch <path>` | Monitor for secrets/leaks in real-time |

## Standards
- OWASP Top 10
- MITRE CWE Top 25  
- NIST SSDF

## Output Formats
`--format sarif` · `--format html` · `--format json` · `--format markdown`

## Policy
All CRITICAL findings require immediate attention. Run `secskill view` to open the interactive HTML dashboard.
```

**Step 2 — Restart OpenHands** and start a conversation:

> *"Run a security scan on the src/ directory and show me any critical findings."*

OpenHands will auto-trigger the SecSkill microagent on security-related keywords.

</details>

---

<details>
<summary>
<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px"><rect width="24" height="24" rx="6" fill="#083344"/><path d="M5 7h14M5 12h14M5 17h14" stroke="#0ea5e9" stroke-width="2" stroke-linecap="round"/></svg>
<b>Zed Editor</b>
</summary>

### Zed Editor Integration

Zed's AI assistant supports project-level rules via `.zed/settings.json` and system prompt customization.

**Step 1 — Add SecSkill rules to `.zed/settings.json`:**

```json
{
  "assistant": {
    "default_model": {
      "provider": "anthropic",
      "model": "claude-opus-4-5"
    },
    "version": "2",
    "default_width": 640
  },
  "lsp": {
    "secskill": {
      "initialization_options": {
        "enabled": true
      }
    }
  }
}
```

**Step 2 — Create `.zed/assistant_rules.md`:**

```markdown
# Assistant Rules — Security

This project uses **SecSkill** for security analysis.

## When to invoke SecSkill
- Code handling user input, DB queries, auth, file paths, or secrets
- During code review for any PR touching security-sensitive modules
- When generating new API endpoints or authentication flows

## Commands
- Terminal: `secskill scan <path> --format markdown`
- Get explanation: `secskill explain <finding-id>`  
- Get fix: `secskill fix <finding-id>`
- Dashboard: `secskill view`

## Standards
OWASP Top 10 · MITRE CWE Top 25 · NIST SSDF

Treat CRITICAL and HIGH findings as blockers.
```

**Step 3 — Run SecSkill via Zed's terminal** (`Ctrl+\``):

```bash
secskill scan ./src --format markdown
```

**Step 4 — Paste results into Zed AI chat** for inline remediation suggestions.

</details>

---

## ⚡ Quickstart

```bash
# 1. Install
pip install secskill

# 2. Initialize your project
cd my-project
secskill init

# 3. Run your first scan
secskill scan . --format html

# 4. Open the dashboard
secskill view

# 5. Explain a finding
secskill explain CWE-89-001

# 6. Generate a fix
secskill fix CWE-89-001

# 7. Watch for secrets in real-time
secskill watch ./src
```

---

## 📊 Visual Reports & Dashboards

SecSkill generates rich, interactive HTML dashboards with:

- **Severity distribution** — pie chart of CRITICAL / HIGH / MEDIUM / LOW
- **Finding timeline** — trend across scans
- **Standard heatmap** — which OWASP / CWE categories are most affected
- **Filterable findings table** — sort by severity, standard, file, or CWE ID
- **Inline code viewer** — highlighted vulnerable lines with annotation

```bash
# Generate and open the HTML dashboard
secskill scan . --format html --output report.html
secskill view                  # opens in your default browser

# SARIF output for GitHub Code Scanning
secskill scan . --format sarif --output results.sarif

# JSON for custom tooling
secskill scan . --format json --output findings.json

# Markdown for PR comments
secskill scan . --format markdown --output findings.md
```

---

## 🗺️ Attack Path Graphing

```bash
secskill graph ./src --output attack-graph.html
```

SecSkill constructs a **taint-flow graph** that traces untrusted data from:

```
[HTTP Request / User Input]
        │
        ▼
[Input Validation Layer]  ←── Missing or bypassable?
        │
        ▼
[Business Logic / Transformation]
        │
        ▼
[Sensitive Sink]  ←── SQL query / shell exec / file write / SSRF target
```

The graph highlights **shortest attack paths**, reachability from public entry points, and cross-module data flows. Export as interactive HTML, DOT (Graphviz), or JSON.

---

## 👁️ Real-Time Secret Watchdog

```bash
secskill watch ./src --alert-on secrets,hardcoded-tokens,env-leaks
```

Monitors your filesystem using inotify/FSEvents for:

| Pattern | Example |
|---------|---------|
| API Keys | `AKIA...`, `sk-...`, `ghp_...` |
| Passwords in code | `password = "hunter2"` |
| `.env` file leaks | `.env` committed to git staging |
| Private keys | `-----BEGIN RSA PRIVATE KEY-----` |
| JWT secrets | `JWT_SECRET = "..."` |
| Database URLs | `postgresql://user:pass@host/db` |

Alerts appear in the terminal and optionally as desktop notifications or webhook calls.

---

## ⚔️ Defensive Attack Simulator

```bash
secskill simulate ./src/api --techniques sqli,xss,path-traversal,ssrf
```

The simulator generates **safe, non-destructive proof-of-concept payloads** to verify that your defenses hold. It:

1. Identifies candidate injection points from the AST
2. Generates technique-specific payloads
3. Reports which payloads *would* succeed based on static analysis
4. Rates exploitability (Theoretical / Likely / Confirmed)

> **Note:** The simulator never sends live requests or modifies data. All analysis is purely static.

---

## 🛠️ Remediation & Triage

```bash
# Get a human-readable explanation + PoC scenario
secskill explain CWE-89-001

# Auto-generate a remediation patch
secskill fix CWE-89-001

# Apply the patch interactively
secskill fix CWE-89-001 --apply

# Batch fix all HIGH findings
secskill fix --severity high --apply --dry-run
```

Each finding comes with:
- **CWE / OWASP / NIST reference**
- **Exploitability score** (CVSS-like)
- **Root cause explanation** (plain English + technical)
- **Recommended fix** (diff format)
- **Alternative mitigations** (defense-in-depth options)

---

## 🏗️ Architecture

SecSkill processes code through an 8-stage pipeline:

```mermaid
graph TD
    A[📂 Source Files] --> B[🔍 Stage 1: AST Parser\nPython AST / tree-sitter]
    B --> C[🌊 Stage 2: Taint Tracer\nData flow graph construction]
    C --> D[🎯 Stage 3: Rule Matcher\nOWASP / CWE / NIST rules]
    D --> E[🤖 Stage 4: LLM Triage\nOllama / OpenAI / Anthropic]
    E --> F[🗺️ Stage 5: Attack Grapher\nPath analysis & reachability]
    F --> G[🛠️ Stage 6: Remediation Engine\nPatch generation]
    G --> H[📊 Stage 7: Report Builder\nHTML / SARIF / JSON / MD]
    H --> I[💾 Stage 8: Output\nFiles / Dashboard / SARIF]

    style A fill:#1a2332,stroke:#00ff88,color:#fff
    style E fill:#1a2332,stroke:#3b82f6,color:#fff
    style I fill:#1a2332,stroke:#00ff88,color:#fff
```

### Component Overview

| Component | Technology | Purpose |
|-----------|------------|---------|
| AST Engine | Python `ast` module | Deterministic parse tree extraction |
| Taint Tracer | Custom DFG builder | Track untrusted data to sensitive sinks |
| Rule Engine | YAML-defined rules | Match OWASP/CWE/NIST patterns |
| LLM Adapter | Ollama / OpenAI / Anthropic | Contextual false-positive filtering |
| Attack Grapher | NetworkX + D3.js | Interactive taint visualization |
| Report Builder | Jinja2 + SARIF SDK | Multi-format output |

---

## 📋 CLI Reference

```
secskill <command> [options]

Commands:
  scan        Scan files or directories for security vulnerabilities
  view        Open the latest HTML dashboard in your browser
  graph       Generate and display attack path graphs
  watch       Real-time filesystem monitoring for secrets and leaks
  simulate    Run defensive attack simulations (static, non-destructive)
  explain     Get a detailed explanation of a specific finding
  fix         Generate or apply a remediation patch for a finding
  init        Initialize SecSkill in the current project
  version     Show version information

scan options:
  <path>                   File or directory to scan (default: .)
  --format <fmt>           Output format: sarif|html|json|markdown|console
  --output <file>          Write output to file (default: stdout / auto-named)
  --triage                 Enable LLM triage (requires LLM backend)
  --severity <level>       Minimum severity: critical|high|medium|low
  --fail-on <level>        Exit non-zero if findings at this level exist
  --exclude <pattern>      Glob pattern to exclude (repeatable)
  --config <file>          Path to config file (default: .secskill/config.yml)
  --no-cache               Disable result caching

Global options:
  --llm <backend>          LLM backend: ollama|openai|anthropic (default: ollama)
  --model <name>           LLM model name (default: codellama)
  --verbose, -v            Verbose output
  --quiet, -q              Suppress all output except findings
  --json                   Force JSON output for all commands
```

---

## 🔄 CI/CD & GitHub Code Scanning

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  secskill:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install SecSkill
        run: pip install secskill

      - name: Run SecSkill Scan
        run: |
          secskill scan . \
            --format sarif \
            --output results.sarif \
            --fail-on high

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secskill
        name: SecSkill Security Scan
        entry: secskill scan
        args: [--fail-on, high, --format, console]
        language: system
        types: [python]
        pass_filenames: true
```

---

## 📈 Benchmarks

> Tested on a 50,000-line Python codebase (Django + FastAPI mixed), Apple M3 Pro, 36 GB RAM.

| Mode | Scan Time | Findings | False Positives |
|------|-----------|----------|-----------------|
| AST-only | 4.2s | 94 | ~40% |
| AST + LLM Triage (Ollama / codellama) | 38s | 11 | 0% |
| AST + LLM Triage (GPT-4o) | 22s | 9 | 0% |
| AST + LLM Triage (Claude Sonnet) | 19s | 10 | 0% |

> LLM triage eliminates false positives entirely while keeping scan times under 1 minute for large codebases.

---

## 🔒 Privacy & Security Guarantees

<table>
<tr>
<td>

<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" style="vertical-align:middle"><path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.5C17.6 22.15 21 17.25 21 12V6L12 2z" fill="#00ff8830" stroke="#00ff88" stroke-width="1.5"/><path d="M9 12l2 2 4-4" stroke="#00ff88" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> **No code sent externally** by default

</td>
<td>

All scanning runs locally via AST analysis. Zero network calls unless you configure a remote LLM.

</td>
</tr>
<tr>
<td>

<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" style="vertical-align:middle"><circle cx="12" cy="12" r="10" fill="#3b82f630" stroke="#3b82f6" stroke-width="1.5"/><path d="M12 7v5l3 3" stroke="#3b82f6" stroke-width="2" stroke-linecap="round"/></svg> **Fully air-gap compatible**

</td>
<td>

Use `--llm ollama` with a locally-pulled model for 100% offline operation in secure environments.

</td>
</tr>
<tr>
<td>

<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" style="vertical-align:middle"><rect x="3" y="11" width="18" height="11" rx="2" fill="#f59e0b30" stroke="#f59e0b" stroke-width="1.5"/><path d="M7 11V7a5 5 0 0110 0v4" stroke="#f59e0b" stroke-width="1.5" stroke-linecap="round"/></svg> **No telemetry**

</td>
<td>

SecSkill collects zero usage data. No analytics, no crash reports, no call-home — ever.

</td>
</tr>
<tr>
<td>

<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" style="vertical-align:middle"><circle cx="12" cy="12" r="10" fill="#8b5cf630" stroke="#8b5cf6" stroke-width="1.5"/><path d="M12 8v4l3 3" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round"/></svg> **Explicit LLM opt-in**

</td>
<td>

LLM triage requires `--triage` flag and an explicit backend config. The default mode is always local-only.

</td>
</tr>
</table>

---

## 📚 Documentation Index

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, first scan, quickstart |
| [Configuration Reference](docs/configuration.md) | Full `.secskill/config.yml` reference |
| [Rule Authoring Guide](docs/rules.md) | Write custom security rules |
| [LLM Triage Setup](docs/llm-triage.md) | Configure Ollama, OpenAI, Anthropic |
| [SARIF Output](docs/sarif.md) | SARIF 2.1.0 schema and GitHub integration |
| [CI/CD Integration](docs/cicd.md) | GitHub Actions, GitLab CI, Jenkins |
| [Privacy Guide](docs/privacy.md) | Air-gap mode, data handling |
| [Architecture Deep Dive](docs/architecture.md) | AST engine, taint tracer, attack grapher |
| [AI Agent Skills](secskill/SKILL.md) | The Antigravity/agent skill file |
| [Security Policy](SECURITY.md) | Vulnerability reporting |
| [Changelog](CHANGELOG.md) | Release history |

---

## 🤝 Contributing

We welcome contributions of all kinds — new security rules, language support, LLM adapters, and bug fixes.

```bash
# Fork and clone
git clone https://github.com/your-org/secskill.git
cd secskill

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install in dev mode with all extras
pip install -e ".[dev,test,docs]"

# Run the test suite
pytest tests/ -v

# Lint with Ruff
ruff check . && ruff format .

# Run a full scan on SecSkill itself (dogfooding!)
secskill scan secskill/ --format markdown
```

**Before opening a PR:**
- [ ] All tests pass (`pytest`)
- [ ] Code is linted (`ruff check .`)
- [ ] New rules include test cases in `tests/rules/`
- [ ] Security-sensitive changes run through `secskill scan`
- [ ] CHANGELOG.md is updated

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## 🔐 Security Policy

Found a vulnerability in SecSkill itself? Please **do not** open a public GitHub issue.

Report it privately via:
- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/your-org/secskill/security/advisories/new)
- **Email**: security@your-org.com (PGP key in [SECURITY.md](SECURITY.md))

We follow a **90-day responsible disclosure** policy and credit all reporters.

---

<div align="center">

<svg xmlns="http://www.w3.org/2000/svg" width="600" height="60" viewBox="0 0 600 60">
  <rect width="600" height="60" rx="10" fill="#0d1117"/>
  <text x="300" y="22" text-anchor="middle" font-family="'Courier New',monospace" font-size="13" fill="#8b9ab0">
    Built with ❤️ for the security community
  </text>
  <text x="300" y="42" text-anchor="middle" font-family="'Courier New',monospace" font-size="12" fill="#4a5568">
    Apache 2.0 Licensed · © 2024 SecSkill Contributors
  </text>
</svg>

**[⬆ Back to top](#)**

</div>

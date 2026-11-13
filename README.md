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
Omni-Agent Security Reviewer &amp; Full-Stack (SAST/DAST) Audit Engine
</text>

  <!-- Version pill -->
  <rect x="197" y="158" width="130" height="24" rx="12" fill="#00ff8822" stroke="#00ff8855" stroke-width="1"/>
  <text x="262" y="174" text-anchor="middle"
        font-family="'Courier New', Courier, monospace"
        font-size="12" fill="#00ff88" font-weight="600">v0.2.0-omni</text>

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

[![CI Pipeline](<https://img.shields.io/badge/CI-Passing%20(69%2F69%20Tests)-00ff88?style=flat-square&logo=github-actions&logoColor=white>)](https://github.com/anasahmed67/sec-skill/actions)
[![MCP Protocol](https://img.shields.io/badge/MCP-Standard%202024--11--05-blueviolet?style=flat-square&logo=anthropic&logoColor=white)](https://modelcontextprotocol.io/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square&logo=apache&logoColor=white)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-9333ea?style=flat-square)](https://sarifweb.azurewebsites.net/)
[![OWASP Top 10](<https://img.shields.io/badge/standard-OWASP%20Top%2010%20(Web%20%2B%20API%20%2B%20LLM)-dc2626?style=flat-square&logo=owasp&logoColor=white>)](https://owasp.org/www-project-top-ten/)
[![MITRE CWE](https://img.shields.io/badge/standard-MITRE%20CWE%20Top%2025-7c3aed?style=flat-square)](https://cwe.mitre.org/top25/)
[![NIST SSDF](<https://img.shields.io/badge/standard-NIST%20SSDF%20(SP%20800--218)-2563eb?style=flat-square>)](https://csrc.nist.gov/Projects/ssdf)
[![ISO 27001](https://img.shields.io/badge/standard-ISO%2FIEC%2027001%20Annex%20A.8-059669?style=flat-square)](https://www.iso.org/standard/27001)

</div>

---

<div align="center">

[**Why SecSkill?**](#-why-secskill) · [**Omni-Agent Installation**](#-omni-agent-installation--setup) · [**One-Command Update**](#-one-command-update--agent-sync) · [**How to Use This Skill**](#-how-to-use-this-skill-in-your-ai-assistant) · [**Model Context Protocol (MCP)**](#-model-context-protocol-mcp-server) · [**Key Features**](#-key-features) · [**CLI Reference**](#-cli-command-reference) · [**Standards Matrix**](#-international-security-standards-matrix) · [**Python SDK**](#-python-sdk--programmatic-api)

</div>

---

## 🛡️ Why SecSkill?

As AI coding assistants (**Cursor, Claude Code, Google Antigravity, GitHub Copilot, OpenAI Codex**) generate code at lightning speed, they consistently introduce subtle security vulnerabilities that traditional tools and standard LLM self-reviews fail to catch.

**SecSkill** is an agent-native application security reviewer and static/dynamic analysis engine engineered to close these blind spots. It operates as both a **universal AI-agent skill** and a **standalone terminal security suite**.

### What AI Coding Agents Miss (and How SecSkill Solves It)

| What AI Agents Typically Miss           | Why LLMs Miss It                                                                                               | How SecSkill Neutralizes It                                                                             |
| :-------------------------------------- | :------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------ |
| **BOLA / IDOR Authorization Flaws**     | LLMs assume called methods are authorized; they miss missing tenant filters (e.g., `user_id=current_user.id`). | **Deterministic AST dataflow analysis** flags unconstrained database reads and updates.                 |
| **Live Website & Infrastructure Flaws** | LLMs analyze static code in isolation, completely blind to live network ciphers, CORS, or missing headers.     | **Built-in DAST URL Scanner (`scan-url`)** audits TLS, CSP, HSTS, CORS, and cookie flags.               |
| **Transitive Dependency CVEs**          | LLMs review code syntax, ignoring transitive lockfile vulnerabilities or malicious upstream releases.          | **SCA Engine (`dep_scan.py`)** audits package manifests against Google OSV and known vulnerability DBs. |
| **Hallucinated or Bypassed Fixes**      | LLMs frequently write naive regex filters (like stripping `<script>`) that are easily bypassed.                | **Verified Remediation Engine** applies virtual patches and re-scans to ensure zero regressions.        |
| **Prompt Injection & AI Tool Abuse**    | Malicious PR comments or repo text can hijack AI coding assistants.                                            | **Agent Security Auditor (`audit-agent`)** audits prompts, MCP tools, and LLM permissions.              |

---

### Comparison: SecSkill vs. Legacy Tools

<div align="center">

| Capability                                                 | SecSkill | Semgrep (OSS) | Bandit | CodeQL | Snyk |
| ---------------------------------------------------------- | :------: | :-----------: | :----: | :----: | :--: |
| **Omni-Agent Skill (Cursor, Claude, Antigravity, Codex)**  |    ✅    |      ❌       |   ❌   |   ❌   |  ❌  |
| **Standard Model Context Protocol (MCP) Server**           |    ✅    |      ❌       |   ❌   |   ❌   |  ❌  |
| **Live Website & API DAST Scanner (`scan-url`)**           |    ✅    |      ❌       |   ❌   |   ❌   |  ⚠️  |
| **Autonomous AI Red Team vs. Blue Team Duel Arena**        |    ✅    |      ❌       |   ❌   |   ❌   |  ❌  |
| **Differential Verified Patch Testing (Zero Regressions)** |    ✅    |      ❌       |   ❌   |   ❌   |  ❌  |
| **AI Agent & MCP Tool Security Auditor**                   |    ✅    |      ❌       |   ❌   |   ❌   |  ❌  |
| **Real-Time Desktop Secret Watchdog**                      |    ✅    |      ❌       |   ❌   |   ❌   |  ❌  |
| **Attack Path Visualizer (HTML, Mermaid, Terminal)**       |    ✅    |      ❌       |   ❌   |   ⚠️   |  ❌  |
| **SARIF 2.1.0 Export (GitHub Code Scanning)**              |    ✅    |      ✅       |   ❌   |   ✅   |  ✅  |
| **100% Local / Air-Gapped by Default**                     |    ✅    |      ⚠️       |   ✅   |   ❌   |  ❌  |

</div>

---

## 🚀 Omni-Agent Installation & Setup

SecSkill features a **single-command universal installer** that configures skills, rule sets, MCP servers, and CI workflows across all modern AI coding agents:

```bash
# 1. Install SecSkill
pip install secskill

# 2. Initialize across ALL agent platforms simultaneously
secskill init --agent all
```

Or target a specific AI assistant:

```bash
secskill init --agent antigravity  # Configures Google Antigravity (.gemini/skills & plugin.json)
secskill init --agent claude       # Configures Claude Code (.claude/skills, rules.md, CLAUDE.md)
secskill init --agent cursor       # Configures Cursor (.cursor/rules/secskill.mdc & .cursor/mcp.json)
secskill init --agent codex        # Configures OpenAI Codex / Windsurf (.mcp/secskill.json & AGENTS.md)
```

---

### 🔄 One-Command Update & Agent Sync (`secskill update`)

Whenever new security rules, CWE detections, or features are added, users and AI agents **do not need to manually re-download or re-clone the repository**. Simply run:

```bash
secskill update
```

#### What `secskill update` does automatically:

1. **Pulls Latest Code**: Fetches new commits and rules directly from Git (`git pull`).
2. **Upgrades Environment**: Re-installs or updates the Python package in-place (`pip install -e .` or `pip install --upgrade`).
3. **Synchronizes AI Agent Skills**: Automatically updates `SKILL.md`, rules, and MCP configurations across **Google Antigravity**, **Claude Code**, **Cursor**, and **Codex** (both project-level and global user directories).

```bash
# Useful Update Flags:
secskill update                   # Full update (git pull + pip refresh + all agent skills)
secskill update --skills-only     # Refresh agent skills & rules without touching git or pip
secskill update --agent cursor    # Sync only a specific agent target (antigravity, claude, cursor, codex)
secskill upgrade                  # Convenience alias for secskill update
```

---

### 1. Google Antigravity (AGY)

SecSkill ships an official agent skill descriptor [`secskill/SKILL.md`](secskill/SKILL.md) and Antigravity Plugin bundle:

- **Project Setup:** `secskill init --agent antigravity` automatically places the skill into `.gemini/skills/secskill/SKILL.md` and `.gemini/plugins/secskill/plugin.json`.
- **Global Setup:** Copy `secskill/SKILL.md` to `~/.gemini/skills/secskill/SKILL.md` (or symlink for live development).

#### Conversational Prompts in Antigravity:

- _"Review this PR for security vulnerabilities before I merge."_
- _"Audit our live website https://staging.example.com for TLS, CORS, and header misconfigurations."_
- _"Verify this remediation patch for CWE-89 to ensure zero regressions."_

---

### 2. Anthropic Claude Code & Claude Desktop

Run `secskill init --agent claude` to generate:

- `.claude/skills/secskill/SKILL.md`: Claude Code skill manifest.
- `.claude/rules.md` & `CLAUDE.md`: Security guardrails enforcing query parameterization and credential hygiene.

#### Connect to Claude Desktop / Claude Code via MCP:

Add SecSkill to your `claude_desktop_config.json` or `.claude/config.json`:

```json
{
  "mcpServers": {
    "secskill": {
      "command": "secskill",
      "args": ["mcp"]
    }
  }
}
```

---

### 3. Cursor IDE & Windsurf

Run `secskill init --agent cursor` to generate:

- `.cursor/rules/secskill.mdc`: Modern Cursor Rules 2.0 format with YAML frontmatter globs (`**/*.{py,js,ts,java,go}`).
- `.cursor/mcp.json`: Standard Model Context Protocol server configuration.
- `.cursorrules`: Legacy compatibility rules file.

In Cursor Chat, invoke SecSkill tools natively:

> _"Audit this new endpoint with SecSkill before saving, and verify the patch with secskill_verify_patch."_

---

### 4. OpenAI Codex, Windsurf, & Generic MCP Clients

SecSkill provides an out-of-the-box **Model Context Protocol (MCP)** server over standard I/O:

```bash
secskill mcp
```

Connect any MCP-compatible agent to `secskill mcp` to grant it full access to SecSkill's SAST, DAST, and verification tools.

---

## 💬 How to Use This Skill in Your AI Assistant

Once installed in your project (`secskill init --agent all`), SecSkill operates as an **autonomous security copilot** inside your AI coding assistant (**Google Antigravity**, **Cursor**, **Claude Code**, or **Codex**).

You don't have to leave your IDE or memorize complex CLI flags. You simply chat with your AI assistant using natural language, and the agent automatically invokes SecSkill's underlying tools (`secskill_scan`, `secskill_scan_url`, `secskill_verify_patch`) to perform rigorous, deterministic security testing.

---

### 🎯 5 Core Real-World Use Cases

#### 1. Pre-Merge Pull Request Security Audit

Before merging a branch or pushing to production, ask your AI agent to perform a comprehensive framework audit:

> **You:**  
> _"@agent Review our current git diff against main for OWASP Top 10 and CWE security vulnerabilities before I create the PR."_

**What the AI Agent does:**

1. The AI calls `secskill_scan(diff="main")` to analyze all modified files.
2. It traces dataflows from untrusted inputs (`req.body`, `request.args`) to dangerous sinks (`cursor.execute`, `subprocess.run`, `open`).
3. It presents a structured security audit table highlighting exact line numbers, CWE identifiers, CVSS severities, and concrete attack vectors.

---

#### 2. Live Website & Staging API Security Audit

Verify your deployed web application, staging environment, or public API for runtime misconfigurations:

> **You:**  
> _"@agent Audit our staging site https://staging.myapp.com for security headers, TLS configuration, CORS, and exposed assets."_

**What the AI Agent does:**

1. The AI invokes `secskill_scan_url("https://staging.myapp.com")`.
2. It inspects SSL/TLS certificates (cipher suites, protocols, expiration dates).
3. It checks HTTP headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options: nosniff`).
4. It audits cookies for `HttpOnly`, `Secure`, and `SameSite` flags.
5. It tests CORS for `Access-Control-Allow-Origin: *` with credentials.
6. It checks for exposed files (`/.env`, `/.git/HEAD`, `/actuator`, `/swagger.json`).
7. It reports findings mapped to **NIST SP 800-53**, **ISO 27001**, and **PCI-DSS v4.0**.

---

#### 3. Autonomous Verified Vulnerability Remediation

AI agents often introduce new bugs or ineffective regex filters while trying to fix vulnerabilities. SecSkill solves this with **virtual patch verification**:

> **You:**  
> _"@agent Fix finding CWE-89 in app/users.py, and verify that your patch completely resolves the issue with zero regressions."_

**What the AI Agent does:**

1. The AI drafts a remediation (e.g. converting string formatting to parameterized queries).
2. Before modifying your file, it calls `secskill_verify_patch(file_path="app/users.py", proposed_patch=...)`.
3. SecSkill tests the patch in an isolated sandbox, re-runs static analysis, and verifies:
   - Original vulnerability is neutralized (`PASS`).
   - No new security flaws (like `eval` or shell injection) were introduced (`0 regressions`).
4. The AI only presents you with the change once it is mathematically verified.

---

#### 4. Instant Security Check on New Code While Typing

Double-check any newly created function, route handler, or file before saving:

> **You:**  
> _"@agent I just wrote this file upload endpoint in routes/upload.js. Check it with SecSkill for path traversal, arbitrary file upload, and size limits."_

**What the AI Agent does:**

1. The AI evaluates the file against SecSkill's language-specific rules (`javascript.yaml`).
2. It flags if `path.join(UPLOAD_DIR, req.body.filename)` allows `../` directory traversal (CWE-22).
3. It recommends safe path canonicalization with `path.resolve` boundary verification.

---

#### 5. Auditing AI Agents, MCP Servers, and Prompts

If your project builds AI agents or MCP servers, audit them against the **OWASP Top 10 for LLM Applications (2025)**:

> **You:**  
> _"@agent Audit our AI agent tools and system prompts for prompt injection risks and excessive permissions."_

**What the AI Agent does:**

1. The AI calls `secskill_audit_agent(".")`.
2. It flags prompts lacking isolation delimiters (CWE-74 / LLM01 Prompt Injection).
3. It alerts if tools expose destructive capabilities (raw shell execution, unconstrained file deletion).
4. It provides a calculated **Trust Index Score (0-100)** and letter grade.

---

### 🗣️ Natural Language Trigger Phrases

Your AI assistant automatically activates SecSkill whenever you use natural phrases like:

| Developer Intent      | Sample Conversational Prompts                                                                                                                                                               |
| :-------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Code Review**       | • _"Review this file for security before I commit."_<br/>• _"Scan our auth module for SQLi, XSS, or hardcoded API keys."_<br/>• _"Is this code safe against OWASP Top 10 vulnerabilities?"_ |
| **Website Audit**     | • _"Check https://example.com for missing security headers or SSL issues."_<br/>• _"Audit our staging API for CORS misconfiguration or cookie leaks."_                                      |
| **Vulnerability Fix** | • _"Explain finding CWE-78 and show a verified patch."_<br/>• _"Fix this vulnerability and verify it with SecSkill."_                                                                       |
| **AI Architecture**   | • _"Audit our MCP server and tool definitions for prompt injection."_<br/>• _"Check if our system prompt is vulnerable to jailbreaks."_                                                     |

---

## 🔌 Model Context Protocol (MCP) Server

SecSkill implements the **open standard MCP JSON-RPC 2.0 protocol** (`2024-11-05`), functioning as the universal bridge between AI models and security analysis tools:

```
┌────────────────────────────────────────────────────────┐
│  Host AI Agents (Cursor, Claude, Antigravity, Codex)   │
└───────────────────────────┬────────────────────────────┘
                            │ Standard JSON-RPC over stdio
┌───────────────────────────▼────────────────────────────┐
│                  SecSkill MCP Server                   │
├────────────────────────────────────────────────────────┤
│ • secskill_scan         • secskill_verify_patch        │
│ • secskill_scan_url     • secskill_audit_agent         │
│ • secskill_explain      • secskill_attack_map          │
└────────────────────────────────────────────────────────┘
```

### Exposed MCP Tools Catalog:

1. `secskill_scan`: Scans codebase, directories, git diffs, or specific files for vulnerabilities.
2. `secskill_scan_url`: Audits live websites/APIs for TLS, security headers, CORS, cookies, and sensitive exposure.
3. `secskill_verify_patch`: Safely tests proposed code in a virtual sandbox, comparing baseline findings against patched findings to verify remediation with **zero regressions**.
4. `secskill_audit_agent`: Audits AI agent prompts, tool definitions, and MCP servers for OWASP LLM vulnerabilities.
5. `secskill_explain`: Returns deep attack path simulations, technical impact, and international compliance remediation advice for any CWE or OWASP category.
6. `secskill_attack_map`: Generates an interactive, clickable HTML Visual Attack Map with 1-click remediation drawer and plain-English ELI5 explanations.

---

## ✨ Key Features

### 1. 🌐 Live Website & Web Application DAST (`secskill scan-url`)

Audit live URLs, staging environments, and production APIs without installing agents on the server:

- **Transport Layer & TLS/SSL:** Checks TLS versions (flags deprecated TLS 1.0/1.1), verifies SSL certificates, and alerts if certs expire within 14 days.
- **HTTP Security Headers:** Validates `Content-Security-Policy` (CSP), `Strict-Transport-Security` (HSTS), `X-Frame-Options` (Clickjacking), `X-Content-Type-Options: nosniff`, and technology banners in `Server` / `X-Powered-By`.
- **Cookie Security:** Audits `Set-Cookie` headers for missing `HttpOnly`, missing `Secure`, or missing `SameSite` flags.
- **CORS Misconfiguration:** Detects insecure `Access-Control-Allow-Origin: *` with credentials or unvalidated reflection of untrusted origins.
- **Sensitive Path Probing:** Detects publicly exposed files (`/.env`, `/.git/HEAD`, `/actuator/health`, `/swagger.json`, `/openapi.json`).

```bash
secskill scan-url https://example.com
secskill scan-url https://example.com --format sarif -o web_results.sarif
```

---

### 2. 💻 Deterministic SAST & Data-Flow Taint Tracking

- **Multi-Language Support:** Python (AST + regex rules), JavaScript/TypeScript, Java, Go, Rust, and configuration files.
- **Taint Tracking:** Tracks untrusted sources (`request.args`, `req.body`, cookies, env vars) to dangerous sinks (`cursor.execute`, `subprocess`, `innerHTML`, `open`, `pickle.loads`).
- **Secret Detection:** Combines high-entropy Shannon entropy checks with 30+ regex signatures (AWS, GitHub tokens, OpenAI keys, JWTs, GCP, private keys) with **mandatory output redaction** (`AKIA...XYZ`).
- **Software Composition Analysis (SCA):** Scans `requirements.txt`, `package.json`, and lockfiles against Google OSV and local high-severity CVE databases.

```bash
secskill scan .
secskill scan --diff main
secskill scan --file app/auth.py
```

---

### 3. 🔄 Differential Verified Auto-Remediation

Never guess if an AI-generated fix actually resolved the issue. SecSkill's verification engine:

1. Scans original baseline code.
2. Applies the proposed patch in a virtual sandbox.
3. Re-scans the patched code.
4. Alerts if the fix failed (`FAIL`), or if it introduced new vulnerabilities like `eval` or `shell=True` (`REGRESSION`), or verifies clean resolution (`PASS`).

---

### 4. ⚔️ Autonomous AI Red Team vs. Blue Team Duel (`secskill duel`)

Pits two AI agents against each other in the terminal:

- **Red Team:** Generates evasion payloads attempting to bypass filters.
- **Blue Team:** Writes cryptographic parameterization and input validation.
- The arena battles in real-time until code is verified impenetrable:

```bash
secskill duel sqli --apply
secskill duel path-traversal -r 5 --provider ollama
```

---

### 5. 🤖 AI-Agent & MCP Security Auditor (`secskill audit-agent`)

Audits other AI agents, MCP servers, and system prompts against the **OWASP Top 10 for LLMs** and **MITRE ATLAS**:

- Detects prompt injection vulnerabilities and lack of safety delimiters.
- Flags over-privileged tools (arbitrary shell execution, uncontrolled file deletion).
- Generates an interactive **Cyberpunk HTML Agent Security Dashboard**:

```bash
secskill audit-agent . --format html --open
```

---

### 6. 👁️ Real-Time Secret Leak Watchdog (`secskill watch`)

Watches your project directory in real-time. If a developer or AI assistant accidentally pastes an API key or private token into any file, SecSkill immediately fires a native **desktop toast notification** and audio chime:

```bash
secskill watch ./src
```

---

### 7. 🗺️ Clickable Visual Attack Map (Interactive HTML & Dataflow)

Visualizes the exact source-to-sink journey of vulnerabilities in a lightweight, responsive vector map:

- **Zero-Dependency Lightweight SVG**: Downsized from heavy JavaScript physics clumps to an ultra-fast, responsive SVG canvas (~84 KB, renders in <10ms).
- **Visibly Separated 4-Tier Topology**: Clean, spacious horizontal tiers with 110px vertical breathing room:
  - **Tier 1 (Cyan)**: Untrusted Public Entrypoints (`req.body`, HTTP routes, query params)
  - **Tier 2 (Purple)**: Application Source Files (`.py`, `.ts`, `.js`, etc.)
  - **Tier 3 (Severity-Coded Sinks)**: Insecure execution sinks (`subprocess`, SQL queries, eval)
  - **Tier 4 (Crimson Targets)**: Crown jewel assets (Database, OS Shell, Secrets Vault)
- **Animated Laser Attack Vectors**: Glowing, pulsating red exploit paths illustrating real hacker jumps from public inputs to critical infrastructure.
- **Clickable Remediation Inspector**: Clicking any red line or sink opens an instant inspector drawer featuring:
  - Vulnerability root cause and affected file location
  - **ELI5 ("Explain Like I'm 5")**: Clear, jargon-free real-world analogy
  - Complete, pre-tested parameterized remediation code
  - 1-Click **"Copy Fix"** button
- **Premium Vector SVG Icons**: Modern, professional vector iconography throughout (no emojis).
- **Live Search & Dynamic Pan/Zoom**: Smooth mouse-wheel zooming, click-drag panning, and instant client-side keyword search.

```bash
secskill graph . --format html --open    # Launches the interactive attack map in browser
secskill graph . --format mermaid        # Exports GitHub-ready Mermaid diagrams
secskill graph .                         # Renders colorful terminal ASCII dataflow pipelines
```

---

### 8. 🔄 One-Command Self-Updater (`secskill update`)

Automatically keeps SecSkill and all installed AI agent configurations fresh without manual downloads or Git re-cloning:

- Pulls latest rules, definitions, and code from Git.
- Refreshes the local Python environment (`pip`).
- Re-synchronizes `SKILL.md` and MCP server manifests across **Google Antigravity**, **Claude Code**, **Cursor**, and **Codex**.

```bash
secskill update                   # One command updates everything
secskill update --skills-only     # Quick-sync AI agent skills only
secskill upgrade                  # Convenience alias
```

---

## 📖 CLI Command Reference

| Command                   | Description                                                      | Example                                   |
| :------------------------ | :--------------------------------------------------------------- | :---------------------------------------- |
| `secskill scan [path]`    | Run SAST/SCA security scan on codebase, file, or git diff        | `secskill scan . --diff main`             |
| `secskill scan-url <url>` | Audit live website or API for TLS, headers, CORS, cookies        | `secskill scan-url https://example.com`   |
| `secskill mcp`            | Launch Model Context Protocol server over stdio                  | `secskill mcp`                            |
| `secskill init`           | Initialize agent skills, rules, and CI workflows                 | `secskill init --agent all`               |
| `secskill update`         | Pull latest code, refresh pip package, and sync all agent skills | `secskill update`                         |
| `secskill upgrade`        | Alias for `secskill update`                                      | `secskill upgrade --skills-only`          |
| `secskill explain`        | Deep-dive explanation and attack simulation for finding/CWE      | `secskill explain --finding CWE-89`       |
| `secskill fix`            | Generate or preview remediation diff for finding                 | `secskill fix --finding F-1001 --dry-run` |
| `secskill watch [path]`   | Real-time secret leak watcher with desktop alerts                | `secskill watch ./src`                    |
| `secskill simulate <id>`  | Simulate exploit payload execution vs fixed code                 | `secskill simulate sqli`                  |
| `secskill graph [path]`   | Render visual attack path dataflow diagrams                      | `secskill graph . --format html --open`   |
| `secskill audit-agent`    | Audit AI agents, prompts, and MCP configurations                 | `secskill audit-agent . --format html`    |
| `secskill duel <target>`  | Autonomous AI Red vs. Blue code hardening battle                 | `secskill duel sqli --apply`              |
| `secskill version`        | Display SecSkill version                                         | `secskill version`                        |

---

## 🏛️ International Security Standards Matrix

Every finding generated by SecSkill carries full bidirectional traceability to international standards:

| Framework / Standard          | Version           | Coverage & Mapping in SecSkill                                                                                                |
| :---------------------------- | :---------------- | :---------------------------------------------------------------------------------------------------------------------------- |
| **OWASP Top 10**              | 2021              | Mapped to `A01:2021` through `A10:2021` on all source code and website findings.                                              |
| **OWASP API Security Top 10** | 2023              | Specialized API checks for BOLA (`API1:2023`), Broken Auth (`API2:2023`), and SSRF (`API7:2023`).                             |
| **OWASP Top 10 for LLMs**     | 2025              | Mapped in `secskill audit-agent` (LLM01 Prompt Injection, LLM02 Sensitive Disclosure, LLM07 Insecure Plugin Design).          |
| **MITRE CWE / SANS Top 25**   | v4.14             | Exact CWE ID assigned to every finding (`CWE-89`, `CWE-78`, `CWE-79`, `CWE-319`, `CWE-1021`, etc.).                           |
| **NIST SP 800-218 (SSDF)**    | v1.1              | Practice mapping: `PO` (Prepare Org), `PS` (Protect Software), `PW` (Produce Well-Secured Software), `RV` (Respond to Vulns). |
| **NIST SP 800-53 Rev 5**      | Security Controls | Controls mapping: `SC-8` (Transmission Confidentiality), `SI-10` (Input Validation), `AC-3` (Access Enforcement).             |
| **ISO/IEC 27001:2022**        | Annex A.8         | Controls: `A.8.20` (Network Security), `A.8.24` (Cryptography), `A.8.26` (App Security), `A.8.28` (Secure Coding).            |
| **PCI-DSS**                   | v4.0              | Requirement 6: `6.2` (Software Development), `6.3` (Identify & Mitigate Vulns), `6.4` (Protect Web Applications).             |
| **OASIS SARIF**               | v2.1.0            | Full native SARIF export for GitHub Code Scanning and GitLab SAST.                                                            |

---

## 🐍 Python SDK / Programmatic API

SecSkill can be integrated directly into custom Python agents, scripts, or test pipelines via `SecSkillAgentSkill`:

```python
from secskill.agent_skill import SecSkillAgentSkill

# 1. Initialize skill
skill = SecSkillAgentSkill(target_dir=".")

# 2. Run source code security scan
findings = skill.run_security_scan("src/api/users.py")
for f in findings:
    print(f"[{f['severity']}] {f['title']} ({f['cwe_id']}) at line {f['line_number']}")

# 3. Audit a live website or API (DAST)
web_report = skill.scan_url("https://example.com", check_sensitive_paths=True)
print(f"Status: {web_report['status_code']} | Findings: {len(web_report['findings'])}")

# 4. Verify a proposed remediation patch (with differential regression detection)
verification = skill.verify_remediation(
    file_path="src/api/users.py",
    proposed_patch='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    original_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
)
print(f"Verification Verdict: {verification['status']} - {verification['message']}")
# Output: PASS - Remediation successfully verified. 1 finding(s) neutralized with 0 regressions.

# 5. Audit AI Agent prompts & MCP configs
agent_audit = skill.audit_agent(".")
print(f"Trust Index: {agent_audit['security_score']}/100 (Grade {agent_audit['grade']})")
```

---

## ⚙️ The 8-Stage Review Pipeline

When invoked, SecSkill executes an 8-stage verification pipeline:

```
[Stage 0: Scope & Consent] ──> [Stage 1: Repo Indexing] ──> [Stage 2: Parallel Scan]
                                                                     │
[Stage 5: Validation Filter] <── [Stage 4: LLM Review] <── [Stage 3: Normalize]
       │
       └──> [Stage 6: Reporting] ──> [Stage 7: Remediate & Re-scan]
```

1. **Stage 0: Scope & Consent:** Determine target (`.`, git diff, file, or URL) and enforce local privacy boundaries.
2. **Stage 1: Repo Indexing:** Index entry points, routing tables, auth middleware, and dependency lockfiles.
3. **Stage 2: Parallel Scanning:** Executes AST analyzers, secret entropy checks, dependency CVE lookups, and DAST probes.
4. **Stage 3: Normalize:** Normalizes findings into the Unified Finding Schema with CWE, OWASP, and CVSS severity.
5. **Stage 4: LLM Contextual Review:** (Optional `--llm`) Evaluates code context to eliminate false positives.
6. **Stage 5: Validation Filter:** Validates reachability and respects `# secskill:ignore` comments.
7. **Stage 6: Multi-Format Reporting:** Emits Console tables, SARIF 2.1.0, JSON, Markdown, or HTML dataflow graphs.
8. **Stage 7: Remediate & Re-scan:** Generates verified patches and verifies zero regressions.

---

## 🛠️ CI/CD & GitHub Code Scanning Integration

SecSkill integrates seamlessly with GitHub Actions to publish findings directly into the **GitHub Security Tab**:

`.github/workflows/secskill.yml`:

```yaml
name: SecSkill Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  secskill:
    name: SecSkill SAST Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install SecSkill
        run: pip install secskill

      - name: Run SecSkill Scan
        run: secskill scan . --format sarif --output secskill.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secskill.sarif
```

---

## 🤝 Contributing

We welcome community contributions, custom rule packs, and framework additions!

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/awesome-rule`.
3. Add tests in `tests/`.
4. Ensure all tests pass: `pytest`.
5. Format code: `ruff check . --fix`.
6. Submit a Pull Request.

Please see [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

---

## 📄 License

SecSkill is open-source software licensed under the [Apache License 2.0](LICENSE).

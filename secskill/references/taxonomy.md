# SecSkill Vulnerability Taxonomy & Threat Model

This reference document outlines the vulnerability taxonomy, prioritization hierarchy, detectability classes, and threat model utilized by SecSkill during security audits.

---

## 1. Vulnerability Classes & Prioritization Matrix

SecSkill prioritizes findings using a weighted combination of MITRE CWE Top 25 and OWASP Top 10:2021 risks.

| Priority | Vulnerability Class | Example CWEs | OWASP (2021) | Primary Detection Method |
|:---:|---|---|---|---|
| **1** | **Injection** | CWE-89 (SQLi), CWE-78 (Cmd Injection), CWE-94 (Code Injection), CWE-1336 (SSTI) | A03:2021-Injection | Static AST rules, source-to-sink data-flow tracing, LLM contextual review |
| **2** | **Broken Access Control** | CWE-862 (Missing Authorization), CWE-863 (Incorrect Authz), CWE-639 (IDOR) | A01:2021-Broken Access Control | Route/controller parsing, AST decorator analysis, LLM authorization flow triage |
| **3** | **Cryptographic Failures** | CWE-327 (Broken Crypto), CWE-328 (Reversible One-Way Hash), CWE-330 (Insecure PRNG), CWE-798 (Hardcoded Keys) | A02:2021-Cryptographic Failures | Static rule matching, secret scanner, entropy analysis |
| **4** | **Input Validation & XSS** | CWE-79 (XSS), CWE-22 (Path Traversal), CWE-502 (Insecure Deserialization), CWE-611 (XXE) | A03:2021-Injection / A08:2021-Software & Data Integrity | Sanitization checks, framework-aware AST analysis, data-flow heuristics |
| **5** | **Authentication & Session Flaws** | CWE-287 (Improper Authentication), CWE-384 (Session Fixation), CWE-613 (Insufficient Session Expiration) | A07:2021-Identification & Auth Failures | Framework-aware rules, auth config audit, LLM review |
| **6** | **Security Misconfiguration** | CWE-16 (Configuration), CWE-489 (Active Debug Code), CWE-1004 (Sensitive Cookie Without HttpOnly) | A05:2021-Security Misconfiguration | Config file inspection (`.env`, `settings.py`, `web.xml`), header analysis |
| **7** | **Server-Side Request Forgery (SSRF)** | CWE-918 (SSRF) | A10:2021-SSRF | URL parsing analysis, HTTP client sink tracing, LLM network boundary review |
| **8** | **Vulnerable & Outdated Dependencies** | CVE-linked third-party libraries | A06:2021-Vulnerable & Outdated Components | Dependency manifest parser (`requirements.txt`, `package.json`, `pom.xml`), OSV lookup |
| **9** | **Secrets Exposure** | CWE-798 (Hardcoded Credentials), CWE-259 (Hardcoded Password), CWE-321 (Cryptographic Key) | A02:2021-Cryptographic Failures / A05:2021-Security Misconfiguration | Regex patterns, Shannon entropy heuristics, contextual variable naming |
| **10** | **Insecure AI-Agent Behavior** | CWE-74 (Prompt Injection / Untrusted Input into LLM), CWE-77 (Command Execution by Agent), CWE-400 (Uncontrolled Resource Consumption), CWE-284 (Improper Access Control by Agent) | A04:2021-Insecure Design / A08:2021-Software & Data Integrity | Heuristic scanning of agent prompts, tool definitions, inter-agent protocol boundaries |

---

## 2. Detectability Classification

The confidence and phrasing of findings are conditioned on the detectability class:

### Easily Detectable
- **Characteristics:** Unambiguous syntax patterns, obvious direct injections, high-entropy API keys matching vendor prefixes (`AKIA...`), pinned outdated package versions.
- **Reporting Stance:** Reported with **High Confidence** (`0.85 - 1.0`). Concrete fix diff provided immediately.

### Context-Dependent
- **Characteristics:** Missing authorization checks, Insecure Direct Object References (IDOR), insecure multi-step business workflows.
- **Reporting Stance:** Reported as **Likely** or **Suspicious** (`0.60 - 0.84`). Always includes explicit verification criteria, attack conditions, and marks `requires_human_review: true`.

### Dynamic-Only or Difficult
- **Characteristics:** Concurrency bugs, race conditions (TOCTOU), complex polymorphic deserialization gadgets, DNS rebinding SSRF.
- **Reporting Stance:** Reported with diagnostic notes highlighting that static analysis cannot guarantee reachability. Suggests automated unit test generation and dynamic testing in an isolated sandbox.

### Human-Review Required
- **Characteristics:** Business-logic flaws (e.g., negative quantity in e-commerce cart, discount coupon reuse, authorization rules based on proprietary organizational hierarchy).
- **Reporting Stance:** Stated transparently that automated analysis cannot settle domain logic correctness. Recommends manual threat modeling and architectural review.

---

## 3. Threat Model

SecSkill evaluates software across modern application architectures and AI-assisted development lifecycles.

### Scenarios
1. **Direct Prompt-Based Code Generation:** Developer asks LLM (Copilot, ChatGPT, Claude) to write a function or module.
2. **IDE-Assisted Completion:** Inline AI autocomplete suggests boilerplate code.
3. **Autonomous Agent Modifications:** Multi-agent workflows (Devin, SWE-agent, Antigravity) creating branches or resolving bug tickets.
4. **LLM-Based Automated Repair:** Agents iteratively patching code based on test output.
5. **Human-Written Legacy Codebases:** Existing enterprise applications undergoing modernization or security audits.

### Assets at Risk
- User Personally Identifiable Information (PII) and financial data.
- User session tokens, OAuth refresh tokens, and passwords.
- Source code, proprietary intellectual property, and internal system architectures.
- Cloud infrastructure credentials (AWS IAM keys, Azure service principals, GCP service account keys).
- Production relational and NoSQL databases.
- Underlying host operating system, local file system, and container runtimes.
- Internal microservices, private VPC endpoints, and metadata services (`169.254.169.254`).
- CI/CD build environments, secret management vaults, and signing keys.

### Trust Boundaries
1. **Public Web & API Boundary:** External HTTP requests (headers, query params, cookies, JSON bodies, multipart uploads) passing to web application endpoints.
2. **Third-Party Supply Chain Boundary:** External npm packages, PyPI libraries, Maven dependencies, and container base images.
3. **Environment & Configuration Boundary:** System environment variables, configuration files, and vault secrets.
4. **Storage & Data Persistence Boundary:** Relational SQL tables, document stores, and file storage.
5. **AI Agent Tool & Context Boundary:** Scanned repository files, commit messages, issue descriptions, and tool execution outputs fed back into agent context.

### Attacker Capabilities
- Injection of malicious strings, SQL fragments, shell metacharacters, or template tags into external parameters.
- Direct invocation of unauthenticated or poorly protected endpoints.
- Dependency confusion, typosquatting, or poisoning of upstream packages.
- Harvesting of exposed credentials committed to source code or git history.
- **Indirect Prompt Injection:** Crafting malicious docstrings, comments, or repository files designed to hijack agent execution during code review.

### AI-Specific Failure Modes
SecSkill explicitly inspects code for common AI generation pitfalls:
- **"Works But Unsafe" Syndrome:** Code that passes functional unit tests but omits defensive boundaries (e.g., using string concatenation for SQL because it is simpler to generate).
- **Hallucinated Packages & Typosquats:** LLM imports libraries that do not exist or resemble well-known packages, exposing users to supply chain takeover.
- **Deprecated or Insecure Cryptographic APIs:** Use of outdated libraries (e.g., `Crypto.Cipher` instead of `cryptography.hazmat`) or broken algorithms (`MD5`, `SHA1`, `DES`) copied from obsolete web tutorials.
- **Mock & Debug Flags in Production:** AI models frequently leave debug configurations (`DEBUG = True`, `CORS_ALLOW_ALL = True`, bypass auth flags) active in generated code.
- **Missing Multitenancy Isolation:** Endpoints fetching database records by primary key (`SELECT * FROM orders WHERE id = ?`) without validating ownership against the authenticated session user.


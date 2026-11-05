# OWASP Top 10:2021 Reference & Guidance

This guide outlines the 10 critical security risk categories defined in the OWASP Top 10 (2021) standard, accompanied by SecSkill's one-line guidance, primary CWE mappings, and detection strategies.

---

### A01:2021 – Broken Access Control
- **One-Line Guidance:** Enforce server-side authorization checks on every endpoint, verify object ownership on every database query, and adopt default-deny access control policies.
- **Key CWEs:** CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-639 (Insecure Direct Object References - IDOR), CWE-284 (Improper Access Control), CWE-22 (Path Traversal).
- **Detection Strategy:** Map controller routes to authentication/authorization middleware decorators, verify whether database lookup filters include tenant/user IDs, and review client-side role check assumptions.

---

### A02:2021 – Cryptographic Failures
- **One-Line Guidance:** Never use obsolete algorithms (MD5, SHA1, DES, RC4) for security, use cryptographically secure PRNGs for tokens, enforce strong authenticated encryption (AES-256-GCM), and never hardcode cryptographic keys.
- **Key CWEs:** CWE-327 (Broken or Risky Crypto Algorithm), CWE-328 (Reversible One-Way Hash), CWE-330 (Use of Insufficiently Random Values), CWE-798 (Use of Hard-coded Credentials), CWE-326 (Inadequate Encryption Strength).
- **Detection Strategy:** Static regex and AST analysis targeting cryptographic imports (`hashlib`, `crypto`, `java.security`), entropy scanning of string literals, and detection of non-CSPRNG functions (e.g., Python `random`, Math.random()).

---

### A03:2021 – Injection
- **One-Line Guidance:** Strictly separate untrusted data from execution interpreters by using parameterized queries, safe execution APIs, context-aware encoders, and structured serializers.
- **Key CWEs:** CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-79 (Cross-Site Scripting), CWE-94 (Code Injection), CWE-1336 (Server-Side Template Injection).
- **Detection Strategy:** Source-to-sink data-flow tracing from request inputs (`request.args`, `req.body`, `argv`) to sensitive sinks (`cursor.execute()`, `subprocess.run(shell=True)`, `child_process.exec()`, `eval()`).

---

### A04:2021 – Insecure Design
- **One-Line Guidance:** Establish formal threat modeling, secure design patterns, reference architectures, and defense-in-depth principles before writing functional code.
- **Key CWEs:** CWE-209 (Generation of Error Message with Sensitive Info), CWE-256 (Plaintext Storage of Password), CWE-501 (Trust Boundary Violation), CWE-657 (Violation of Secure Design Principles).
- **Detection Strategy:** Architectural context analysis, heuristic detection of missing rate limits on sensitive endpoints, and unauthenticated state changes in multi-step workflows.

---

### A05:2021 – Security Misconfiguration
- **One-Line Guidance:** Disable debug flags, remove default credentials and sample accounts, establish explicit CORS origins, and enforce secure HTTP response headers across all deployment environments.
- **Key CWEs:** CWE-16 (Configuration), CWE-489 (Active Debug Code), CWE-1004 (Sensitive Cookie Without HttpOnly Flag), CWE-614 (Sensitive Cookie in HTTPS Without Secure Attribute), CWE-942 (Permissive CORS Policy).
- **Detection Strategy:** Audit configuration files (`settings.py`, `application.properties`, `.env`, web server configs), check cookie initialization flags, and verify CORS configurations (`Access-Control-Allow-Origin: *`).

---

### A06:2021 – Vulnerable and Outdated Components
- **One-Line Guidance:** Maintain a software inventory (SBOM), continuously monitor dependency lockfiles against vulnerability databases (OSV/NVD), and pin dependencies to secure, patched versions.
- **Key CWEs:** CWE-1104 (Use of Unmaintained Third-Party Components), CWE-1395 (Dependency on Vulnerable Third-Party Component).
- **Detection Strategy:** Parse project lockfiles (`requirements.txt`, `package-lock.json`, `pom.xml`, `go.mod`), cross-reference with advisory feeds, and identify vulnerable pinned versions and fixed target versions.

---

### A07:2021 – Identification and Authentication Failures
- **One-Line Guidance:** Implement multi-factor authentication, rate-limit login attempts, use cryptographically salted password hashes (Argon2id, bcrypt), and ensure session identifiers are invalidated upon logout.
- **Key CWEs:** CWE-287 (Improper Authentication), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-384 (Session Fixation), CWE-613 (Insufficient Session Expiration).
- **Detection Strategy:** Inspect authentication routes for password hashing implementations, check token validation routines (e.g., verifying JWT signature vs naive payload decoding), and detect missing rate limiters.

---

### A08:2021 – Software and Data Integrity Failures
- **One-Line Guidance:** Verify digital signatures on application updates and libraries, protect CI/CD pipeline integrity, and reject untrusted serialized objects.
- **Key CWEs:** CWE-502 (Deserialization of Untrusted Data), CWE-494 (Download of Code Without Integrity Check), CWE-829 (Inclusion of Functionality from Untrusted Sphere).
- **Detection Strategy:** AST matching for unsafe deserialization functions (`pickle.loads`, `yaml.unsafe_load`, `ObjectInputStream.readObject`, `Marshal.load`), unverified auto-update scripts, and untrusted CDN script tags.

---

### A09:2021 – Security Logging and Monitoring Failures
- **One-Line Guidance:** Log all authentication, authorization, and input validation failures with sufficient context, prevent logging of sensitive credentials, and forward logs to centralized alerting systems.
- **Key CWEs:** CWE-117 (Improper Output Handling for Logs / Log Injection), CWE-778 (Insufficient Logging), CWE-532 (Insertion of Sensitive Information into Log File).
- **Detection Strategy:** Detect logging calls (`logger.info`, `console.log`) receiving passwords, API tokens, credit card numbers, or unsanitized user inputs containing carriage returns/newlines.

---

### A10:2021 – Server-Side Request Forgery (SSRF)
- **One-Line Guidance:** Validate and sanitize all user-supplied destination URLs, enforce strict domain allowlists, block private/internal IP ranges (RFC 1918, link-local 169.254.169.254), and disable HTTP redirects on fetching clients.
- **Key CWEs:** CWE-918 (Server-Side Request Forgery).
- **Detection Strategy:** Source-to-sink data-flow analysis tracing user-controlled URLs to HTTP request clients (`requests.get`, `fetch`, `axios`, `HttpURLConnection`) without loopback or private subnet protections.


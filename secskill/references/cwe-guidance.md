# CWE Detection Guidance & Remediation Catalog

This reference provides actionable detection heuristics, false positive filters, and concrete remediations for the most critical Common Weakness Enumerations (CWEs) encountered during application security audits.

---

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **Severity:** Critical | **OWASP:** A03:2021-Injection | **SSDF:** PW.5.1
- **Vulnerable Sinks:** `cursor.execute()`, `session.execute()`, `db.query()`, `rawQuery()`, `createStatement().executeQuery()` with concatenated strings or f-strings.
- **Detection Hints:** Look for string formatting (`%`, `.format()`, f-strings, string concatenation `+`) directly inside SQL query strings.
- **False Positive Filter:** Verify whether the query string uses database driver placeholders (`?`, `%s`, `:param`) and supplies parameters as a tuple/dictionary. ORM query builders (SQLAlchemy `filter_by(id=val)`, Prisma `where: { id }`) are safe unless raw SQL interpolation is used.
- **Remediation:** Always bind parameters through the database driver.
  - *Vulnerable (Python):* `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
  - *Secure (Python):* `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
  - *Secure (Java):* `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, userId);`

---

### CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **Severity:** Critical | **OWASP:** A03:2021-Injection | **SSDF:** PW.5.1
- **Vulnerable Sinks:** `subprocess.run(..., shell=True)`, `os.system()`, `child_process.exec()`, `Runtime.getRuntime().exec(String)`.
- **Detection Hints:** Sinks that invoke an OS command interpreter with user-controlled arguments, especially when string concatenation is used.
- **False Positive Filter:** If `shell=False` is set and arguments are passed as an array/list of strings without shell evaluation, arbitrary shell injection is prevented (though parameter injection may remain if options are uncontrolled).
- **Remediation:** Avoid shell interpreters. Use argument lists with `shell=False` or dedicated safe APIs.
  - *Vulnerable (Python):* `subprocess.run(f"ping -c 1 {host}", shell=True)`
  - *Secure (Python):* `subprocess.run(["ping", "-c", "1", host], check=True, shell=False)`
  - *Vulnerable (Node.js):* `exec(`cat ${filename}`, cb)`
  - *Secure (Node.js):* `execFile('cat', [filename], cb)`

---

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting - XSS')
- **Severity:** High | **OWASP:** A03:2021-Injection | **SSDF:** PW.5.1
- **Vulnerable Sinks:** `res.send()`, `innerHTML`, `document.write()`, `dangerouslySetInnerHTML`, `render_template_string()`, `@html`.
- **Detection Hints:** Directly rendering untrusted input into HTML responses or client DOM without contextual encoding.
- **False Positive Filter:** Standard React `{var}` automatically escapes strings. Jinja2 templates loaded from files have auto-escaping enabled by default. Only flag if raw unescaped bypasses are explicitly used (e.g., `| safe`, `dangerouslySetInnerHTML`).
- **Remediation:** Use context-aware output encoding or template engines with contextual escaping.
  - *Vulnerable (Node.js):* `res.send(`<h1>Welcome, ${req.query.name}</h1>`)`
  - *Secure (Node.js):* `res.render('welcome', { name: req.query.name }) // using auto-escaping EJS/Handlebars`
  - *Vulnerable (React):* `<div dangerouslySetInnerHTML={{ __html: userBio }} />`
  - *Secure (React):* `<div>{userBio}</div>` (or sanitize with `DOMPurify.sanitize(userBio)`)

---

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **Severity:** High | **OWASP:** A01:2021-Broken Access Control | **SSDF:** PW.5.1
- **Vulnerable Sinks:** `open()`, `fs.readFile()`, `FileInputStream()`, `send_file()`, `res.sendFile()`.
- **Detection Hints:** File system paths constructed by concatenating user inputs without resolving and asserting base directory canonicalization.
- **False Positive Filter:** Check if `os.path.abspath()` or `path.resolve()` is followed by an assertion that the resolved path starts with the authorized base directory prefix.
- **Remediation:** Canonicalize and strictly verify path boundaries.
  - *Vulnerable (Python):*
    ```python
    path = os.path.join(UPLOAD_DIR, filename)
    return open(path, "rb").read()
    ```
  - *Secure (Python):*
    ```python
    safe_name = os.path.basename(filename)
    path = os.path.abspath(os.path.join(UPLOAD_DIR, safe_name))
    if not path.startswith(os.path.abspath(UPLOAD_DIR) + os.sep):
        raise ValueError("Path traversal attempt detected")
    return open(path, "rb").read()
    ```

---

### CWE-918: Server-Side Request Forgery (SSRF)
- **Severity:** High | **OWASP:** A10:2021-SSRF | **SSDF:** PW.5.1
- **Vulnerable Sinks:** `requests.get()`, `httpx.get()`, `fetch()`, `axios.get()`, `HttpURLConnection.openStream()`.
- **Detection Hints:** User input specifies or controls the destination URL, host, or protocol of an outbound HTTP client call.
- **False Positive Filter:** Check if the destination host is validated against a strict domain/IP allowlist or validated to ensure it does not resolve to loopback (`127.0.0.1`), link-local (`169.254.169.254`), or private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Remediation:** Parse the target URL, resolve DNS before connecting, verify that the IP is publicly routable, and prevent client redirects to internal endpoints.

---

### CWE-502: Deserialization of Untrusted Data
- **Severity:** Critical | **OWASP:** A08:2021-Software and Data Integrity Failures | **SSDF:** PW.5.1
- **Vulnerable Sinks:** `pickle.loads()`, `yaml.load(..., Loader=yaml.Loader)`, `ObjectInputStream.readObject()`, `Marshal.load()`.
- **Detection Hints:** Parsing serialized object binary streams received from network, files, or cookies.
- **False Positive Filter:** Safe parsers like `json.loads()`, `yaml.safe_load()`, or cryptographically signed payloads with valid HMAC verification.
- **Remediation:** Never deserialize untrusted object graphs. Use structured data formats like JSON or Protocol Buffers.
  - *Vulnerable (Python):* `obj = pickle.loads(request.data)`
  - *Secure (Python):* `obj = json.loads(request.data)`

---

### CWE-611: Improper Restriction of XML External Entity Reference ('XXE')
- **Severity:** High | **OWASP:** A05:2021-Security Misconfiguration | **SSDF:** PW.5.1
- **Vulnerable Sinks:** `xml.etree.ElementTree`, `DocumentBuilderFactory.newInstance()`, `SAXParserFactory`.
- **Detection Hints:** Parsing untrusted XML documents without disabling external DTDs and entity expansion.
- **Remediation:** Explicitly disable DTD processing and external entity resolution features on the parser factory.
  - *Secure (Java):*
    ```java
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    ```

---

### CWE-798 / CWE-259: Use of Hard-coded Credentials / Passwords
- **Severity:** High/Critical | **OWASP:** A02:2021-Cryptographic Failures / A05:2021-Security Misconfiguration
- **Vulnerable Patterns:** Strings matching known API key signatures (`AKIA...`, `ghp_...`, `eyJ...`) or variables named `password`, `secret_key`, `token` assigned literal values.
- **False Positive Filter:** Allowlist sample placeholders (`EXAMPLE_KEY`, `your_token_here`, `test`, `localhost`, mock test files).
- **Remediation:** Load credentials from environment variables, secret managers (HashiCorp Vault, AWS Secrets Manager), or `.env` files ignored by git. Redact the credential immediately, rotate the compromised key, and scrub git history.

---

### CWE-327 & CWE-328: Use of Broken Cryptographic Algorithm / Hash
- **Severity:** Medium/High | **OWASP:** A02:2021-Cryptographic Failures
- **Vulnerable Sinks:** `hashlib.md5()`, `hashlib.sha1()`, `DES.new()`, `Cipher.getInstance("DES")` when used for password hashing or integrity checks.
- **False Positive Filter:** MD5/SHA1 used exclusively as checksums for cache keys or git commit identifiers are not vulnerabilities if collision attacks do not compromise security.
- **Remediation:** Use SHA-256/SHA-512 for cryptographic hashing, Argon2id or bcrypt for password hashing, and AES-256-GCM for symmetric encryption.

---

### CWE-330: Use of Insufficiently Random Values
- **Severity:** Medium | **OWASP:** A02:2021-Cryptographic Failures
- **Vulnerable Sinks:** Python `import random; random.randint()`, JavaScript `Math.random()`, Java `java.util.Random` used for tokens, password reset links, or session IDs.
- **Remediation:** Use cryptographically secure pseudorandom number generators (CSPRNG): Python `secrets.token_urlsafe()`, Node.js `crypto.randomBytes()`, Java `java.security.SecureRandom`.

---

### CWE-862 & CWE-639: Missing Authorization & IDOR
- **Severity:** High | **OWASP:** A01:2021-Broken Access Control
- **Vulnerable Pattern:** Directly querying or modifying an object by ID provided in request parameters without verifying that the authenticated user owns or has rights to that object.
- **Remediation:** Always scope queries to the authenticated tenant/user ID:
  - *Vulnerable:* `Invoice.objects.get(id=request.GET['id'])`
  - *Secure:* `Invoice.objects.get(id=request.GET['id'], organization_id=request.user.organization_id)`

---

### CWE-74: Prompt Injection / Untrusted Input in AI Context
- **Severity:** High | **OWASP:** A04:2021-Insecure Design / A08:2021-Software and Data Integrity Failures
- **Vulnerable Pattern:** Inserting unsanitized user input, document content, or web scraping results directly into system prompt strings without boundary demarcation or intent validation.
- **Remediation:** Use structured prompt boundaries (e.g., XML tags `<user_input>...</user_input>`), enforce system instruction primacy, validate model outputs against strict schemas, and restrict tool permissions.


# Python Security Guidance & Language Pack

This reference provides language-specific vulnerability patterns, sources, sinks, framework idiosyncrasies, and secure coding practices for Python codebases (Django, Flask, FastAPI, raw Python).

---

## 1. Sources & Sinks in Python

### Untrusted Sources
- **Flask:** `request.args`, `request.form`, `request.json`, `request.values`, `request.cookies`, `request.headers`, `request.data`, `request.files`.
- **Django:** `request.GET`, `request.POST`, `request.COOKIES`, `request.META`, `request.body`, `request.FILES`.
- **FastAPI / Starlette:** Query parameters, body Pydantic models, `Request.headers`, `Request.cookies`.
- **CLI / Env:** `sys.argv`, `argparse`, `click`, `os.environ`.

### Critical Sinks
- **SQL Execution:** `cursor.execute()`, `session.execute()`, `raw()`, `extra()`.
- **Command Execution:** `os.system()`, `os.popen()`, `subprocess.Popen(..., shell=True)`, `subprocess.run(..., shell=True)`, `subprocess.call(..., shell=True)`.
- **Code Execution / Deserialization:** `eval()`, `exec()`, `pickle.loads()`, `pickle.load()`, `shelve.open()`, `yaml.load(..., Loader=Loader)`.
- **File System / Path Traversal:** `open()`, `os.remove()`, `os.chmod()`, `shutil.rmtree()`, `flask.send_file()`.
- **Template / XSS:** `flask.render_template_string()`, `django.utils.safestring.mark_safe()`.
- **Network / SSRF:** `requests.get()`, `urllib.request.urlopen()`, `httpx.get()`, `aiohttp.ClientSession.get()`.

---

## 2. Common Vulnerabilities & Remediations

### SQL Injection (CWE-89)
*Vulnerable:*
```python
# Unsafe f-string / % format in cursor.execute
cursor.execute(f"SELECT id, username FROM users WHERE status = '{status}'")
```
*Secure:*
```python
# Parameterized query with bound parameters
cursor.execute("SELECT id, username FROM users WHERE status = %s", (status,))
# SQLite placeholder
cursor.execute("SELECT id, username FROM users WHERE status = ?", (status,))
```

### OS Command Injection (CWE-78)
*Vulnerable:*
```python
import subprocess
# shell=True invokes /bin/sh or cmd.exe allowing metacharacter injection (&, |, ;)
subprocess.run(f"ls -l {user_input}", shell=True, check=True)
```
*Secure:*
```python
import subprocess
# Pass command as a list of discrete arguments with shell=False
subprocess.run(["ls", "-l", user_input], shell=False, check=True)
```

### Unsafe Deserialization (CWE-502)
*Vulnerable:*
```python
import pickle, yaml
data = pickle.loads(untrusted_bytes)
config = yaml.load(untrusted_yaml, Loader=yaml.Loader)
```
*Secure:*
```python
import json, yaml
data = json.loads(untrusted_bytes)
config = yaml.safe_load(untrusted_yaml)
```

### Cryptographic Weaknesses (CWE-327, CWE-330)
*Vulnerable:*
```python
import random, hashlib
# Insecure PRNG for tokens or password resets
reset_token = str(random.randint(100000, 999999))
# Broken hash algorithm
password_hash = hashlib.md5(password.encode()).hexdigest()
```
*Secure:*
```python
import secrets, hashlib
# Cryptographically secure random token
reset_token = secrets.token_urlsafe(32)
# Secure password hashing (Argon2 or bcrypt)
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
```

### Path Traversal (CWE-22)
*Vulnerable:*
```python
import os
path = os.path.join("/var/data/uploads", filename)
with open(path, "rb") as f:
    return f.read()
```
*Secure:*
```python
import os
base_dir = os.path.abspath("/var/data/uploads")
target_path = os.path.abspath(os.path.join(base_dir, os.path.basename(filename)))
if not target_path.startswith(base_dir + os.sep):
    raise PermissionError("Access outside authorized directory denied")
with open(target_path, "rb") as f:
    return f.read()
```

---

## 3. AI-Specific Pitfalls in Python

- **Missing ORM Tenant Isolation:** AI-generated models frequently do `User.objects.filter(id=req.id)` instead of validating tenant or organization boundaries.
- **Insecure Default Temporary Files:** AI code often uses `open(f"/tmp/{name}", "w")` instead of `tempfile.NamedTemporaryFile()` or `tempfile.mkdtemp()`.
- **Hallucinated PyPI Modules:** Always check imported packages in `requirements.txt` to ensure they are legitimate.


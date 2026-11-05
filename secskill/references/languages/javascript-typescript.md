# JavaScript & TypeScript Security Guidance & Language Pack

This reference provides language-specific vulnerability patterns, sources, sinks, framework idiosyncrasies, and secure coding practices for Node.js, Express, React, and TypeScript codebases.

---

## 1. Sources & Sinks in JavaScript / TypeScript

### Untrusted Sources
- **Express / Fastify / Koa:** `req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies`, `req.files`.
- **Browser DOM:** `location.search`, `location.hash`, `document.referrer`, `window.name`, `postMessage` events.
- **Node.js Environment / CLI:** `process.argv`, `process.env`.

### Critical Sinks
- **Command Execution:** `child_process.exec()`, `child_process.execSync()`, `child_process.spawn(..., { shell: true })`.
- **Code Evaluation:** `eval()`, `new Function()`, `setTimeout(string, ...)`, `setInterval(string, ...)`, `vm.runInThisContext()`.
- **XSS & DOM Injection:** `res.send(html)`, `element.innerHTML`, `document.write()`, React `dangerouslySetInnerHTML`, Vue `v-html`.
- **Path Traversal:** `fs.readFile()`, `fs.createReadStream()`, `path.join(__dirname, userInput)`, `res.sendFile()`.
- **SQL / NoSQL Injection:** Unescaped query string building, MongoDB `$where` clause, raw query interpolation (`db.query('SELECT ... ' + id)`).
- **Prototype Pollution:** `Object.assign()`, deep merge utilities, lodash `merge()`, `_.set()`.

---

## 2. Common Vulnerabilities & Remediations

### Cross-Site Scripting (XSS - CWE-79)
*Vulnerable (Express):*
```javascript
app.get('/search', (req, res) => {
  // Directly writing unsanitized user query into response
  res.send(`<h1>Results for: ${req.query.q}</h1>`);
});
```
*Secure (Express / Template):*
```javascript
// Render through auto-escaping template engine or encode
const escapeHtml = require('escape-html');
app.get('/search', (req, res) => {
  res.send(`<h1>Results for: ${escapeHtml(req.query.q)}</h1>`);
});
```
*Note on React:* JSX expressions `{userInput}` automatically encode HTML entities. Only flag when developers bypass React's sanitization:
```javascript
// Vulnerable:
<div dangerouslySetInnerHTML={{ __html: userBio }} />

// Secure:
<div>{userBio}</div>
// Or if HTML is required, sanitize with DOMPurify:
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userBio) }} />
```

### OS Command Injection (CWE-78)
*Vulnerable (Node.js):*
```javascript
const { exec } = require('child_process');
exec(`convert ${req.body.filename} output.png`, (err) => { ... });
```
*Secure (Node.js):*
```javascript
const { execFile } = require('child_process');
// Pass command arguments in an array without spawning a subshell
execFile('convert', [req.body.filename, 'output.png'], (err) => { ... });
```

### Insecure JWT Token Handling (CWE-287 / CWE-347)
*Vulnerable:*
```javascript
const jwt = require('jsonwebtoken');
// Decoding payload WITHOUT verifying signature!
const user = jwt.decode(token);
req.user = user;
```
*Secure:*
```javascript
const jwt = require('jsonwebtoken');
// Strictly verify signature with secret/public key and enforce algorithm
const user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
req.user = user;
```

### Prototype Pollution (CWE-1321)
*Vulnerable:*
```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key]; // if key is "__proto__", pollutes Object prototype
    }
  }
  return target;
}
```
*Secure:*
```javascript
// Reject prototype keys or create objects without prototype
function safeMerge(target, source) {
  for (let key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

---

## 3. AI-Specific Pitfalls in JavaScript / TypeScript

- **Client-Side Authorization Checks:** AI often places authorization logic solely in client components (`if (user.role === 'admin') showButton()`) without verifying permissions in the backend API route.
- **Naive Regex Sanitizers:** AI models frequently write faulty custom regexes (`val.replace(/<script>/gi, '')`) instead of using proven libraries like `DOMPurify` or `validator`.
- **Weak Randomness for Tokens:** AI often defaults to `Math.random().toString(36)` instead of Node's built-in `crypto.randomBytes()`.


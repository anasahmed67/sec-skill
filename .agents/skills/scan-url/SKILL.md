---
name: scan-url
description: "Prompts for a target URL and audits headers, CORS policies, cookies, and TLS/SSL ciphers. Also triggered by the /scan-url slash command."
metadata:
  icon: public
---

# /scan-url: Live Website & Dynamic DAST Infrastructure Audit

Performs dynamic non-destructive security auditing against live web endpoints and APIs, validating TLS/SSL certificates, HTTP security hardening headers, CORS configurations, cookie security flags, and public directory exposures.

## Execution Procedure

1. **Obtain Target URL**:
   - Check if the user passed a URL argument (e.g. `/scan-url https://example.com` or in chat).
   - If no URL was provided, prompt the user for the target URL before proceeding.
   - Validate URL scheme (must be `https://` or `http://`).

2. **Execute Dynamic Scan**:
   - Call the `secskill_scan_url` MCP tool with the target URL, or run via CLI:
     `secskill scan-url <target_url>`

3. **Audit Key Defense Vectors**:
   - **TLS / SSL**: Certificate expiration, issuer trust, TLS version (TLS 1.2 / 1.3 required; deprecate SSLv3, TLS 1.0/1.1), weak cipher suites.
   - **Security Headers**:
     - `Strict-Transport-Security` (HSTS: max-age >= 31536000, includeSubDomains, preload).
     - `Content-Security-Policy` (CSP: default-src, script-src, absence of `unsafe-inline` / `unsafe-eval`).
     - `X-Frame-Options` (`DENY` or `SAMEORIGIN` to prevent clickjacking).
     - `X-Content-Type-Options` (`nosniff`).
     - `Referrer-Policy` (`strict-origin-when-cross-origin` or `no-referrer`).
     - `Permissions-Policy` (geolocation, camera, microphone restrictions).
   - **CORS Misconfiguration**: Wildcard origins (`Access-Control-Allow-Origin: *`) paired with credentials (`Access-Control-Allow-Credentials: true`).
   - **Cookie Security**: Ensure all sensitive session cookies have `Secure`, `HttpOnly`, and `SameSite=Lax|Strict` flags.
   - **Information Leaks & Sensitive Exposures**: Server banners (`Server`, `X-Powered-By`), exposed `.env`, `.git/`, phpinfo, or Swagger docs.

4. **Output Report & Hardening Snippets**:
   - Provide a clear Infrastructure Security Scorecard (Pass / Fail / Warning for each header/category).
   - Generate copy-paste configuration snippets for common web servers (Nginx, Caddy, Apache, or Cloudflare Workers) to instantly resolve missing headers.


---
name: web-app-security
description: "Comprehensive web application security testing covering OWASP Top 10, injection attacks (SQL injection, XSS, HTML injection), authentication bypass, IDOR, file upload/path traversal vulnerabilities, API security, and web scanner tools (Burp Suite, SQLMap). Use when: penetration testing, web vulnerability assessment, SQL injection, XSS testing, OWASP, authentication bypass, API fuzzing, file upload security, WordPress security, Burp Suite, web app security audit."
---

# Web Application Security Testing

Comprehensive skill for web application vulnerability assessment and penetration testing.

## Vulnerability Categories

| Category | Reference | Key Attacks |
|----------|-----------|-------------|
| Injection | [injection-attacks.md](references/injection-attacks.md) | SQLi, XSS, HTML injection, SQLMap |
| Auth & Access | [auth-access-vulns.md](references/auth-access-vulns.md) | Auth bypass, IDOR, path traversal, file upload |
| API Security | [api-security.md](references/api-security.md) | API fuzzing, REST/GraphQL security |
| Tools | [tools-and-scanners.md](references/tools-and-scanners.md) | Burp Suite, WordPress pentesting |
| OWASP Top 10 | [owasp-top-vulns.md](references/owasp-top-vulns.md) | Full OWASP coverage |

## Quick Decision Guide

1. Testing for injection? → Read injection-attacks.md
2. Testing authentication/authorization? → Read auth-access-vulns.md
3. Testing APIs? → Read api-security.md
4. Need tool guidance? → Read tools-and-scanners.md
5. General vulnerability assessment? → Start with owasp-top-vulns.md

## Core Testing Workflow

1. **Reconnaissance**: Map application, identify endpoints and parameters
2. **Input Discovery**: Find all user-controllable inputs (URL params, forms, headers, cookies)
3. **Vulnerability Detection**: Test each input for injection, auth bypass, access control
4. **Exploitation**: Validate findings with proof-of-concept
5. **Reporting**: Document severity, impact, remediation

## Legal Requirements
- Written authorization required before testing
- Stay within defined scope
- Report critical findings immediately
- Handle extracted data per agreements

# OWASP Top Vulnerabilities Reference

Comprehensive catalog of web application vulnerability categories aligned with OWASP standards.

## OWASP Top 10 (2021) Mapping

| OWASP 2021 | Key Vulnerabilities | Key Controls |
|------------|-------------------|--------------|
| A01: Broken Access Control | IDOR, privilege escalation, forceful browsing | RBAC, least privilege, authorization checks |
| A02: Cryptographic Failures | Unencrypted data, weak TLS | Encryption at rest/transit, strong ciphers |
| A03: Injection | SQLi, XSS, command injection, SSTI, XXE | Parameterized queries, input validation, output encoding |
| A04: Insecure Design | Business logic flaws, missing validation | Threat modeling, abuse case testing |
| A05: Security Misconfiguration | Default passwords, directory listing, missing headers | Secure defaults, hardening, patching |
| A06: Vulnerable Components | Outdated libraries, unpatched software | Patch management, dependency scanning |
| A07: Auth Failures | Session fixation, brute force, credential stuffing | MFA, session management, account lockout |
| A08: Data Integrity | Insecure deserialization, unsigned updates | Integrity validation, avoid untrusted data |
| A09: Logging Failures | Insufficient logging, no alerting | SIEM, security event logging |
| A10: SSRF | Server-side request forgery | URL whitelisting, egress filtering |

## Vulnerability Categories

### 1. Injection Vulnerabilities
- **SQL Injection**: Malicious SQL in inputs → Use parameterized queries
- **XSS**: Script injection into web pages → Output encoding, CSP
- **Command Injection**: OS commands via inputs → Avoid shell execution, whitelist
- **SSTI**: Code in template engines → Sandbox templates, no user input in templates
- **XML/LDAP/XPath Injection**: Query manipulation → Input validation, escaping

### 2. Authentication & Session
- **Session Fixation**: Attacker pre-sets session ID → Regenerate session on login
- **Brute Force**: Automated password guessing → Lockout, rate limiting, MFA, CAPTCHA
- **Session Hijacking**: Stolen/predicted tokens → Secure random tokens, HTTPS, HttpOnly
- **Credential Stuffing**: Breached credential reuse → MFA, breach password checks
- **CAPTCHA Bypass**: Bot detection circumvention → reCAPTCHA v3, layered detection

### 3. Sensitive Data Exposure
- **IDOR**: Direct object access without auth checks → Authorization validation
- **Data Leakage**: Inadvertent disclosure → DLP, encryption, access controls
- **Information Disclosure**: System details in errors → Generic errors, disable debug

### 4. Security Misconfiguration
- **Missing Security Headers**: No CSP, X-Frame-Options, HSTS → Implement all headers
- **Default Passwords**: Unchanged vendor defaults → Mandatory changes
- **Directory Listing**: Exposed directory contents → Disable indexing
- **Unprotected API Endpoints**: Missing auth on APIs → OAuth/API keys, rate limiting
- **Misconfigured CORS**: Overly permissive policies → Whitelist trusted origins

### 5. XML Vulnerabilities
- **XXE**: External entity processing → Disable external entities
- **XML Entity Expansion (Billion Laughs)**: Resource exhaustion → Limit expansion
- **XML DoS**: Complex document processing → Schema validation, size limits

### 6. Access Control
- **Privilege Escalation**: Gaining elevated access → Least privilege, monitoring
- **Missing Function-Level Access Control**: Unprotected admin functions → Server-side RBAC
- **Forceful Browsing**: Direct URL to restricted resources → Server-side access controls

### 7. Insecure Deserialization
- **RCE via Deserialization**: Malicious serialized objects → Avoid untrusted deserialization
- **Object Injection**: Malicious object instantiation → Type restrictions, whitelisting

### 8. Communication Security
- **MITM**: Traffic interception → TLS/SSL, certificate pinning
- **Weak TLS**: Outdated protocols → TLS 1.2+, strong ciphers, HSTS
- **Insecure Protocols**: HTTP, Telnet, FTP → HTTPS, SSH, SFTP

### 9. Client-Side Vulnerabilities
- **DOM-Based XSS**: Client-side JS manipulation → Safe DOM APIs, CSP
- **Clickjacking**: UI redress attacks → X-Frame-Options, CSP frame-ancestors
- **Browser Cache Poisoning**: Manipulated cached content → Cache-Control, HTTPS

### 10. Denial of Service
- **DDoS**: Traffic flooding → DDoS protection, CDN, rate limiting
- **Application Layer DoS**: Logic-based resource exhaustion → WAF, code optimization
- **Slowloris**: Partial HTTP requests → Connection timeouts, reverse proxy

### 11. SSRF
- **SSRF**: Server makes requests to internal resources → URL whitelisting, network segmentation
- **Blind SSRF**: No direct response → Allowlists, WAF, network restrictions

## Critical Security Headers

```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=()
```

## Vulnerability Verification Techniques

| Vulnerability Type | Verification Approach |
|-------------------|----------------------|
| Injection | Payload testing with encoded variants |
| XSS | Alert boxes, cookie access, DOM inspection |
| CSRF | Cross-origin form submission |
| SSRF | Out-of-band DNS/HTTP callbacks |
| XXE | External entity with controlled server |
| Access Control | Horizontal/vertical privilege testing |
| Authentication | Credential rotation, session analysis |

## Assessment Challenges

| Challenge | Solution |
|-----------|----------|
| False positives | Manual verification, contextual analysis |
| Business logic flaws | Manual testing, threat modeling |
| WAF blocking tests | Rate adjustment, payload encoding |
| API discovery | Swagger/OpenAPI enumeration, traffic analysis |

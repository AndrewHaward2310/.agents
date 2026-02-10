---
name: Network Security
description: >
  Consolidated network security skill covering network penetration testing,
  protocol testing (SMTP, SSH), reconnaissance (Shodan, Nmap, Masscan),
  traffic analysis (Wireshark), port scanning, service enumeration,
  vulnerability scanning, and web application security assessment.
metadata:
  author: zebbern
  version: "2.0"
  merged_from:
    - network-101
    - smtp-penetration-testing
    - ssh-penetration-testing
    - wireshark-analysis
    - shodan-reconnaissance
    - scanning-tools
    - vulnerability-scanner
---

# Network Security

Consolidated skill for network penetration testing, reconnaissance, protocol analysis, traffic inspection, and vulnerability assessment.

## Reference Files

| Reference | Contents | File |
|-----------|----------|------|
| Network Fundamentals | HTTP/HTTPS/SNMP/SMB setup, service enumeration, log analysis | [references/network-fundamentals.md](references/network-fundamentals.md) |
| Protocol Testing | SMTP & SSH penetration testing, brute force, tunneling | [references/protocol-testing.md](references/protocol-testing.md) |
| Reconnaissance | Shodan, Nmap, Masscan, vulnerability scanners, OWASP 2025 | [references/reconnaissance.md](references/reconnaissance.md) |
| Traffic Analysis | Wireshark capture, display filters, stream analysis, security detection | [references/traffic-analysis.md](references/traffic-analysis.md) |

---

## Quick-Start Workflow

1. **Discover** - Identify live hosts and open ports
2. **Enumerate** - Determine services, versions, and banners
3. **Scan** - Run vulnerability scanners against discovered services
4. **Analyze** - Capture and inspect traffic for anomalies
5. **Exploit** - Test identified weaknesses (with authorization)
6. **Report** - Document findings with severity and remediation

---

## Essential Commands

### Host & Port Discovery

```bash
nmap -sn 192.168.1.0/24                 # Ping sweep
nmap -sS -T4 -p- 192.168.1.100         # Full SYN scan
nmap -sV -sC -p 22,25,80,443 TARGET    # Service detection + default scripts
masscan -p0-65535 192.168.1.0/24 --rate=5000  # High-speed port scan
```

### Reconnaissance

```bash
shodan host 1.1.1.1                      # Passive host recon
shodan search 'org:"Target" port:443'    # Organization search
nmap --script=vuln TARGET                # Vulnerability scripts
```

### Protocol Testing

```bash
# SMTP
smtp-user-enum -M VRFY -U users.txt -t TARGET
nmap -p 25 --script smtp-open-relay TARGET

# SSH
ssh-audit TARGET
hydra -l admin -P passwords.txt ssh://TARGET
ssh -D 1080 user@TARGET                  # SOCKS proxy pivot
```

### Traffic Analysis

```bash
# Wireshark display filters
ip.addr == 192.168.1.1 && tcp.port == 80
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN scan detection
dns.qry.name contains "suspicious"
```

---

## Common Ports

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 445 | SMB |
| 23 | Telnet | 587 | SMTP Submission |
| 25 | SMTP | 3306 | MySQL |
| 53 | DNS | 3389 | RDP |
| 80 | HTTP | 5432 | PostgreSQL |
| 161 | SNMP (UDP) | 8080 | HTTP Alt |

## Tool Selection

| Task | Tools |
|------|-------|
| Network Discovery | Nmap, Masscan |
| Passive Recon | Shodan |
| Vulnerability Scan | Nessus, OpenVAS, Nmap NSE |
| Web App Testing | Burp Suite, OWASP ZAP, Nikto |
| Protocol Testing | Hydra, Medusa, smtp-user-enum, ssh-audit |
| Traffic Analysis | Wireshark, tcpdump |
| Wireless | Aircrack-ng, Kismet |
| Cloud Security | Prowler, ScoutSuite |
| Compliance | Lynis, OpenSCAP |

## Constraints

- Always obtain written authorization before testing
- Start with non-intrusive scans, escalate gradually
- Document all scanning and testing activities
- Respect scope boundaries and legal requirements
- Lab environments should be isolated from production

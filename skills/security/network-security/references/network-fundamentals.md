# Network Fundamentals

> Source: network-101 skill

## Purpose

Configure and test common network services (HTTP, HTTPS, SNMP, SMB) for penetration testing lab environments. Enable hands-on practice with service enumeration, log analysis, and security testing against properly configured target systems.

## Prerequisites

- Windows Server or Linux system for hosting services
- Kali Linux or similar for testing
- Administrative access to target system
- Basic networking knowledge (IP addressing, ports)
- Firewall access for port configuration

## Essential Ports

| Service | Port | Protocol |
|---------|------|----------|
| HTTP | 80 | TCP |
| HTTPS | 443 | TCP |
| SNMP | 161 | UDP |
| SMB | 445 | TCP |
| NetBIOS | 137-139 | TCP/UDP |

---

## HTTP Server Setup (Port 80)

### Linux Apache

```bash
sudo apt update && sudo apt install apache2
sudo systemctl start apache2
sudo systemctl enable apache2
echo "<html><body><h1>Test Page</h1></body></html>" | sudo tee /var/www/html/index.html
curl http://localhost
```

### Windows IIS

1. Open IIS Manager
2. Right-click Sites > Add Website
3. Configure site name and physical path
4. Bind to IP address and port 80

### Firewall Rules

```bash
# Linux (UFW)
sudo ufw allow 80/tcp

# Windows PowerShell
New-NetFirewallRule -DisplayName "HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
```

---

## HTTPS Server Setup (Port 443)

### Generate Self-Signed Certificate

```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/apache-selfsigned.key \
  -out /etc/ssl/certs/apache-selfsigned.crt

sudo a2enmod ssl
sudo systemctl restart apache2
```

### Enable SSL Site

```bash
sudo a2ensite default-ssl
sudo systemctl reload apache2
```

### Verify HTTPS

```bash
nmap -p 443 192.168.1.1
openssl s_client -connect 192.168.1.1:443
curl -kv https://192.168.1.1
```

---

## SNMP Service Setup (Port 161)

### Linux

```bash
sudo apt install snmpd snmp
sudo nano /etc/snmp/snmpd.conf
# Add: rocommunity public
# Add: rwcommunity private
sudo systemctl restart snmpd
```

### Windows

1. Server Manager > Add Features > SNMP Service
2. Configure community strings in Services > SNMP Service > Properties

### SNMP Enumeration

```bash
snmpwalk -c public -v1 192.168.1.1
snmpwalk -c public -v1 192.168.1.1 1.3.6.1.2.1.1          # System info
snmpwalk -c public -v1 192.168.1.1 1.3.6.1.2.1.25.4.2.1.2  # Processes
snmp-check 192.168.1.1 -c public
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.1.1
```

---

## SMB Service Setup (Port 445)

### Linux Samba

```bash
sudo apt install samba
sudo mkdir -p /srv/samba/share
sudo chmod 777 /srv/samba/share
sudo nano /etc/samba/smb.conf
# [public]
#    path = /srv/samba/share
#    browsable = yes
#    guest ok = yes
#    read only = no
sudo systemctl restart smbd
```

### SMB Enumeration

```bash
smbclient -L //192.168.1.1 -N
smbclient //192.168.1.1/share -N
smbmap -H 192.168.1.1
enum4linux -a 192.168.1.1
nmap --script smb-vuln* 192.168.1.1
```

---

## Log Analysis

```bash
# Apache access/error logs
sudo tail -f /var/log/apache2/access.log
sudo tail -f /var/log/apache2/error.log

# Windows IIS logs: C:\inetpub\logs\LogFiles\W3SVC1\

# Parse for POST requests
grep "POST" /var/log/apache2/access.log

# Extract user agents
awk '{print $12}' /var/log/apache2/access.log | sort | uniq -c
```

---

## Service Verification Quick Reference

```bash
curl -I http://target        # HTTP
curl -kI https://target       # HTTPS
snmpwalk -c public -v1 target # SNMP
smbclient -L //target -N     # SMB
```

## Common Enumeration Tools

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and scripts |
| nikto | Web vulnerability scanning |
| snmpwalk | SNMP enumeration |
| enum4linux | SMB/NetBIOS enumeration |
| smbclient | SMB connection |
| gobuster | Directory brute forcing |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Port not accessible | Check firewall rules (ufw, iptables, Windows Firewall) |
| Service not starting | Check logs with `journalctl -u service-name` |
| SNMP timeout | Verify UDP 161 is open, check community string |
| SMB access denied | Verify share permissions and user credentials |
| HTTPS certificate error | Accept self-signed cert or add to trusted store |
| Cannot connect remotely | Bind service to 0.0.0.0 instead of localhost |

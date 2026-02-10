# Traffic Analysis with Wireshark

> Source: wireshark-analysis skill

## Purpose

Execute comprehensive network traffic analysis using Wireshark to capture, filter, and examine network packets for security investigations, performance optimization, and troubleshooting.

## Prerequisites

- Wireshark installed (Windows, macOS, or Linux)
- Network interface with capture permissions (admin/root)
- PCAP/PCAPNG files for offline analysis
- Understanding of TCP/IP, OSI model, common attack patterns

---

## Phase 1: Capturing Traffic

### Start Live Capture

1. Launch Wireshark
2. Select network interface
3. Click shark fin icon or double-click interface
4. Capture begins immediately

### Capture Controls

| Action | Shortcut |
|--------|----------|
| Start/Stop Capture | Ctrl+E |
| Restart Capture | Ctrl+R |
| Open PCAP File | Ctrl+O |
| Save Capture | Ctrl+S |

### Capture Filters (apply before capture)

```
host 192.168.1.100                 # Specific host
port 80                            # Specific port
net 192.168.1.0/24                 # Network range
not arp                            # Exclude ARP
host 192.168.1.100 and port 443   # Combined
```

---

## Phase 2: Display Filters

### IP Address Filters

```
ip.addr == 192.168.1.1              # All traffic to/from IP
ip.src == 192.168.1.1               # Source IP only
ip.dst == 192.168.1.1               # Destination IP only
```

### Port Filters

```
tcp.port == 80                       # TCP port 80
udp.port == 53                       # UDP port 53
tcp.dstport == 443                   # Destination port 443
tcp.srcport == 22                    # Source port 22
```

### Protocol Filters

```
http                                  # HTTP traffic
https or ssl or tls                   # Encrypted web traffic
dns                                   # DNS queries/responses
ftp                                   # FTP traffic
ssh                                   # SSH traffic
icmp                                  # Ping/ICMP
arp                                   # ARP requests/responses
smb or smb2                          # SMB file sharing
```

### TCP Flag Filters

```
tcp.flags.syn == 1                   # SYN packets
tcp.flags.ack == 1                   # ACK packets
tcp.flags.fin == 1                   # FIN packets
tcp.flags.reset == 1                 # RST packets
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN-only (initial connection)
```

### Content Filters

```
frame contains "password"            # Packets containing string
http.request.uri contains "login"    # HTTP URIs with string
tcp contains "GET"                   # TCP packets with string
```

### Analysis Filters

```
tcp.analysis.retransmission          # TCP retransmissions
tcp.analysis.duplicate_ack           # Duplicate ACKs
tcp.analysis.zero_window             # Zero window (flow control)
dns.flags.rcode != 0                 # DNS errors
```

### Combining Filters

```
ip.addr == 192.168.1.1 && tcp.port == 80           # AND
dns || http                                         # OR
!(arp || icmp)                                      # NOT
(ip.src == 192.168.1.1 || ip.src == 192.168.1.2) && tcp.port == 443
```

---

## Phase 3: Following Streams

### TCP Stream Reconstruction

1. Right-click on any TCP packet
2. Select Follow > TCP Stream
3. View reconstructed conversation
4. Toggle between ASCII, Hex, Raw views

### Stream Types

| Stream | Access | Use Case |
|--------|--------|----------|
| TCP Stream | Follow > TCP Stream | Web, file transfers |
| UDP Stream | Follow > UDP Stream | DNS, VoIP |
| HTTP Stream | Follow > HTTP Stream | Web content, headers |
| TLS Stream | Follow > TLS Stream | Encrypted (if keys available) |

---

## Phase 4: Statistical Analysis

### Available Statistics (Statistics menu)

| Feature | Purpose |
|---------|---------|
| Protocol Hierarchy | Protocol distribution, packet counts |
| Conversations | Communication pairs (Ethernet, IP, TCP, UDP) |
| Endpoints | Active network participants |
| Flow Graph | Packet sequence visualization |
| I/O Graphs | Traffic over time plots |

---

## Phase 5: Security Analysis

### Port Scan Detection

```
ip.src == SUSPECT_IP && tcp.flags.syn == 1
# Look for single source hitting many destination ports in Conversations
```

### Suspicious Traffic Detection

```
tcp.dstport > 1024 && tcp.dstport < 49152    # Unusual ports
!(ip.addr == 192.168.1.0/24)                  # Traffic outside trusted network
dns.qry.name contains "suspicious-domain"     # Unusual DNS queries
frame.len > 1400                              # Large data transfers
```

### ARP Spoofing Detection

```
arp.duplicate-address-frame
# Look for multiple MACs for same IP, gratuitous ARP floods
```

### File Extraction

```
# HTTP downloads
http.request.method == "GET" && http contains "Content-Disposition"
# File > Export Objects > HTTP to extract files
```

### DNS Analysis

```
dns                                   # All DNS traffic
dns.flags.response == 0              # Queries only
dns.flags.response == 1              # Responses only
dns.flags.rcode != 0                 # Failed lookups
dns.qry.name contains "domain.com"  # Specific domain
```

---

## Phase 6: Expert Information

Access via: Analyze > Expert Information

### Common Expert Findings

| Finding | Meaning | Action |
|---------|---------|--------|
| TCP Retransmission | Packet resent | Check for packet loss |
| Duplicate ACK | Possible loss | Investigate network path |
| Zero Window | Buffer full | Check receiver performance |
| RST | Connection reset | Check for blocks/errors |
| Out-of-Order | Packets reordered | Excessive = issue |

---

## Quick Reference

### Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Open file | Ctrl+O |
| Save file | Ctrl+S |
| Start/Stop capture | Ctrl+E |
| Find packet | Ctrl+F |
| Go to packet | Ctrl+G |
| Apply filter | Enter |
| Clear filter | Ctrl+Shift+X |

### Common Filter Patterns

```
http || https          # Web traffic
smtp || pop || imap    # Email
smb || smb2 || ftp     # File sharing
ldap || kerberos       # Authentication
snmp || icmp           # Network management
tls || ssl             # Encrypted
```

### Export Options

```
File > Export Specified Packets    # Save filtered subset
File > Export Objects > HTTP       # Extract HTTP files
File > Export Packet Dissections   # Export as text/CSV
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No Packets Captured | Verify interface, check admin/root permissions, confirm adapter active |
| Filter Not Working | Check syntax (red = error), use Expression button for valid fields |
| Performance Issues | Use capture filters, split large captures, disable name resolution |
| Cannot Decrypt TLS | Obtain server private key, configure in Preferences > Protocols > TLS |

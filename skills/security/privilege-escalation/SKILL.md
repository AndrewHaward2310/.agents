---
name: privilege-escalation
description: "Privilege escalation techniques for Linux, Windows, Active Directory, and cloud environments (AWS/Azure/GCP). Covers SUID exploitation, kernel exploits, token manipulation, Kerberoasting, Pass-the-Hash, IAM misconfigurations, and cloud metadata attacks. Use when: privilege escalation, privesc, Linux root, Windows admin, Active Directory attack, Kerberoasting, cloud penetration testing, AWS security, lateral movement, domain compromise."
---

# Privilege Escalation & Infrastructure Attacks

Comprehensive privilege escalation across operating systems, Active Directory, and cloud platforms.

## Platform Guide

| Platform | Reference | Key Techniques |
|----------|-----------|----------------|
| Linux | [linux-privesc.md](references/linux-privesc.md) | SUID, kernel exploits, cron, capabilities |
| Windows | [windows-privesc.md](references/windows-privesc.md) | Token abuse, services, UAC bypass, DLL hijack |
| Active Directory | [active-directory.md](references/active-directory.md) | Kerberoasting, PtH, lateral movement |
| Cloud (AWS/Azure/GCP) | [cloud-security.md](references/cloud-security.md) | IAM, metadata, S3, cloud enumeration |

## Quick Start

1. Identify target OS/platform
2. Read the corresponding reference file
3. Follow enumeration -> exploitation -> persistence flow
4. Document findings with evidence

## Enumeration First

Always enumerate before exploiting:
- Linux: `id`, `uname -a`, `find / -perm -4000`, linpeas
- Windows: `whoami /priv`, `systeminfo`, winPEAS
- AD: BloodHound, PowerView, ldapsearch
- Cloud: enumerate IAM, list buckets, check metadata service

## Legal Requirements
- Written authorization required
- Stay within defined scope
- Report critical findings immediately

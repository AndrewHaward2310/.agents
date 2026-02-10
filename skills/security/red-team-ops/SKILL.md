---
name: red-team-ops
description: >
  Consolidated red team operations skill covering offensive security methodology,
  MITRE ATT&CK tactics, exploitation frameworks (Metasploit), reconnaissance tooling,
  vulnerability discovery, payload generation, post-exploitation, and bug bounty workflows.
  Use when the user asks about red teaming, penetration testing, exploit development,
  msfconsole, msfvenom, adversary simulation, or offensive security tooling.
metadata:
  author: consolidated
  version: "1.0"
  sources:
    - red-team-tactics
    - red-team-tools
    - metasploit-framework
allowed-tools: Read, Glob, Grep
---

# Red Team Operations

> Unified offensive security reference: tactics, tooling, and exploitation frameworks.

## Scope

This skill consolidates three domains into a single operational reference:

| Domain | Reference | Coverage |
|--------|-----------|----------|
| **Tactics** | [references/tactics.md](references/tactics.md) | MITRE ATT&CK phases, privesc, lateral movement, AD attacks, evasion, reporting |
| **Tools** | [references/tools.md](references/tools.md) | Recon tooling, subdomain enum, content discovery, XSS hunting, vuln scanning |
| **Metasploit** | [references/metasploit.md](references/metasploit.md) | msfconsole, modules, msfvenom payloads, meterpreter, post-exploitation |

---

## Engagement Lifecycle

```
1. SCOPE & RULES OF ENGAGEMENT
2. RECONNAISSANCE        → references/tools.md  (subdomain enum, asset discovery)
3. INITIAL ACCESS         → references/tactics.md (access vectors, phishing, exploits)
4. EXPLOITATION           → references/metasploit.md (modules, payloads, handlers)
5. POST-EXPLOITATION      → references/metasploit.md (meterpreter, credential harvest)
6. LATERAL MOVEMENT       → references/tactics.md (pass-the-hash, AD attacks)
7. REPORTING              → references/tactics.md (attack narrative, detection gaps)
```

---

## Quick Decision Matrix

| Task | Start Here |
|------|------------|
| Map attack surface / enumerate subdomains | [tools.md](references/tools.md) - Sections 1-3 |
| Choose initial access vector | [tactics.md](references/tactics.md) - Section 3 |
| Exploit a known CVE | [metasploit.md](references/metasploit.md) - Phases 3-4 |
| Generate a standalone payload | [metasploit.md](references/metasploit.md) - Phase 9 (msfvenom) |
| Post-exploitation / credential dump | [metasploit.md](references/metasploit.md) - Phases 6, 8 |
| Privilege escalation (Windows/Linux) | [tactics.md](references/tactics.md) - Section 4 |
| Evade detection / OPSEC | [tactics.md](references/tactics.md) - Section 5 |
| Hunt for XSS / web vulns | [tools.md](references/tools.md) - Sections 7-8 |
| Active Directory attacks | [tactics.md](references/tactics.md) - Section 7 |
| Set up recon automation pipeline | [tools.md](references/tools.md) - Section 10 |

---

## Essential Tool Summary

| Category | Tools |
|----------|-------|
| Subdomain Enum | Amass, Subfinder, Assetfinder, Findomain |
| Live Hosts | httpx, httprobe, massdns |
| Content Discovery | ffuf, waybackurls, gau |
| Vuln Scanning | Nuclei, Dalfox, Burp Suite |
| Exploitation | Metasploit (msfconsole), msfvenom |
| Post-Exploitation | Meterpreter, post/ modules |

---

## Ethical Boundaries

- **Always** operate within written scope and rules of engagement
- **Always** document all actions for the final report
- **Always** minimize impact on production systems
- **Never** retain sensitive data beyond what is required for reporting
- **Never** exceed proof-of-concept access without authorization

> Red team operations exist to improve defenses, not to cause harm.

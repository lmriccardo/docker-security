#!/bin/bash

# Section: 4.2.2. - Audit for Docker Artifacts
# Simple script to setup an auditing for Docker
# artifacts, such as binaries, configuration files
# system services etc. This uses the Linux Audi
# Framework provided with the auditd utility.

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

function check_command_output {
	if [ ! $? -eq 0 ]; then
		echo -e "[*] ${RED}Error. Exiting ...${NC}"
		exit 1
	fi;
}

if [ -z $(id | grep root) ]; then
	echo -e "[*] ${RED}Run this program with sudo${NC}"
	exit 1
fi;

echo -e "[*] ${GREEN}Check if the Linux Audit Framework is installed${NC}"
audit=$(which auditctl)
if [ -z ${audit} ]; then
	echo -e "[*] ${YELLOW}Linux Audit Framework not found. Installing ...${NC}"
	sudo apt-get install -y auditd
	check_command_output
	echo -e "[*] ${GREEN}Linux Audit Framework installed${NC}"
fi;

artifacts=(/usr/bin/docker
 		   /run/containerd
	       /var/lib/docker
	   	   /etc/docker
	       /lib/systemd/system/docker.service
	       /lib/systemd/system/docker.socket
	       /etc/docker/daemon.json
	       /usr/bin/docker-containerd
	   	   /usr/bin/docker-runc
	       /usr/bin/containerd
	   	   /usr/bin/containerd-shim
	       /usr/bin/containerd-shim-runc-v1
	       /usr/bin/containerd-shim-runc-v2)

for art in "${artifacts[@]}"; do
	echo -e "    ${GREEN}- adding file ${art}${NC}"
	sudo auditctl -w ${art} -k docker
	check_command_output
done

echo -e "[*] ${GREEN}Audit rules added successfully${NC}"
echo -e "[*] ${GREEN}Making these rules permanent${NC}"
sudo auditctl -l >> /etc/audit/rules.d/audit.rules
check_command_output

echo -e "[*] ${GRREN}Exiting ...${NC}"
exit 0

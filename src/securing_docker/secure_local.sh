#!/bin/bash

# Section: 4.2.1 (secure local login)
# This a simple script to secure local accounts
# It is possible to give to this script which 
# accounts should be create, which of those will 
# have sudo permission, or docker access, or none 
# of previous. 

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
YELLOW='\033[1;33'

function check_command_output {
	if [ ! $? -eq 0 ]; then
		echo -e "[*] ${RED}Error. Exiting ...${NC}"
		exit 1
	fi;
}

function usage {
	echo "Usage: secure_local.sh [-d [user1, ...]] [-s [user1, ...]] [-u [user1, ...]]"
	echo "                        -d: Create and add users to docker group"
	echo "                        -s: Create and add users to sudo group"
	echo "                        -u: Create users without any access either docker or sudo"
	echo ""
	echo "       The best configuration would be having three users. The first user is the"
	echo "       root user. The second user is the admin with sudo access. The third user"
	echo "       is the normal user, which docker access but without any privileges. Please"
	echo "       do not add any other sudoers. It cuold be a very insecure procedure"
}

create_user() {
	user=$1
	sudo useradd -c "User ${user}" -m -s /bin/bash ${user}
	check_command_output

	sudo passwd ${user}
	check_command_output
}

declare -a dockers
declare -a sudoers
declare -a users

while getopts ":hd:s:u:" opt; do
	case $opt in
		h ) usage
			exit 0;;
		d ) set -f
			IFS=','
			dockers=($OPTARG);;
		s ) set -f
			IFS=','
			sudoers=($OPTARG);;
		u ) set -f
			IFS=','
			users=($OPTARG);;
		? ) usage
			exit 0;;
		* ) usage
			exit 1
	esac
done

echo -e "[*] ${GREEN}Dockers users: ${dockers[@]}${NC}"
echo -e "[*] ${GREEN}Sudoers users: ${sudoers[@]}${NC}"
echo -e "[*] ${GREEN}Normal  users : ${users[@]}${NC}"

echo -e "[*] ${GREEN}Would you like to continue (leave blank to exit)?${NC}"
read ans

if [ -z ${ans} ]; then
	echo -e "[*] ${GREEN}Exiting ...${NC}"
	exit 0
fi;

echo -e "[*] ${GREEN}Creating normal users${NC}"
for user in "${users[@]}"; do
	if id -u "${user}" &> /dev/null; then
		echo -e "    ${GREEN}- ${user} already exists${NC}"
	else
		echo -e "    ${GREEN}- creating ${user}${NC}"
		create_user ${user}
		echo -e "    ${GREEN}- ${user} created${NC}"
	fi;
done

echo -e "[*] ${GREEN}Creating dockers users${NC}"
for docku in "${dockers[@]}"; do
	if id -u "${docku}" &> /dev/null; then
		echo -e "    ${GREEN}- ${docku} already exists${NC}"
		groups=$(groups ${docku} | grep docker)
		if [ -z ${groups} ]; then
			echo -e "    ${GREEN}- adding ${docku} to docker group${NC}"
			sudo usermod -aG docker ${docku}
			check_command_output
		else
			echo -e "    ${GREEN}- ${docku} already belong to docker group${NC}"
		fi;
	else
		echo -e "    ${GREEN}- creating ${docku}${NC}"
		create_user ${docku}
		check_command_output
		echo -e "    ${GREEN}- ${docku} created${NC}"
		echo -e "    ${GREEN}- adding ${docku} to docker group${NC}"
		sudo usermod -aG docker ${user}
		check_command_output
	fi;
done

echo -e "[*] ${GREEN}Creating sudoers users${NC}"
for sudou in "${sudoers[@]}"; do
	if id -u "${sudou}" &> /dev/null; then
		echo -e "    ${GREEN}- ${sudou} already exists${NC}"
		groups=$(groups ${sudou} | grep sudo)
		if [ -z ${groups} ]; then
			echo -e "    ${GREEN}- adding ${sudou} to sudo group${NC}"
			sudo usermod -aG sudo ${sudou}
			check_command_output
		else
			echo -e "    ${GREEN}- ${sudou} already belong to sudo group${NC}"
		fi;
	else
		echo -e "    ${GREEN}- creating ${sudou}${NC}"
		create_user ${sudou}
		check_command_output
		echo -e "    ${GREEN}- ${sudou} created${NC}"
		echo -e "    ${GREEN}- adding ${sudou} to sudo group${NC}"
		sudo usermod -aG sudo ${sudou}
		check_command_output
	fi;
done

echo -e "[*] ${GREEN}Exiting ...${NC}"
exit 0

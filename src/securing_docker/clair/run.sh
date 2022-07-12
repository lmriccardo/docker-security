#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

function check_command_output {
	if [ ! $? -eq 0 ]; then
		echo -e "[*] ${RED}Error. Exiting${NC}"
		exit 1
	fi;
}

echo -e "[*] ${GREEN}Downloading the Clair Scanner${NC}"
sudo curl -L https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64 -o /usr/bin/clair-scanner
check_command_output

sudo chmod +x /usr/bin/clair-scanner
check_command_output

echo -e "[*] ${GEEN}Starting Clair database and Clair local scanner${NC}"
docker-compose up -d
check_command_output

echo -e "[*] ${GREEN}Docker containers started${NC}"
echo -e "[*] ${GREEN}To scan run the following command: "
echo -e "    clair-scanner -r {report-name.json} --ip 172.17.0.1 {image}${NC}"
exit 0

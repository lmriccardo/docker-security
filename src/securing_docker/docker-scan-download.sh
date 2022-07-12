#!/bin/bash

# This script provide a simple way of downloading 
# the Docker Scan utility, since it is not present
# inside the standard repository of, at least, my 
# Linux distribution (Ubuntu).
#
# Note: This should work with every Debian-based distribution

cd /home
wget https://download.docker.com/linux/ubuntu/dists/focal/pool/stable/amd64/docker-scan-plugin_0.7.0~ubuntu-focal_amd64.deb
sudo dpkg -i docker-scan-plugin_0.7.0\~ubuntu-focal_amd64.deb
rm docker-scan-plugin_0.7.0\~ubuntu-focal_amd64.deb
exit 0

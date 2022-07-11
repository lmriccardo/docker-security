#!/bin/bash

# This simple script summarize all the commands needed to setup 
# a TLS authentication, hence generating the CA certificate, 
# both server and client signed certificate and, finally, both
# server and client keys for authentication.

serverdns=$1
serverip=$2

if [[ -z ${serverdns} || -z ${serverip} ]]; then
	echo "Usage: bash tls_sec.sh server_dns IP"
	exit 1
fi;

# ---------------- DOCKER HOST (server) --------------------------
# Generate CA key and CA certificate
openssl genrsa -aes256 -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

# Create server key and certificate signing request
openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=${serverdns}" -sha256 -new -key server-key.pem -out server.csr

# The IP addressed used for the TLS connection must be specified 
# when creating the certificate
echo subjectAltName = DNS:${serverdns},IP:${serverip} >> extfile.cnf
echo extendedKeyUsage = serverAuth >> extfile.cnf

# Generating the signed certificate
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem \
	-CAkey ca-key.pem -CAcreateserial -out server-cert.pem \
	-extfile extfile.cnf

# ----------------- DOCKER REMOTE CLIENT -------------------------
# Create client key and certificate signing request
openssl genrsa -out key.pem 4096
openssl req -subj '/CN=client' -new -key key.pem -out client.csr
echo extendedKeyUsage = clientAuth > extfile-client.cnf

# Generating signed certificate
openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.pem \
	-CAkey ca-key.pem -CAcreateserial -out cert.pem \
	-extfile extfile-client.cnf

# Removing uneeded files
rm -v client.csr server.csr extfile.cnf extfile-client.cnf

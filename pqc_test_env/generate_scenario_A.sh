#!/bin/sh
echo "Generating Classical RSA Root CA..."
openssl genrsa -out root_rsa.key 2048
openssl req -x509 -new -nodes -key root_rsa.key -sha256 -days 365 -out root_rsa.crt -subj "/CN=My_Classical_Root_CA"

echo "Generating PQC ML-DSA Server Certificate..."
openssl genpkey -algorithm mldsa44 -out server_pqc.key
openssl req -new -key server_pqc.key -out server_pqc.csr -subj "/CN=localhost"

echo "Signing PQC Server Cert with Classical Root CA..."
openssl x509 -req -in server_pqc.csr -CA root_rsa.crt -CAkey root_rsa.key -CAcreateserial -out server_pqc.crt -days 365

echo "Combining certs into chain..."
cat server_pqc.crt root_rsa.crt > chain_pqc_ready.crt
echo "Done! Certificates for Scenario A are ready."

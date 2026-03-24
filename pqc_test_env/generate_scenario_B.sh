#!/bin/sh
echo "Generating PQC Root CA (ML-DSA)..."
openssl genpkey -algorithm mldsa44 -out root_pqc.key
openssl req -x509 -new -nodes -key root_pqc.key -days 365 -out root_pqc.crt -subj "/CN=My_Pure_PQC_Root_CA"

echo "Generating PQC Server Certificate (ML-DSA)..."
openssl genpkey -algorithm mldsa44 -out server_pure_pqc.key
openssl req -new -key server_pure_pqc.key -out server_pure_pqc.csr -subj "/CN=localhost"

echo "Signing PQC Server Cert with PQC Root CA..."
openssl x509 -req -in server_pure_pqc.csr -CA root_pqc.crt -CAkey root_pqc.key -CAcreateserial -out server_pure_pqc.crt -days 365

echo "Combining certs into pure chain..."
cat server_pure_pqc.crt root_pqc.crt > chain_fully_qs.crt
echo "Done! Certificates for Scenario B are ready."

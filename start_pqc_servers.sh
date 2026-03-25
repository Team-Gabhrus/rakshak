#!/bin/sh
cd /tmp

# --- Server 1: PQC Ready (Port 4433) ---
openssl genrsa -out root_rsa.key 2048
openssl req -x509 -new -nodes -key root_rsa.key -sha256 -days 365 -out root_rsa.crt -subj "/CN=My_Classical_Root_CA"

openssl genpkey -algorithm mldsa44 -out server_pqc.key
openssl req -new -key server_pqc.key -out server_pqc.csr -subj "/CN=localhost"
openssl x509 -req -in server_pqc.csr -CA root_rsa.crt -CAkey root_rsa.key -CAcreateserial -out server_pqc.crt -days 365

cat server_pqc.crt root_rsa.crt > chain_pqc_ready.crt
openssl s_server -cert chain_pqc_ready.crt -key server_pqc.key -port 4433 -www -tls1_3 -groups mlkem768 &

# --- Server 2: Fully Quantum Safe (Port 4434) ---
openssl genpkey -algorithm mldsa44 -out root_pqc.key
openssl req -x509 -new -nodes -key root_pqc.key -days 365 -out root_pqc.crt -subj "/CN=My_Pure_PQC_Root_CA"

openssl genpkey -algorithm mldsa44 -out server_pure_pqc.key
openssl req -new -key server_pure_pqc.key -out server_pure_pqc.csr -subj "/CN=localhost"
openssl x509 -req -in server_pure_pqc.csr -CA root_pqc.crt -CAkey root_pqc.key -CAcreateserial -out server_pure_pqc.crt -days 365

cat server_pure_pqc.crt root_pqc.crt > chain_fully_qs.crt
openssl s_server -cert chain_fully_qs.crt -key server_pure_pqc.key -port 4434 -www -tls1_3 -groups mlkem768 &

# Keep the container running in the foreground
wait

# PQC Mini Server Setup Guide

To test the **PQC Ready** and **🟢 Fully Quantum Safe** network labels locally against your scanner, you can spawn your own test HTTP servers using the `openquantumsafe/curl` Docker container. This container comes pre-loaded with an OpenSSL fork that supports Post-Quantum algorithms like `ML-DSA` and `ML-KEM`.

Below is a step-by-step plan to achieve both statuses.

---

## Prerequisites
You only need **Docker** installed. Make sure Docker Desktop is running.

Open a terminal (e.g., PowerShell) and jump into the OQS sandbox shell:
```bash
# Create a local directory to hold the test certificates
mkdir pqc_test_env
cd pqc_test_env

# Start an interactive shell inside the OQS container
docker run -it --rm -v ${PWD}:/opt/test -w /opt/test openquantumsafe/curl sh
```

*(You will run all the `openssl` commands below inside this container shell).*

---

## Scenario A: Achieving 🔵 "PQC Ready"
*Definition: The server uses PQC for Key Exchange (e.g., ML-KEM) and Authentication (e.g., ML-DSA), but the Root Certificate Authority (CA) establishing trust is Classical (e.g., RSA).*

### 1. Generate the Classical Root CA (RSA)
```bash
# Generate Classical RSA 2048 Root CA key
openssl genrsa -out root_rsa.key 2048

# Create a self-signed Root Certificate
openssl req -x509 -new -nodes -key root_rsa.key -sha256 -days 365 -out root_rsa.crt -subj "/CN=My_Classical_Root_CA"
```

### 2. Generate the PQC Server Certificate (ML-DSA)
```bash
# Generate a Post-Quantum Server Key using ML-DSA-44 (formerly Dilithium2)
openssl genpkey -algorithm mldsa44 -out server_pqc.key

# Create a Certificate Signing Request (CSR)
openssl req -new -key server_pqc.key -out server_pqc.csr -subj "/CN=localhost"

# Sign the PQC Server Certificate using the Classical RSA Root CA
openssl x509 -req -in server_pqc.csr -CA root_rsa.crt -CAkey root_rsa.key -CAcreateserial -out server_pqc.crt -days 365
```

### 3. Combine the Chain and Start the Server
```bash
# Combine the PQC server cert and the Classical Root cert into a chain file
cat server_pqc.crt root_rsa.crt > chain_pqc_ready.crt

# Start the OpenSSL test server listening on port 4433
# We force the use of a PQC Key Exchange algorithm: mlkem768 (ML-KEM)
openssl s_server -cert chain_pqc_ready.crt -key server_pqc.key -port 4433 -www -tls1_3 -groups mlkem768
```

### 4. Test it!
Leave the server running in that terminal. Open a **new terminal** on your Windows host, point your scanner to `localhost:4433` (or whatever the IP of your Docker container is mapped to), and run the Rakshak scan. 
It should return **🔵 PQC Ready** because the KEX and Leaf are PQC, but the Root CA is RSA!

---

## Scenario B: Achieving 🟢 "Fully Quantum Safe"
*Definition: The server uses PQC for Key Exchange, PQC for Authentication, AND the Root CA is also PQC!*

### 1. Generate the PQC Root CA (ML-DSA)
```bash
# Generate Post-Quantum Root CA Key using ML-DSA-44
openssl genpkey -algorithm mldsa44 -out root_pqc.key

# Create a self-signed Root Certificate entirely using PQC
openssl req -x509 -new -nodes -key root_pqc.key -days 365 -out root_pqc.crt -subj "/CN=My_Pure_PQC_Root_CA"
```

### 2. Generate the PQC Server Certificate (ML-DSA)
```bash
# Generate a second Post-Quantum Server Key
openssl genpkey -algorithm mldsa44 -out server_pure_pqc.key

# Create a Certificate Signing Request (CSR)
openssl req -new -key server_pure_pqc.key -out server_pure_pqc.csr -subj "/CN=localhost"

# Sign the Server Certificate using the PQC Root CA!
openssl x509 -req -in server_pure_pqc.csr -CA root_pqc.crt -CAkey root_pqc.key -CAcreateserial -out server_pure_pqc.crt -days 365
```

### 3. Combine the Chain and Start the Server
```bash
# Combine the PQC server cert and the PQC Root cert into a pure chain file
cat server_pure_pqc.crt root_pqc.crt > chain_fully_qs.crt

# Start the OpenSSL test server listening on port 4434
# Force the use of PQC Key Exchange: mlkem768
openssl s_server -cert chain_fully_qs.crt -key server_pure_pqc.key -port 4434 -www -tls1_3 -groups mlkem768
```

### 4. Test it!
Run the Rakshak scan targeting `localhost:4434`. 
Because the KEX (`kyber768`), the Leaf Certificate (`ML-DSA-44`), and the Root Certificate (`ML-DSA-44`) are ALL Post-Quantum, your scanner will correctly flag it as **🟢 Fully Quantum Safe**!

---

### Troubleshooting PQC Algorithms
If you want to play with the latest NIST standardized names instead of the old OQS draft names (e.g., using `mldsa44` instead of `dilithium2`), ensure your `openquantumsafe/curl` docker image is fully updated via `docker pull openquantumsafe/curl:latest`.

#!/bin/bash
# ================================================================
# Rakshak Hybrid PQC KEX Debug Script — Run on EC2
# ================================================================
# Copy this to your EC2 instance and run: bash debug_ec2_oqs.sh
# ================================================================

set -e
TARGET="${1:-support.google.com}"
PORT="${2:-443}"

echo ""
echo "============================================================"
echo "  STEP 1: Docker availability"
echo "============================================================"
if command -v docker &> /dev/null; then
    echo "  ✅ Docker CLI found: $(docker --version)"
else
    echo "  ❌ Docker NOT found! Install with: sudo apt install docker.io"
    echo "     Then: sudo usermod -aG docker \$USER && newgrp docker"
    exit 1
fi

if docker info &> /dev/null; then
    echo "  ✅ Docker daemon is running"
else
    echo "  ❌ Docker daemon not running or no permission!"
    echo "     Try: sudo systemctl start docker"
    echo "     Or:  sudo usermod -aG docker \$USER && newgrp docker"
    exit 1
fi

echo ""
echo "============================================================"
echo "  STEP 2: OQS Docker image"
echo "============================================================"
if docker images openquantumsafe/curl --format '{{.Repository}}:{{.Tag}}' | grep -q curl; then
    echo "  ✅ OQS image found:"
    docker images openquantumsafe/curl --format '  {{.Repository}}:{{.Tag}}  ({{.Size}}, created {{.CreatedSince}})'
else
    echo "  ⚠️  OQS image NOT found. Pulling..."
    docker pull openquantumsafe/curl:latest
    echo "  ✅ Pulled openquantumsafe/curl:latest"
fi

echo ""
echo "============================================================"
echo "  STEP 3: Check OQS OpenSSL version & supported groups"
echo "============================================================"
echo "  OQS OpenSSL version:"
docker run --rm openquantumsafe/curl openssl version 2>&1 | sed 's/^/    /'

echo ""
echo "  Checking for hybrid group support..."
# List all supported groups in the OQS build
GROUPS_OUTPUT=$(docker run --rm openquantumsafe/curl openssl list -kem-algorithms 2>&1 || echo "list command not supported")
echo "$GROUPS_OUTPUT" | head -5 | sed 's/^/    /'

# Check specific group names
echo ""
echo "  Testing group name variants:"
for GROUP in "x25519_mlkem768" "X25519MLKEM768" "x25519_kyber768" "X25519Kyber768Draft00" "mlkem768" "kyber768" "x25519_frodo640shake"; do
    RESULT=$(echo "Q" | docker run --rm -i openquantumsafe/curl openssl s_client \
        -connect "${TARGET}:${PORT}" -servername "${TARGET}" \
        -groups "${GROUP}" 2>&1 | head -30)
    
    if echo "$RESULT" | grep -q "Cipher is (NONE)"; then
        echo "    ❌ ${GROUP}: handshake failed (server or client doesn't support this group)"
    elif echo "$RESULT" | grep -q "unknown group\|Error\|no cipher\|invalid"; then
        echo "    ❌ ${GROUP}: NOT SUPPORTED by this OQS build"
    elif echo "$RESULT" | grep -q "CONNECTED" && echo "$RESULT" | grep -q "Cipher is "; then
        CIPHER=$(echo "$RESULT" | grep "Cipher is " | head -1)
        echo "    ✅ ${GROUP}: SUCCESS — ${CIPHER}"
    else
        echo "    ⚠️  ${GROUP}: unclear result"
        echo "$RESULT" | head -3 | sed 's/^/        /'
    fi
done

echo ""
echo "============================================================"
echo "  STEP 4: Full OQS probe output (what Rakshak sees)"
echo "============================================================"
echo "  Running: openssl s_client -connect ${TARGET}:${PORT} -groups x25519_mlkem768:x25519_kyber768:mlkem768:x25519"
echo ""
FULL_OUTPUT=$(echo "Q" | docker run --rm -i openquantumsafe/curl \
    openssl s_client \
    -connect "${TARGET}:${PORT}" \
    -servername "${TARGET}" \
    -showcerts \
    -groups "x25519_mlkem768:x25519_kyber768:mlkem768:x25519" 2>&1)

echo "$FULL_OUTPUT" | grep -E "CONNECTED|Protocol|Cipher is|Server Temp Key|Peer signature|Signature type|Certificate chain|Signature Algorithm" | head -20 | sed 's/^/    /'

echo ""
if echo "$FULL_OUTPUT" | grep -qi "mlkem\|kyber\|ML-KEM"; then
    echo "  ✅ PQC/hybrid KEX indicators found in output!"
else
    echo "  ❌ No PQC/hybrid KEX indicators in output"
    echo "     The OQS build may not support the hybrid group names."
    echo "     See Step 5 for the fix."
fi

echo ""
echo "============================================================"
echo "  STEP 5: Diagnosis & Fix"
echo "============================================================"
echo "  If Step 3 shows all groups as NOT SUPPORTED:"
echo "    → Your OQS Docker image is too old. Update it:"
echo "      docker pull openquantumsafe/curl:latest"
echo ""
echo "  If the hybrid groups (x25519_mlkem768) fail but pure mlkem768 works:"
echo "    → The OQS build uses different hybrid names."
echo "    → Check: docker run --rm openquantumsafe/curl openssl list -kem-algorithms 2>&1 | grep -i mlkem"
echo "    → Common OQS hybrid names: X25519MLKEM768, x25519_kyber768, X25519Kyber768Draft00"
echo "    → Update tls_scanner.py line 54 with the correct group name."
echo ""
echo "  If Docker works but Rakshak still shows 'not quantum safe':"
echo "    → Check the Rakshak app logs: docker logs <container> | grep -i 'OQS probe'"
echo "    → Or: cat server_log.txt | grep -i 'OQS'"
echo "    → Make sure you RE-SCANNED the target (old results are cached in DB)"
echo ""
echo "  If Docker is not accessible from inside the Rakshak container:"
echo "    → Mount the Docker socket: -v /var/run/docker.sock:/var/run/docker.sock"
echo "    → Or install Docker CLI inside the Rakshak container"
echo ""
echo "============================================================"
echo "  STEP 6: Check existing scan results in DB"
echo "============================================================"
echo "  Old scan results are cached. You MUST re-scan after deploying."
echo "  To check what's stored:"
echo "    sqlite3 rakshak.db \"SELECT target_url, key_exchange, authentication, pqc_label FROM scan_results WHERE target_url LIKE '%google%' ORDER BY scanned_at DESC LIMIT 5;\""
echo ""

# Debug Script 2: Test KEX negotiation with OpenSSL directly
# Shows the gap between system OpenSSL and Chrome's BoringSSL
#
# Usage:
#   .\scripts\debug_openssl_kex.ps1 support.google.com

param(
    [string]$Hostname = "support.google.com",
    [int]$Port = 443
)

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "  OPENSSL KEX NEGOTIATION TEST: $Hostname`:$Port" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

# Test 1: Default connection (what sslyze does)
Write-Host "`n[TEST 1] Default OpenSSL connection (what sslyze sees):" -ForegroundColor Yellow
$result1 = echo "Q" | openssl s_client -connect "${Hostname}:${Port}" -servername $Hostname 2>&1
$result1 | Select-String "Protocol|Cipher|Server Temp Key|Peer signature|Signature type" | ForEach-Object { Write-Host "    $_" -ForegroundColor White }

# Test 2: Try with -groups to detect hybrid PQC KEX support
Write-Host "`n[TEST 2] With -groups x25519_mlkem768 (hybrid PQC):" -ForegroundColor Yellow
try {
    $result2 = echo "Q" | openssl s_client -connect "${Hostname}:${Port}" -servername $Hostname -groups x25519_mlkem768 2>&1
    $result2 | Select-String "Protocol|Cipher|Server Temp Key|Peer signature|Signature type|groups" | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    if ($result2 -match "Cipher is \(NONE\)") {
        Write-Host "    >>> OpenSSL could NOT negotiate x25519_mlkem768 (this OpenSSL doesn't support it)" -ForegroundColor Red
    } elseif ($result2 -match "Cipher is (\S+)") {
        Write-Host "    >>> Successfully negotiated with x25519_mlkem768!" -ForegroundColor Green
    }
} catch {
    Write-Host "    >>> OpenSSL does not support -groups x25519_mlkem768" -ForegroundColor Red
}

# Test 3: Try pure mlkem768 (what OQS probe uses)
Write-Host "`n[TEST 3] With -groups mlkem768 (pure PQC, what OQS probe tries):" -ForegroundColor Yellow
try {
    $result3 = echo "Q" | openssl s_client -connect "${Hostname}:${Port}" -servername $Hostname -groups mlkem768 2>&1
    $result3 | Select-String "Protocol|Cipher|Server Temp Key|Peer signature|Signature type|groups" | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    if ($result3 -match "Cipher is \(NONE\)") {
        Write-Host "    >>> Server REJECTED pure mlkem768 (it only supports HYBRID x25519_mlkem768)" -ForegroundColor Red
    } elseif ($result3 -match "Cipher is (\S+)") {
        Write-Host "    >>> Negotiated with pure mlkem768" -ForegroundColor Green
    }
} catch {
    Write-Host "    >>> OpenSSL does not support -groups mlkem768" -ForegroundColor Red
}

# Test 4: Show supported groups
Write-Host "`n[TEST 4] OpenSSL version and PQC support:" -ForegroundColor Yellow
$version = openssl version 2>&1
Write-Host "    Version: $version" -ForegroundColor White

# Try to list groups
try {
    $groups = openssl ecparam -list_curves 2>&1 | Select-String -Pattern "mlkem|kyber|x25519" -CaseSensitive:$false
    if ($groups) {
        Write-Host "    Supported PQC-related curves/groups:" -ForegroundColor Green
        $groups | ForEach-Object { Write-Host "      $_" -ForegroundColor White }
    } else {
        Write-Host "    NO PQC curves/groups found in this OpenSSL build" -ForegroundColor Red
    }
} catch {
    Write-Host "    Could not list curves" -ForegroundColor Red
}

Write-Host "`n[CONCLUSION]" -ForegroundColor Cyan
Write-Host "    Chrome uses BoringSSL which supports X25519_MLKEM768 (hybrid PQC KEX)." -ForegroundColor White
Write-Host "    Your system OpenSSL likely does NOT support ML-KEM key exchange." -ForegroundColor White
Write-Host "    sslyze inherits this limitation from Python's OpenSSL binding." -ForegroundColor White
Write-Host "    Result: sslyze sees ECDHE, Chrome sees X25519_MLKEM768 for the SAME server." -ForegroundColor White
Write-Host ""

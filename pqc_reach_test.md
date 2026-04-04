# PQC Endpoint Reachability Test

Verifying proposed `reachability_check` logic won't misclassify PQC servers.

**Key rule**: if TCP connects → host is reachable → never gets `intranet_only`.
sslyze may still fail, but OQS probe takes over → correct PQC label.

## `scans.rakshak.live:4433`

| Check | Result | Detail |
|---|---|---|
| DNS | ✅ OK | 13.232.195.253 |
| TCP :4433 | ✅ OK (65ms) | connected |
| TLS stdlib (no-verify) | ❌ FAIL (5326ms) | [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1010) |
| OQS Docker probe | ✅ CONNECTED | cipher=TLS_AES_256_GCM_SHA384 proto=TLSv1.3 |
| OQS PQC KEX | ✅ Yes | ML-KEM group negotiated |
| OQS PQC Sig | ✅ Yes | sig=mldsa44 |

**Decision (proposed reachability_check):**
- Proposed label: `reachable` → proceeds to full scan (sslyze + OQS probe)
- Verdict: ✅ Correct — OQS probe will detect PQC

## `scans.rakshak.live:4434`

| Check | Result | Detail |
|---|---|---|
| DNS | ✅ OK | 13.232.195.253 |
| TCP :4434 | ✅ OK (56ms) | connected |
| TLS stdlib (no-verify) | ❌ FAIL (5333ms) | [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1010) |
| OQS Docker probe | ✅ CONNECTED | cipher=TLS_AES_256_GCM_SHA384 proto=TLSv1.3 |
| OQS PQC KEX | ✅ Yes | ML-KEM group negotiated |
| OQS PQC Sig | ✅ Yes | sig=mldsa44 |

**Decision (proposed reachability_check):**
- Proposed label: `reachable` → proceeds to full scan (sslyze + OQS probe)
- Verdict: ✅ Correct — OQS probe will detect PQC

## `test.openquantumsafe.org:6182`

| Check | Result | Detail |
|---|---|---|
| DNS | ✅ OK | 158.177.245.197 |
| TCP :6182 | ✅ OK (243ms) | connected |
| TLS stdlib (no-verify) | ❌ FAIL (1099ms) | [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1010) |
| OQS Docker probe | ✅ CONNECTED | cipher=TLS_AES_256_GCM_SHA384 proto=TLSv1.3 |
| OQS PQC KEX | ✅ Yes | ML-KEM group negotiated |
| OQS PQC Sig | ✅ Yes | sig=mldsa44 |

**Decision (proposed reachability_check):**
- Proposed label: `reachable` → proceeds to full scan (sslyze + OQS probe)
- Verdict: ✅ Correct — OQS probe will detect PQC

---
## Summary

✅ **All PQC servers are TCP-reachable** — the `intranet_only` classification is safe.
None of the known PQC endpoints would be misclassified.

**Conclusion for plan**: The reachability check must use the target's own port,
not hardcode port 443. `scan_service._scan_single()` already parses the port
from the URL, so passing that same port to `reachability_check()` is sufficient.
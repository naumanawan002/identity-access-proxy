# Threat Model & Security Mitigations

This document outlines the threat vectors evaluated for the Zero Trust Identity-Aware Access Proxy and the corresponding technical mitigations.

| Threat Category | Threat Scenario | Mitigation in Architecture |
| :--- | :--- | :--- |
| **Spoofing (Identity)** | Attacker sends forged HTTP headers (e.g. `X-ZTNA-Subject: admin`) directly to the edge to impersonate privileged users. | The proxy unconditionally purges all untrusted `X-ZTNA-*` and identity headers before dispatching to upstream services. Verified headers are generated only by the proxy after cryptographic validation. |
| **Tampering (Token Integrity)** | Attacker alters claims inside a JWT (e.g. changes `roles: ["user"]` to `roles: ["admin"]`) without a valid signature. | Strict cryptographic signature verification (`crypto/hmac` or `crypto/rsa`). Any signature mismatch results in immediate HTTP 401 rejection. |
| **Side-Channel (Timing Attacks)** | Attacker measures slight differences in HMAC comparison time to infer secret key bytes byte-by-byte. | Uses `crypto/subtle.ConstantTimeCompare` during signature validation to ensure equal-time execution regardless of match position. |
| **Replay & Expired Credential Abuse** | Attacker captures a previously valid JWT and attempts to replay it after user session termination. | Temporal validation checks `exp` (expiration) and `nbf` (not before) against system UTC time with configurable clock skew leeway. Short token lifetimes (e.g., 5-15 minutes) are enforced. |
| **Elevation of Privilege (BYOD/Unmanaged Hardware)** | An employee with valid credentials logs in from an infected, unmanaged personal computer without disk encryption to access sensitive finance APIs. | The Policy Engine enforces Device Posture validation (`min_trust_level: high`, `require_managed: true`, `require_disk_encrypt: true`). Even with valid admin tokens, access is denied (HTTP 403). |
| **Lateral Movement** | Attacker compromises a non-privileged internal service and attempts to access adjacent internal endpoints. | Upstream microservices reside in an isolated network segment accessible only through the proxy with optional mutual TLS (mTLS) certificate verification. |
| **Confused Deputy / Audience Confusion** | Token minted for Service A is replayed against Service B. | Strict `aud` (Audience) claim checking ensures tokens are accepted only when intended specifically for this gateway. |

# Architecture Specification: Zero Trust Identity-Aware Access Proxy

## 1. Overview
The **Zero Trust Identity-Aware Access Proxy (ZTNA Gateway)** is an edge security reverse proxy implemented in Go. It eliminates implicit trust based on network location (e.g. perimeter firewalls or VPNs) and replaces it with continuous, per-request cryptographic authentication, device posture evaluation, and dynamic policy authorization.

The architecture is designed strictly from public foundational specifications:
- **NIST SP 800-207**: Zero Trust Architecture (Control Plane vs Data Plane separation, PEP/PDP model).
- **Google BeyondCorp**: Context-Aware Access Proxy design.
- **RFC 7519**: JSON Web Tokens (JWT).
- **RFC 8446**: Transport Layer Security (TLS 1.3 / Mutual TLS).

---

## 2. Structural Topology

```
[ Client / Device ]
        │  HTTPS + Bearer Token + Device Posture Header
        ▼
┌────────────────────────────────────────────────────────┐
│  Policy Enforcement Point (PEP) — Edge Reverse Proxy   │
│                                                        │
│  1. Extract Client IP & Device Posture                 │
│  2. Cryptographic Token Verification (RFC 7519)         │
│  3. Consult Policy Decision Point (PDP)                │
│  4. Strip Untrusted Headers & Inject Verified Claims   │
└──────────────────────────┬─────────────────────────────┘
                           │  Internal Network / mTLS
                           ▼
            ┌──────────────────────────────┐
            │ Protected Upstream Services  │
            │ (Admin, Billing, Data APIs)  │
            └──────────────────────────────┘
```

---

## 3. Core Subsystems

### 3.1 Policy Enforcement Point (PEP)
- Intercepts all inbound traffic at the network edge.
- Uses Go's native `net/http/httputil.ReverseProxy`.
- Operates under a **Default Deny** posture: any request not explicitly granted by an active policy rule is rejected immediately with HTTP 403 Forbidden.

### 3.2 Policy Decision Point (PDP)
- Evaluates access requests against declarative policy tables using longest-prefix matching.
- Multi-dimensional decision criteria:
  - **Subject Identity**: User identifier (`sub`) and email.
  - **Role & Group Membership**: RBAC attributes extracted from validated tokens.
  - **Device Posture**: Trust score (0–100), management status (`is_managed`), and disk encryption state (`disk_encrypted`).
  - **Network Origin**: Allowed IPv4/IPv6 CIDR subnets.

### 3.3 Identity Propagation & Header Cleansing
To prevent upstream microservices from having to re-authenticate or parse raw JWT tokens, the proxy performs **Identity Propagation**:
1. Incoming client headers matching `X-ZTNA-*` or `X-Forwarded-Identity` are **unconditionally stripped** to defeat spoofing attempts.
2. The proxy injects cryptographically validated identity headers:
   - `X-ZTNA-Subject`: Authenticated user ID.
   - `X-ZTNA-Email`: User email.
   - `X-ZTNA-Roles`: Comma-separated validated roles.
   - `X-ZTNA-Device-Trust`: Device posture rating (`low`, `medium`, `high`).
   - `X-ZTNA-Request-ID`: Distributed tracing request identifier.

### 3.4 Telemetry & Audit Logging
Every access attempt (permitted or denied) generates a structured JSON audit event conforming to CloudEvents formatting. Audit logs include:
- Request UUID
- Timestamp (UTC ISO 8601)
- Client IP
- Subject identity & roles
- HTTP method & target path
- Device trust metrics
- Enforcement decision (`allowed: true/false`)
- Specific rule ID & human-readable decision rationale
- Latency in microseconds

# 📧 SMTP Tunnel - Technical Documentation

This document provides in-depth technical details about the SMTP Tunnel Proxy, including protocol design, DPI evasion techniques, security analysis, and implementation details.

> 📖 For basic setup and usage, see [README.md](README.md).

---

## 📑 Table of Contents

- [📨 Why SMTP?](#-why-smtp)
- [🎭 Detection Considerations](#-detection-considerations)
- [⚡ Why It's Fast](#-why-its-fast)
- [🏗️ Architecture](#️-architecture)
- [📐 Protocol Design](#-protocol-design)
- [🔧 Component Details](#-component-details)
- [🔐 Security Analysis](#-security-analysis)
- [🌐 Domain vs IP Address](#-domain-name-vs-ip-address-security-implications)
- [⚙️ Advanced Configuration](#️-advanced-configuration)

---

## 📨 Why SMTP?

SMTP (Simple Mail Transfer Protocol) is the protocol used for sending emails. It's an excellent choice for tunneling because:

### 1️⃣ Ubiquitous Traffic
- Email is essential infrastructure - blocking it breaks legitimate services
- SMTP traffic on port 587 (submission) is expected and normal
- Millions of emails traverse networks every second

### 2️⃣ Expected to be Encrypted
- STARTTLS is standard for SMTP - encrypted email is normal
- DPI systems expect to see TLS-encrypted SMTP traffic
- Encrypted SMTP-like traffic can be less obvious than a custom plaintext protocol, but it is still observable as TLS metadata and traffic behavior

### 3️⃣ Flexible Protocol
- SMTP allows large data transfers (attachments)
- Binary data is normal (MIME-encoded attachments)
- Long-lived connections are acceptable

### 4️⃣ Hard to Block
- Blocking port 587 would break email for everyone
- A passive observer cannot read post-STARTTLS payload bytes without TLS interception
- A national firewall can still classify or block traffic using metadata, TLS fingerprints, active probing, timing, volume, reputation, and policy rules

---

## 🎭 Detection Considerations

Deep Packet Inspection (DPI) systems analyze network traffic to identify and block certain protocols or content. SMTP Tunnel reduces some obvious plaintext protocol fingerprints, but it does not guarantee avoidance of detection or blocking.

### 🔍 Phase 1: The Deception (Plaintext)

```
┌──────────────────────────────────────────────────────────────┐
│                    DPI CAN SEE THIS                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Server: 220 mail.example.com ESMTP Postfix (Ubuntu)         │
│  Client: EHLO client.local                                   │
│  Server: 250-mail.example.com                                │
│          250-STARTTLS                                        │
│          250-AUTH PLAIN                                      │
│          250 8BITMIME                                        │
│  Client: STARTTLS                                            │
│  Server: 220 2.0.0 Ready to start TLS                        │
│                                                              │
│  DPI Analysis: "This is a normal email server connection"    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**What DPI sees:**
- Standard SMTP greeting from "Postfix" mail server
- Normal capability negotiation
- STARTTLS upgrade (expected for secure email)

**What makes it convincing:**
- Greeting matches real Postfix servers
- Capabilities list is realistic
- Proper RFC 5321 compliance
- Port 587 is standard SMTP submission port

### 🔒 Phase 2: TLS Handshake

```
┌──────────────────────────────────────────────────────────────┐
│                    DPI CAN SEE THIS                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  [TLS 1.2/1.3 Handshake]                                     │
│  - Client Hello                                              │
│  - Server Hello                                              │
│  - Certificate Exchange                                      │
│  - Key Exchange                                              │
│  - Finished                                                  │
│                                                              │
│  DPI Analysis: "Normal TLS for email encryption"             │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**What DPI sees:**
- Standard TLS handshake
- Server certificate for mail domain
- Normal cipher negotiation

### 🚀 Phase 3: Encrypted Tunnel Payload

```
┌──────────────────────────────────────────────────────────────┐
│                   PAYLOAD ENCRYPTED WITH TLS                 │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Client: EHLO client.local                                   │
│  Server: 250-mail.example.com                                │
│          250-AUTH PLAIN                                      │
│          250 8BITMIME                                        │
│  Client: AUTH PLAIN <token>                                  │
│  Server: 235 2.7.0 Authentication successful                 │
│  Client: BINARY                                              │
│  Server: 299 Binary mode activated                           │
│                                                              │
│  [Binary streaming begins - raw TCP tunnel]                  │
│                                                              │
│  Passive payload inspection is blocked by TLS                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**What DPI sees:**
- Encrypted TLS traffic
- Packet sizes, timing, duration, TLS fingerprint, certificate metadata, and endpoint reputation
- Payload bytes are protected from passive inspection when TLS is not intercepted

**What actually happens:**
- Authentication with pre-shared key
- Switch to binary streaming mode
- Full-speed TCP tunneling

### Detection Limits

This implementation reduces some obvious static protocol artifacts, but it is
detectable in principle. A DPI/firewall system may still use:

| Signal | Remaining risk |
|--------|----------------|
| **Port analysis** | Port 587 can be monitored, rate-limited, or blocked by policy |
| **Protocol analysis** | The plaintext pre-STARTTLS transcript is SMTP-like but minimal |
| **TLS fingerprinting** | Python/OpenSSL ClientHello and server behavior remain visible |
| **Certificate analysis** | Private-CA/self-issued deployments can stand out compared with public mail infrastructure |
| **Traffic behavior** | Long-lived, high-volume, full-duplex sessions are not typical email submission |
| **Active probing or MITM** | Unsafe TLS verification settings allow stronger active attacks |

---

## ⚡ Why It's Fast

Previous versions used SMTP commands for every data packet, requiring:
- 4 round-trips per data chunk (MAIL FROM → RCPT TO → DATA → response)
- Base64 encoding (33% overhead)
- MIME wrapping (more overhead)

### 🚀 The New Approach: Protocol Upgrade

```
┌─────────────────────────────────────────────────────────────┐
│                    HANDSHAKE PHASE                          │
│                    (One time only)                          │
├─────────────────────────────────────────────────────────────┤
│  EHLO → STARTTLS → TLS → EHLO → AUTH → BINARY               │
│                                                             │
│  Time: ~200-500ms (network latency dependent)               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    STREAMING PHASE                          │
│                    (Rest of session)                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────┬────────────┬────────────┬─────────────┐        │
│  │  Type   │ Channel ID │   Length   │   Payload   │        │
│  │ 1 byte  │  2 bytes   │  2 bytes   │  N bytes    │        │
│  └─────────┴────────────┴────────────┴─────────────┘        │
│                                                             │
│  - Full duplex - send and receive simultaneously            │
│  - No waiting for responses                                 │
│  - 5 bytes overhead per frame (vs hundreds for SMTP)        │
│  - Raw binary - no base64 encoding                          │
│  - Speed limited only by network bandwidth                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 📊 Performance Comparison

| Metric | Old SMTP Method | New Binary Method |
|--------|-----------------|-------------------|
| **Overhead per packet** | ~500+ bytes | 5 bytes |
| **Round trips per send** | 4 | 0 (streaming) |
| **Encoding overhead** | 33% (base64) | 0% |
| **Duplex mode** | Half-duplex | Full-duplex |
| **Effective speed** | ~10-50 KB/s | Limited by bandwidth |

---

## 🏗️ Architecture

### 🖥️ System Components

```
YOUR COMPUTER                           YOUR VPS                        INTERNET
┌────────────────────┐                  ┌────────────────────┐          ┌─────────┐
│                    │                  │                    │          │         │
│  ┌──────────────┐  │                  │  ┌──────────────┐  │          │ Website │
│  │   Browser    │  │                  │  │    Server    │  │          │   API   │
│  │   or App     │  │                  │  │   server.py  │  │          │ Service │
│  └──────┬───────┘  │                  │  └──────┬───────┘  │          │         │
│         │          │                  │         │          │          └────┬────┘
│         │ SOCKS5   │                  │         │ TCP      │               │
│         ▼          │                  │         ▼          │               │
│  ┌──────────────┐  │   TLS Tunnel     │  ┌──────────────┐  │               │
│  │    Client    │◀─┼──────────────────┼─▶│   Outbound   │◀─┼───────────────┘
│  │   client.py  │  │   Port 587       │  │  Connector   │  │
│  └──────────────┘  │                  │  └──────────────┘  │
│                    │                  │                    │
└────────────────────┘                  └────────────────────┘
     Censored Network                      Free Internet
```

### 📡 Data Flow

```
1. Browser wants to access https://example.com

2. Browser → SOCKS5 (client.py:1080)
   "CONNECT example.com:443"

3. Client → Server (port 587, looks like SMTP)
   [FRAME: CONNECT, channel=1, "example.com:443"]

4. Server → example.com:443
   [Opens real TCP connection]

5. Server → Client
   [FRAME: CONNECT_OK, channel=1]

6. Browser ↔ Client ↔ Server ↔ example.com
   [Bidirectional data streaming]
```

---

## 📐 Protocol Design

### 📦 Frame Format (Binary Mode)

All communication after handshake uses this simple binary frame format:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│     Type      │          Channel ID           │    Length     │
├───────────────┼───────────────────────────────┼───────────────┤
│    Length     │            Payload...                         │
├───────────────┼───────────────────────────────────────────────┤
│                        Payload (continued)                    │
└───────────────────────────────────────────────────────────────┘

Type (1 byte):
  0x01 = DATA         - Tunnel data
  0x02 = CONNECT      - Open new channel
  0x03 = CONNECT_OK   - Connection successful
  0x04 = CONNECT_FAIL - Connection failed
  0x05 = CLOSE        - Close channel
  0x06 = KEEPALIVE    - Optional application-level keepalive
  0x07 = KEEPALIVE_ACK - Keepalive acknowledgement

Channel ID (2 bytes): Identifies the connection (supports 65535 simultaneous connections)
Length (2 bytes): Payload size (max 65535 bytes)
Payload (variable): The actual data
```

This 5-byte header is the active protocol used by `client.py` and `server.py`.
`common.py` also contains older experimental helpers such as `TunnelMessage`,
`TrafficShaper`, `SMTPMessageGenerator`, and `FrameBuffer`; those are retained
for compatibility/reference but are not used by the current fast binary tunnel.

Validation rules in the active codec:
- frame type must be one of the defined active frame constants;
- channel frames use channel IDs `1..65535`;
- control frames (`KEEPALIVE`, `KEEPALIVE_ACK`) use channel ID `0`;
- payload length must fit in the 16-bit frame length field.

### Keepalive Behavior

Keepalive is client-originated for compatibility with old clients. When enabled,
the client periodically sends `FRAME_KEEPALIVE` on channel `0`; a new server
responds with `FRAME_KEEPALIVE_ACK`. If the ACK is not received before
`tunnel.keepalive_timeout`, the client closes the tunnel and reconnects.

Because there is no explicit protocol negotiation yet, keepalive should only be
enabled after both sides are upgraded. Existing configs do not contain the
keepalive keys, so runtime fallback keeps keepalive disabled.

### Reconnect And Backoff

The client uses exponential reconnect backoff after initial failures and after
established tunnel loss. The delay starts at `tunnel.reconnect_initial_delay`,
caps at `tunnel.reconnect_max_delay`, and applies `tunnel.reconnect_jitter` to
avoid a fixed retry cadence. This is a stability feature, not a guarantee
against traffic classification.

### Current Topologies

Normal outbound mode remains the default:

`Application / V2Ray -> local SOCKS5 on client -> one outbound TLS tunnel -> server -> Internet`

Optional true reverse mode reverses only the TCP/TLS connection direction:

`Application / V2Ray -> local SOCKS5 on Access Node -> inbound reverse tunnel from VPS -> Exit Node/VPS -> Internet`

In reverse mode, the Access Node is the TLS server and the Exit Node is the TLS
client. The active 5-byte binary frame protocol is unchanged. Stage 2 supports
multiple independent reverse tunnel sessions using `tunnel.connections`.
The Access Node assigns each new SOCKS channel to the least-active authenticated
reverse session. This improves aggregate throughput and concurrent flows on
links that perform better with parallel streams. A single TCP flow is still
carried by one tunnel session; single-flow striping is not implemented.
mTLS remains a separate planned stage.

### 🔗 CONNECT Payload Format

```
┌───────────────┬─────────────────────────┬───────────────┐
│  Host Length  │         Host            │     Port      │
│   (1 byte)    │    (variable, UTF-8)    │   (2 bytes)   │
└───────────────┴─────────────────────────┴───────────────┘
```

### 🔄 Session State Machine

```
                    ┌─────────┐
                    │  START  │
                    └────┬────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   TCP Connected     │
              └──────────┬──────────┘
                         │ 220 greeting
                         ▼
              ┌─────────────────────┐
              │   EHLO Exchange     │
              └──────────┬──────────┘
                         │ 250 OK
                         ▼
              ┌─────────────────────┐
              │     STARTTLS        │
              └──────────┬──────────┘
                         │ 220 Ready
                         ▼
              ┌─────────────────────┐
              │   TLS Handshake     │
              └──────────┬──────────┘
                         │ Success
                         ▼
              ┌─────────────────────┐
              │   EHLO (post-TLS)   │
              └──────────┬──────────┘
                         │ 250 OK
                         ▼
              ┌─────────────────────┐
              │   AUTH PLAIN        │
              └──────────┬──────────┘
                         │ 235 Success
                         ▼
              ┌─────────────────────┐
              │   BINARY Command    │
              └──────────┬──────────┘
                         │ 299 OK
                         ▼
              ┌─────────────────────┐
              │   Binary Streaming  │◀──────┐
              │   (Full Duplex)     │───────┘
              └─────────────────────┘
```

---

## 🔧 Component Details

### 🖥️ server.py - Server Component

**Purpose:** Runs on your VPS in an uncensored network. Accepts tunnel connections and forwards traffic to the real internet.

**What it does:**
- Listens on port 587 (SMTP submission)
- Presents itself as a Postfix mail server
- Handles SMTP handshake (EHLO, STARTTLS, AUTH)
- Switches to binary streaming mode after authentication
- Manages multiple tunnel channels
- Forwards data to destination servers
- Sends responses back through the tunnel

**Key Classes:**
| Class | Description |
|-------|-------------|
| `TunnelServer` | Main server, accepts connections |
| `TunnelSession` | Handles one client connection |
| `Channel` | Represents one tunneled TCP connection |

### 💻 client.py - Client Component

**Purpose:** Runs on your local computer. Provides a SOCKS5 proxy interface and tunnels traffic through the server.

**What it does:**
- Runs SOCKS5 proxy server on localhost:1080
- Connects to tunnel server on port 587
- Performs SMTP handshake to look legitimate
- Switches to binary streaming mode
- Multiplexes multiple connections over single tunnel
- Handles SOCKS5 CONNECT requests from applications

**Key Classes:**
| Class | Description |
|-------|-------------|
| `TunnelClient` | Manages connection to server |
| `SOCKS5Server` | Local SOCKS5 proxy |
| `Channel` | One proxied connection |

### 📚 common.py - Shared Utilities

**Purpose:** Code shared between client and server.

**What it contains:**
| Component | Description |
|-----------|-------------|
| `TunnelCrypto` | Handles authentication tokens |
| Active frame codec | Canonical 5-byte tunnel frame encode/decode and validation |
| `TrafficShaper` | Legacy/unused padding and timing helper |
| `SMTPMessageGenerator` | Legacy/unused email content generator |
| `FrameBuffer` | Legacy parser for the older 6-byte `TunnelMessage` format |
| `load_config()` | YAML configuration loader |
| `ServerConfig` | Server configuration dataclass |
| `ClientConfig` | Client configuration dataclass |

### 🔐 generate_certs.py - Certificate Generator

**Purpose:** Creates TLS certificates for the tunnel.

**What it generates:**
| File | Description |
|------|-------------|
| `ca.key` | Certificate Authority private key |
| `ca.crt` | Certificate Authority certificate |
| `server.key` | Server private key |
| `server.crt` | Server certificate (signed by CA) |

**Features:**
- Customizable hostname in certificate
- Configurable key size (default 2048-bit RSA)
- Configurable validity period
- Includes proper extensions for TLS server auth

---

## 🔐 Security Analysis

### 🔑 Authentication Flow

```
┌─────────────────────────────────────────────────────────────┐
│                  Authentication Flow                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Client generates timestamp                              │
│                                                             │
│  2. Client computes:                                        │
│     HMAC-SHA256(secret, "smtp-tunnel-auth:" + timestamp)    │
│                                                             │
│  3. Client sends: AUTH PLAIN base64(timestamp + ":" + hmac) │
│                                                             │
│  4. Server verifies:                                        │
│     - Timestamp within 5 minutes (prevents replay)          │
│     - HMAC matches (proves knowledge of secret)             │
│                                                             │
│  5. Server responds: 235 Authentication successful          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 🔒 Encryption Layers

| Layer | Protection |
|-------|------------|
| **TLS 1.2+** | All traffic after STARTTLS |
| **Pre-shared Key** | Authentication |
| **HMAC-SHA256** | Token integrity |

### ⚠️ Threat Model

| Threat | Mitigation |
|--------|------------|
| Passive eavesdropping | TLS encryption |
| Active MITM | Certificate verification (requires domain) |
| Replay attacks | Timestamp validation (5-minute window) |
| Unauthorized access | Pre-shared key authentication |
| Protocol detection | SMTP mimicry during handshake |

### ✅ Security Recommendations

1. **Use a strong secret:** Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`

2. **Keep secret secure:** Never commit to version control, share securely

3. **Use certificate verification:** Copy `ca.crt` to client and set `ca_cert` in config

4. **Restrict server access:** Use whitelist to limit source IPs if possible

5. **Monitor logs:** Watch for failed authentication attempts

6. **Update regularly:** Keep Python and dependencies updated

---

## 🌐 Domain Name vs IP Address: Security Implications

### 🔍 Understanding TLS Certificate Verification

TLS certificates are digital documents that prove a server's identity. When your client connects to a server, it can verify:

1. **The certificate is signed by a trusted authority** (in our case, your own CA)
2. **The certificate matches who you're connecting to** (hostname/IP verification)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     TLS Certificate Verification Process                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Client wants to connect to: mail.example.com                               │
│                                                                             │
│  Step 1: Server presents certificate                                        │
│          ┌─────────────────────────────────────┐                            │
│          │ Certificate Contents:               │                            │
│          │   Subject: mail.example.com         │                            │
│          │   SAN: DNSName=mail.example.com     │                            │
│          │   Signed by: Your CA                │                            │
│          └─────────────────────────────────────┘                            │
│                                                                             │
│  Step 2: Client checks                                                      │
│          - Is certificate signed by trusted CA? → YES                       │
│          - Does "mail.example.com" match SAN?   → YES                       │
│                                                                             │
│  Step 3: Connection established securely                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### ❌ The IP Address Problem

TLS certificates store identifiers in specific fields within the **Subject Alternative Name (SAN)** extension:

| Identifier Type | SAN Field Type | Example |
|-----------------|----------------|---------|
| Domain name | `DNSName` | `mail.example.com` |
| IP address | `IPAddress` | `192.168.1.100` |

**These are different field types.** A certificate generated with `--hostname 192.168.1.100` creates:

```
SAN: DNSName = "192.168.1.100"    ← This is what happens
SAN: IPAddress = 192.168.1.100   ← This is what would be needed
```

When the TLS library verifies a connection to an IP address, it looks for a matching `IPAddress` field, **not** a `DNSName` field. Even if the values are identical, the types don't match, so verification fails.

### 🚨 Man-in-the-Middle Attack Explained

When certificate verification is disabled, an attacker can intercept your connection:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Man-in-the-Middle Attack Scenario                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  WITHOUT Certificate Verification (ca_cert not set):                        │
│                                                                             │
│  ┌────────┐       ┌────────────┐       ┌────────────┐       ┌────────┐     │
│  │ Client │──────▶│  Attacker  │──────▶│  Firewall  │──────▶│ Server │     │
│  │        │◀──────│  (MITM)    │◀──────│   (DPI)    │◀──────│        │     │
│  └────────┘       └────────────┘       └────────────┘       └────────┘     │
│       │                 │                                                   │
│       │    Attacker presents          Attacker decrypts your traffic,      │
│       │    their own certificate      reads everything, re-encrypts        │
│       │                               and forwards to real server          │
│       │                 │                                                   │
│       │    Client accepts it                                                │
│       │    (no verification!)                                               │
│       │                                                                     │
│       ▼                                                                     │
│    YOUR TRAFFIC IS COMPLETELY EXPOSED TO THE ATTACKER                       │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  WITH Certificate Verification (ca_cert set + domain name):                 │
│                                                                             │
│  ┌────────┐       ┌────────────┐                                            │
│  │ Client │──────▶│  Attacker  │                                            │
│  │        │   X   │  (MITM)    │                                            │
│  └────────┘       └────────────┘                                            │
│       │                 │                                                   │
│       │    Attacker presents          Client checks certificate:           │
│       │    their own certificate      "This isn't signed by my CA!"        │
│       │                               CONNECTION REFUSED                    │
│       │                 │                                                   │
│       │    Attack blocked!                                                  │
│       │                                                                     │
│       ▼                                                                     │
│    Client connects directly to real server (or not at all)                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 📊 Security Options Comparison

| Configuration | MITM Protected? | Works? | Recommended? |
|---------------|-----------------|--------|--------------|
| Domain + `ca_cert` set | **YES** | YES | **BEST** |
| Domain + no `ca_cert` | NO | YES | Not ideal |
| IP address + `ca_cert` set | — | NO | Won't work |
| IP address + no `ca_cert` | NO | YES | Vulnerable |

### 🎯 Risk Assessment

| Threat | With Verification | Without Verification |
|--------|-------------------|----------------------|
| Passive eavesdropping | Protected (TLS) | Protected (TLS) |
| Active MITM by ISP | Protected | **Vulnerable** |
| Active MITM by government | Protected | **Vulnerable** |
| Server impersonation | Protected | **Vulnerable** |
| DPI/firewall blocking | Not guaranteed | Not guaranteed |

**Bottom line:** TLS encryption protects against passive eavesdropping in both cases. But only with certificate verification are you protected against **active** attacks where someone intercepts and impersonates your server.

---

## ⚙️ Advanced Configuration

### 📝 Full Configuration Reference

```yaml
# ============================================================================
# Server Configuration (for server.py on VPS)
# ============================================================================
server:
  # Interface to listen on
  # "0.0.0.0" = all interfaces (recommended)
  # "127.0.0.1" = localhost only
  host: "0.0.0.0"

  # Port to listen on
  # 587 = SMTP submission (recommended, expected for email)
  # 465 = SMTPS (alternative)
  # 25 = SMTP (often blocked)
  port: 587

  # Hostname for SMTP greeting and TLS certificate
  # Should match your server's DNS name for authenticity
  hostname: "mail.example.com"

  # Pre-shared secret for authentication
  # MUST be identical on client and server
  # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
  secret: "CHANGE-ME-TO-RANDOM-SECRET"

  # TLS certificate files
  cert_file: "server.crt"
  key_file: "server.key"

  # IP whitelist (optional)
  # Empty list = allow all connections
  # Supports individual IPs and CIDR notation
  whitelist: []
  # whitelist:
  #   - "192.168.1.100"
  #   - "10.0.0.0/8"

# ============================================================================
# Client Configuration (for client.py on local machine)
# ============================================================================
client:
  # Server domain name (FQDN required for certificate verification)
  # Use free DNS: DuckDNS, No-IP, FreeDNS, Dynu, or CloudFlare
  server_host: "yourdomain.duckdns.org"

  # Server port (must match server config)
  server_port: 587

  # Local SOCKS5 proxy port
  socks_port: 1080

  # Local SOCKS5 bind address
  # "127.0.0.1" = localhost only (recommended)
  # "0.0.0.0" = allow external connections (use with caution!)
  socks_host: "127.0.0.1"

  # Pre-shared secret (MUST match server!)
  secret: "CHANGE-ME-TO-RANDOM-SECRET"

  # CA certificate for server verification (RECOMMENDED)
  # Required to prevent Man-in-the-Middle attacks
  # Copy ca.crt from server to client
  ca_cert: "ca.crt"

# ============================================================================
# Tunnel Runtime Configuration (optional)
# ============================================================================
tunnel:
  # 0 disables application-level keepalive for maximum compatibility with
  # older mixed-version deployments. Fresh installs use the values below.
  keepalive_interval: 45
  keepalive_timeout: 120

  # Client reconnect backoff after initial failures or established tunnel loss.
  reconnect_initial_delay: 2
  reconnect_max_delay: 60
  reconnect_jitter: 0.35

# ============================================================================
# SMTP Compatibility Configuration (optional)
# ============================================================================
smtp:
  # EHLO name sent by the client during the SMTP-like handshake.
  ehlo_name: "client.local"

# ============================================================================
# Stealth Configuration (optional, for legacy SMTP mode)
# ============================================================================
stealth:
  # Random delay range between messages (milliseconds)
  min_delay_ms: 50
  max_delay_ms: 500

  # Message padding sizes
  pad_to_sizes:
    - 4096
    - 8192
    - 16384

  # Probability of dummy messages
  dummy_message_probability: 0.1
```

### 📜 SMTP Protocol Compliance

The tunnel implements these SMTP RFCs during handshake:
- **RFC 5321** - Simple Mail Transfer Protocol
- **RFC 3207** - SMTP Service Extension for Secure SMTP over TLS
- **RFC 4954** - SMTP Service Extension for Authentication

### 📡 Multiplexing

Multiple TCP connections are multiplexed over tunnel sessions. Normal mode and
reverse mode with `tunnel.connections: 1` use one tunnel session. Reverse mode
can run multiple independent tunnel sessions from the VPS Exit Node to the
Iran-side Access Node:

```
┌─────────────────────────────────────────────────────────────┐
│                    One TLS Tunnel Session                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Channel 1: Browser Tab 1 → google.com:443                  │
│  Channel 2: Browser Tab 2 → github.com:443                  │
│  Channel 3: curl → ifconfig.me:443                          │
│  Channel 4: SSH → remote-server:22                          │
│  ...                                                        │
│  Channel 65535: Maximum channel ID                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 💾 Memory Usage

For reverse mode, the final tested production target for this deployment is:

```yaml
tunnel:
  connections: 20
  adaptive_connections: true
  min_connections: 8
  max_connections: 20

performance:
  profile: throughput
```

The best value is network-dependent. Connection-count guidance from real
deployment testing:

- `4`: conservative
- `8`: improved aggregate throughput
- `12`: good balance
- `16`: high performance
- `20`: recommended production value for this deployment
- `24`: experimental; may improve download but can hurt upload and increase noise
- `>24`: not recommended without explicit testing

Adaptive reverse-dial mode starts `min_connections` sessions, scales toward
`max_connections` when active channels or throughput cross thresholds, and scales
down after idle time. It never closes sessions with active channels. Fixed mode
remains available by setting `adaptive_connections: false`; existing
`connections: 20` deployments keep their old behavior unless adaptive mode is
enabled.

Reconnect storm protection tracks failed reverse dial attempts in a rolling
window. If failures exceed `reconnect_circuit_breaker_failures`, most sessions
pause for `reconnect_circuit_breaker_cooldown` while one probe continues. When
connectivity returns, adaptive mode ramps sessions gradually using
`session_start_interval_seconds` plus jitter. Idle session recycling is disabled
by default and, when enabled, only recycles idle sessions one at a time by
default.

Port behavior also matters. In this deployment, `8443` performed better than
`587`. The tunnel cannot exceed a bad raw path, and upload/download can behave
differently. ICMP/ping alone is not conclusive; use TCP checks such as:

```bash
nc -vz -w5 ACCESS_DOMAIN 8443
sudo tcpdump -ni any host VPS_IP and port 8443
```

Stage 2.1 adds explicit health and accounting per reverse session:

- `authenticated`
- `writable`
- `last_read`
- `last_write`
- `active_channels`
- `total_channels`
- `failure_count`
- `bytes_in`
- `bytes_out`
- `connected_since`

Session selection skips unauthenticated, non-writable, closing, or disconnected
sessions. If a write to the selected session fails while opening a channel, the
Access Node marks that session unhealthy and retries the channel assignment once
on another healthy session. If no healthy session exists, the SOCKS CONNECT fails
quickly.

The Access Node can emit periodic reverse status logs:

```yaml
metrics:
  enabled: true
  log_interval: 30
  verbose: false
```

By default, reverse status is concise:

```text
Reverse status: mode=adaptive min=8 max=20 target=8 active=8 active_channels=0 failures=0 bytes_in=... bytes_out=...
```

Per-session metrics are logged only when `metrics.verbose: true` or debug
logging is enabled.

Destination logging is privacy-safe by default:

```yaml
logging:
  log_destinations: false
  log_session_events: true
  log_metrics: true
```

Transport tuning does not alter the 5-byte frame protocol:

```yaml
performance:
  profile: balanced  # compatibility | balanced | throughput

transport:
  read_chunk_size: 65535
  drain_bytes: 262144
  drain_interval_ms: 10
  socket_send_buffer: 0
  socket_recv_buffer: 0
  tcp_nodelay: true
  tcp_keepalive: true
  pending_buffer_limit: 1048576
```

Cloudflare and other public speed endpoints can rate-limit concurrent curl tests
with HTTP `429` or tiny response sizes. Use raw `iperf3` port tests and mobile
app tests alongside tunnel-level curl checks.
```

`performance.profile` only selects defaults for local read sizes, drain cadence,
and optional socket buffers. Explicit `transport.*` keys override the profile.
`read_chunk_size` is capped at 65535 because the active frame payload length is
still a 16-bit field.

- **Server:** ~50MB base + ~1MB per active connection
- **Client:** ~30MB base + ~0.5MB per active channel

### ⚙️ Concurrency Model

Both client and server use Python's `asyncio` for efficient handling of multiple simultaneous connections without threads.

---

## Production Deployment Assumptions

- In normal mode, the server role runs on the outside/VPS host and listens for inbound tunnel sessions.
- In normal mode, the client role runs beside V2Ray or the application and exposes local SOCKS5.
- In reverse mode, the Iran-side Access Node runs `client.py` with `client.mode: reverse-listen`; the VPS Exit Node runs `server.py` with `server.mode: reverse-dial`.
- Reverse mode supports multiple VPS-to-Access tunnel sessions with `tunnel.connections`. New SOCKS channels use least-active-session selection. Existing channels on a failed session fail cleanly and new channels avoid the dead session.
- The tested production target for this deployment is reverse port `8443`, `tunnel.connections: 20`, and `performance.profile: throughput`.
- Reverse mode requires the Access Node reverse listener port to be reachable from the VPS. NAT/CGNAT requires port forwarding or a different rendezvous/relay design.
- Reverse mode TLS uses the Access Node certificate. Let's Encrypt HTTP-01, DNS-01/manual, existing certificates, and private CA fallback are installer-supported.
- `scripts/bootstrap.sh` is the supported GitHub entry point for fresh installs and upgrades. It downloads a selected branch/tag/ref, then delegates to `install.sh`.
- Production installs use `/opt/smtp-tunnel` for application code, `/opt/smtp-tunnel/venv` for Python dependencies, `/etc/smtp-tunnel/config.yaml` for active config, `/etc/smtp-tunnel/users.yaml` for users, and `/etc/smtp-tunnel/certs` for private CA/server certificates.
- Server-side client packages are tar.gz bundles containing one user's client config, `ca.crt` when available, runtime files, and install notes. They must not include server private keys or other users' credentials.
- Install/upgrade operations back up existing application files, config, users, certificates, and the service unit under `/var/backups/smtp-tunnel/YYYYMMDD-HHMMSS/` and write a `rollback.sh`.
- TLS verification is recommended. For private-CA deployments, copy `ca.crt` to the client and set `client.ca_cert`.
- New installs use client-originated keepalive and jittered reconnect defaults. Existing configs continue to use runtime fallbacks unless migrated.
- `users.yaml` is loaded on server startup. Restart the service after adding, deleting, or editing users.
- Long-lived TLS over an SMTP-like port and Python/OpenSSL TLS fingerprints remain observable. This project does not provide any guarantee against DPI/firewall detection or blocking.

---

## 📋 Version Information

- **Current Version:** 1.3.0
- **Protocol Version:** Binary streaming v1
- **Minimum Python:** 3.8

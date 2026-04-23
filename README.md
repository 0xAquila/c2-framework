# C2//OPS Framework

A command-and-control framework built for portfolio demonstration and red team education. Implements real adversary infrastructure techniques — beaconing, C2 profiles, encrypted comms, ECDH forward secrecy, and operator tooling — in a clean, understandable codebase.

> **Disclaimer:** This project is for educational purposes and authorized lab use only. Do not deploy against systems you do not own or have explicit written permission to test.

---

## Dashboard

![Diagram architecture](diagrams/diagram_architecture.png)

![Network map with two active agents](map_2_targets.png)
---

## Security Architecture

This is not a basic "send commands over HTTP" demo. Every layer is hardened:

| Layer | Implementation |
|---|---|
| **Transport** | TLS 1.3 — self-signed cert, CN: `nexacloud.io` |
| **Payload** | AES-256-CBC — random IV per message, base64 transport |
| **Key exchange** | ECDH (SECP256R1) — per-session key derived via HKDF-SHA256. Capturing one agent's traffic does not compromise any other session. |
| **Auth — agents** | Per-agent session tokens issued post-ECDH. Burning one token only kills that agent. |
| **Auth — operator** | X-Operator-Key gateway header + session-based login. `/login` returns 404 without the header — indistinguishable from any missing page. |
| **Error pages** | All errors (404/403/405/500) render an nginx-style template. `Server` header spoofed to `nginx/1.24.0` on every response. |
| **Cert pinning** | SHA-256 fingerprint embedded in generated agents. MITM proxy presents a different cert — agent exits silently. |
| **DB at rest** | Sensitive SQLite fields (hostname, IP, username, commands, results) encrypted with AES-256-CBC at column level. |
| **Agent identity** | Random UUID persisted to a hidden file — not the MAC address. |
| **Secrets** | No hardcoded fallbacks. Server refuses to start if any secret is missing from the environment. |
| **Rate limiting** | Beacon endpoints rate-limited. Limit violations return 404 — identical to wrong token, no fingerprinting. |

---

## C2 Profile — The Decoy

The server actively lies. Every visitor type gets a different response:

| Visitor | Has | Sees |
|---|---|---|
| Agent | `X-Beacon-Token` header | Beacon endpoints (encrypted) |
| Operator | `X-Operator-Key` header + credentials | Redirect to `/login` → Dashboard |
| Analyst / scanner | Nothing | NexaCloud decoy site |
| Anyone hitting `/login` without the header | Nothing | `404 Not Found` (nginx error page) |

![NexaCloud decoy site](decoy_site.png)

---

## Features

**Operator Dashboard**
- Live network map — agents shown as nodes, OS identified, click for detail panel
- MITRE ATT&CK tagged command results
- Screenshot gallery — captures transmitted over beacon channel
- Event log — full audit trail of every registration, task, and result
- Agent notes — operator annotations per compromised host
- Payload generator — pre-configured agents in Python
- Dropper generator — PowerShell, Python, Bash, VBScript, VBA macro delivery vehicles

**Agent Capabilities**
```
shell <cmd>         arbitrary shell command
sysinfo             hostname, IP, OS, username, arch
screenshot          full screen capture → gallery
clipboard           read clipboard (Windows/Linux)
netstat             active connections
arp                 ARP table (network discovery)
privs               privilege level + admin check
ps                  running processes
env                 environment variables
download <path>     file exfiltration (base64)
upload <path> <b64> file write to victim
sleep <seconds>     change beacon interval live
keylogger start/dump/stop
persist add/remove  HKCU Run key (Windows, survives reboot)
kill                terminate agent
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- pip
- [Burp Suite Community](https://portswigger.net/burp/communitydownload) (for operator access)

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate secrets

```bash
cd server
python setup_secrets.py
```

This creates `server/.env` with cryptographically random values for all secrets. The operator password is printed once — save it.

### 3. Generate TLS certificate

```bash
python gen_cert.py
```

Creates `cert.pem`, `key.pem`, and `cert_fingerprint.txt` (used for agent certificate pinning).

### 4. Start the server

```bash
python app.py
```

Server starts on `https://0.0.0.0:5000`.

### 5. Configure Burp Suite for operator access

`/login` is a hidden endpoint — it returns `404 Not Found` to any request that does not carry the correct `X-Operator-Key` header. The login form is invisible to scanners, analysts, and browsers without the gateway header. Even knowing the URL does not help without the key.

The easiest way to inject the header automatically on every request:

1. Open Burp Suite → **Proxy** → **Options** → **Match and Replace** → **Add**
2. Type: `Request header`
3. Match: *(leave blank)*
4. Replace: `X-Operator-Key: <your OPERATOR_KEY from .env>`
5. Set your browser to use Burp's proxy (`127.0.0.1:8080`)

![Burp Suite Match and Replace rule](auto_header_editor.png)

6. Navigate to `https://127.0.0.1:5000` — the server detects the header and redirects to `/login`
7. Accept the self-signed cert warning, then log in with `OPERATOR_USER` / `OPERATOR_PASS` from `.env`

![Login page with injected header](login_with_header_added.png)

### 6. Deploy an agent

**Option A — Manual (dev/testing)**

Edit `agent/config.py`:
```python
C2_SERVER      = "https://<server-ip>:5000"
API_KEY        = "<C2_API_KEY from .env>"
ENCRYPTION_KEY = "<ENCRYPTION_KEY from .env>"
CERT_FINGERPRINT = "<contents of server/cert_fingerprint.txt>"
```

Then run:
```bash
python agent/agent.py
```

**Option B — Generator (recommended)**

1. In the dashboard, go to **Generator** tab
2. Enter server address, adjust beacon interval
3. Click **Generate Agent** → download the file
4. The generated agent has all config pre-filled, including the cert fingerprint

---

## Architecture

![Architecture Overview](diagrams/diagram_architecture.png)

---

## Gallery

| Screenshot | Event Log |
|---|---|
| ![Screenshot gallery](screenshot_tab.png) | ![Event log](event_log.png) |

![Payload generator](payload_gen.png)

---

## Encryption

![Encryption layers](diagrams/encryption_layers.png)

**Without encryption (HTTP)** — Wireshark reads everything:

![Wireshark unencrypted](wireshark_old.png)

**With TLS + AES** — zero readable content:

![Wireshark encrypted](wireshark_new.png)

---

## Project Structure

```
c2-framework/
├── server/
│   ├── app.py                  Flask factory — config, blueprints, TLS
│   ├── crypto.py               AES-256-CBC + ECDH + HKDF
│   ├── database.py             SQLAlchemy models with EncryptedText columns
│   ├── extensions.py           Flask-Limiter instance
│   ├── gen_cert.py             TLS cert generator + fingerprint output
│   ├── setup_secrets.py        One-time secret generation → .env
│   ├── mitre.py                MITRE ATT&CK command → technique mapping
│   ├── routes/
│   │   ├── agent.py            Beacon endpoints (ECDH, rate-limited)
│   │   ├── operator.py         Operator API
│   │   ├── auth.py             Gateway + session auth
│   │   ├── gallery.py          Screenshot gallery
│   │   ├── generator.py        Agent + dropper generator
│   │   ├── eventlog.py         Event log
│   │   └── map.py              Network map
│   └── templates/              Jinja2 HTML templates
├── agent/
│   ├── agent.py                Hardened agent — ECDH, cert pinning, all commands
│   └── config.py               Per-deployment configuration
├── diagrams/                   Architecture and flow diagram screenshots
├── requirements.txt
├── HOW_IT_WORKS.md             Technical deep-dive
├── BUILD_PROCESS.md            Build narrative and design decisions
└── README.md
```

---

## Documentation

- **[HOW_IT_WORKS.md](HOW_IT_WORKS.md)** — technical explanation of every component, with diagrams and Wireshark captures
- **[BUILD_PROCESS.md](BUILD_PROCESS.md)** — honest build narrative covering architecture decisions, challenges, and security hardening

---

## Tech Stack

`Python 3.10+` · `Flask` · `SQLAlchemy` · `SQLite` · `cryptography` · `Flask-Limiter` · `Pillow` · `TLS 1.3` · `AES-256-CBC` · `ECDH SECP256R1` · `HKDF-SHA256`

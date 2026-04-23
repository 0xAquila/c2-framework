"""
SQLAlchemy models for the C2 framework.

Sensitive fields (hostname, ip, username, command, output) are encrypted at rest
using EncryptedText — a TypeDecorator that transparently applies AES-256-CBC
encryption when reading/writing those columns. The DB_ENCRYPTION_KEY is kept
separate from the beacon ENCRYPTION_KEY so they can be rotated independently.
"""

import os
import base64
import uuid
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import types
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

db = SQLAlchemy()


# ── Encrypted column type ──────────────────────────────────────────────────────

class EncryptedText(types.TypeDecorator):
    """
    Column type that AES-256-CBC encrypts values before writing to SQLite
    and decrypts transparently on read.

    Stored format: base64( IV[16 bytes random] + AES-256-CBC(PKCS7(UTF-8 value)) )

    If the DB is seized without the DB_ENCRYPTION_KEY, all encrypted columns
    appear as opaque base64 ciphertext — hostnames, IPs, usernames, commands,
    and results are unreadable.
    """
    impl  = types.Text
    cache_ok = True

    @staticmethod
    def _key() -> bytes:
        from flask import current_app
        return bytes.fromhex(current_app.config['DB_ENCRYPTION_KEY'])

    def process_bind_param(self, value, dialect):
        """Encrypt before writing to DB."""
        if value is None:
            return None
        key = self._key()
        iv  = os.urandom(16)
        raw = value.encode('utf-8')
        pad = 16 - len(raw) % 16
        raw += bytes([pad] * pad)
        enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
        ct  = enc.update(raw) + enc.finalize()
        return base64.b64encode(iv + ct).decode('ascii')

    def process_result_value(self, value, dialect):
        """Decrypt after reading from DB. Falls back to raw value on failure."""
        if value is None:
            return None
        try:
            key = self._key()
            raw = base64.b64decode(value)
            iv, ct = raw[:16], raw[16:]
            dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
            pt  = dec.update(ct) + dec.finalize()
            return pt[:-pt[-1]].decode('utf-8')
        except Exception:
            return value  # Graceful fallback for unencrypted legacy rows


# ── Models ─────────────────────────────────────────────────────────────────────

class Agent(db.Model):
    __tablename__ = 'agents'
    id           = db.Column(db.String(36),  primary_key=True)
    hostname     = db.Column(EncryptedText)            # encrypted at rest
    ip           = db.Column(EncryptedText)            # encrypted at rest
    os           = db.Column(db.String(255))           # not PII, unencrypted for filtering
    os_version   = db.Column(db.String(255))
    username     = db.Column(EncryptedText)            # encrypted at rest
    first_seen   = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen    = db.Column(db.DateTime, default=datetime.utcnow)
    status       = db.Column(db.String(20), default='active')
    # ECDH session state — unique per registration, replaced on every reconnect
    session_key  = db.Column(db.String(64), nullable=True)   # HKDF-derived hex key
    session_token = db.Column(db.String(64), nullable=True)  # per-agent bearer token
    tasks  = db.relationship('Task',      backref='agent', lazy=True)
    notes  = db.relationship('AgentNote', backref='agent', lazy=True)


class Task(db.Model):
    __tablename__ = 'tasks'
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id    = db.Column(db.String(36), db.ForeignKey('agents.id'), nullable=False)
    command     = db.Column(EncryptedText, nullable=False)   # encrypted at rest
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    status      = db.Column(db.String(20), default='pending')
    mitre_id    = db.Column(db.String(20))
    mitre_name  = db.Column(db.String(120))
    mitre_tactic = db.Column(db.String(60))
    mitre_color  = db.Column(db.String(10))


class Result(db.Model):
    __tablename__ = 'results'
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id     = db.Column(db.String(36), db.ForeignKey('tasks.id'), nullable=False)
    agent_id    = db.Column(db.String(36), nullable=False)
    output      = db.Column(EncryptedText)               # encrypted at rest
    output_type = db.Column(db.String(20), default='text')  # 'text' | 'screenshot'
    received_at = db.Column(db.DateTime, default=datetime.utcnow)


class AgentNote(db.Model):
    __tablename__ = 'agent_notes'
    id        = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id  = db.Column(db.String(36), db.ForeignKey('agents.id'), nullable=False)
    content   = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class EventLog(db.Model):
    __tablename__ = 'event_log'
    id            = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    event_type    = db.Column(db.String(50), nullable=False)
    agent_id      = db.Column(db.String(36), nullable=True)
    agent_hostname = db.Column(db.String(255), nullable=True)  # plaintext copy for log readability
    description   = db.Column(db.Text)

